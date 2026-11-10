---
id: web-python-deserialization-pker-opcode-primitives
title: pker 语法到 pickle opcode 的映射：GLOBAL/INST/OBJ/属性赋值/索引赋值/return 六类原语与可写不可读约束
type: scenario
domain: web
path: web/python/deserialization
technique: pker-opcode-primitive-mapping
tags:
- python
- pickle
- pker
- opcode
- payload-generation
- deserialization
- setitem
- setattr
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:40:17+08:00'
  notes: 已对照原文核对；GLOBAL/INST/OBJ/R/s/b/0 六类映射与原文一致，可写不可读约束与原文描述一致；属载荷构造方法论卡，最终危害由关联的 SETITEM/SETATTR 利用链证明，未执行载荷
url: /docs/web/python/deserialization/web-python-deserialization-pker-opcode-primitives/
draft: false
kb_aliases:
- pker 语法
- pickle opcode 手写
- GLOBAL INST OBJ 区别
- SETITEM SETATTR opcode
- pickle 载荷手写原语
---

## 一句话结论

手写 pickle 载荷时可以按 pker 的六类语法直接映射到 opcode：`GLOBAL(module,name)`→`c`（按名字取模块属性）、`INST(module,func,args...)`→`i`（建实例/执行函数）、`OBJ(callable,args...)`→`o`（对栈上 callable 传参执行）、`fn(args)`→`R`（`r`/`R` 的 REDUCE 调用）、`lst[i]=v` / `dict[k]=v`→`s`（SETITEM）、`obj.attr=v`→`b`（SETATTR）、`return x`→`0`（STOP，出栈作为 `loads` 返回值）；关键约束是**索引与点号访问只能作赋值左值，不能作取值右值**——想"读"必须改用 `getattr(obj,'x')` 或 `dict.get(k)`，这直接决定了载荷的设计方式。

## 原理

- **GLOBAL（`c`）**：`c<module>\n<name>\n` 让 unpickler 调 `find_class(module,name)` 并把结果入栈。它是最基础的"取对象"原语，模块不必事先 import（unpickler 会自己 import），因此 `GLOBAL('os','system')` 能直接拿到 `os.system`。
- **INST（`i`）**：`(i<module>\n<name>\n...` —— 建一个"类实例"并把栈上参数交给它；在 protocol 0 语义里等价于 `cls(*args)`。用它既能实例化普通类（`INST('__main__','Animal','1','2')`），也能直接执行函数（`INST('os','system','whoami')`），因为 Python 侧都是 callable。
- **OBJ（`o`）**：`(o` —— 先压入 callable（常来自 `GLOBAL`），再压参数、`o` 触发出栈调用，等价于 `callable(*args)`；多参数即 `OBJ(GLOBAL(m,f), p0, p1, ...)`。
- **REDUCE（`R`）**：先把 callable 与参数元组/参数压栈，`R` 执行 `callable(*args)`。pker 里写 `system(s)` 这种"函数调用"就落到 `R`；`b'R'` 与 `b'r'` 的区别只在是否带参数字典/全局。
- **SETITEM（`s`）**：`s` 对"栈上对象 + 键 + 值"执行 `obj[key]=value`，可用于写列表下标（`li[0]=321`）和字典键（`globals_dic['local_var']='hello'`）。这是篡改模块字典/`sys.modules` 等运行时状态的核心原语。
- **SETATTR（`b`）**：`b` 执行 `setattr(obj, name, value)`，用于 `xx.attr=123` 与覆盖模块级变量（如 `game.curr_ticket='123'`）。
- **STOP（`0`）**：`0` 停止反序列化并把栈顶作为 `loads()` 返回值；一次只能返回一个对象（即便写逗号也只回一个元组）。
- **可写不可读的成因**：pickle 栈机对"取值"只提供 `GLOBAL`（按名字）与 `REDUCE`（调函数）；没有"按索引取字典值"或"按属性名取对象属性"的原语。因此 `value = obj.attribute`、`value = my_dict[key]` 这类右值写法无法编码，必须绕成 `getattr(obj,'attribute')`/`my_dict.get(key)`（各对应一次 `GLOBAL` + `REDUCE`）。而赋值方向恰好有 `s`/`b` 两个专用 opcode，所以"写"不受限——这正是许多绕过（篡改黑名单列表、覆盖模块变量、重绑 `sys.modules`）只依赖赋值的原因。
- **pker 是语法糖而非等价翻译**：原文明确"对应的 opcode 会被生成，但并不与 pker 代码相互等价"——pker 只负责产出字节流，栈上顺序、引用计数、以及"先压 callable 再压参数"的次序仍需自己理解，出错时会得到 `UnpicklingError` 或静默错误结果。

## 触发条件

- 有 `pickle.loads` 类可控入口，且能提交原始字节（不限于 JSON 包装）；
- 需要在不依赖现成 gadget 的情况下，按目标的白名单/过滤条件现场组合原语；
- 了解目标 Python 版本的 pickle opcode 集合（protocol 0 的 `c/i/o/s/b/0` 各版本都支持，protocol 2+ 的 `\x93` STACK_GLOBAL、`BINPUT` 等属扩展）。

## 利用步骤

1. 先明确要达成的动作序列：取对象（GLOBAL）、调函数（REDUCE/OBJ/INST）、写状态（SETITEM/SETATTR）、返回（STOP）。
2. 按"可写不可读"规则改写：需要读属性/取键的地方一律换成 `getattr`/`dict.get` 调用。
3. 用 pker 写等价代码并生成字节流，或用 `pickletools.dis` 反查生成的 opcode 序列，确认栈次序。
4. 本地 `pickle.loads` 验证（用无害动作如 `print`），再替换为目标的危险调用。
5. 若目标有 base64 等包装，解码后再交给 `pickle.loads`；注意载荷里不能出现被黑名单匹配的子串（如 `os`、`system`），此时把字符串拆成 SETITEM 拼接或用 `_codecs.encode` 变换。

## PoC

```python
# pker 思路（生成等价 pickle 字节流），六类原语示例
s = 'whoami'
system = GLOBAL('os', 'system')     # c: 取 os.system
system(s)                           # R: 调用
return                              # 0: STOP

# INST 直接执行
INST('os', 'system', 'whoami')      # i

# OBJ 对栈上 callable 调用
OBJ(GLOBAL('os', 'system'), 'whoami')   # c + o

# 赋值类原语
li[0] = 321                         # s: SETITEM
globals_dic['local_var'] = 'hello'  # s: SETITEM
xx.attr = 123                       # b: SETATTR

# 读取必须走函数（不能写 obj.attr / dict[key] 作右值）
val = getattr(obj, 'attribute')
val = my_dict.get(key)
```

验证 opcode 序列：

```bash
python -c "import pickletools,sys; pickletools.dis(open('payload.pkl','rb').read())"
```

## 变体与关联

- 变体：protocol 2+ 用 `\x93` STACK_GLOBAL 显式压模块名/属性名，避免 `builtins` 被记成 `builtin` 的差异。
- 变体：用 `\x85` TUPLE1/`\x86` TUPLE2 精确控制 REDUCE 的参数元组，处理"参数个数不匹配"。
- 变体：把 `GLOBAL` 结果先 `BINPUT` 存 memo，后面多次复用（少写字节、也便于构造长链）。
- 关联：[[web-python-deserialization-pickle-sys-modules-self-rebind]]（SETITEM 的实际利用：重绑 `sys.modules['sys']` 绕过白名单）。
- 关联：[[web-python-deserialization-pickle-codetype-function-hijack]]（SETATTR 的实际利用：`setattr(fn,'__code__',CodeType(...))` 接管函数）。
- 关联：[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（"可写不可读"迫使的 getattr 路线，正是白名单绕过的入口）。
- 边界：不同 Python 版本的 CodeType 字段、opcode 支持、`find_class` 行为有差异；pker 生成的字节流需在目标同版本环境验证。

## 检测与防御

- 检测：对 pickle 载荷做 `pickletools` 静态分析，关注 `GLOBAL` 的 (module,name) 是否在允许集合、是否出现 `SETITEM`/`SETATTR` 对模块或函数对象写入（这类写入几乎只出现在攻击载荷）。
- 防御：用严格 `find_class` 允许列表（枚举具体 (module,name)）或改 JSON/MessagePack；反序列化放低权独立进程；禁用 `pickle` 处理不可信数据。
