---
id: binary-pwn-sandbox-escape-python-coroutine-cr-frame
title: Python 沙箱：未 await 协程的 cr_frame 直接取 f_globals 逃逸
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-coroutine-frame-escape
tags:
- python
- pyjail
- sandbox-escape
- cpython
- frame
- coroutine
- builtins
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:20:13+08:00'
  notes: 已对照图 11 核对未 await 协程 cr_frame.f_globals['__builtins__'].__import__('os').system 执行与 RuntimeWarning；已修正原文 __import__.('os') 的语法错误；未验证点：原文未在 __builtins__ 置空的真实沙箱中验证，卡片已标 medium
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-coroutine-cr-frame/
draft: false
kb_aliases:
- 协程 cr_frame 逃逸
- async def 栈帧逃逸
- Python 3.11 生成器帧失效替代
- cr_frame f_globals
---

## 一句话结论

在只禁止 `import`、`sys`、`__builtins__` 相关源码写法、但仍允许 `async def` 与属性访问的 Python 沙箱中，可以创建一个永不 `await` 的协程，通过 `coro.cr_frame.f_globals['__builtins__'].__import__('os')` 取回导入能力和命令执行；该路径不依赖 `f_back`，因此在 Python 3.11+ 生成器静态帧链失效时仍可用。

## 原理

- `async def` 定义的函数被调用时不会执行函数体，而是返回一个协程对象；CPython 在创建协程时就已经分配了帧，挂在 `cr_frame` 属性上，与生成器的 `gi_frame` 地位相同。
- 协程帧的 `f_globals` 指向协程**定义/执行所在的模块全局字典**。如果沙箱只做了源码级过滤（禁止 `import` 关键字、禁止出现 `sys`/`__builtins__` 字样），但执行代码时使用的 globals 仍带有真实的 `__builtins__`，那么该字典里可以直接取到 `__import__`。
- 因为不需要 `f_back` 回溯调用者，协程路径避开了 Python 3.11+ 的一个限制：挂起状态、尚未运行的生成器 `gi_frame.f_back` 为 `None`，导致 `gi_frame.f_back...` 链断裂。协程只需创建即取 `cr_frame`。
- 获取 `__builtins__` 有两种形态：模块（`bti.__import__`）或 dict（`bti['__import__']`）；随后 `__import__('os').system('whoami')`。
- 关键前提：`cr_frame.f_globals` 中的 `__builtins__` 必须是真实可用的，而不是被 `exec(code, {'__builtins__': None}, ...)` 置空。若沙箱把 exec globals 的 `__builtins__` 置 None，本路径失效，需要改用 `f_back` 回溯外层解释器帧（见关联卡）。

## 触发条件

- 目标允许提交/执行 Python 代码，且 `async def`、协程对象、属性访问未被禁用；
- 沙箱仅做源码/名称黑名单（过滤 `import`、`sys`、`open`、`__` 等），执行环境的 `f_globals` 仍保留真实 `__builtins__`；
- Python 版本 ≥ 3.5（协程语法）；在 3.11+ 场景下尤其适合替代失效的生成器静态帧；
- 若 `__builtins__` 被置空，需目标同时允许 `f_back` 或异常回溯路径。

## 利用步骤

1. 确认可以定义并调用 `async def`（无需 `await`）。
2. 创建一个空协程：`c = spy()`；此时函数体未执行，但 `c.cr_frame` 已存在。
3. 从 `c.cr_frame.f_globals` 取 `__builtins__`，判断是模块还是 dict。
4. 用 `__import__('os')` 导入 os，执行 `system('whoami')` 或读 flag。
5. 忽略 `RuntimeWarning: coroutine 'spy' was never awaited`；这正是“未执行但已建帧”的副作用。

## PoC

```python
async def spy():
    pass

c = spy()  # 不 await，代码未执行，但已分配协程帧

# 模块形态的 __builtins__
os_mod = c.cr_frame.f_globals['__builtins__'].__import__('os')

# 若 __builtins__ 是 dict
# os_mod = c.cr_frame.f_globals['__builtins__']['__import__']('os')

os_mod.system('whoami')
```

触发后输出当前用户（如 `laptop-...`），并伴随：

```text
RuntimeWarning: coroutine 'spy' was never awaited
```

## 变体与关联

- 变体：`__builtins__` 为 dict 时用下标取 `__import__`；被过滤 `__` 时用字符串拼接构造键名。
- 变体：协程帧的 `f_locals` 可读取协程定义处捕获的局部变量；`cr_code.co_consts` 可读硬编码常量。
- 关联：[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]（生成器 gi_frame 回溯；本文补充 cr_frame 在 3.11+ 的替代路径）。
- 关联：[[binary-pwn-sandbox-escape-python-traceback-frame-escape]]（异常回溯取帧，另一条不依赖 f_back 的路径）。
- 局限：原文在普通脚本中演示，未在“`__builtins__` 置空”的真实沙箱中验证；该前提决定了本路径是否可用，故 confidence 记 medium。

## 检测与防御

- 检测：用户代码中出现 `async def`、`cr_frame`、`f_globals`、`__builtins__`、`__import__` 等组合；出现“创建协程但不 await”的模式。
- 检测：运行时告警 `coroutine ... was never awaited` 与随后命令执行/文件读取的关联。
- 防御：不要把 `exec`/`eval` 当沙箱；不可信代码放到独立进程/容器，低权限、只读文件系统、无网络、seccomp。
- 防御：若必须做 Python 层限制，使用 AST 白名单，禁止 `AsyncFunctionDef`、`Attribute`、`Subscript` 等可触达帧对象的语法；同时确保执行 globals 的 `__builtins__` 确实为空，且没有外层帧可回溯。
