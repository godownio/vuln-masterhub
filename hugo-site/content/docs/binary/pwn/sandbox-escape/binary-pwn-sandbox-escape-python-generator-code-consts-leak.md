---
id: binary-pwn-sandbox-escape-python-generator-code-consts-leak
title: Python 沙箱：生成器 gi_code 常量池与 gi_yieldfrom 嵌套帧信息泄露
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-generator-code-leak
tags:
- python
- pyjail
- sandbox-escape
- cpython
- generator
- code-object
- information-disclosure
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:20:16+08:00'
  notes: 已对照原文核对 gi_code.co_consts/co_filename/co_code 与 gi_yieldfrom 内层帧；未验证点：co_consts 与 yieldfrom 示例无截图，属信息泄露原语而非直接 RCE
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-generator-code-consts-leak/
draft: false
kb_aliases:
- gi_code.co_consts
- 生成器常量池泄露
- gi_yieldfrom 嵌套帧
- 不执行生成器读 flag
---

## 一句话结论

在 Python 沙箱中即使无法执行生成器、无法回溯 `gi_frame.f_back`（Python 3.11+ 会断链），仍可通过生成器的 `gi_code` 读取代码对象常量池 `co_consts`、文件名与字节码，泄露硬编码的 flag/密钥；若生成器使用 `yield from`，还可用 `gi_yieldfrom` 拿到内层生成器帧读取其局部变量。

## 原理

- 任何生成器对象都持有 `gi_code`（编译后的代码对象），它不依赖生成器是否运行、帧链是否连通。代码对象的 `co_consts` 元组保存函数体内所有字面量常量：字符串、数字、`None`、嵌套代码对象等。若 flag、密钥、口令被硬编码在函数中，会直接出现在 `co_consts` 里。
- 其他元数据：`co_name` 泄露函数名，`co_filename` 泄露服务器绝对路径（对文件包含/路径拼接类后续利用有价值），`co_code` 是原始字节码，可配合 `dis` 分析。
- `gi_frame` 保存暂停时的栈帧，但 Python 3.11+ 中刚创建、未运行的生成器 `f_back` 可能为 `None`，`gi_frame.f_back...` 链断裂；`gi_code` 不受此影响，是更稳定的信息面。
- `yield from inner()` 会把执行委托给内层生成器。外层生成器的 `gi_yieldfrom` 指向内层生成器对象；拿到它就能访问 `inner_gen.gi_frame.f_locals`（若帧可用）或 `inner_gen.gi_code.co_consts`，深入到被委托的敏感作用域。
- 这条路径的“危害”是信息泄露而非直接 RCE，但在 CTF/沙箱中往往足以直接拿到 flag，且可与帧回溯/代码对象构造组合成更完整的逃逸链。

## 触发条件

- 目标允许用户代码创建/访问生成器对象，且未禁用 `gi_code`、`co_consts`、`gi_yieldfrom` 等属性；
- 敏感数据（flag/密钥/口令）被硬编码在生成器函数或其嵌套函数的源码中，或以局部变量形式存在于尚未清理的内层生成器帧；
- 源码黑名单未覆盖 `gi_code`/`co_consts`/`gi_yieldfrom`，或可用字符串拼接/`getattr` 绕过；
- Python 3.11+ 时仍可直接用 `gi_code`，但 `gi_frame.f_back` 可能为 `None`，需改用协程/异常回溯或先驱动生成器。

## 利用步骤

1. 在受限代码中定义含敏感常量的生成器函数（或拿到题目提供的生成器对象）。
2. 不调用 `next()`，直接取 `g.gi_code.co_consts`，遍历并打印所有常量，寻找 flag/密钥。
3. 若目标使用 `yield from`，对已启动的外层生成器取 `g.gi_yieldfrom`，再访问内层 `gi_frame.f_locals`（若可用）或内层 `gi_code.co_consts`。
4. 需要环境信息时读 `co_filename`、`co_name`；需要逆向时取 `co_code` 配合 `dis`。
5. 将泄露的常量用于后续利用（登录、解密、直接提交 flag）。

## PoC

```python
def check():
    if input() == "FLAG{Hardcoded_Secret}":
        return True
    yield

g = check()
# 不执行生成器，直接读编译期常量
print(g.gi_code.co_consts)
# (None, 'FLAG{Hardcoded_Secret}')
print(g.gi_code.co_name)      # check
print(g.gi_code.co_filename)  # 服务器上的绝对路径
```

```python
# yield from 进入内层生成器作用域
def inner():
    secret = "Deep Secret"
    yield

def outer():
    yield from inner()

g = outer()
next(g)  # 启动，使外层停在 yield from

inner_gen = g.gi_yieldfrom
print(inner_gen.gi_frame.f_code.co_name)  # inner
print(inner_gen.gi_frame.f_locals)        # {'secret': 'Deep Secret'}
print(inner_gen.gi_code.co_consts)        # 内层常量同样可读
```

## 变体与关联

- 变体：`gi_code.co_consts` 中嵌套的 code object 可继续递归读取其 `co_consts`。
- 变体：`gi_frame.f_locals` 在帧可用时直接读变量；3.11+ 帧链断裂后用 `gi_code`/`co_consts`。
- 变体：`__code__.co_consts` 对普通函数同样适用，不限于生成器。
- 关联：[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]（gi_frame.f_back 回溯恢复 builtins）；[[binary-pwn-sandbox-escape-python-coroutine-cr-frame]]（协程帧）；[[binary-pwn-sandbox-escape-python-traceback-frame-escape]]（异常回溯）。
- 局限：仅解决信息泄露，不直接提供命令执行；若 flag 不在常量池/局部变量中，需要结合其他逃逸路径。

## 检测与防御

- 检测：用户代码出现 `gi_code`、`co_consts`、`gi_yieldfrom`、`f_locals`、`__code__` 等属性访问；异常的生成器对象创建后未迭代。
- 检测：沙箱执行结果中出现大量常量枚举/打印（`for i in ...co_consts`）。
- 防御：不要把 flag/密钥硬编码在可执行代码的常量池中；通过独立进程/权限域读取，代码中不出现敏感字面量。
- 防御：真正隔离不可信代码（独立进程/容器、无敏感环境变量与文件）；Python 层黑名单不足以阻止 `co_consts` 读取。
- 防御：若必须限制，AST 白名单禁止 `Attribute` 访问与生成器表达式/`yield`，并过滤 `gi_`/`co_` 相关属性。
