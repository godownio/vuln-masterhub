---
id: binary-pwn-sandbox-escape-python-eval-filter-bypass
title: eval 沙箱的源码黑名单与单表达式限制绕过
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-eval-filter-bypass
aliases:
- eval 沙箱绕过
- Unicode 沙箱绕过
- NFKC 绕过
- pyjail 过滤绕过
- 海象表达式绕过
tags:
- python
- pyjail
- sandbox-escape
- unicode
- nfkc
- eval
- waf-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-H
  verified_at: '2026-11-04T19:40:03+08:00'
  notes: 来源 93062；已对照原文核对；NFKC 全角标识符绕过、exec/compile 突破单表达式限制、海象表达式串联赋值均与原文一致；未在真实目标环境复测。
---

## 一句话结论

`eval` 沙箱若只对“原始源码字符串”做正则黑名单、却把完整 `__builtins__` 暴露给执行环境，可以用 Unicode 兼容字符（如全角字母）让正则看不见危险单词、而 Python 解析器在 NFKC 规范化后还原成正常标识符；再配合 `exec`/`compile`/海象表达式突破 `eval` 只能执行单条表达式的限制。

## 原理

Python 3 允许非 ASCII 标识符，并在编译前按 NFKC 规范化标识符。全角 `ｏｐｅｎ` 是 ASCII `open` 的兼容字符，NFKC 后等价于 `open`；但正则匹配的是原始字符串，`\bopen\b` 匹配不到全角形式。于是“检查的字符串”和“实际执行的代码”不是同一个东西。

`eval` 只接受表达式，但 `exec()`、`compile()` 是函数调用，本身是表达式；把语句写成字符串传给它们即可执行多行代码。Python 3.8+ 的海象运算符 `:=` 允许在表达式内部完成赋值，从而在单个表达式里串联“导入模块 → 调用方法”。

## 触发条件

- 过滤发生在原始源码层面，且过滤后没有再做 NFKC 规范化或非 ASCII 标识符拒绝；
- 执行时仍暴露完整 `__builtins__`（例如 `eval(line, {"__builtins__": __builtins__})`）；
- 只按 `eval` 的表达式语义限制了语句，但没有禁用 `exec`、`compile`、`__import__`；
- 全角字符能进入输入且不被额外转义（过滤 `\u`/`\x` 转义不影响直接输入的全角字符）。

## 利用步骤

1. 确认过滤是对原始字符串做正则，且执行环境内置函数可用；
2. 把黑名单中的 ASCII 关键字替换成等价的全角字符，例如 `ｏｐｅｎ`、`ｉｍｐｏｒｔ`；
3. 直接 `eval` 触发；若目标只允许单表达式，用 `exec('...')` 或 `compile(...,'','exec')` 包裹语句；
4. 需要在一个表达式里完成多步时使用海象运算符；
5. 读取文件或执行命令验证。

## PoC

```python
# 全角标识符：正则看到的是 ｏｐｅｎ，Python 解析后是 open
ｏｐｅｎ('/flag').read()

# eval 中执行多行语句
eval("exec('import os\\nprint(os.getcwd())')")

# 编译为 code object 再执行（exec/eval 被禁时的替代）
eval(compile('import os;os.system("id")', '', 'exec'))

# 海象表达式：单个表达式中完成导入和调用（3.8+）
eval('[a := __import__("os"), b := a.system("id")]')
```

全角字符适用于字母标识符，不适用于字符串字面量或标点；`import("os")` 不是合法调用，导入模块要用 `__import__("os")`。

## 变体与关联

- 变体：其他 NFKC 兼容字符（数学字母、带圈字母等）；用 `chr()`/`bytes(...).decode()` 在运行时构造关键字；用 `compile` 绕过多行限制；用海象运算符在列表/元组推导中串联赋值。
- 关联：子类遍历基础逃逸；审计钩子沙箱中同样可以用 chr/bytes 拼关键字；同形异义字符（如西里尔字母）不被 NFKC 折叠为 ASCII，不能直接替代。

## 检测与防御

- 检测：输入中出现非 ASCII 标识符、全角字母；`exec`/`compile`/`__import__`/海象运算符与字符串拼接组合。
- 防御：过滤前先做 NFKC 规范化，并拒绝或白名单非 ASCII 标识符；不要用正则黑名单作为主要防线，使用 AST 白名单并禁止 `Call`/`Attribute`/`Import` 等节点；执行环境使用独立进程和系统级隔离，且不向不可信代码暴露完整 `__builtins__`。
- 单靠禁用 `eval`/`exec` 字符串不够，`compile`、`__import__`、对象属性链都可能成为替代路径。
