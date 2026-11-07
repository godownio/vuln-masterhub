---
id: binary-pwn-sandbox-escape-nfkc-ast-name-decorator-cr-bypass
title: AST 变量名回查 + 禁括号 pyjail：NFKC 全角标识符、装饰器链与 \r 换行绕过
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-ast-name-source-check-nfkc-decorator-cr-bypass
tags:
- python
- pyjail
- ast
- nfkc
- unicode
- decorator
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:02:17+08:00'
  notes: 已对照原文no nonsense核对：全角eval/bytes/format、装饰器链、\r换行、class _:pass 与exp一致；未验证点：未复跑；卡内等价式把format位置写反，实际为eval(bytes.fromhex("<hex>".format(_)))，属表述小瑕疵。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-nfkc-ast-name-decorator-cr-bypass/
draft: false
kb_aliases:
- no nonsense
- JailCTF 2024 no nonsense
- AST Name 检查绕过
- 装饰器链无括号调用
- \r 换行绕过 input
---

## 一句话结论

当 pyjail 用 `ast.parse` 后的 `Name.id` 回查“标识符是否原样出现在源码中”，同时禁用 `(`、`[`、`=` 时，可以用全角字母写 `ｅｖａｌ` 让 AST 规范化成 `eval` 而原始字符串里看不到 `eval`，用装饰器链在不写括号的情况下完成 `eval(bytes.fromhex("...").format(...))`，再用 `\r` 代替 `\n` 在单次 `input()` 中塞入多行装饰器与类定义，最终执行任意代码。

## 原理

- **检查对象错位**：`NoNonsenseVisitor.visit_Name` 检查的是 `n.id in inp`，即“AST 规范化后的标识符是否作为子串出现在原始输入里”。Python 在词法分析阶段会对标识符做 NFKC 规范化：全角 `ｅｖａｌ`、`ｂｙｔｅｓ`、`ｆｏｒｍａｔ` 在 AST 中分别变成 `eval`、`bytes`、`format`，但原始 `inp` 中仍是全角字符，因此 `'eval' in inp` 为假，检查通过。
- **无括号调用**：`([=])` 禁掉了普通函数调用、下标和赋值。装饰器语法 `@expr` 等价于 `f(目标对象)`，在解析阶段自动完成一次调用，不需要写括号；多个装饰器从下往上依次应用。
- **装饰器链**：`class _:pass` 先创建类对象 `_`；`@"<hex>".format` 把 `_` 作为参数传给 `str.format`，由于格式串没有占位符，多余参数被忽略，返回 hex 字符串本身；`@bytes.fromhex` 把字符串解成字节；最上层的 `@ｅｖａｌ` 对字节调用 `eval`，执行字节里的 Python 代码。
- **换行绕过**：`input()` 读到 `\n` 就停止，但会保留 `\r`；Python 的源码解析器把 `\r` 同样视为换行。因此把载荷中的 `\n` 全部换成 `\r`，就能在一次 `input()` 中提交多行装饰器和 `class` 定义，而不会提前结束输入。
- **检查盲区**：`visit_Name` 只处理 `Name` 节点；类名 `_` 存在 `ClassDef.name` 字符串里，不是 `Name` 节点，所以不会被回查。

## 触发条件

- 沙箱对源码做 `ast.parse`/`NodeVisitor` 检查，且检查逻辑是“标识符是否出现在原始字符串”这类字符串包含判断。
- 过滤器禁用括号/中括号/等号，但没有禁用装饰器 `@`，也没有拒绝非 ASCII 标识符。
- 执行端仍保留完整 `__builtins__`（至少 `eval`/`bytes`/`format` 可用）。
- 输入通过 `input()` 单行读入，但后续 `exec` 能接受 `\r` 作为换行。

## 利用步骤

1. 确认过滤字符集与 AST 检查的具体逻辑：是否只查 `Name.id`、是否对源码做 NFKC、是否允许 `@` 和全角字符。
2. 把要执行的 Python 代码转成 hex，避免任何括号、引号、等号出现在最终源码里。
3. 用全角字符拼出装饰器名：`@eｖal`、`@byｔes.fromhex`、`@"<hex>".foｒmat`；最底层放 `class _:pass` 作为装饰器参数。
4. 把生成的多行字符串中的 `\n` 全部替换成 `\r`，一次性提交。
5. 装饰器链会依次执行 `format` → `bytes.fromhex` → `eval`，运行 hex 中的任意代码（如 `__import__('os').system('cat flag.txt')`）。

## PoC

```python
e = "__import__('os').system('cat flag.txt')"
e = e.encode().hex()

payload = f"""@eｖal
@byｔes.fromhex
@"{e}".foｒmat
class _:pass
""".replace("\n", "\r")

print(payload)
```

```text
# 实际提交给 input() 的字符串（\r 显示为换行）：
@eｖal\r@byｔes.fromhex\r@"<hex>" .foｒmat\rclass _:pass\r
# 等价执行：
# eval(bytes.fromhex("<hex>").format(_))
# 即 eval(b"__import__('os').system('cat flag.txt')")
```

## 变体与关联

- 若 `format` 被过滤，可用其他“接收任意对象并返回字符串”的装饰器，如 `@repr`、`@str`；若 `bytes.fromhex` 不可用，可用 `@ｅｖａｌ` 直接接收全角/转义字符串。
- 若 `@` 被禁，可寻找其他无括号调用语法（如 `with` 上下文管理器、`except` 匹配、类继承 `class X(Y)` 仍需括号）。
- 关联：[[binary-pwn-sandbox-escape-python-eval-filter-bypass]]（NFKC 绕过正则黑名单）、[[binary-pwn-sandbox-escape-python-regex-ast-alias-concat]]（AST/正则双层黑名单的其他绕过）。
- 边界：如果 AST 检查改为“白名单允许的节点/标识符”，或执行前对源码再次做 NFKC 并用规范化结果做检查，本手法失效；如果过滤器拒绝所有非 ASCII 字符，也无法使用全角标识符。

## 检测与防御

- 检测：审计 pyjail 的 AST 检查是否只比较原始源码字符串；对输入中出现全角字母、数学字母、零宽字符等非 ASCII 标识符告警；监控装饰器链式嵌套与 `\r` 分隔的多行输入。
- 修复：不要执行用户提供的 Python 源码；必须执行时使用 AST 白名单（只允许字面量、算术、允许的函数名），并在 NFKC 规范化后再做检查；显式拒绝非 ASCII 标识符和装饰器语法。
- 加固：清空 `__builtins__` 或使用受限命名空间；把 `input()` 改为一次性读取并拒绝 `\r`；在独立低权限进程/容器中运行，不把 flag 放在可读路径。
