---
id: ctf-misc-bagua-nine-palace-base9-ascii
title: 九宫八卦符号编码：卦象映射 0-8 后按九进制转 ASCII
type: scenario
domain: ctf
path: ctf/misc
technique: bagua-nine-palace-base9-ascii
aliases:
- 九宫八卦编码
- 洛书九宫
- 八卦九进制
- Deduced gossip
- 卦象转 ASCII
tags:
- ctf
- misc
- encoding
- bagua
- base9
- ascii
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:20:18+08:00'
  notes: 已对照原文与图06九宫八卦图核对：映射坎1→0…离9→8(九宫数字-1)与原文dict、示例符号串及九进制转ASCII脚本一致；与bagua-five-stroke卡(笔画数→Unicode码点)机制不同非同链；未验证点：未实际解码
---

## 一句话结论

题目用八卦符号（☰☱☲☳☴☵☶☷ 与“空”）组成空格分隔的符号串，每个符号对应 0–8 的一个数字；把每段符号串按九进制转十进制再转 ASCII 字符，即可还原明文/flag。

## 原理

- 九宫（洛书）把 1–9 排成 3×3：上排 4 9 2、中排 3 5 7、下排 8 1 6，并与八卦方位对应；出题人常用这套对应关系给八卦符号分配 0–8 的数字（不同题目的映射可能不同，需按题面/图片确定）。
- 符号串以空格分段，每段是一个九进制数（digit 0–8）；`int(segment, 9)` 得到十进制码点，`chr()` 即 ASCII 字符。
- 因为 9 进制每位恰好对应一个卦象，符号序列与数字序列一一对应；跨段拼接后即为完整字符串。
- 若直接按八卦二进制（三爻）读会得到 3 bit/卦，但此类题的设计是“符号→数字→九进制”，不要混淆。

## 触发条件

- 题面给出由八卦符号与空格组成的字符串，或图片展示九宫/洛书对应关系。
- 分组长度与 ASCII 码点范围（如 2–3 位九进制数）吻合，转出的字符可打印。
- 符号种类为 8 个卦象 + 占位符（“空”/空格），共 9 种。

## 利用步骤

1. 从题面图片或源码确认“卦象→数字 0–8”的映射表（九宫图/洛书方位）。
2. 把符号串按空格切分，每段逐字符查表转数字，得到九进制数字串。
3. 对每段做 `int(seg, 9)`，再 `chr()`；若出现不可打印字符，检查映射是否取反/旋转。
4. 拼接所有字符得到 flag；必要时按 `flag{`/`ctf{` 前后缀校正分段。

## PoC

```python
s = '☲☵ ☷☵☳ ☶空 ☷☵☳ ☶☱ ☶空 ☷空☱ ☶空 ☷☳☰ ☷☳☱ ☷☴☳ ☷☳☳ ☷☴☶ ☷☳☳ ☷☷☰ ☷☳空 ☰☴ ☷☴☶ ☷☴☶ ☷☴空 ☷空☲'

table = {'☵': '0', '☷': '1', '☳': '2', '☴': '3',
         '空': '4', '☰': '5', '☱': '6', '☶': '7', '☲': '8'}

digits = ''.join(' ' if ch == ' ' else table[ch] for ch in s)
print(digits)  # 80 102 74 102 76 74 146 74 125 126 132 122 137 122 115 124 53 137 137 134 148

plain = ''.join(chr(int(seg, 9)) for seg in digits.split())
print(plain)
```

- 原文示例：[HSCSEC2023]Deduced gossip，按上述映射与九进制转换还原出可读 flag。
- 注意“空”是数字 4 的占位符，不是空格；真实空格用于分隔字符。

## 变体与关联

- 其他八卦/中文符号编码：[[ctf-misc-bagua-five-stroke-minus-one-unicode-codepoint]]（笔画数减一拼 Unicode）、[[crypto-classical-pigpen-variant-fence-column-decode]]（猪圈密码）、[[crypto-classical-lookup-table-multibyte-substitution-reverse]]（打表替换通用解法）。
- 若映射表未知，可用已知明文（如 `flag{`）反推 2–3 个符号对应关系，再验证。

## 检测与防御

- CTF 技巧，非真实漏洞；出题方可旋转/置换九宫映射或混入噪声符号。
- 实际系统若用符号表编码数据，应定义明确码表并校验，避免歧义。
