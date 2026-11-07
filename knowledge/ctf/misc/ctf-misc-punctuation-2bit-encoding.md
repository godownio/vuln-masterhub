---
id: ctf-misc-punctuation-2bit-encoding
title: 标点符号 2-bit 编码：四种标点映射 00/01/10/11 还原 ASCII
type: scenario
domain: ctf
path: ctf/misc
technique: punctuation-2bit-encoding
aliases:
- 标点隐写
- 标点符号编码
- 四种标点
- 2-bit 编码
- signin
tags:
- ctf
- misc
- stego
- encoding
- punctuation
- binary
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:08:36+08:00'
  notes: 已对照原文全文与 7 张内嵌图片核对：题目步骤、密码链、脚本与 flag/密码均与原文一致。未验证点：PoC 按原文重写未本机复跑；原文无组件版本，未设置 versions；卡 frontmatter 无 sources/source_url。
---

## 一句话结论

当文本中只有四种标点符号（如 `，。；：`）反复出现、且去掉文字后长度可被 4 整除时，可把四种标点映射为 2-bit 码 `00/01/10/11`，每 4 个标点拼成 8 bit 转 ASCII，即可还原隐藏的 flag。

## 原理

- **四种符号 = 2 bit**：2²=4，正好用两个二进制位表示一个标点；4 个标点 = 8 bit = 1 字节。
- **编码载体**：正常文本中插入标点不会影响阅读，肉眼容易忽略；删除文字后只剩标点序列，长度/分布暴露编码。
- **映射顺序**：题目通常按标点出现顺序/给定表映射（本题 `，→00、。→01、；→10、：→11`）；不同题目可能换表，需按可读性/flag 前缀尝试。
- **为什么成立**：这是确定性的 2-bit 编码，类似 Base4；只要符号集和顺序正确，拼接即得明文。
- **边界**：符号种类多于 4 时可扩展为 3-bit/Base8；若文本中混有普通标点，需要先按题目给的符号集过滤。

## 触发条件

- 文本中大量重复的四类标点，文字内容语义不连贯/明显是填充。
- 标点总数可被 4 整除（或按题目分组）。
- 明文为 ASCII/flag 格式，可用 `flag{` 前缀验证。
- 题目提示“标点/符号/删除文字”等。

## 利用步骤

1. 读取文本，统计标点种类与数量；确认只有四类目标标点。
2. 按题目映射表把每个标点转成 2-bit（本题 `，。；：` → `00 01 10 11`）。
3. 每 4 个 2-bit 拼成 8 bit，转 ASCII。
4. 用 `flag{`/可打印性验证；若乱码，调整映射顺序/位序（正向/反向）。
5. 本题输出 `sdpcsec{...}`。

## PoC

```python
from pathlib import Path

text = Path("ai_reply.txt").read_text(encoding="utf-8")
mapping = {"，": "00", "。": "01", "；": "10", "：": "11"}
bits = "".join(mapping[ch] for ch in text if ch in mapping)
assert len(bits) % 8 == 0
flag = "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8))
print(flag)
```

## 变体与关联

- **变体（符号集）**：四种括号/箭头/表情符号；按出现频率和题目表映射。
- **变体（进制）**：三种符号=三进制、八种=3-bit；分组/位序按题目。
- **变体（混合隐写）**：标点 + 零宽字符 + 大小写；先剥离可见文字再解码。
- **关联卡片**：[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（零宽字符二/五进制）、[[crypto-classical-pigpen-variant-fence-column-decode]]（符号替换）、[[ctf-misc-bagua-five-stroke-minus-one-unicode-codepoint]]（Unicode 码点编码）。
- **边界**：符号表未知时需暴力尝试 4! 种映射；文本编码/全半角标点差异会导致匹配失败。

## 检测与防御

- **CTF 识别**：文本只剩标点、四类符号重复、长度 4 的倍数，按本卡解码。
- **数据防泄露**：DLP 可检测异常标点密度/非自然文本；导出时规范化标点。
- **教学**：2-bit 编码是 Base4 的直观例子；不要用隐写保护敏感数据。
