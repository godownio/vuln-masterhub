---
id: ctf-misc-unicode-variation-selector-hex-stego
title: Unicode 变体选择符隐写：U+FE00–U+FE0F 映射十六进制还原隐藏数据
type: scenario
domain: ctf
path: ctf/misc
technique: unicode-variation-selector-hex-stego
aliases:
- 变体选择符隐写
- Variation Selectors
- U+FE00 隐写
- 不可见字符藏 flag
- novel.txt 隐写
- EF B8 xx
tags:
- ctf
- misc
- stego
- unicode
- variation-selector
- text-stego
- encoding
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:55:47+08:00'
  notes: 已对照原文 §如烟大帝独断万古核对：EF B8 变体选择符 U+FE00..U+FE0F 映射 0..f、拼接 hex→bytes、正则取 NepCTF{...}、flag 均一致；未本机复跑。
---

## 一句话结论

文本中大量 `EF B8 xx` 字节序列对应 Unicode 变体选择符 `U+FE00`–`U+FE0F`；把每个字符的码位减去 `0xFE00` 得到 0–f 的十六进制数字，按顺序拼接后 `bytes.fromhex()`，即可从看似普通的小说正文里还原出隐藏的 flag/二进制数据。

## 原理

- Unicode 变体选择符 `U+FE00`–`U+FE0F`（Variation Selectors）在 UTF-8 中编码为 `EF B8 80`–`EF B8 8F`，共 16 个码位，刚好可以一一映射为十六进制数字 0–f。
- 这些字符通常不可见或只有很弱的字形差异，复制/阅读正文时容易被忽略；但按字节检查就能看到大量 `EF B8 xx`。
- 把每个变体选择符映射为一位 hex，拼接成偶数长度的 hex 字符串，再转字节，即可得到隐藏的二进制数据（案例中直接是 flag 文本）。
- 这是“文本载体隐写”的一种：载体可以是小说、日志、聊天记录、HTML 等，隐藏数据不改变可见文本的语义。
- 同类字符还有补充变体选择符 `U+E0100`–`U+E01EF`（4 字节 UTF-8）和标签字符 `U+E0000`–`U+E007F`，需要按码位范围调整映射。

## 触发条件

- 文本中出现异常多的 `EF B8 80`–`EF B8 8F` 序列，或 `U+FE00`–`U+FE0F` 字符密度远高于正常排版。
- 可见正文没有 flag，但题面/文件名暗示“隐藏的名字/信息”。
- 能按 Unicode 码位遍历文本，而不是只按可见字符处理。
- 隐藏数据长度是偶数个 hex 位（或需要补齐/截断）。

## 利用步骤

1. 用 `xxd`/十六进制编辑器查看文本，统计 `EF B8` 开头序列；或用 Python 遍历字符码位。
2. 筛选 `0xFE00 <= ord(ch) <= 0xFE0F` 的字符，按出现顺序映射为 `ord(ch)-0xFE00` 的 hex 数字。
3. 拼接 hex 字符串；若长度为奇数，尝试补前导/尾随 0 或丢弃最后一个半字节。
4. `bytes.fromhex()` 转字节，搜索 `flag{`/`CTF{` 或按文件头判断类型。
5. 若变体选择符是补充平面 `U+E0100`–`U+E01EF`，映射为 `ord(ch)-0xE0100` 的 0–f；标签字符则按 `U+E0000` 偏移解码 ASCII。

## PoC

```python
import re
import zipfile
from pathlib import Path

with zipfile.ZipFile("challenge.zip") as z:
    text = z.read("novel.txt").decode("utf-8")

hex_stream = "".join(
    format(ord(ch) - 0xFE00, "x")
    for ch in text
    if 0xFE00 <= ord(ch) <= 0xFE0F
)
raw = bytes.fromhex(hex_stream)
print(re.search(rb"flag\{[^}]+\}", raw, re.I).group(0).decode())
```

案例输出：`NepCTF{var1at10n_s3l3ct0rs_h4unt_th3_n0v3l-afk6324}`。

## 变体与关联

- 变体：补充变体选择符 `U+E0100`–`U+E01EF` 提供 16 个码位，同样映射 hex；标签字符 `U+E0000`–`U+E007F` 可映射 ASCII/控制码。
- 变体：把 hex 位映射到 `U+FE00`/`U+FE01` 表示二进制 0/1，再按 8 位分组。
- 变体：隐藏数据经过压缩/加密时，先还原字节流，再按文件头（zip/gzip/png）继续解码。
- 关联：[[ai-security-prompt-injection-invisible-unicode-tag-variation-selector-smuggling]]（同一类字符的提示注入走私）、[[ai-security-rag-security-unicode-bidi-zws-rendered-vs-logical-input]]（不可见 Unicode 影响渲染/解析）、[[ctf-forensics-midi-shared-tick-register-stego]]（其他载体隐写）。

## 检测与防御

- 检测：统计文本中 `U+FE00`–`U+FE0F`、`U+E0100`–`U+E01EF`、`U+E0000`–`U+E007F` 的出现次数与密度；正常文本中这些字符极少。
- 防御：对用户生成内容做 Unicode 规范化/不可见字符过滤；在日志、审核、复制粘贴链路中剥离变体选择符与标签字符。
- 响应：发现隐藏数据后按字节流分析其类型，检查是否还有同载体的其他隐藏段；保留原始文件与码位序列作为证据。
