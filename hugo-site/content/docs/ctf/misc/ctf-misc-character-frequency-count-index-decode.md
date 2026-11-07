---
id: ctf-misc-character-frequency-count-index-decode
title: 字符频次反查编码：用出现次数作为索引恢复消息
type: scenario
domain: ctf
path: ctf/misc
technique: character-frequency-count-index-decode
tags:
- ctf
- misc
- frequency-analysis
- steganography
- text
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:18+08:00'
  notes: 已对照原文 Frequency 3000 核对：hex flag 解出数字串、删除 Fake_Flag、转小写、Counter 反查次数->字符均一致；未实际运行。
url: /docs/ctf/misc/ctf-misc-character-frequency-count-index-decode/
draft: false
kb_aliases:
- 频率统计隐写
- 字符出现次数索引
- Frequency 3000
- 频次反查
- 文本频次编码
---

## 一句话结论

题目给出的“flag”里不是明文，而是一串数字；每个数字对应一段长文本中某个字符的出现次数，统计文本字符频次后按“次数 → 字符”反查，即可把数字串还原成真正的 flag。

## 原理

- 长文本（如字幕、剧本、日志）中每个字符的出现次数是确定的；把消息字符替换成它的出现次数，就得到一串数字。
- 解码需要：确定统计范围（整段文本、去掉干扰行、统一大小写）、统计每个字符的频次、建立“频次 → 字符”映射、按数字查表。
- 干扰项会污染频次：题目常在文本末尾放一个假 flag（如 `{Fake_Flag_For_Reasons}}`），必须先删除，否则某些字符的计数会偏移。
- 大小写敏感会导致同一字母分成两个计数；题目通常要求转小写后再统计。
- 频次映射可能不唯一（多个字符出现次数相同），需要题目保证目标数字对应的字符唯一，或用上下文/flag 格式消歧。

## 触发条件

- 题目给出“数字串 + 长文本”两个附件，或 flag 解码后是数字列表。
- 文本长度足够大，字符频次分布有明显差异。
- 题目提示“频率”“统计”“字幕/剧本”等。
- 存在需要剔除的假 flag/噪声行。

## 利用步骤

1. 把 `flag.txt` 的 hex 解码成字符串，提取花括号内的数字列表。
2. 读取长文本，删除题目给出的假 flag/噪声片段。
3. 按题目要求统一大小写（通常转小写）。
4. 用 `collections.Counter` 统计每个字符出现次数。
5. 建立 `count -> char` 映射；对数字列表逐个查表，拼出消息。
6. 套上 flag 格式提交；若冲突，检查是否漏删噪声、大小写或标点统计范围。

## PoC

```python
from collections import Counter

def decode_hex_flag(path="flag.txt"):
    data = open(path, encoding="utf-8").read().strip()
    return "".join(chr(int(x, 16)) for x in data.split())

def extract_numbers(decoded):
    inner = decoded[decoded.index("{") + 1:decoded.rindex("}")]
    return [int(x) for x in inner.split()]

decoded = decode_hex_flag()
nums = extract_numbers(decoded)

text = open("transcript.txt", encoding="utf-8").read()
text = text.replace("{Fake_Flag_For_Reasons}}", "")
text = text.lower()
freq = Counter(text)

inv = {cnt: ch for ch, cnt in freq.items()}
msg = "".join(inv[n] for n in nums)
print(f"DawgCTF{{{msg}}}")
```

## 变体与关联

- 变体：统计对象换成单词、双字符组、行首字母；数字对应词频/ngram 频次。
- 变体：大小写敏感、保留/去除标点、只统计字母。
- 变体：频次映射有冲突时，用多个文本/多轮统计或 flag 格式约束消歧。
- 关联：[[ctf-misc-first-last-char-line-stego]]（文本行首尾隐写）、[[ctf-misc-punctuation-2bit-encoding]]（标点编码）、[[crypto-classical-pigpen-variant-fence-column-decode]]（古典替换）。

## 检测与防御

- 检测：题目/附件中出现“长文本 + 数字串”、数字范围与文本字符频次吻合、文本含假 flag。
- 防御：该场景是 CTF 文本隐写，不是真实漏洞；真实系统不要把敏感信息编码进公开文本的统计特征。
- 响应：若业务数据中出现异常数字串与统计特征，按隐写/泄露排查。
