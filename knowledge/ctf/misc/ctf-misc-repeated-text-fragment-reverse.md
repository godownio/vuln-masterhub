---
id: ctf-misc-repeated-text-fragment-reverse
title: 重复文本碎片逆序反转：3 字符片段从后往前拼接
type: scenario
domain: ctf
path: ctf/misc
technique: repeated-text-fragment-reverse
aliases:
- 重复文本隐写
- 碎片逆序
- crazy text
- 3 字符片段
- 反转拼接
tags:
- ctf
- misc
- text
- steganography
- string-reversal
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:21+08:00'
  notes: 已对照原文 crazy? i was crazy once 核对：每轮 3 字符碎片、从后往前且每片反转、末尾 waD->Dawg 提示均一致；tokens 列表与原文一致；未实际运行。
---

## 一句话结论

一段不断重复同一句话的长文本中，每重复一轮就夹带一个 3 字符碎片；把所有碎片按出现顺序收集后，从后往前读取、每个碎片再反转，即可拼出 flag，末尾的 `waD` 反转后是 `Dawg` 前缀提示。

## 原理

- 长文本由固定句子反复拼接而成，句子之间/句子内部插入 3 字符碎片，形成“正常文本 + 隐写碎片”的混合。
- 碎片的排列顺序与真实消息相反，且每个碎片自身也被反转；因此需要“逆序 + 逐片反转”两步还原。
- 末尾的 `waD` 是 `Dawg` 的反转，提示反转规则和 flag 前缀；类似地，开头/结尾的异常字符常是提示。
- 碎片长度固定（示例 3），便于从重复文本中按位置/正则提取；若长度可变，需用分隔符或已知句子边界定位。
- 该编码不是加密，只是字符级置换；识别重复模式和异常碎片即可逆推。

## 触发条件

- 附件是单行/少行的大文本，内容高度重复同一句子。
- 每轮重复中出现固定长度（如 3 字符）的异常片段，且片段字符集与正常文本不同。
- 文本末尾有反转的前缀提示（如 `waD`）。
- 题目名/描述暗示“疯狂重复”“碎片”“倒着读”等。

## 利用步骤

1. 观察文本，找出重复句子与每轮插入的异常片段。
2. 用正则/分割提取所有碎片（示例为 `}`、`_`、字母等 3 字符组合）。
3. 将碎片列表逆序，再对每个碎片反转。
4. 拼接得到消息主体；补上前缀/后缀（如 `DawgCT` + `F{...}`）。
5. 检查 flag 格式，必要时调整碎片长度、是否包含分隔符。

## PoC

```python
s = open("crazy.txt", encoding="utf-8").read()

# 示例：按题目给出的碎片列表；实际可用正则从重复文本中提取
tokens = [
    "}pl","eh_","dne","s_e","sae","lp_","efi","l_y","m_f",
    "o_l","ort","noc","_ll","a_t","sol","_ev","ah_","i{F"
]

msg = "".join(x[::-1] for x in tokens[::-1])
print("DawgCT" + msg)
```

## 变体与关联

- 变体：碎片长度 2/4/可变；插入位置在句首、句尾或句中。
- 变体：只逆序不反转，或只反转不逆序；末尾提示字符可能被替换。
- 变体：重复文本本身也参与编码（如每轮首字母）。
- 关联：[[ctf-misc-first-last-char-line-stego]]（行首尾字符隐写）、[[ctf-misc-character-frequency-count-index-decode]]（文本频次编码）、[[ctf-reverse-printable-ascii-caesar-hidden-permutation-table]]（字符置换）。

## 检测与防御

- 检测：文本重复度高但夹杂固定长度异常片段、末尾出现反转前缀、字符集突变。
- 防御：该场景是 CTF 文本隐写；真实系统不要把敏感信息嵌入公开文本。
- 响应：若业务文本中出现类似重复+碎片模式，按隐写/泄露排查。
