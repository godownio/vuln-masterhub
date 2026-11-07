---
id: ctf-misc-text-diff-ord-delta-flag
title: 两个文本单字符差分取 ord 差值还原 flag
type: scenario
domain: ctf
path: ctf/misc
technique: text-diff-ord-delta
aliases:
- badyuri
- 文本差分
- ord 差值
- 单字符差异还原
tags:
- ctf
- misc
- text-diff
- stego
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:08+08:00'
  notes: 已对照原文 badyuri 段核对：两文件等长、30 处单字符差异、ord(new)-ord(old) 拼接与原文脚本一致；未本机跑附件；原文未标注组件版本。
---

## 一句话结论

给两个长度相同、仅少量位置单字符不同的文本时，把每个差异位置的 `ord(修改后字符) - ord(原字符)` 当作 ASCII 码拼接，即可直接得到 flag。

## 原理

- 出题人把 flag 的每个字符编码成“原文某位置字符到修改后字符的偏移量”；因为两个文件长度相同且只有 30 处单字符差异，差异位置就是 flag 字符的位置。
- `ord(new) - ord(old)` 是一个小整数，落在可打印 ASCII 范围内；按位置顺序转成 `chr` 即还原明文。
- 该方法不依赖文件内容语义，只依赖“差异位置 + 字符差值”这一编码约定。

## 触发条件

- 拿到两个同长度文本文件（如 `yuri.txt` 与 `yuri_1.txt`）。
- 差异数量与 flag 长度一致，且差值可打印。

## 利用步骤

1. 解压附件，读取两个文本。
2. 逐字符比较，记录所有 `a != b` 的位置。
3. 对每个差异计算 `delta = ord(b) - ord(a)`，转成 `chr(delta)`。
4. 按位置拼接，得到 flag。

## PoC

```python
s1 = open('yuri.txt', encoding='utf-8').read()
s2 = open('yuri_1.txt', encoding='utf-8').read()
assert len(s1) == len(s2)
flag = ''.join(chr(ord(b) - ord(a)) for a, b in zip(s1, s2) if a != b)
print(flag)
```

## 变体与关联

- 差值可加偏移/取模，或改用异或、字符索引等编码。
- 关联：[[ctf-misc-punctuation-2bit-encoding]]（字符级编码）、[[ctf-reverse-printable-ascii-caesar-hidden-permutation-table]]（字符置换）。

## 检测与防御

- 这是 CTF misc 题型；防御上可打乱差异位置、加入噪声差异或使用非线性编码。
- 检测：两个文本高度相似但存在固定数量单字符差异。
