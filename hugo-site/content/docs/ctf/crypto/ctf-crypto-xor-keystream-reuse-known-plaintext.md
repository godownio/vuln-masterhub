---
id: ctf-crypto-xor-keystream-reuse-known-plaintext
title: 异或密钥流重用：已知一段明文恢复另一段密文（two-time pad）
type: scenario
domain: ctf
path: ctf/crypto
technique: xor-keystream-reuse-known-plaintext
tags:
- ctf
- crypto
- xor
- stream-cipher
- keystream-reuse
- known-plaintext
- two-time-pad
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:43:27+08:00'
  notes: 已对照原文 lit_xor_two_story 核对：密文 hex 与已知明文 m2 一致，两步异或逻辑正确；PoC 未本机执行
url: /docs/ctf/crypto/ctf-crypto-xor-keystream-reuse-known-plaintext/
draft: false
kb_aliases:
- lit_xor_two_story
- two-time pad
- 密钥流重用
- 已知明文异或
- XOR 自反
---

## 一句话结论

两段密文 `c1 = m1 ^ k`、`c2 = m2 ^ k` 使用同一条异或密钥流 `k` 时，只要已知其中一段明文 `m2`，就能恢复密钥流 `k = m2 ^ c2`，再解出另一段 `m1 = c1 ^ k`；本质是一次性密码本/流密码 nonce 重用的 two-time pad 攻击。

## 原理

- **异或自反**：`c = m ^ k`，则 `m = c ^ k`；同一 `k` 加密两段明文时，`c1 ^ c2 = m1 ^ m2`，即两段明文的异或。
- **已知明文攻击**：如果 `m2` 已知（题面/格式/固定前缀），直接 `k = c2 ^ m2`，再 `m1 = c1 ^ k`；不需要恢复密钥本身。
- **部分已知**：如果只知道 `m2` 的前缀（如 `litctf{`），可恢复密钥流前缀并解出 `m1` 的对应前缀；结合语言/格式做 crib-dragging 逐步扩展。
- **为什么危险**：XOR 流密码/OTP 的安全性完全依赖密钥流一次性使用；重用后两段密文的异或抵消密钥，泄露明文间关系。

## 触发条件

- 同一密钥流/nonce 被用于加密两条或多条消息。
- 至少一条消息的明文（或足够长的已知片段/固定格式）可获得。
- 密文以 hex/base64/原始字节提供，长度对齐。

## 利用步骤

1. 确认两条密文等长/使用同一密钥流（例如同一随机数、同一 nonce、同一 OTP 密钥）。
2. 用已知明文 `m2` 与 `c2` 异或得到密钥流 `k`。
3. 用 `k` 解 `c1`，得到 `m1`。
4. 若只有部分已知，先恢复对应前缀，再用格式/字典做 crib-dragging 扩展。

## PoC

```python
c1 = bytes.fromhex("5f70a847ce12759e156e3cad1aa9530a119386a02ffc1c31bf14ab7a0a82ccc108f8476f75c98a28")
c2 = bytes.fromhex("5f70a847ce123cc153283ca710ae7f042b8490a238eb2228970fad6a2694f2985dc5557e69e5f474")
known_m2 = b"litctf2026_xor_keystream_reuse_40bytes!!"

k = bytes(a ^ b for a, b in zip(known_m2, c2))
m1 = bytes(a ^ b for a, b in zip(c1, k))
print(m1)
```

## 变体与关联

- OTP 密钥复用、流密码 nonce 重用、AES-CTR/GCM 固定 nonce（GCM 还会泄露 GHASH 子密钥）。
- 只有密文时：用 `c1 ^ c2 = m1 ^ m2` + 语言模型/crib-dragging/空格推断恢复。
- 密钥流可来自 PRNG（MT19937/LCG）；先恢复 PRNG 状态再生成密钥流。
- 关联：AES-GCM nonce 重用、AES-CTR 固定 nonce、OTP 复用卡。

## 检测与防御

- 流密码/OTP 密钥流绝不重用；每次加密使用唯一 nonce/随机盐，或使用 AEAD（AES-GCM/ChaCha20-Poly1305）并严格管理 nonce。
- 不要用固定 XOR key 加密多条消息；使用 KDF 派生每消息密钥。
- 检测：同一密钥/nonce 下多条密文、密文异或呈现可读模式、固定前缀重复。
