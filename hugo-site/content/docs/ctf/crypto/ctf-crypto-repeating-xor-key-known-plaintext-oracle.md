---
id: ctf-crypto-repeating-xor-key-known-plaintext-oracle
title: 重复 XOR 密钥恢复：Base32 密文已知前缀反推 4 字节 key，加密 oracle 全零明文直接泄露 key
type: scenario
domain: ctf
path: ctf/crypto
technique: repeating-xor-key-known-plaintext-oracle
tags:
- ctf
- crypto
- xor
- repeating-key
- known-plaintext
- oracle
- base32
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:22:39+08:00'
  notes: 已对照原文与图16核对：Encrypted Audit Logs 中 ORSXG5A= Base32 解码为 test、XOR key_len=4、目标 token Base32 解码后用 SDG{ 反推 key=3589f743 得 SDG{3589f7439ae690b0772be5b16da4019e}；Pharmacy XOR Oracle 提交 32 字节全 0 取 key、解出 SDG{b759e4557ba000dfd7ca7689f593810a}（图16 回显）均一致。未验证点：PoC 未连接远程复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-repeating-xor-key-known-plaintext-oracle/
draft: false
kb_aliases:
- 重复异或
- repeating key XOR
- Base32
- 已知明文前缀
- 全零明文 oracle
- key_len=4
- Encrypted Audit Logs
- Pharmacy XOR Oracle
---

## 一句话结论

审计日志 token 先 Base32 再 4 字节循环 XOR；用已知 flag 前缀 `SDG{` 与密文前 4 字节异或反推 key；另一题提供 encrypt oracle，提交 32 字节全 `00` 得到 key 重复两次，直接解密密文。

## 原理

- **repeating-key XOR**：`ct[i] = pt[i] ^ key[i % key_len]`；key 周期短时，已知任意 `key_len` 个连续明文字节即可恢复全部 key 字节。
- **已知前缀**：flag 格式固定 `SDG{`，密文前 4 字节与 `SDG{` 异或即得 4 字节 key；随后整体循环异或还原。
- **全零明文 oracle**：加密接口对任意输入返回密文；提交 32 字节 `0x00`，`0x00 ^ key = key`，返回的前 16 字节（或按 key_len 重复）就是 key。
- **Base32 只是编码层**：日志中 `ORSXG5A=` Base32 解码为 `test`，用于确认编码；目标 token 先 Base32 解码再 XOR。

## 触发条件

- 密文使用 repeating-key XOR，key 长度短（4/8/16 字节）。
- 已知明文前缀/后缀/格式，或存在加密 oracle 可提交任意明文。
- 密文可能先经过 Base32/Base64/hex 编码。

## 利用步骤

1. 从日志/题目确认编码层（Base32）与 XOR 配置（`key_len=4`）。
2. Base32 解码目标 token 得到 XOR 密文。
3. 已知明文攻击：`key[i] = ct[i] ^ pt[i]`，pt 取 `SDG{`；整体 `pt[i]=ct[i]^key[i%4]`。
4. oracle 变体：向 encrypt 接口提交 `b"\x00"*32`，取返回值前 key_len 字节作为 key。
5. 解出明文后按题目格式 claim。

## PoC

```python
import base64

enc = "M3G3AOAGXTHXUU56YNYAZ2ESOUGLTFLTAK7MKIKQXSKXEA7NSZ3QLOGOEZEA===="
ct = base64.b32decode(enc)
key = bytes(ct[i] ^ b"SDG{"[i] for i in range(4))
print(bytes(c ^ key[i % 4] for i, c in enumerate(ct)))

# oracle 变体：resp = encrypt(b"\x00"*32); key = resp[:16]
```

## 变体与关联

- **key 长度未知**：用重合指数/汉明距离/已知明文位置推断；多段已知明文可交叉验证。
- **编码变体**：Base64/hex/Base32、多层编码、先压缩再 XOR。
- **oracle 变体**：只加密固定前缀、返回长度受限、带随机 IV；需要选择明文构造。
- **关联卡片**：[[ctf-crypto-xor-keystream-reuse-known-plaintext]]（two-time pad）、[[ctf-misc-png-trailing-data-lcg-xor-base62]]（LCG 流 XOR）、[[ctf-forensics-docx-customxml-base64-comment]]（Base64 隐藏数据）。
- **边界**：若 key 长度接近明文长度或每次随机，已知前缀只能恢复部分；若 oracle 对输入做了转义/压缩，全零明文不直接等于 key。

## 检测与防御

- **CTF/验证**：解出明文应为可打印 flag；key 应能正向加密回原密文。
- **防御**：不要用 repeating-key XOR 做加密；使用 AES-GCM/ChaCha20-Poly1305 等 AEAD；加密 oracle 限制输入、不要返回裸密文；日志不要记录密钥/密文。
- **检测信号**：密文长度短且重复模式明显；日志出现 `XOR mode=repeating`；接口提供任意明文加密。
