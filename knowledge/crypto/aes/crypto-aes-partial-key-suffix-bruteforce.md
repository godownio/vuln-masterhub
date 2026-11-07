---
id: crypto-aes-partial-key-suffix-bruteforce
title: AES 密钥仅缺少量字节：已知前缀 + 24 位后缀爆破解密
type: scenario
domain: crypto
path: crypto/aes
technique: aes-partial-key-suffix-bruteforce
aliases:
- lit_tiny_key_aes
- AES 密钥爆破
- 已知部分 key
- 3 字节后缀
- ECB 模式
- PKCS#7 校验
tags:
- ctf
- crypto
- aes
- key-bruteforce
- partial-key
- ecb
- pkcs7
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:43:29+08:00'
  notes: 已对照原文 lit_tiny_key_aes 核对：KEY_PREFIX 13 字节+3 字节后缀=16 字节，密文转 hex 与原文逐字节一致；一句话结论中“12 字节前缀”为笔误（应为 13），不影响技术内容；PoC 未本机执行
---

## 一句话结论

AES 密钥只有少量字节未知（如已知 12 字节前缀 `LitCTF2026!!!`、仅 3 字节后缀未知）时，直接枚举 `256^3 = 16,777,216` 种后缀，用 AES-ECB 解密并检查明文是否以预期格式（如 `litctf{`）开头、PKCS#7 填充是否合法，即可唯一恢复密钥并解出 flag。

## 原理

- **密钥空间**：AES-128 密钥 16 字节；若 13 字节已知/固定、只有 3 字节未知，密钥空间仅 2^24，现代 CPU/GPU 可快速穷举。
- **验证方式**：AES-ECB 解密后，明文通常有固定前缀（`litctf{`/`flag{`）、可打印字符、PKCS#7 填充（末尾 `pad` 个 `pad` 字节）；这些约束足以过滤错误候选。
- **ECB 特性**：同样的 16 字节明文块产生同样密文块，且无需 IV/nonce；解密是逐块独立的，便于暴力。
- **为什么可行**：密钥熵不足/结构化（已知前缀 + 小后缀）使穷举成本远低于 2^128；这是密钥生成/管理缺陷，不是 AES 算法被攻破。

## 触发条件

- 已知 AES 密钥的大部分字节（前缀/后缀/固定模板），未知部分 ≤ 4 字节（2^32 以内可行）。
- 有至少一个密文块可解密，且明文有可验证格式/填充。
- 使用 ECB 或已知 IV 的 CBC/CTR；ECB 最简单。
- 计算资源允许 2^24~2^32 次 AES 解密（可用 C/OpenSSL/GPU 加速）。

## 利用步骤

1. 从源码/附件确认密钥构造：已知前缀 + 未知后缀长度。
2. 取密文，确认模式（ECB/CBC/CTR）与填充（PKCS#7/无）。
3. 枚举未知后缀，AES 解密，检查明文前缀/可打印性/填充。
4. 命中后输出密钥与明文；若多个候选，用更多密文块/格式约束过滤。

## PoC

```python
import itertools
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY_PREFIX = b"LitCTF2026!!!"   # 13 bytes, 3 unknown -> 16
ciphertext = bytes.fromhex("0cdb2760c931f705912b0f4dedbc9bf1d844cdfd0cb9b6b24a3c8619064bb3a2a418873c76ac1b627523aab5497fd8d3")

for suffix in itertools.product(range(256), repeat=3):
    key = KEY_PREFIX + bytes(suffix)
    dec = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
    if dec.startswith(b"litctf{"):
        try:
            print(key, unpad(dec, AES.block_size))
            break
        except ValueError:
            continue
```

## 变体与关联

- 未知字节更多时可用字典/掩码攻击（hashcat mode 25400 等）、已知明文/crib、或从其他泄露恢复。
- 模式可换 CBC（已知 IV）、CTR（已知 nonce/keystream）；CTR 下已知明文可直接恢复密钥流，不需要爆破 key。
- 密钥可来自弱 KDF/时间戳/固定模板；先分析生成逻辑缩小空间。
- 关联：AES 密钥管理缺陷、弱 KDF、CTF AES 爆破卡。

## 检测与防御

- AES 密钥必须由 CSPRNG/高熵 KDF 生成，不要用“固定前缀 + 短后缀”模板。
- 使用 AEAD（GCM/CCM）并校验 tag，增加错误候选过滤成本；但根本仍是密钥熵。
- 检测：密钥长度/熵异常、固定前缀、短密钥空间；对密钥生成代码做审计。
