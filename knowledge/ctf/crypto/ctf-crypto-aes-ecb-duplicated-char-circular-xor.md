---
id: ctf-crypto-aes-ecb-duplicated-char-circular-xor
title: 字符重复 + AES-ECB 块循环移位异或：已知前缀逐字符唯一推出 flag
type: scenario
domain: ctf
path: ctf/crypto
technique: aes-ecb-char-block-circular-xor
aliases:
- ecb-lasagna
- 字符重复 AES
- 循环移位异或
- 逐字符唯一位推导
tags:
- ctf
- crypto
- aes
- ecb
- known-prefix
- circular-shift
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:15+08:00'
  notes: 已对照原文 ecb-lasagna 段核对：F[i]=AES(char*16)、R[j] 循环移位异或公式、E/O 奇偶拆分、已知 bctf{ 爆破 3 字符、INV(b0,b0^b1)、verify 全量校验均一致；PoC 未本机跑附件。
---

## 一句话结论

当每个 flag 字符被重复两次、再对 `AES_ECB(char*16)` 的 16 字节块按位置循环移位异或时，输出每个字节只依赖当前位置之前的 8 个原始字符；利用已知前缀 `bctf{`、爆破接下来的 3 个字符，再逐位唯一推导即可恢复整条 flag。

## 原理

- 设 `F[i] = AES_ECB(flag[i] * 16)`，第 i 个重复字符的块被循环移位 i 后异或进结果：
  `R[j] = XOR_{k=0..15} F[j-k][k]`。
- flag 每个字符重复两次，因此位置 `2t` 和 `2t+1` 使用同一个 `F`；把输出按奇偶拆成 `E=out[0::2]`、`O=out[1::2]`，可把问题压成“每个原始字符一组”。
- 对第 t 个原始字符，`E[t]`、`O[t]` 中除当前字符外的贡献都来自前 8 个原始字符的 `F`；因此可先减掉已知历史贡献，得到只含当前字符块两个字节的约束。
- 预计算 256 个字符块的 `(b0, b0^b1)` 到字符的映射，即可从 `(u,v)` 反查候选字符；大多数位置唯一，少数歧义（如 `.` 与 `x`）用栈回溯，最后用完整输出校验。
- 已知前缀 `bctf{` 提供初始 5 个字符，只需爆破接下来 3 个可打印字符即可启动推导。

## 触发条件

- 加密使用 ECB 且明文是“单字符重复 16 次”的块；
- 每个块按位置循环移位后异或，输出长度足够（flag 长度 × 2）；
- 已知 flag 前缀或可爆破少量起始字符；
- 密钥已知或可复现（本例 `KEY = b"lasagna!" * 2`）。

## 利用步骤

1. 读取 base64 输出，解码后按奇偶拆成 `E`、`O`。
2. 用密钥预计算 256 个 `AES_ECB(c*16)` 块，建立 `(b0, b0^b1) -> c` 的反查表。
3. 用已知前缀 `bctf{` 初始化，爆破后续 3 个可打印字符。
4. 对每个位置 t，从 `E[t]`/`O[t]` 减掉前 1..8 个字符块的贡献，反查候选字符；歧义时回溯。
5. 用完整加密流程 `verify(chars)` 校验，输出 flag。

## PoC

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
KEY = b"lasagna!" * 2
BLOCKS = []
cipher = Cipher(algorithms.AES(KEY), modes.ECB())
for c in range(256):
    enc = cipher.encryptor()
    BLOCKS.append(enc.update(bytes([c]) * 16))

INV = {}
for c, b in enumerate(BLOCKS):
    INV.setdefault((b[0], b[0] ^ b[1]), []).append(c)

def next_candidates(chars, t):
    u = E[t]; v = O[t]
    for k in range(1, 9):
        g = BLOCKS[chars[t-k]]
        u ^= g[2*k-1] ^ g[2*k] if 2*k < 16 else g[15]
        if 2*k+1 < 16:
            v ^= g[2*k] ^ g[2*k+1]
    return [c for c in INV.get((u, v), []) if 32 <= c < 127]
```

## 变体与关联

- 重复次数、移位步长、异或方向可变化，核心是“每字节只依赖有限历史”。
- 若前缀未知，可对前若干字符做更大规模爆破或利用可打印约束。
- 关联：[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（ECB 固定 key 复现）、[[ctf-crypto-xor-keystream-reuse-known-plaintext]]（已知明文逐位恢复）。

## 检测与防御

- 不要使用 ECB；使用随机 IV 的 CBC/GCM 等语义安全模式。
- 不要对“单字符重复块”加密，避免块内容可枚举。
- 检测：密文块与 256 个单字符块的可枚举关系、按位置循环移位的异或结构。
