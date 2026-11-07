---
id: ctf-crypto-asmuth-bloom-rsa-share-crt-recovery
title: Asmuth-Bloom 秘密共享 + RSA 加密 share：CRT 重构 zip 密码
type: scenario
domain: ctf
path: ctf/crypto
technique: asmuth-bloom-rsa-share-crt-recovery
tags:
- ctf
- crypto
- rsa
- secret-sharing
- asmuth-bloom
- crt
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:49:20+08:00'
  notes: 已对照原文核对：简化Asmuth-Bloom share=di:ki:original_bits、message1+message2..10 share拼接、RSA两分支(OAEP+AES-GCM/裸RSA 16B key+AES-GCM)、共享素因子/Wiener/Fermat恢复私钥、CRT重构message7得level2密码均与原文一致。未验证点：未复跑CRT/RSA脚本。
url: /docs/ctf/crypto/ctf-crypto-asmuth-bloom-rsa-share-crt-recovery/
draft: false
kb_aliases:
- Asmuth-Bloom 秘密共享
- share 的 CRT 重构
- RSA 加密 share
- 秘密共享与 RSA 组合
- 多级密码题
---

## 一句话结论

题目把每个 message 拆成多个 `di : S mod di : bitlen` 的简化 Asmuth-Bloom share，再分别用多把 RSA 公钥加密；先利用共享素因子/Wiener/Fermat 恢复部分私钥、解出 share，再对同一 message 的多个同余式做 CRT，即可重构出 `S`（即 message 明文），从中拿到下一层 zip 密码。

## 原理

- 简化版 Asmuth-Bloom：选一组递增的素数 `d1 < d2 < ... < dn`，对秘密整数 `S` 计算 `ki = S mod di`，share 表示为 `di:ki:original_bits`（十六进制）。只要收集到足够多的 share，且所有 `di` 的乘积大于 `S`，就能用中国剩余定理唯一恢复 `S`。
- 题目把多个 message 的 share 拼进同一份明文：`plaintext-j` 第一行是 `message1` 的内容，后面 9 行是 `message2..message10` 的 share。因此每解出一个 ciphertext，就同时获得 9 个 message 各一份 share。
- share 再用 RSA 公钥加密。`encrypt.py` 有两个分支：
  - `n_bits >= 2048`：RSA-OAEP 加密 32 字节对称密钥，再 AES-GCM 加密 message；
  - `n_bits < 2048`：随机 16 字节对称密钥直接裸 RSA（`pow(key, e, n)`），再 AES-GCM。
- 多把公钥中存在可攻击的弱点：两两共享素因子（`gcd(n_i, n_j)` 直接分解）、Wiener 小私钥、Fermat 近素因子。恢复出足够多的私钥后，按密文长度/密钥长度匹配解密，得到 share。
- 对每个 message 收集到足够多的 `(di, ki)` 后，CRT 恢复 `S`；`S` 转回字节即 message 明文。示例中 `message7` 里包含下一层 zip 的密码。

## 触发条件

- 题目给出多把 RSA 公钥与多段密文，明文由“固定前缀 + 多条 `di:ki:bitlen` share”拼接。
- 公钥集合存在共享素因子、小私钥或近素因子等弱点，能恢复部分私钥。
- 同一 message 的 share 数量足够（`∏di > S`），且 `di` 两两互素。
- 能从密文中解密出 share 文本，或能通过其他方式获得 share。

## 利用步骤

1. 解析所有公钥，提取 `n/e`；对 `n` 两两求 `gcd`，命中共享素因子的直接分解；对剩余公钥尝试 Wiener（大 `e` 小 `d`）与 Fermat（`p`、`q` 接近）。
2. 对每个密文，根据长度判断走 OAEP+AES-GCM 还是裸 RSA+AES-GCM；用恢复的私钥解密出对称密钥，再 AES-GCM 解密 message。
3. 解析明文中的 `di:ki:bitlen` 行，按 message 分组；每行是一个同余式 `S ≡ ki (mod di)`。
4. 对每个 message 取足够多的 share，做 CRT 得到 `S`；用 `bitlen` 或最小字节数把 `S` 转回 bytes。
5. 从恢复的 message 中提取密码/下一层线索；示例用 `message7` 中的密码解 `level2.zip`，继续下一层 RSA 题。

## PoC

```python
from math import prod

def crt_shares(shares):
    # shares: [(di, ki), ...]，di 两两互素，prod(di) > S
    M = prod(d for d, _ in shares)
    S = 0
    for di, ki in shares:
        Mi = M // di
        S = (S + ki * Mi * pow(Mi, -1, di)) % M
    return S

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, "big")

# 示例：把同一 message 的 10 条 share 转成 (di, ki) 后 CRT
# shares = [(int(d,16), int(k,16)) for d,k,bits in parsed_lines]
# msg = int_to_bytes(crt_shares(shares))
```

```python
# RSA 侧：共享素因子
from math import gcd
for i in range(len(keys)):
    for j in range(i + 1, len(keys)):
        g = gcd(keys[i].n, keys[j].n)
        if 1 < g < keys[i].n:
            p, q = g, keys[i].n // g
```

## 变体与关联

- 变体：完整的 Asmuth-Bloom 会引入随机数 `alpha` 与阈值 `k`，share 为 `(S + alpha*m) mod di`；本题是去掉随机项的简化版，CRT 直接恢复 `S`。
- 变体：share 的编码可能是十进制/十六进制/字节串；`bitlen` 字段用于确定 `S` 的字节长度，缺失时用 `S.bit_length()` 向上取整。
- 变体：RSA 侧也可能使用共模、低指数广播、Coppersmith 部分私钥等；先做批量 `gcd` 与常见弱密钥筛查。
- 关联：[[ctf-crypto-rsa-shared-prime-batch-gcd]]（共享素因子批量 gcd）、[[crypto-rsa-wiener-small-private-exponent-large-e]]（Wiener 小私钥）、[[ctf-crypto-rsa-hastad-broadcast-e3-crt]]（CRT 在 RSA 广播中的用法）。
- 边界：share 数量不足或 `∏di <= S` 时 CRT 结果不唯一；`di` 不互素时需先处理公因子；恢复出的 `S` 需按 `bitlen` 截断。

## 检测与防御

- CTF 识别：多把公钥/多段密文 + 明文中的 `modulus:remainder:bitlen` 行 + 提到“秘密共享/Asmuth-Bloom”，优先做批量 gcd 与 CRT。
- 防御：不要复用 RSA 素数，使用足够大的私钥指数与标准填充；秘密共享不能替代加密，share 的传输/存储仍需认证加密。
- 取证：保留公钥、密文与 share 原文；记录每个 message 的 share 数量与 `di` 乘积，确认 CRT 唯一性。
