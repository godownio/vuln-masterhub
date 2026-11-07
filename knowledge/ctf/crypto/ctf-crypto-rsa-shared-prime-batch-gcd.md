---
id: ctf-crypto-rsa-shared-prime-batch-gcd
title: 批量 RSA 模数两两 gcd：共享素因子直接分解并恢复明文
type: scenario
domain: ctf
path: ctf/crypto
technique: rsa-batch-gcd-shared-prime
aliases:
- 共享素因子
- 批量 gcd
- RSA 共享素数
- 多模数分解
- common prime
- GCD attack
tags:
- ctf
- crypto
- rsa
- gcd
- shared-prime
- batch-analysis
- rng-failure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:44:46+08:00'
  notes: 已对照原文核对；二十组 2048 位模数仅 (4,17) 共享 1024 位因子，PoC 与回环校验一致
---

## 一句话结论

同时给出多组 RSA 模数时，只需两两计算 gcd：任意一对非互素的模数立刻暴露 1024 位共享素因子，分解两组模数、求私钥、解密即可；二十组模数只需 190 次大数除法，是批量 RSA 题的第一动作。

## 原理

- **RSA 模数本应互素**：每个 `n = p*q` 由独立随机素数生成；两个独立生成的 1024 位素数相同的概率约为 2^-1024，实际上不可能。
- **共享因子即分解**：若 `gcd(n_i, n_j) = p > 1`，则 `p` 同时整除两个模数，`q_i = n_i / p`、`q_j = n_j / p`，两组模数同时被分解。
- **根因是生成侧随机源失败**：熵池未初始化、种子硬编码、同一进程连续生成多对密钥时 RNG 状态未更新，都会导致跨密钥的素因子复用。
- **解密流程是标准的**：`phi=(p-1)(q-1)`、`d=e^-1 mod phi`、`m=c^d mod n`；最后用 `pow(m,e,n)==c` 回环验证。
- **为什么先做 gcd**：成本 O(k²) 次大数除法，远低于 Wiener、因子库查询、Coppersmith 等尝试；看到“多组 n/c 并列”就应先跑 gcd。

## 触发条件

- 题目/附件同时给出多组 RSA 模数（同指数或不同指数均可）。
- 其中至少两组的模数共享素因子（生成侧 RNG 缺陷、密钥批量生成、跨批次复用）。
- 攻击者能运行大整数 gcd 与模幂运算（Python/gmpy2 即可）。
- 每组密文对应可解密的目标（相同或不同明文均可，共享因子的两组都能解）。

## 利用步骤

1. 解析所有 `n`（和对应的 `c`、`e`），确认位长与分组。
2. 对所有模数对跑 `gcd(n_i, n_j)`；非 1 即命中，记录公因子位长并做素性检验。
3. 用公因子分解命中对：`q_i = n_i // p`，断言 `p*q_i == n_i`。
4. 对每组计算 `phi`、`d`，解出 `m`，按字节长度还原明文。
5. 用 `pow(m, e, n) == c` 回环验证；多组结果互相印证。
6. 若 gcd 全部为 1，再排查小因子、Wiener、素数幂、Fermat 近邻素数等其他缺陷，避免只盯一种。

## PoC

```python
from math import gcd

ns = [int(x) for x in open("moduli.txt")]
for i in range(len(ns)):
    for j in range(i + 1, len(ns)):
        g = gcd(ns[i], ns[j])
        if g != 1:
            print("shared factor:", i, j, g.bit_length())

# 命中 (4, 17) 后
p = gcd(ns[4], ns[17])
q4, q17 = ns[4] // p, ns[17] // p
assert p * q4 == ns[4] and p * q17 == ns[17]

phi = (p - 1) * (q4 - 1)
d = pow(e, -1, phi)
m = pow(cs[4], d, ns[4])
plain = m.to_bytes((m.bit_length() + 7) // 8, "big")
assert pow(m, e, ns[4]) == cs[4]
```

原文实测：二十组 2048 位模数中仅 (4,17) 共享 1024 位素因子，其余 378 对互素；解出 `flag{abdcbe5fd94e23b3de429223ab9c2fdf}`。

## 变体与关联

- **跨批次变体**：不同批次/不同年份的密钥台账中复用同一素数，三组密钥可同时失效（同篇 OTA 题中三个批次共享 512 位素数）。
- **混合缺陷变体**：同一题可同时存在共享素因子与小指数广播，两条路径应分别走通并交叉验证。
- **排除项**：小因子试除、Wiener 连分数（`d` 过小）、模数为素数幂；这些都不命中时再考虑共享因子。
- **关联卡片**：[[crypto-rsa-fermat-close-prime-factorization]]（近邻素数）、[[crypto-rsa-pollard-pminus1-smooth-prime]]（p-1 光滑）、[[crypto-rsa-common-modulus]]（共模攻击）。
- **边界**：只有一组模数时 gcd 无从比较；共享因子必须真实存在，不能靠猜测；强随机源生成的密钥不会命中。

## 检测与防御

- **CTF 验证**：分解后必须回环 `pow(m,e,n)==c`；多组明文可读性互相印证。
- **密钥生成审计**：对一批公钥做两两 gcd 与熵源检查；禁止硬编码种子、共享 RNG 状态、在 fork 后复用随机数。
- **工程防御**：使用系统 CSPRNG（`secrets`/`os.urandom`/HSM）；每对密钥独立生成并做自检；密钥台账定期做共享因子扫描。
- **检测信号**：批量公钥中出现非互素对；密钥生成时间/进程高度集中；不同批次密钥共享素因子。
