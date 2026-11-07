---
id: crypto-rsa-next-prime-square-moduli-continued-fraction
title: 相邻素数双模数 RSA：n1=p1²q1、n2=next_prime(p1)²q2，连分数恢复 q1 与 p1
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-next-prime-square-moduli-continued-fraction
tags:
- crypto
- rsa
- next-prime
- continued-fraction
- perfect-square
- related-primes
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:19:00+08:00'
  notes: 已对照原文脚本与图13核对：n1=p1^2*q1、n2=next_prime(p1)^2*q2、连分数收敛子den|n1且商为完全平方、phi=p(p-1)(q-1)，flag输出一致；未独立复算大数
url: /docs/crypto/rsa/crypto-rsa-next-prime-square-moduli-continued-fraction/
draft: false
kb_aliases:
- ez_rsa
- next_prime RSA
- 相邻素数双模数
- p1^2*q1 RSA
- 连分数恢复 q1
- 完全平方因子
- HECTF ez_rsa
---

## 一句话结论

当两个模数按 `n1=p1²·q1`、`n2=p2²·q2` 生成且 `p2=next_prime(p1)` 时，`p2≈p1` 使 `n2/n1≈q2/q1`；对 `n2/n1` 做连分数展开，若某个收敛子的分母 `den` 满足 `n1 % den == 0` 且 `n1/den` 为完全平方，则 `den=q1`、`sqrt(n1/q1)=p1`；再由 `next_prime(p1)` 得 p2、`q2=n2/p2²`，分别用 `φ(p²q)=p(p−1)(q−1)` 求 d 解密两段密文并拼接。

## 原理

- **模数结构**：`n1 = p1²·q1`、`n2 = p2²·q2`；p1、p2 为大素数，p2 是 p1 的下一个素数，因此 `p2 = p1 + δ`（δ 很小）。于是 `n2/n1 = (p2²/p1²)·(q2/q1) ≈ q2/q1`。
- **连分数逼近**：若 `q2/q1` 是有理数且分母 q1 不太大，`n2/n1` 的连分数收敛子中会包含以 q1 为分母（或与之相关的分母）的分数。对每个收敛子 `(num, den)` 检查 `den | n1`；若 `n1/den` 是完全平方，则 den 就是 q1，开方得到 p1。
- **为什么用完全平方判定**：`n1 = p1²·q1`，所以任何真正整除 n1 的 q1 都会让商为 p1²；这比直接分解 n1 容易得多，也把“哪个收敛子是正确的”变成可验证条件。
- **恢复 p2/q2**：`p2 = next_prime(p1)` 可直接计算；若 `n2 % (p2²) == 0`，则 `q2 = n2 // p2²`，验证 `p2²·q2 == n2`。
- **计算 φ 与 d**：`n=p²·q` 时 `φ(n)=φ(p²)·φ(q)=p(p−1)(q−1)`；`d=e^{-1} mod φ`，`m=c^d mod n`。两个模数用同一 e 加密同一明文的两个部分，分别解密后拼接。
- **为什么可行**：p2 与 p1 的相邻关系让两个模数高度相关；连分数把“分解 1024 bit 模数”降为“枚举少量收敛子 + 完全平方判定”。若 p2 与 p1 无关或 q1 很大，收敛子不再命中。

## 触发条件

- 已知 `n1、n2、c1、c2、e`，且题目/生成脚本暗示 p2 是 p1 的下一个素数、模数含平方因子。
- `n1 = p1²·q1`、`n2 = p2²·q2`，p1、p2、q1、q2 为素数；`gcd(e, φ(n1))=gcd(e, φ(n2))=1`。
- `n2/n1` 的连分数收敛子中能以较高概率出现 q1；q1 不太大（否则需要更多收敛子/其他方法）。
- 明文被拆成两段分别用 n1、n2 加密，拼接后为完整 flag。

## 利用步骤

1. **确认结构**：检查 `n1` 是否含平方因子（试 `isqrt`、小因子、`gcd(n1,n2)`）；观察两个模数是否接近（p2≈p1）。
2. **连分数展开**：对 `n2/n1` 生成收敛子 `(num, den)`。
3. **筛选 q1**：对每个 `den`，若 `n1 % den == 0` 且 `isqrt(n1//den)² == n1//den`，则 `q1=den`、`p1=isqrt(n1//q1)`。
4. **推 p2/q2**：`p2=next_prime(p1)`；若 `n2 % p2² == 0`，`q2=n2//p2²`；验证乘积。
5. **求 d 解密**：`φ1=p1(p1−1)(q1−1)`、`φ2=p2(p2−1)(q2−1)`；`d1=inverse(e,φ1)`、`d2=inverse(e,φ2)`；`m1=pow(c1,d1,n1)`、`m2=pow(c2,d2,n2)`。
6. **拼接**：`long_to_bytes(m1)+long_to_bytes(m2)`，检查 flag 格式。

## PoC

```python
import math
from Crypto.Util.number import long_to_bytes, inverse, isPrime

def next_prime(n):
    n += 1 if n % 2 == 0 else 2
    while not isPrime(n):
        n += 2
    return n

def continued_fraction(n, d):
    while d:
        q = n // d
        yield q
        n, d = d, n % d

def convergents(n, d):
    h1, k1 = 1, 0
    h2, k2 = 0, 1
    for q in continued_fraction(n, d):
        h1, h2 = q * h1 + h2, h1
        k1, k2 = q * k1 + k2, k1
        yield h1, k1

for num, den in convergents(n2, n1):
    if den == 0 or n1 % den:
        continue
    sq = n1 // den
    p1 = math.isqrt(sq)
    if p1 * p1 != sq:
        continue
    q1 = den
    p2 = next_prime(p1)
    if n2 % (p2 * p2):
        continue
    q2 = n2 // (p2 * p2)
    if p2 * p2 * q2 != n2:
        continue
    phi1 = p1 * (p1 - 1) * (q1 - 1)
    phi2 = p2 * (p2 - 1) * (q2 - 1)
    m1 = pow(c1, inverse(e, phi1), n1)
    m2 = pow(c2, inverse(e, phi2), n2)
    print((long_to_bytes(m1) + long_to_bytes(m2)).decode())
    break
```

原文输出：`HECTF{cRoss_0v3r_v&ry_yOxi}`。

## 变体与关联

- 变体：p2 与 p1 的差值更大时用 Fermat/Coppersmith；q1 很大时连分数收敛子不够，改用格/近似公因子；模数结构换成 `n=p²q` 单模数（见 p² 卡）、`n=pq` 共享因子（见相关模数卡）。
- 关联：[[crypto-rsa-structurally-related-moduli-continued-fraction-crt]]（结构相似双模数 + 连分数 + CRT）、[[crypto-rsa-perfect-square-modulus-p-squared]]（p² 模数的 φ 计算）、[[crypto-rsa-fermat-close-prime-factorization]]（接近素数分解）、[[crypto-rsa-continued-fraction-lambda-factorization]]（连分数与 λ 分解）。
- 同题：`simple_math` 用特殊模数结构 + e=8 多层平方根；`ez_ecc` 用点减半恢复 ECC 参数。

## 检测与防御

- **密钥生成**：不要用 `next_prime`/相邻素数生成多个密钥；p、q 应独立随机，且不同密钥之间不得共享因子或存在已知代数关系。
- **模数检查**：对生成的 n 检查是否为完全平方、是否含小平方因子、与其他模数的 gcd 是否为 1；发现共享/相关模数立即轮换。
- **指数与填充**：使用 e=65537、OAEP 填充；避免同一明文用相关模数分别加密。
- **审计**：在多密钥部署中批量计算 `gcd(n_i,n_j)` 与模数比值连分数，检测相关密钥；对历史密文评估可解性。
