---
id: crypto-rsa-multiprime-cube-hint-linear-prime
title: 多素数 RSA 立方提示 p³ mod n + q=7p+i：直接开立方恢复 p 并分解 n
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-multiprime-cube-hint-linear-prime-relation
tags:
- crypto
- rsa
- multiprime
- factorization
- hint
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V228
  verified_at: '2026-11-07T07:06:43+08:00'
  notes: 已对照原文数据复算：hint=p³（3071位）、n为3074位（原卡误写7168位，已修正）、q=7p+88（原卡写“个位数到几十”，已补实际i=88）、r=n/(pq)，解密得f8be83156f83438cb172651ec3c5e168，与原文一致。dup-scan三对均为related（dp泄露、e=19多轮、复合模数Coppersmith），非同一链。未验证点：未运行原文脚本；frontmatter无sources/source_url；无版本。
url: /docs/crypto/rsa/crypto-rsa-multiprime-cube-hint-linear-prime/
draft: false
kb_aliases:
- hint=p^3
- 立方提示 RSA
- q=7p+i
- 三素数 RSA hint
- 解压密码2
- 多素数 RSA 提示分解
---

## 一句话结论

当多素数 RSA 使用 `n = p*q*r`（p、r 各 1024 位，q = 7p + i 且 i 很小），并额外泄露 `hint = p³ mod n` 时，由于 `p³ < n`，`pow(p,3,n)` 不会回绕，直接对 hint 开整数立方根就得到 p；再枚举很小的 i 用 `(n/p) % (7p+i)` 找到 q，最后 `r = n/(p*q)`，即可计算 φ(n)、私钥并解密。

## 原理

- **提示为何是精确立方**：p 是 1024 位（p³ 为 3071 位）；n = p·q·r 中 q≈7p（本题 1027 位）、r 是 1024 位，n 约 1024+1027+1024 = 3075 位（本题实测 3074 位）。p³ 与 n 仅差约 3 位（n/p³≈8），但 p³ < n，所以 `pow(p, 3, n)` 不发生回绕，hint 就是 p³ 的精确值，`gmpy2.iroot(hint, 3)` 可还原 p；边界是 p³ 必须严格小于 n，而不是“远小于”。
- **q 的线性关系**：题目构造 q = 7p + i，i 从 0 开始递增直到 q 为素数。i 只需在较小范围内枚举（本题实际 i=88），在已知 p 和 n/p 后，枚举 i 检查 `n_p % (7*p + i) == 0` 即可恢复 q；随后 r = n/(p*q)。
- **为什么能解密**：得到三个素因子后 φ(n) = (p-1)(q-1)(r-1)，`d = e^{-1} mod φ(n)`，`m = c^d mod n`，`long_to_bytes` 得到明文。整个攻击的根因是“泄露了素因子的幂，且另一素因子与它只差一个小偏移”。
- **与常规多素数 RSA 的区别**：正常多素数 RSA 只要三个 1024 位独立随机素数就安全；本卡利用的是题目/实现的密钥生成缺陷（hint + 线性关系），不是 RSA 算法本身的通用弱点。

## 触发条件

- 多素数 RSA，n = p·q·r（或更多因子），且 p^k < n，hint = p^k mod n 被公开（k=2/3 等）。
- 至少一个素因子与其他因子存在小偏移线性关系（如 q = a·p + i，i 可枚举），或能通过其它方式验证候选因子。
- 攻击者拿到 n、e、c、hint，且 e 与 φ(n) 互素（常规情况）。
- 若 p^k > n，hint 只是模值，需要 Coppersmith/模根等更复杂方法；本卡不覆盖。

## 利用步骤

1. 用 `gmpy2.iroot(hint, k)` 对 hint 开 k 次整数根，验证 `pow(p, k) == hint`（未取模的精确幂）。
2. 计算 `n_p = n // p`，从 i=1 开始枚举候选 `q = a*p + i`，检查 `n_p % q == 0`；命中后验证 q 为素数、p*q 整除 n。
3. 计算 `r = n // (p*q)`，验证 `p*q*r == n` 且 r 为素数。
4. 计算 `phi = (p-1)*(q-1)*(r-1)`，`d = inverse(e, phi)`，`m = pow(c, d, n)`，`long_to_bytes(m)` 得到明文/密码。
5. 若开立方得到的 p 不整除 n，说明 p^k >= n 或 hint 有噪声，需换 Coppersmith/模根/枚举分支。

## PoC

```python
from Crypto.Util.number import long_to_bytes, inverse
from sympy import isprime
import gmpy2

c = <ciphertext>
n = <modulus>
e = 65537
hint = <hint>

# 1) 立方提示直接开根（p^3 < n）
p = gmpy2.iroot(hint, 3)[0]
assert pow(p, 3) == hint and n % p == 0

# 2) q = 7p + i，枚举小 i
n_p = n // p
i = 0
while True:
    i += 1
    q = 7 * p + i
    if n_p % q == 0:
        break
assert isprime(q)

# 3) 剩余因子 r
r = n // (p * q)
assert p * q * r == n

# 4) 解密
phi = (p - 1) * (q - 1) * (r - 1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m).decode())
```

原文在 1024 位 p/r、q=7p+i 的实例上运行成功，输出解压密码 `f8be83156f83438cb172651ec3c5e168`。

## 变体与关联

- 指数变体：hint = p²、p⁴ 等；只要能开整数根并整除 n 即可。
- 关系变体：q = a·p + i（a 已知）、q = p + i、q = next_prime(p) 等；i 较大时改用 Coppersmith 小根或 Fermat 分解。
- 噪声变体：hint 带随机噪声/只给高位时，转到格攻击（Coppersmith/LLL）。
- 关联：[[crypto-rsa-hint-difference-gcd-factorization]]（多组 hint 差值 GCD）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（三素数高位泄露）、[[crypto-rsa-fermat-close-prime-factorization]]（近邻素数）。
- 边界：p^k >= n 时开根不再精确；i 很大或 q 与 p 无关系时枚举失效；e 与 φ 不互素时需特殊处理。

## 检测与防御

- 防御：不要公开任何素因子的幂/乘积等提示；多素数 RSA 的三个因子应独立均匀随机生成，禁止 `q=a*p+i` 之类可预测关系。
- 防御：使用标准库生成 RSA 密钥，避免自实现密钥生成；对私钥材料做访问控制与审计。
- 检测：代码/题面中出现 `pow(p, k, n)`、`hint`、`q = a*p + i` 等模式；密钥生成脚本中素因子存在线性关系。
- 加固：迁移到 RSA-OAEP/RSA-KEM 或 ECC；密钥长度满足当前标准；泄露 hint 后立即轮换密钥。
