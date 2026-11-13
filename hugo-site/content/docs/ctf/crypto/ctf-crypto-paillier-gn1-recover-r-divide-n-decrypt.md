---
id: ctf-crypto-paillier-gn1-recover-r-divide-n-decrypt
title: Paillier CTF 解密（g=n+1）：分解 n 后用 n 在 φ(n) 上的模逆恢复随机数 r，再按 n 整除取出明文 m
type: scenario
domain: ctf
path: ctf/crypto
technique: paillier-known-factor-recover-randomness
tags:
- ctf
- crypto
- paillier
- homomorphic-encryption
- rsa-like
- known-factorization
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:48:50+08:00'
  notes: 已对照原文全文与4张图核对，并独立复算公式：图04 二项式展开 g^m=(n+1)^m=...+mn+1 mod n^2 与卡片一致；解密路径 r^n≡c mod n、d=n^{-1} mod φ(n)、r=(c mod n)^d mod n、a=c·r^{-n} mod n^2−1=mn、m=a/n 均正确。用 p=61,q=53,n=3233,φ=3120,m=1234,r=17 实跑：加密 c=8593617，恢复 r=17，a=3989522 且 a%n=0，m=1234 还原成功；卡片『标准路径对照』另以 λ=(p-1)(q-1)、μ=λ^{-1} mod n 复算亦得 1234（注意原文板子2 写 miu=inverse(Lambda,n*n) 有误，卡片采用正确形式，属于对原文代码的修正而非偏离）。原文无版本信息、无 CVE，不设 affected_versions 正确；该卡为 CTF 技巧，severity/confidence medium 合理。dedup recommendation=new，13 个 related 均为 RSA 类（d 泄漏/共模/连分数分解等），非 Paillier；库内除本卡外无 paillier 命中；dup-scan.json 未涉及。去留：保留并 verified。
url: /docs/ctf/crypto/ctf-crypto-paillier-gn1-recover-r-divide-n-decrypt/
draft: false
kb_aliases:
- Paillier 解密
- Paillier 同态加密 CTF
- g=n+1 恢复 r
- Paillier 已知 n c 求 m
- 加法同态 Paillier
---

## 一句话结论

Paillier 加密 `c = g^m · r^n mod n²` 在 `g = n+1` 时，二项式展开给出 `g^m = mn + 1 mod n²`，且 `g ≡ 1 (mod n)`，于是 `r^n ≡ c (mod n)`；只要分解 `n` 得到 p、q，就能用 `d = n^{-1} mod φ(n)` 像 RSA 一样恢复随机数 `r`，再算 `a = c · r^{-n} mod n² − 1 = mn`，按 n 整除即得明文 `m`。CTF 中给出 `n、c`（`g=n+1`）且 n 可分解时可直接解出。

## 原理

- Paillier 密钥生成：选大素数 p、q，满足 `gcd(pq, (p−1)(q−1)) = 1`，`n = pq`，`λ = lcm(p−1, q−1)`，随机选 `g`（常取 `g = n+1` 加速），公钥 `(n, g)`，私钥 `(λ, μ)`，`μ = L(g^λ mod n²)^{-1} mod n`，`L(x) = (x−1)/n`。
- 加密：`c = g^m · r^n mod n²`，其中 `0 ≤ m < n`，随机 `r ∈ Z_n*`。
- 取 `g = n+1` 时，二项式展开 `(n+1)^m = 1 + mn + C(m,2)n² + …`，模 n² 后 `g^m = mn + 1 mod n²`；同时 `g ≡ 1 (mod n)`，所以 `c ≡ r^n (mod n)`。
- 因为密钥生成要求 `gcd(pq, (p−1)(q−1)) = 1`，`n` 在模 `φ(n) = (p−1)(q−1)` 下可逆，`d = n^{-1} mod φ(n)`；对 `r^n ≡ c (mod n)` 两边取 d 次幂即 `r ≡ (c mod n)^d mod n`（与 RSA 解密同构）。
- 恢复 r 后：`c · r^{-n} ≡ g^m ≡ mn + 1 (mod n²)`，令 `a = c · r^{-n} mod n² − 1`，则 `a ≡ mn (mod n²)` 且 n | a；`m = (a / n) mod n`，因 `0 ≤ m < n` 直接就是明文。
- 与标准解密的区别：标准路径需要 λ、μ；本方法在只有 `n、c、g=n+1` 且 n 可分解时，绕开 μ 直接恢复随机数 r 取 m。

## 触发条件

- CTF/题目给出 Paillier 公钥 `(n, g=n+1)` 与密文 `c`，没有 λ、μ。
- `n` 可分解（弱素数、共享素数、factordb/yafu 可解等），且满足 Paillier 要求 `gcd(pq, (p−1)(q−1)) = 1`。
- 明文 `m < n`（Paillier 正常加密范围）。

## 利用步骤

1. 对 `n` 分解得到 p、q（yafu、factordb、sympy 或题目泄漏）。
2. 计算 `φ = (p−1)(q−1)`，`d = invert(n, φ)`。
3. 恢复随机数：`r = pow(c % n, d, n)`；可验证 `pow(r, n, n) == c % n`。
4. 计算 `a = c * pow(invert(r, n*n), n, n*n) % (n*n) - 1`。
5. `m = (a // n) % n`，`long_to_bytes(m)` 得到明文。

## PoC

```python
from gmpy2 import invert
from Crypto.Util.number import long_to_bytes

n = ...
c = ...
p, q = ...          # 分解 n 得到
assert p * q == n

phi = (p - 1) * (q - 1)
d = invert(n, phi)
r = pow(c % n, d, n)
assert pow(r, n, n) == c % n

a = c * pow(invert(r, n * n), n, n * n) % (n * n) - 1
m = (a // n) % n
print(long_to_bytes(m))
```

标准路径对照（已知 λ、μ 时）：

```python
def L(x, n): return (x - 1) // n
lam = (p - 1) * (q - 1)
mu = invert(lam, n)          # g = n+1 时 L(g^lam mod n^2) = lam mod n
m = (L(pow(c, lam, n * n), n) * mu) % n
```

## 变体与关联

- 变体：`g ≠ n+1` 时上述 `g ≡ 1 mod n` 不成立，需按通用 Paillier 用 λ、μ 解密，或先按 `L` 函数求 μ。
- 变体：n 不可分解但泄漏 λ、μ 或 `p+q` 时，走标准 Paillier 解密或先分解 n。
- 关联：[[crypto-rsa-wiener-small-private-exponent-large-e]]、[[crypto-rsa-schmidt-samoa-known-d-factor]]——同为「已知/恢复参数后解公开钥密码」的 CTF 思路。
- 关联：RSA 的乘法同态（`c1·c2` 解密为 `m1·m2`）与 Paillier 的加法同态（`c1·c2` 解密为 `m1+m2`）是两类同态性质的对照。

## 检测与防御

- 该卡是 CTF 解密思路，不是实际系统漏洞：真实部署中 Paillier 的 n 必须足够大且不可分解，p、q 等长强素数，避免共享素数/弱随机。
- 防御：密钥生成校验 `gcd(pq,(p−1)(q−1))=1`；不要复用素数；私钥 λ、μ 与随机数 r 不得泄漏。
- 检测（CTF/审计）：题目同时给出 n、c 且 g=n+1 时，优先尝试分解 n + 恢复 r 的路径；若 n 很小或可从多组模数 gcd 分解，直接按本卡解密。
