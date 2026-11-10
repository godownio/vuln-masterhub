---
id: crypto-rsa-ciphertext-p-cube-q-near-integer-square-root
title: 密文 C ≡ p³q mod N：C·n⁻¹ mod N 退化为 p²，整数开方直接分解 n
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-ciphertext-product-prime-power-integer-root
tags:
- crypto
- rsa
- integer-root
- small-exponent
- factorization
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:28:33+08:00'
  notes: 已对照原文核对：task.py 中 p/q 1001bit（while p%3==1 保证 e=3 可逆）、P/Q 1024bit、C=(pow(p,e,N)*q)%N，exp 用 D=C*inverse(n,N)%N、gmpy2.iroot(D,2) 求得 p 后 q=n//p、d=inverse(3,phi)、pow(c,d,n)，与原文逐行一致；原文 p 为 1001bit 故 p^2≈2002bit<N(2048bit)，无回绕，卡片边界条件说明成立；未设 affected_versions（CTF 题无版本）；未复跑
url: /docs/crypto/rsa/crypto-rsa-ciphertext-p-cube-q-near-integer-square-root/
draft: false
kb_aliases:
- RSARSA
- C ≡ p^3 q mod N
- 密文含素数乘积
- C*n^-1 开平方
- 双 RSA 嵌套
---

## 一句话结论

题目除了普通 RSA 的 `c = m³ mod n` 之外，还额外输出 `C ≡ p³·q (mod N)`（`N` 是另一对 2048 bit 素数 `P·Q` 的模数）；因为 `p³q = p²·(pq) = p²·n`，所以 `C·n⁻¹ ≡ p² (mod N)`，而此时 `p²` 只有约 2002 bit 小于 2048 bit 的 `N`、没有发生模约减，对 `C·n⁻¹ mod N` 直接开平方就得到 `p`，接下来 `q = n//p`、求 `d` 解出明文。

## 原理

- **代数化简**：`C = p³q mod N = (p²)·(p·q) mod N = p²·n mod N`。因此 `C·n⁻¹ ≡ p² (mod N)`，攻击者第一步只做一次模逆。
- **为什么能开方而不需要 Coppersmith**：`p` 是 1001 bit，`p²` 约 2002 bit，而 `N = P·Q` 是 2048 bit（`P`、`Q` 各 1024 bit）。于是 `p² < N`，`p² mod N` 不产生回绕，`C·n⁻¹ mod N` 的取值恰好等于整数 `p²`，`gmpy2.iroot(·, 2)` 一次得到 `p`。
- **边界条件**：只要 `p² < N` 就成立；若 `p` 与 `N` 的因子量级接近（例如 `P`、`Q` 与 `p` 同位数），`p² > N` 会产生回绕，就需要枚举 `k` 使得 `p² = C·n⁻¹ + k·N` 且为完全平方（或改用 Coppersmith 求 `p` 的小根）。
- **另一条并行线索**：`c = m³ mod n` 用 `e=3` 正常解密即可（`d = inverse(3, (p-1)(q-1))` 在 `p,q ≢ 1 mod 3` 时存在，题目正是用 `while p%3==1` 生成素数保证可逆）。
- **为什么这个“多输出”是致命的**：`n` 本来只该在 `m³ mod n` 里作为模数出现，把 `n` 的因子乘进一个**模另一个模数**的表达式里，等于把 `n` 的因子以“平方”形式泄露给攻击者；两个互不相干的 RSA 实例被同一个乘积式绑在一起。

## 触发条件

- 同时给出 `n`（被分解目标）、`N`（另一个模数）、`c`、`C`。
- `C` 的表达式含 `p` 的幂次与 `q` 的乘积，使得 `C ≡ p^k·n mod N` 且 `p^k < N`。
- `e` 与 `p-1`、`q-1` 互素（本题 `e=3`，素数生成时避开了 `≡1 mod 3`）。

## 利用步骤

1. 读输出得到 `n, c, N, C`。
2. 算 `D = C * inverse(n, N) % N`，验证 `D` 的 bit 长度约等于 `2 * bitlen(p)`。
3. `p = gmpy2.iroot(D, 2)[0]`，检查 `n % p == 0`；不整除则说明发生了回绕，改用 `k` 枚举或 Coppersmith。
4. `q = n // p`，`d = inverse(3, (p-1)*(q-1))`，`m = pow(c, d, n)`，`long_to_bytes` 取 flag。
5. 校验：`pow(m, 3, n) == c` 且 `p*q == n`。

## PoC

```python
from Crypto.Util.number import inverse, long_to_bytes
import gmpy2

n, c, N, C = ...

D = C * inverse(n, N) % N
p = gmpy2.iroot(D, 2)[0]
assert n % p == 0

q = n // p
d = inverse(3, (p - 1) * (q - 1))
m = pow(c, d, n)
assert pow(m, 3, n) == c
print(long_to_bytes(int(m)))
```

## 变体与关联

- 变体：`C ≡ p²·q² mod N` 时 `C·n⁻² ≡ 1`，无信息；要挑“指数差 2 且能约掉 `n`”的形式才有用。
- 变体：`C ≡ p³·q mod N` 且 `p² > N` 时，枚举 `k ∈ [0, ⌈p²/N⌉]` 使 `D + kN` 为完全平方，通常 `k` 很小。
- 变体：若给的是 `C ≡ p^e·q mod N`、`e` 稍大，而 `p^e` 已超 `N`，则需 Coppersmith 求 `p` 小根；可复用 [[crypto-rsa-prime-bit-chunks-multivariate-coppersmith-tiered]] 的框架。
- 关联：[[crypto-rsa-multiprime-cube-hint-linear-prime]]（开立方型提示）、[[crypto-rsa-perfect-square-modulus-p-squared]]（模数本身是完全平方）、[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（同样是“密文未模约减”的开方思路）。

## 检测与防御

- 防御：绝不把模数因子以乘积/幂的形式放进任何对外输出；本题的 `C` 属于纯粹的“出题式泄露”，真实系统里对应的是把私钥材料拼进签名中间值。
- 防御：`e=3` 且无随机填充本身已不安全；再加上因子泄露，等同于直接公布私钥。
- 检测：输出中出现两个不同模数的组合式（一个模数作模、另一个模数的因子作乘数）时应立即拒绝生成。
- 响应：该密钥对作废；同时检查是否有任何日志/接口把 `p` 的幂次运算中间值外泄。
