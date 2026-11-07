---
id: crypto-rsa-bivariate-coppersmith-two-small-roots
title: 二元 Coppersmith 小根：两个未知数联立二次多项式恢复 RSA 明文
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-bivariate-coppersmith
aliases:
- 二次 Coppersmith
- 二元 Coppersmith
- bivariate small_roots
- 两个小整数根
- RSA 模逆高位泄露
tags:
- rsa
- coppersmith
- bivariate
- small-roots
- lattice
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:24+08:00'
  notes: 已对照原文与图04核对：inv=h+r、A_i=h_i、B_i=1-h_i·t_i、消去 s 的二元式系数与原文逐项一致；图04 推导与卡片一致；m=5 参数、r1 回代求 s 与原文一致。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

当 RSA 相关方程中有两个都小于 `2^k` 的未知量（例如两次模逆的高 `k` 位泄露、低 `k` 位未知）时，先消去公共明文得到二元多项式 `f(x,y)`，再用自实现的二元 Coppersmith `small_roots` 在 `(2^k, 2^k)` 范围内同时求出两个小根，即可恢复明文。

## 原理

- 典型题目：明文 `s`，素数 `p` 已知；对两个随机 `t_i` 计算 `inv_i = (s+t_i)^{-1} mod p`，只公开 `h_i = (inv_i >> k) << k`，即模逆的高位、低 `k` 位被清零。于是 `inv_i = h_i + r_i`，`0 ≤ r_i < 2^k`。
- 由 `(h_i+r_i)(s+t_i) ≡ 1 (mod p)` 得 `(h_i+r_i)s ≡ 1 - (h_i+r_i)t_i (mod p)`。令 `A_i=h_i`、`B_i=1-h_i·t_i`，则 `(A_i+r_i)s ≡ B_i - r_i·t_i (mod p)`。
- 两个方程都含同一个 `s`；把第一式乘 `(A_2+r_2)`、第二式乘 `(A_1+r_1)` 后相减，消去 `s`，得到只含 `r_1,r_2` 的二元多项式：
  `f(r1,r2) = B1·A2 - B2·A1 + r2·(B1 + A1·t2) - r1·(B2 + A2·t1) + r1·r2·(t2 - t1) ≡ 0 (mod p)`。
- `r1,r2` 都小于 `2^k`，相对 `p` 很小；这是模已知素数 `p` 的二元小根问题。二元 Coppersmith 用 `f` 的幂与 `x^i y^j` 移位构造格，LLL 后取短向量，再求理想簇（`variety`）得到整数根。
- 得到 `r1` 后，`inv1 = h1 + r1 mod p`，由 `(inv1)(s+t1) ≡ 1` 解出 `s = (1 - inv1·t1)·inv1^{-1} mod p`。
- Sage 9.3 自带的 `small_roots` 不支持二元多项式，需要自实现多元版本；示例用 `m=5` 的移位参数。

## 触发条件

- 已知模数 `p`（或 `p` 是 `n` 的因子且满足相应 `beta` 条件）、两组 `(t_i, h_i)`。
- 每个未知量 `r_i` 都小于 `2^k`，且 `k` 相对 `p` 足够小，使格方法可解。
- 两组方程共享同一个明文 `s`，可消元得到二元多项式。
- 能运行 Sage 的 LLL 与理想簇求解；Sage 版本需支持自定义多元 `small_roots`。

## 利用步骤

1. 解析 `p`、`(t1,h1)`、`(t2,h2)`，确认 `h_i` 是模逆去掉低 `k` 位后的值。
2. 计算 `A1=h1`、`A2=h2`、`B1=1-t1·A1`、`B2=1-t2·A2`。
3. 构造 `f = B1*A2 - B2*A1 + y*(B1 + A1*t2) - x*(B2 + A2*t1) + x*y*(t2-t1)`，变量 `x=r1,y=r2`。
4. 调自定义 `small_roots(f, (2^k, 2^k), m=5)`，得到 `(r1,r2)` 候选。
5. 取 `r1`，计算 `inv1=(h1+r1) mod p`，再算 `s=((1-inv1*t1)*inv1^{-1}) mod p`。
6. 转字节得到 flag；用 `(h1+r1)(s+t1) mod p == 1` 校验。

## PoC

```python
from gmpy2 import *
from Crypto.Util.number import *
import itertools

p = ...
t1, h1 = ...
t2, h2 = ...

A1, A2 = h1, h2
B1, B2 = 1 - t1 * A1, 1 - t2 * A2
PR = PolynomialRing(Zmod(p), names=['x', 'y'])
x, y = PR.gens()
f = B1*A2 - B2*A1 + y*(B1 + A1*t2) - x*(B2 + A2*t1) + x*y*(t2 - t1)

k = 128
X = 2^k
Y = 2^k

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m + 1):
        base = N ^ (m - i) * f ^ i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1 / factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B * monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []

roots = small_roots(f, (X, Y), m=5)
print(roots)
r1 = int(roots[0][0])
inv1 = (h1 + r1) % p
m = ((1 - inv1 * t1) * inverse_mod(inv1, p)) % p
print(long_to_bytes(m))
```

## 变体与关联

- 变体：样本数 `d>2` 时，可两两消元或构造更多变量，用多元 Coppersmith/格方法求解。
- 变体：`p` 不是直接给出、而是 `n` 的未知因子时，需要引入 `beta` 参数，按 `p` 的规模选择界。
- 变体：未知量不是模逆的低位而是高位，可改设 `inv = r·2^k + h_lo`，重新推导消元式。
- 关联：[[crypto-rsa-partial-plaintext-high-bits-coppersmith]]（一元小根）、[[crypto-rsa-partial-prime-high-bits-coppersmith]]（因子小根）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（多元/多素数场景）。

## 检测与防御

- 防御：不要泄露模逆的高位/低位；需要公开校验值时使用随机化或哈希，而不是截断的模逆。
- 防御：使用标准 RSA-OAEP 等方案，避免把明文与随机数组合成可消元的代数关系。
- 检测：审计中出现 `(inv >> k) << k`、两次以上模逆截断、同一明文的多个相关值；CTF 中看到 `p` 与两组 `(t,h)` 即可按本卡尝试。
- 响应：确认模逆部分泄露后，相关明文与私钥材料应视为失陷，轮换密钥并排查历史数据。
