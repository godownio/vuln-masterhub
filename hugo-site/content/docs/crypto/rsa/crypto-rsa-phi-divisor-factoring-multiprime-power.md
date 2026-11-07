---
id: crypto-rsa-phi-divisor-factoring-multiprime-power
title: 已知 e | φ(N) 分解 N=P·Q^r：AMM 求根 + Hensel 提升 + Coppersmith 小根
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-phi-divisor-factor-multiprime-power
tags:
- rsa
- phi
- phi-hiding
- coppersmith
- amm
- hensel
- factorization
- multiprime
- lattice
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V182
  verified_at: '2026-11-06T19:59:20+08:00'
  notes: 已对照原文核对（含13张公式图）；SageMath PoC 未在本机执行；三种 e 结构、界 N^(1/(4r)) / N^(β−rβ²)、AMM/Hensel/CRT/Coppersmith 流程与文中代码及输出一致
url: /docs/crypto/rsa/crypto-rsa-phi-divisor-factoring-multiprime-power/
draft: false
kb_aliases:
- φ-hiding 攻击
- phi-hiding 失效
- e 整除 phi(N)
- RSA 多幂模数分解
- N=P*Q^r 分解
- AMM+Hensel+Coppersmith
- φ 因子泄露分解
---

## 一句话结论

当 RSA 模数取 `N = P·Q^r`（r≥1）且已知一个大整数 e 满足 `e | φ(N)` 时，只要 e 超过 `N^(1/(4r)+ε)`（β 未知）或 `N^(β−rβ²+ε)`（Q≥N^β 已知），就能在多项式时间内分解 N：先用 AMM/Hensel 在模 e 下解出 `u^r ≡ N (mod e)` 得到 Q mod e 的候选，再用 Coppersmith 求小商 `y0=(Q−u)/e`，最后由 `Q=e·y0+u` 恢复因子。φ-hiding 假设的安全区间因此比传统认知更窄。

## 原理

### 从 e | φ(N) 到 u^r ≡ N (mod e)

- `N = P·Q^r` 时，`φ(N) = Q^(r−1)·(P−1)·(Q−1)`。若 `gcd(e,N)=1`（否则直接算 gcd 就分解了），由 `e | φ(N)` 可得 `e | (P−1)(Q−1)`。
- 先尝试 `e | (Q−1)` 的分支：此时 Q = e·y0 + 1，可用同类小根方法先恢复 Q；若 e 不整除 Q−1，则必有 `e | (P−1)`（e 为素数时二选一，合数时需要对 e 的因子做划分）。
- 在 `e | (P−1)` 的分支设 `P = e·x0 + 1`，`Q = e·y0 + u`，其中 `0 < u < e`。代入 `N = P·Q^r` 并对 e 取模：
  ```text
  N ≡ (e·x0 + 1)·u^r ≡ u^r (mod e)
  ```
  所以 u 是 `X^r ≡ N (mod e)` 的根。r=1 时 u = N mod e 可直接算出；r>1 时用 AMM 在有限域上求全部 r 次根（最多 r 个）。
- 对合数 e：先把 e 分解为 `∏ e_i`（含重因子时写成 `∏ ẽ_i^{z_i}`），在每个素因子模下用 AMM 求根；重因子用 Hensel 提升到 `ẽ_i^{z_i}`；再用 CRT 组合出模 e 的全部候选 u（候选数最多为 r 的素因子个数次方）。
- 若 e 的因子需要在 P−1 与 Q−1 之间划分（平方自由合数有 2^n 种划分），对每种划分计算 `s` 使 `e | (P−s)`、`gcd(e,s)=1`，再解 `u^r ≡ N·s^(−1) (mod e)`；对每个候选检查 `e | (Q−u)`。
- 一般合数且含重复因子时，需要额外假设 `gcd(P−1,Q−1)=2`（随机素数下约 6/π²≈61% 概率）；此时先把 e 的因子分成 E1、E2，再按上述流程处理。

### 用 Coppersmith 恢复小商

- 由 `Q = e·y0 + u` 得 `y0 = (Q−u)/e`。因为 `Q ≥ N^β`、`e ≥ N^(β−rβ²+ε)`，所以：
  ```text
  |y0| ≈ Q/e ≤ N^(rβ²−ε)
  ```
  即 y0 是 N 的某个因子 Q 上的小量。
- 由 `e·y0 + u ≡ 0 (mod Q)`，两边乘 `e^(−1) mod N`：
  ```text
  y0 + a ≡ 0 (mod Q),   a = u·e^(−1) mod N
  ```
  于是问题变成：已知 N 的一个未知因子 `Q ≥ N^β`，求多项式 `f(y)=y+a` 在模 Q 下的小根 y0。这正是 Coppersmith 的“模未知因子小根”场景；用 Howgrave-Graham 格/Coppersmith 的 shift 构造即可恢复 y0。
- 恢复 y0 后计算 `Q = e·y0 + u`，检查 `Q | N`；再算 `P = N / Q^r`，完成分解。
- β 未知时，用迭代算法从 `β0=1/r` 开始按 `β ← max(sqrt((β−(γ−μ))/r), γ)` 逐步下调/逼近，对每个 β 跑一次 Coppersmith；β 已知时直接用该 β。

### 界与意义

- **e 为素数**：β 未知时 `e ≥ N^(1/(4r)+ε)`；β 已知时 `e ≥ N^(β−rβ²+ε)`。当 `β=1/(2r)` 时 `β−rβ²` 取最大值 `1/(4r)`，两式一致。
- **e 为平方自由合数**：e 的素因子个数为 O(log log N)；对每种因子划分（2^n 种）分别求根，界与素数情形相同。
- **e 为一般合数**：在 `gcd(P−1,Q−1)=2` 下用 Hensel 处理重因子，候选数仍为 log N 的多项式级，界不变。
- **平衡素数**：若 P 与 Q 位长相近，`β≈1/(r+1)`，代入得 `e ≥ N^(1/(r+1)²+ε)`；r=1 时就是经典的 `N^(1/4)`，r 越大门槛越低。
- **φ-hiding 的含义**：φ-hiding 假设“给定 N 和素数 e，判断 e 是否整除 φ(N) 是困难的”，常用于同态加密等构造的安全性论证。上述结果说明：对 `N=P·Q^r`，只要 e 足够大且确实整除 φ(N)，不仅能判断，还能直接分解 N；传统“e 远小于 N^(1/4) 才安全”的边界需要按模数结构和 e 的大小重新评估。
- **与普通 RSA 的关系**：标准 RSA 是 r=1、P、Q 等长；此时若泄露一个 ≥N^(1/4) 的 e | φ(N)，即可分解。若 e 很小（如 65537）且攻击者只知道 e 而不知道它整除 φ(N)，则本攻击不适用。

## 触发条件

- 已知 `N = P·Q^r` 的 N、r，以及一个满足 `e | φ(N)` 的整数 e；`gcd(e,N)=1`（否则 gcd 直接给出因子）。
- e 的大小达到对应界：β 未知时 `e ≥ N^(1/(4r)+ε)`，β 已知时 `e ≥ N^(β−rβ²+ε)`。
- e 的分解已知（合数情形）；一般合数还要求 `gcd(P−1,Q−1)=2`。
- 能使用 SageMath（AMM/有限域求根、CRT、Coppersmith 格）或等价格基约简工具；N 的规模在格可处理的范围内。
- 题目/协议明确给出 e 整除 φ(N)，或可通过旁路/泄露确认这一关系；仅有公钥 e 不能直接套用。

## 利用步骤

1. 计算 `g = gcd(e,N)`；`g>1` 时直接用 g 分解 N，结束。
2. 判断 e 的结构：素数、平方自由合数、还是一般合数（含重因子）。对 e 做因式分解，记录每个素因子及其指数。
3. 对 e 为素数：在 `Zmod(e)` 上解 `X^r − N = 0`，得到最多 r 个 u 候选（AMM/Sage `.roots()`）。
4. 对平方自由合数：枚举 e 的因子在 P−1/Q−1 之间的划分，计算对应的 s，解 `u^r ≡ N·s^(−1) (mod e_i)`，在每个素因子下 AMM 后用 CRT 组合候选 u；对每个候选检查 `e | (Q−u)`。
5. 对一般合数：在每个 `ẽ_i` 下 AMM 求根，用 Hensel 提升到 `ẽ_i^{z_i}`，CRT 组合；候选数最多 r^t，逐个检查。
6. 对每个候选 u，计算 `a = u·e^(−1) mod N`，构造 `f(y)=y+a`；用 Coppersmith（β 已知）或迭代 β（β 未知）求小根 y0。
7. 计算 `Q = e·y0 + u`，验证 `N % Q == 0`；计算 `P = N // Q^r`，并用 `P·Q^r == N`、P/Q 为素数交叉验证。
8. 若第一组 u 失败，换下一个根/划分；β 未知时按迭代算法继续下调 β。

## PoC

以下为“e 为素数、β 已知”情形的最小 SageMath 实现，直接复用文中的 Coppersmith shift 构造（把 flatter 换成 Sage 自带 LLL，便于复现；原实现用 flatter 加速）：

```python
from sage.all import *

def find_roots_from_basis(B):
    PR.<x> = PolynomialRing(ZZ)
    h = sum(ZZ(B[0, -(i + 1)]) * x**i for i in range(B.ncols()))
    return [int(r[0]) for r in h.roots()]

def coppersmith(f, u, v, beta, eps):
    m = ceil((beta * (2*u + v - u*v*beta)) / eps) - 1
    t = ceil(u * beta * m)
    R = f.base_ring()
    N = R.cardinality()
    f = f.change_ring(ZZ)
    X = int(N ** (u*v*beta**2 - eps))
    g = lambda k: f**k * N**max(ceil((v*(t - k))/u), 0)
    shifts = Sequence([g(k) for k in range(m + 1)], f.parent())
    B, monomials = shifts.coefficients_monomials()
    monomials = vector(monomials)
    bounds = [X]
    factors = [monomial(*bounds) for monomial in monomials]
    for i, fac in enumerate(factors):
        B.rescale_col(i, fac)
    B = B.LLL()
    B = B.change_ring(QQ)
    for i, fac in enumerate(factors):
        B.rescale_col(i, 1 / fac)
    return find_roots_from_basis(B)

def factor_phi_prime_e(N, e, r, beta, eps=0.01):
    # e 为素数，e | phi(N)，gcd(e,N)=1，Q >= N^beta
    R.<x> = PolynomialRing(Zmod(e))
    for root in (x**r - (N % e)).roots():
        u = int(root[0])
        a = (u * inverse_mod(e, N)) % N
        PR.<y> = PolynomialRing(Zmod(N))
        f = y + a
        for y0 in coppersmith(f, r, 1, beta, eps):
            Q = e * y0 + u
            if Q > 1 and N % Q == 0:
                return Q, N // Q**r
    return None
```

使用示例（占位符替换为题目给出的 N、e、r、β）：

```python
N = Integer(0x...)
e = Integer(0x...)
r = 4
beta = 0.2          # Q ≈ N^beta；未知时改用迭代 beta 的版本
Q, P = factor_phi_prime_e(N, e, r, beta)
assert P * Q**r == N
print(P); print(Q)
```

复合 e 的情形不能直接用上面的单素数根枚举：需要按“原理”中的划分/AMM/Hensel/CRT 扩展候选集合；文中对平方自由合数和含重因子合数均给出了完整实现与运行结果，核心的 Coppersmith 与最终 `Q = e·y0 + u` 校验不变。

## 变体与关联

- **e 为素数（Case 1）**：最简单，直接 `X^r−N` 求根；β 未知时用迭代 β，β 已知时一次 Coppersmith。文中示例 r=4、β≈0.2、e≈N^0.103，约 12 秒恢复 486-bit 的 Q。
- **e 为平方自由合数（Case 2）**：e 的素因子在 P−1/Q−1 间有多种划分（2^n），对每种划分用 `s` 归一化成 `u^r ≡ N·s^(−1)`，再对每个素因子 AMM + CRT。
- **e 为一般合数（Case 3）**：含重复素因子时，AMM 只能给出模 `ẽ_i` 的根，需 Hensel 提升到 `ẽ_i^{z_i}`；要求 `gcd(P−1,Q−1)=2`。文中示例 `e=67049·69193²·81031·84559·95819·116531·125149`，AMM+Hensel+CRT 后得到 128 个候选 u，Coppersmith 约 16 秒出结果。
- **r=1 的经典情形**：退化为“已知 e | φ(N) 分解普通 RSA 模数”，界为 `N^(1/4)`（β 未知）或 `N^(β−β²)`（β 已知）；平衡 P、Q 时即 `N^(1/4)`。与“已知 φ(N) 直接求 d”不同，这里只知道 e 整除 φ(N)，仍需格攻击。
- **平衡素数改进**：P、Q 位长相近时 β≈1/(r+1)，界变为 `N^(1/(r+1)²)`；r 增大时门槛下降，多幂模数比标准 RSA 更脆弱。
- **关联：完全平方模数**。`crypto/rsa` 下已有 `n=p²` 的开方卡，那是 r=2、P=Q 的退化特例，不需要格；本卡处理 P≠Q、r≥1 的一般结构。
- **关联：多素数/部分密钥 Coppersmith**。`crypto-rsa-multiprime-partial-key-coppersmith`、`crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d` 等卡覆盖的是“已知因子高位/部分私钥”的格攻击；本卡的已知信息是“e 整除 φ(N)”，入口不同。
- **关联：φ-hiding 与同态加密**。Naccache–Stern 等构造把 φ-hiding 作为安全性假设；本结果说明在 `N=P·Q^r` 且 e 较大时该假设不成立，选参时不能只看 e 是否“远小于 N^(1/4)”。

## 检测与防御

- **避免多幂模数**：不要使用 `N=P·Q^r`（r>1）作为 RSA/同态加密模数；标准 RSA 使用两个独立大素数。
- **保护 φ(N) 的因子信息**：不要在协议、日志、错误消息或旁路中泄露“某个大 e 整除 φ(N)”；e 应由可信方生成并检查 `gcd(e,φ(N))=1`，而不是接受攻击者选取的 e。
- **参数选择**：若必须使用 φ-hiding 类假设，按论文的新界评估安全性，确保 e 落在假设仍可能成立的范围内，并考虑 r、β 与 P/Q 位长比；不要沿用“e<N^(1/4) 就安全”的旧结论。
- **密钥生成校验**：生成后检查 N 的因子结构（是否为完全幂/多幂）、P、Q 位长与 gcd(P−1,Q−1)；对异常模数拒绝使用。
- **CTF/审计检测**：拿到 N、e、r 后先算 `gcd(e,N)`、检查 N 是否为 `P·Q^r` 形式、比较 e 的位长与 `N^(1/(4r))`、`N^(β−rβ²)`；若题目给出 e | φ(N)，直接按本卡流程尝试。
- **实现注意**：Sage 自带 `small_roots` 在 r>1、β 较小时的界可能不够，需要按 `f^k·N^max(...)` 的 shift 构造自定义格；β 未知时用迭代算法逐档尝试，避免一次固定 β 失败就放弃。
- **检测异常**：在密码协议中监控异常大的公钥指数 e、异常的模数位长比、以及重复出现的“e 整除 φ(N)”声明；这些可能是降级/后门参数。
