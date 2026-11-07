---
id: crypto-rsa-pell-equation-prime-generation
title: Pell 方程生成 RSA 素数：x²-2y²=1 的解空间把 p、q 退化成 N 的唯一函数
type: scenario
domain: crypto
path: crypto/rsa
technique: pell-equation-prime-generation
tags:
- rsa
- pell-equation
- prime-generation
- weak-key
- number-theory
- factorization
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:20+08:00'
  notes: 对照 Crypto471：x²-2y²=1、p=next_prime(x)、q=next_prime(y)、k 枚举 gcd 分解一致；未复跑
url: /docs/crypto/rsa/crypto-rsa-pell-equation-prime-generation/
draft: false
kb_aliases:
- Pell 方程 RSA
- NeuroPell
- x^2-2y^2=1 素数生成
- next_prime(Pell 解)
- 代数约束分解 RSA
- 连分数求基本解
---

## 一句话结论

当 RSA 的素数不是随机生成，而是取 Pell 方程 `x²-2y²=1` 的第 k 个解附近的 `next_prime(x)`、`next_prime(y)` 时，`p/q≈√2` 且 `p·q=N` 只留下一个关于 k 的单调方程；攻击者枚举 k、对每个解做 `next_prime` 并与 N 求 gcd，即可在毫秒级分解 512 位 N。

## 原理

- Pell 方程 `x²-2y²=1` 的全部正整数解由基本解 (3,2) 的幂给出：`x_k + y_k√2 = (3+2√2)^k`。解序列增长快、彼此可递推。
- 由 `x²-2y²=1` 得 `x/y = √(2 + 1/y²) → √2`。若 `p=next_prime(x_k)`、`q=next_prime(y_k)`，则 `p/q ≈ x/y ≈ √2`。
- 又 `N=p·q ≈ x·y ≈ √2·y²`，于是 `y ≈ √(N/√2)`、`x ≈ √(N·√2)`。给定 N 后，k 只能落在一个很窄的范围；由于 Pell 解随 k 单调增长，满足量级的 k 基本唯一。
- 攻击者不需要分解 N：从 k=1 开始递推 `(x_k,y_k)`，对每个候选计算 `p=next_prime(x_k)`、`q=next_prime(y_k)`，检查 `gcd(p·q, N)` 是否落在 (1,N)。命中即得到真实因子，因为真实素数就在某个 Pell 解附近几个整数内。
- 安全性依据是“攻击者不知道素数生成规律”，违反 Kerckhoffs 原则：生成算法和参数（连 D=2 都公开）一旦泄露，N 的两个独立大素数就退化成由 N 唯一确定的一个数，RSA 的困难性假设不再成立。

## 触发条件

- 素数生成使用确定性的代数序列（Pell/Lucas/线性递推等）加 `next_prime`，而不是 CSPRNG。
- 生成算法/参数公开或可推断（题目直接给出方程与 D）。
- p、q 均为该序列附近的素数，且 N 的位数量级足以让 k 范围可枚举。
- e 与 N 正常公开，攻击者能拿到 N。

## 利用步骤

1. 识别素数生成规律：题目/代码给出 `x²-Dy²=1`、`p=next_prime(x)`、`q=next_prime(y)`。
2. 用连分数法求基本解；对 D=2 直接得到 (3,2)。
3. 由 `y ≈ √(N/√D)` 估算 k 的上界，或从 k=1 顺序递推并在 `x·y > N` 后停止。
4. 对每个 k 计算 `next_prime(x_k)`、`next_prime(y_k)`，求 `g=gcd(p*q, N)`；`1<g<N` 即命中因子。
5. 得到 p、q 后计算 `phi=(p-1)(q-1)`、`d=e^{-1} mod phi`，标准 RSA 解密；用 CRT 交叉验证。

## PoC

```python
from math import isqrt, gcd

def fundamental(D):
    a0 = isqrt(D)
    m, d, a = 0, 1, a0
    n1, n2, d1, d2 = 1, a0, 0, 1
    while True:
        m = d * a - m
        d = (D - m * m) // d
        a = (a0 + m) // d
        n1, n2 = n2, a * n2 + n1
        d1, d2 = d2, a * d2 + d1
        if n2 * n2 - D * d2 * d2 == 1:
            return n2, d2

def factor_pell(N, D=2, e=65537):
    x, y = fundamental(D)          # D=2 -> (3,2)
    while x * y <= N * 4:          # 留出 next_prime 的余量
        p, q = next_prime(x), next_prime(y)
        g = gcd(p * q, N)
        if 1 < g < N:
            return g, N // g
        x, y = 3 * x + 4 * y, 2 * x + 3 * y   # 乘以基本解 (3+2√2)
    raise ValueError("not found")

p, q = factor_pell(N)
phi = (p - 1) * (q - 1)
m = pow(c, pow(e, -1, phi), N)
print(m.to_bytes((m.bit_length() + 7) // 8, "big"))
```

## 变体与关联

- 变体：D 取其他非平方数；p、q 取 `next_prime` 之外的形式（`x±c`、`x·y` 的线性组合）时，枚举窗口略放宽但仍可试。
- 变体：Lucas 序列、Fibonacci、线性同余生成器生成的素数对同理——只要存在低维代数约束，就能把分解降为枚举。
- 关联：[[crypto-rsa-common-modulus]]（共享模数分解）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（素数高位泄露的格攻击）。
- 边界：若素数在 Pell 解附近取随机偏移且偏移空间很大，枚举会失败；N 的位数过大导致 k 范围过大时也需要更聪明的界估计。

## 检测与防御

- 检测：代码审计中搜索 `pell`、`next_prime` 与固定递推序列；密钥生成是否使用 CSPRNG；对同一公钥的多次生成结果做代数关系检查。
- 修复：素数必须来自 CSPRNG（`secrets`/`os.urandom`/HSM），并做素性检验；不要用确定性序列、时间种子或可预测参数生成 RSA 密钥。
- 加固：密钥生成后做自检（p、q 独立随机、|p-q| 足够大、e 与 phi 互素）；使用成熟库（OpenSSL/GnuTLS）而不是自写数论生成器；定期轮换密钥。
