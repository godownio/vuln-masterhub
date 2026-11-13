---
id: crypto-rsa-pell-hint-linear-combination-factorization
title: RSA Pell 方程 hint 攻击：已知 x·p+y·q 且 x²-D·y²=1，用韦达定理求 xp/yq 后连分数解 Pell 还原 p、q
type: scenario
domain: crypto
path: crypto/rsa
technique: pell-hint-linear-combination-factorization
tags:
- rsa
- pell-equation
- factorization
- number-theory
- hint
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V599
  verified_at: '2026-11-12T17:12:30+08:00'
  notes: 已对照原文与唯一图（连分数定义）核对：hint=xp+yq、a=xp/b=yq 推 z²-hint·z+xy·n=0、判别式开方求根、连分数求 Pell 基本解并按递推枚举，推导与原文一致。复算通过：随机 256 位 p/q、D=0x1337、真实 Pell 解取第12项，按卡内流程在第12项判别式为完全平方并还原 p、q。dedup 首选 crypto-rsa-pell-equation-prime-generation 虽判 likely_duplicate，但其为弱生成 next_prime+gcd 枚举，本卡为 hint 线性组合+二次方程判别式，触发与 PoC 不同，非同链，force new 成立。注意：卡内 PoC 为 Sage 代码（continued_fraction/var/solve），需 Sage 运行；原文 c/n/hint 为空未提供原题数据。原文无组件版本。
url: /docs/crypto/rsa/crypto-rsa-pell-hint-linear-combination-factorization/
draft: false
kb_aliases:
- Pell 方程 RSA hint
- xp+yq 分解
- 佩尔方程 hint 攻击
- 韦达定理分解 RSA
- hint = x*p+y*q
- D=0x1337
---

## 一句话结论

当题目给出 `hint = x*p + y*q`，且 `(x, y)` 是 Pell 方程 `x² - D·y² = 1` 的解时，令 `a = x*p`、`b = y*q`，可推出 `a`、`b` 是 `z² - hint·z + x·y·n = 0` 的两根；又因 `x/y` 逼近 `√D`，可用连分数枚举 Pell 解 `(x, y)`，对每组检查判别式 `hint² - 4·x·y·n` 是否为完全平方，命中即解出 `a, b`，再 `p = a/x`、`q = b/y` 完成分解。

## 原理

- **构造二次方程消去 p、q**：设 `a = x*p`、`b = y*q`，则 `a + b = hint`，且
  `a² - a·hint = x²p² - x·p·(x*p + y*q) = -x·y·p·q = -x·y·n`；
  同理 `b² - b·hint = -x·y·n`。所以 `a, b` 都满足 `z² - hint·z + x·y·n = 0`，由韦达定理即为此方程的两根。
- **判别式给出可验证条件**：该二次方程的判别式为 `Δ = hint² - 4·x·y·n`。只要 `(x, y)` 猜对且 `a, b` 为整数，`Δ` 必须是完全平方数；开方后 `a, b = (hint ± √Δ)/2`。
- **Pell 解可枚举**：`x² - D·y² = 1` 的全部正整数解由基本解（`√D` 的连分数收敛子）的幂给出，也可用递推 `x_{i+1} = x₁x_i + D·y₁y_i`、`y_{i+1} = x₁y_i + y₁x_i` 生成。题目通常给较小的 `D`（例 `0x1337`），基本解很快求出，解序列的规模有限（`x, y` 与 512 位素数同量级），枚举几十项即可覆盖。
- **为什么能恢复 p、q**：真实 `(x, y)` 必在 Pell 解序列里；一旦找到使 `Δ` 为平方的 `(x, y)`，就得到 `a = x*p`、`b = y*q`，整除即得两个 1024 位素数，最后常规 `φ = (p-1)(q-1)`、`d = e⁻¹ mod φ` 解密。
- **与“Pell 生成素数”的区别**：那种场景是 `p = next_prime(x_k)`、`q = next_prime(y_k)`，攻击靠枚举 k 与 `gcd(p·q, n)`；本场景的素数本身随机，泄漏的是因子与 Pell 解的线性组合 `x*p + y*q`，攻击靠二次方程 + 判别式。

## 触发条件

- 已知 `n`、`e`、`c` 与一个整数 `hint`，且题目/源码提示 `hint = x*p + y*q`。
- `(x, y)` 满足某 Pell 方程 `x² - D·y² = 1`，`D` 已知且较小（可求基本解并枚举解序列）。
- `p、q` 为常规大素数（本例各 1024 位），`hint` 与 `√n` 同量级。
- 攻击者能运行 Sage（连分数、多项式/整数开方）。

## 利用步骤

1. 读题确认 `hint = x*p + y*q` 与 Pell 方程参数 `D`；令 `a=xp, b=yq`，写出方程 `z² - hint·z + x·y·n = 0`。
2. 用连分数求 `√D` 的基本解 `(x1, y1)`：遍历 `i` 取收敛子 `(numer, denom)`，检查 `numer² - D·denom² == 1`。
3. 按递推生成 Pell 解序列 `(x, y)`，逐个计算 `Δ = hint² - 4·x·y·n`。
4. 判断 `Δ` 是否为完全平方；若是，解出 `a=(hint+√Δ)/2`、`b=(hint-√Δ)/2`，令 `p=a//x`、`q=b//y`，断言 `p*q == n`。
5. 常规 RSA 解密：`d = pow(e, -1, (p-1)*(q-1))`，`m = pow(c, d, n)`，`long_to_bytes(m)` 得 flag。
6. 若解序列跑完无平方判别式，检查 `D`、hint 符号或 `a/b` 交换（`x,q` 与 `y,p` 配对）后重试。

## PoC

```python
from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot

def solve_pell(N, numTry=100):
    cf = continued_fraction(sqrt(N))
    for i in range(numTry):
        denom = cf.denominator(i)
        numer = cf.numerator(i)
        if numer^2 - N * denom^2 == 1:
            return numer, denom
    return None, None

def gen_pell(D):
    x, y = solve_pell(D)
    xs, ys = [x], [y]
    while True:
        yield xs[-1], ys[-1]
        xs.append(xs[0] * xs[-1] + D * ys[0] * ys[-1])
        ys.append(xs[0] * ys[-1] + ys[0] * xs[-1])

# c, n, hint, D 由题目给出；e = 0x10001
for (x, y) in gen_pell(D):
    delta = hint**2 - 4 * x * y * n
    if iroot(delta, 2)[1]:
        z = var('z')
        sol = solve(z**2 - hint*z + x*y*n == 0, z, solution_dict=True)
        a, b = int(z.subs(sol[0])), int(z.subs(sol[1]))
        a, b = (a, b) if a > b else (b, a)
        p, q = a // x, b // y
        break

assert p * q == n
d = pow(e, -1, (p - 1) * (q - 1))
print(long_to_bytes(int(pow(c, d, n))))
```

## 变体与关联

- **hint 形式变体**：`hint = p + q`、`p - q`、`a*p + b*q` 等线性组合可用同类二次方程/韦达思路（不含 Pell 约束时直接解一元二次）；Pell 约束的价值是把 `(x, y)` 的搜索空间从二维压到一维解序列。
- **Pell 生成素数**：`p = next_prime(x_k)`、`q = next_prime(y_k)` 的弱密钥场景见 `[[crypto-rsa-pell-equation-prime-generation]]`，攻击方式不同。
- **相关卡**：已知 `p+q`/`p²+q²` 的分解见 `[[crypto-rsa-known-prime-sum-quadratic-factorization]]`、`[[crypto-rsa-known-p2-plus-q2-cornacchia-factor]]`；两个线性 hint 求 gcd 见 `[[crypto-rsa-two-linear-hints-small-coefficient-gcd]]`。
- **边界**：若 `D` 很大、Pell 解数量级远超素数规模，或 `x, y` 与 `p, q` 交错配对导致 `a//x` 不整除，需要扩大枚举/检查配对；判别式非平方就继续下一组。

## 检测与防御

- **出题/实现侧**：不要泄漏因子的线性组合（哪怕带 Pell 约束）；RSA 素数应独立随机生成，避免任何可枚举的代数关系。
- **参数选择**：若必须给出 hint，确保 `D`、`x`、`y` 的组合空间足够大且 hint 不暴露因子量级；对 hint 做模 n 归约并混入随机量。
- **测试边界**：CTF 题目只对本地实例求解，不涉及真实系统。
