---
id: crypto-rsa-continued-fraction-lambda-factorization
title: RSA 大 e 小 d 变体：连分数枚举 e·g/n 恢复 λ(n) 并用平方根法分解 N
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-continued-fraction-lambda-factorization
aliases:
- e*g/n 连分数
- λ(n) 分解 N
- Wiener 变体
- 小 d 180-bit
- RSA lambda 分解
- 已知 λ(n) 分解模数
tags:
- crypto
- rsa
- wiener
- continued-fraction
- lambda
- factorization
- small-d
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:40:07+08:00'
  notes: 已对照原文rsa Level2与图57-59核对：e*g/n连分数、g=1..10、k/d收敛、(e*d-1)%k==0得λ(n)、d.bit_length()>256过滤、λ=t*2^s的平方根法分解n、sha256(str(p+q))作下一关密码，均与原文PoC一致。PoC已用原文n/e本机复跑，成功分解并得到sha256(p+q)=2aa9c360df99cbb4209e4dbab5a9f9ffd86d34906e3206fecfdabf0bb7aeb5ac，与原文一致。未验证点：CTF题无组件版本，未设置versions；frontmatter无sources/source_url。
---

## 一句话结论

当 RSA 的 `e` 与 `n` 同量级、私钥 `d` 很小（案例约 180 bit）但 `e/n` 的标准 Wiener 连分数不直接命中时，可以对小整数 `g` 枚举 `e·g/n` 的连分数收敛，恢复满足 `e·d − 1 = k·λ(n)` 的 `k/d`，得到 `λ(n) = (e·d−1)/k`；再用“已知群指数”的平方根法（Miller-Rabin 式）分解 `n`，最后求 `d` 并解密。

## 原理

- RSA 中 `e·d ≡ 1 (mod λ(n))`，因此存在整数 `k` 使
  `e·d − 1 = k·λ(n)`，且通常 `1 ≤ k < d`。
- 两边除以 `n`：
  `e/n = (1 + k·λ(n)) / (d·n) ≈ (k·λ(n))/(d·n)`。
  又 `λ(n) = φ(n)/g`，其中 `g = gcd(p−1, q−1)` 通常是很小的偶数，`φ(n) ≈ n`，所以
  `e·g/n ≈ k/d`。
  这正是 Wiener 攻击的连分数形式；当 `g=1` 时就是标准 Wiener，当 `g≠1` 或 `e/n` 的近似误差略大时，枚举 `g=1..10` 即可覆盖。
- 对每个 `g`，计算 `e·g/n` 的连分数并生成收敛 `k/d`。若 `(e·d−1) mod k == 0`，候选 `λ_c = (e·d−1)/k` 很可能就是 `λ(n)`（或其倍数）。用 `d.bit_length()` 上限（案例 256）过滤明显错误的收敛。
- **已知 λ(n) 分解 n**：把 `λ_c` 写成 `t·2^s`（t 为奇数）。对随机 `a`，计算 `x = a^t mod n`；若 `x=1` 或 `n−1` 换一个 `a`；否则反复平方：
  - 当某步 `y = x² ≡ 1 (mod n)` 且 `x ≠ ±1` 时，`gcd(x−1, n)` 给出非平凡因子；
  - 若 `y ≡ n−1` 则本次失败，换 `a`。
  因为 `a^{λ(n)} ≡ 1 (mod n)`，`λ(n)` 的 2-adic 分解会暴露单位根，标准 Miller-Rabin 论证保证大概率分解成功。
- 拿到 `p,q` 后计算 `φ=(p−1)(q−1)`、`d=e^{−1} mod φ`，即可解密密文；案例只需要 `p+q` 的 SHA-256 作为下一关密码，但攻击本身可用于完整解密。

## 触发条件

- RSA 公钥 `(n,e)`，`e` 与 `n` 位数接近（不是常见的 65537）；
- 私钥 `d` 很小（案例 180 bit），满足 `e·d − 1 = k·λ(n)` 且 `k` 不太大；
- `g = gcd(p−1,q−1)` 较小（通常 2、4、6…），用 `g=1..10` 能覆盖；
- 攻击者能拿到至少一组密文（或只需要分解 `n` 完成挑战）。

## 利用步骤

1. 读取 `n,e`，确认 `e` 很大、`n` 为均衡 RSA 模数。
2. 对 `g = 1..10`：
   - 计算 `e*g / n` 的连分数与收敛 `k/d`；
   - 跳过 `k=0`、`d` 过大（如 > 256 bit）的收敛；
   - 若 `(e*d - 1) % k == 0`，令 `lam = (e*d - 1)//k`。
3. 用 `lam` 调 `try_factor_with_lambda(lam, n)`：
   - `lam = t * 2^s`，随机 `a ∈ [2,n−2]`；
   - `x = a^t mod n`，循环平方并检查 `gcd(x−1,n)`。
4. 一旦得到 `p,q`，验证 `p*q==n`，计算 `d` 并解密密文。
5. 若 `g` 枚举失败，检查是否 `d` 稍大（转 Boneh-Durfee）或 `e` 不是同量级。

## PoC

```python
import math, random
from math import isqrt

def continued_fraction(a, b):
    while b:
        q = a // b
        yield q
        a, b = b, a - q * b

def convergents(cf):
    n0, d0 = 1, 0
    n1, d1 = 0, 1
    for q in cf:
        n2, d2 = q * n0 + n1, q * d0 + d1
        yield n2, d2
        n1, d1 = n0, d0
        n0, d0 = n2, d2

def try_factor_with_lambda(lam, n, trials=32):
    t, s = lam, 0
    while t % 2 == 0:
        t //= 2; s += 1
    for _ in range(trials):
        a = random.randrange(2, n - 1)
        x = pow(a, t, n)
        if x in (1, n - 1):
            continue
        for _ in range(s):
            y = pow(x, 2, n)
            if y == 1:
                p = math.gcd(x - 1, n)
                if p not in (1, n):
                    return p, n // p
                break
            if y == n - 1:
                break
            x = y
    return None

def attack(n, e):
    for g in range(1, 11):
        for k, d in convergents(continued_fraction(e * g, n)):
            if k == 0 or d.bit_length() > 256:
                continue
            if (e * d - 1) % k:
                continue
            lam = (e * d - 1) // k
            res = try_factor_with_lambda(lam, n)
            if res:
                p, q = res
                if p * q == n:
                    return p, q
    return None

# n, e = <目标公钥>
# p, q = attack(n, e)
# phi = (p - 1) * (q - 1)
# d = pow(e, -1, phi)
# m = pow(c, d, n)
```

原文 Level2 用 `g=1..10`、`d.bit_length()<=256`、`trials=24` 成功分解 1024 bit 级模数，并把 `sha256(str(p+q))` 作为下一关密码。

## 变体与关联

- `g=1` 且 `e/n` 近似良好时就是标准 Wiener 攻击；本卡是“乘以小 g 再取连分数”的推广。
- `d` 超过 Wiener 界（约 `n^0.25`）但仍小于 `n^0.292` 时，改用 Boneh-Durfee 格攻击。
- 已知 `λ(n)`（或 `φ(n)`）时也可直接用 `gcd(a^{λ/2}-1,n)` 分解；本卡的核心是先从 `e·g/n` 恢复 `λ(n)`。
- 关联 [[crypto-rsa-wiener-small-private-exponent-large-e]]：标准 Wiener 收敛 `e/n` 恢复 `d`。
- 关联 [[crypto-rsa-boneh-durfee-small-private-exponent]]：更大 `d` 的格攻击。
- 关联 [[ctf-crypto-rsa-shared-prime-batch-gcd]]：另一种从公钥批量恢复私钥的路线（共享素因子）。
- 边界：`d` 过大、`g` 超过枚举范围、或 `k` 不在收敛中时失败；需要 `e` 与 `n` 同量级才有连分数近似优势。

## 检测与防御

- 生成 RSA 密钥时使用标准库与足够大的 `d`（至少不低于 `n^0.292`，实际应接近 `φ(n)` 的随机值），不要为了性能使用小私钥。
- 不要使用与 `n` 同量级的大 `e`；常见 `e=65537` 本身不是问题，配合正常 `d` 即可。
- 私钥运算使用恒定时间实现与盲化，避免 `d` 的位长/汉明重量等侧信道。
- 检测：公钥中 `e` 异常大、`d` 很小、或同一批密钥出现异常 `gcd`；CTF 环境中可直接套用本卡脚本。
