---
id: crypto-rsa-nested-smooth-prime-p1-known-factor
title: 嵌套 RSA p-1 光滑：用内层 n1 的已知因子作光滑数加速分解外层 n
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-nested-smooth-prime-p1-known-factor
tags:
- crypto
- rsa
- p-1
- smooth-prime
- pollard
- nested-modulus
- factorization
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:57:25+08:00'
  notes: 已对照原文 RSA_NestingDoll 与图04/05/06核对：get_smooth_prime(1024,20,p1) 使 p-1 = 2*p1*∏20位小素数*prime1*prime2，外层 n=p*q*r*s，密文用内层 n1 加密；exp 以 a^n1 再 ^L（L=∏[2^9,2^20)素数）并用 gcd(x-1)、gcd(x+1) 分解，随后 gcd(p-1,n1) 还原内层素数并解密，与原文一致。核对中修正一处数学表述：因 L 不含 2，严格成立的是 (p-1)/2 | n1*L（a^E≡±1 mod p），原卡写成 p-1|E 不准确，已同步 knowledge 与 staging 及 PoC 说明。未复跑完整分解；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-nested-smooth-prime-p1-known-factor/
draft: false
kb_aliases:
- RSA_NestingDoll
- 嵌套 RSA p-1 光滑
- 已知 n1 加速 Pollard p-1
- 递归 split 分解外层模数
---

## 一句话结论

外层 RSA 模数 `n = p*q*r*s` 的每个素因子都由内层模数 `n1` 的素因子派生为 p-1 光滑数；把已知的 `n1` 当作预构造的光滑因子，先算 `a^n1 mod n` 再乘上小素数乘积 `L`，即可让 `(p-1)/2 | n1*L`，用 gcd 检查 `a^E±1` 分出外层因子，再通过 `gcd(p-1, n1)` 还原内层素数并解密内层密文。

## 原理

- 题目给出内层 RSA 模数 `n1 = p1*q1*r1*s1`（四个 512 位素数）和外层模数 `n = p*q*r*s`；密文是用 `n1` 加密的，外层 `n` 只是“嵌套娃娃”的包装。
- 外层素数由 `get_smooth_prime(1024, 20, p1)` 生成：`p = 2 * p1 * ∏(20 位小素数) * prime1 * prime2 + 1`，其中 `prime1/prime2` 也是约 20 位素数，最终 `p` 为 1024 位素数。因此 `p-1` 完全光滑，适合 Pollard p-1。
- 直接对 1024 位 `n` 做 p-1 会因上界太大而极慢；关键观察是 `n1` 已经包含 `p1`（以及 q1/r1/s1），把 `n1` 乘进指数即可覆盖 512 位的大因子。
- 构造指数 `E = n1 * L`，其中 `L` 是 `[2^9, 2^20)` 内所有素数的乘积；`p-1 = 2 * p1 * ∏(20 位小素数) * prime1 * prime2`，`p1` 在 `n1` 中，20 位小素数与 `prime1/prime2` 都在 `L` 中，因此 `(p-1)/2 | E`，于是 `a^E ≡ ±1 (mod p)`；PoC 同时计算 `gcd(a^E - 1, n)` 与 `gcd(a^E + 1, n)`，得到 `p` 或其倍数（`p-1` 中的因子 2 不在 `L` 里，所以不能只检查 `x-1`）。
- 分解出外层 `p,q,r,s` 后，`gcd(p-1, n1)` 会留下 `p1`（因为 `n1` 只含 p1/q1/r1/s1，而 `p-1` 含 p1 与小素数），同理得到 q1/r1/s1；计算 `φ(n1)` 并解密 `c`。
- 递归 `split` 处理第一次 gcd 可能分出合数的情况：对得到的因子继续分解，直到素数。

## 触发条件

- 目标给出内层模数 `n1`、外层模数 `n`，且外层素因子的 `p-1` 由内层素因子 + 小素数构成（p-1 光滑）。
- 攻击者知道内层 `n1` 的素因子结构或至少知道 `n1` 本身（题目直接给出）；密文用内层 `n1` 加密。
- `L` 的素数上界（如 2^20）覆盖构造中的小素数；指数运算与 gcd 在可接受时间内完成。
- 外层 `n` 的素因子数量不多（如 4 个），递归分解可行。
- 没有对 `n1`/`n` 做额外混淆或隐藏内层模数。

## 利用步骤

1. 读取 `n1`、`n`、`c`、`e`；确认 `n1` 是内层模数、`c` 是模 `n1` 的密文。
2. 生成小素数乘积 `L = ∏ p_i`，`p_i` 取 `[2^9, 2^20)` 内所有素数（上界按构造调整）。
3. 对 `m = n` 选随机底 `a`，计算 `x = a^n1 mod m`，再 `x = x^L mod m`；计算 `gcd(x-1, m)` 与 `gcd(x+1, m)`，得到外层因子。
4. 递归分解所有外层因子，直到全部为素数。
5. 对每个外层素数 `p`，计算 `gcd(p-1, n1)` 得到对应的内层素数 `p1`；收集 `p1,q1,r1,s1`。
6. 计算 `φ(n1) = ∏(p_i - 1)`，求 `d = e^{-1} mod φ(n1)`，解密 `m = c^d mod n1`，转字节得到明文。

## PoC

```python
from gmpy2 import gcd, is_prime, mpz, powmod
from Crypto.Util.number import long_to_bytes

def primes_below(hi):
    sieve = bytearray([1]) * hi
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(hi ** 0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = bytearray(len(range(i*i, hi, i)))
    return [i for i in range(2, hi) if sieve[i]]

L = 1
for p in primes_below(1 << 20):
    if p >= (1 << 9):
        L *= p

def split(m):
    for a in range(2, 42):
        x = powmod(a, n1, m)
        x = powmod(x, L, m)
        for g in (gcd(x - 1, m), gcd(x + 1, m)):
            if 1 < g < m:
                return int(g)
    return None

def factor(m, out):
    if is_prime(mpz(m)):
        out.append(m)
        return
    g = split(mpz(m))
    factor(g, out)
    factor(m // g, out)

outer = []
factor(n, outer)
inner = [int(gcd(mpz(p) - 1, n1)) for p in outer]
phi = 1
for f in inner:
    phi *= f - 1
d = powmod(e, -1, phi)
print(long_to_bytes(int(powmod(c, d, n1))))
```

无真实目标 PoC：原文给出了完整参数与 exp，实际使用时需替换 `n1/n/c/e` 并按构造调整 `L` 的上界。

## 变体与关联

- **p-1 光滑**：普通 Pollard p-1 用 `a^L` 覆盖 p-1；本题用已知 `n1` 覆盖大因子，属于“预构造光滑数”变体。
- **其他光滑构造**：`p-1` 含大素数但 `p+1` 光滑可用 Williams p+1；`q-1` 光滑同理。
- **嵌套 RSA**：外层模数由内层因子派生，密文仍用内层模数；关键是找到内外层因子的映射关系（gcd）。
- **关联**：RSA p-1 光滑、Pollard p-1、RSA 多素数、共模攻击、模数分解。

## 检测与防御

- **素数生成**：RSA 素数不要用“p-1 光滑”的构造；使用 CSPRNG 生成随机素数，检查 `p-1`/`p+1` 是否含大素因子。
- **密钥隔离**：不要把一个 RSA 模数的素因子复用/派生到另一个模数；内外层密钥必须独立。
- **参数审计**：检查 `gcd(n1, n2)`、`gcd(p-1, n1)` 等交叉关系；多密钥部署时做互素性检测。
- **检测**：监控异常大的指数运算/gcd 批量请求；对已知攻击参数（小素数乘积、光滑上界）做情报匹配。
- **响应**：一旦发现模数可分解，立即轮换密钥、作废相关密文与证书。

## 可信度与边界

- 原文为 CTF crypto 题，给出了完整参数、exp 与运行结果；攻击链与数学推导有实测依据。
- 具体位数（512/1024、smoothness=20）与 `L` 上界为该题构造；真实目标需按参数调整。
- 未在真实目标复跑；卡内不包含题目 flag。
