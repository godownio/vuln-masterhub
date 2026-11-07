---
id: crypto-rsa-pollard-pminus1-smooth-prime
title: RSA 素数 p-1 光滑：Pollard p-1 在 B=100000 内用 gcd(2^L-1,N) 取因子
type: scenario
domain: crypto
path: crypto/rsa
technique: pollard-pminus1-smooth-prime
tags:
- rsa
- pollard-p-1
- smooth-number
- factorization
- weak-key
- prime-generation
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:25+08:00'
  notes: 对照 Crypto247：B=100000 Pollard p-1、素数 15767 命中 512-bit 因子一致；未复跑
url: /docs/crypto/rsa/crypto-rsa-pollard-pminus1-smooth-prime/
draft: false
kb_aliases:
- SmoothGuard
- Pollard p-1
- p-1 光滑素数
- 2^L mod N 分解
- RSA 弱素数生成
- B-smooth
---

## 一句话结论

若 RSA 的某个素数 p 满足 p-1 是 B-光滑的（所有素因子都不超过 B），取 L 为 1..B 的最小公倍数，则 `2^L ≡ 1 (mod p)`，`gcd(2^L-1, N)` 直接给出 p；本题 B=100000 时枚举到素数 15767 即取出 512 位因子。

## 原理

- Pollard p-1 利用费马小定理：若 `p-1 | L`，则对任意与 p 互素的 a 有 `a^L ≡ 1 (mod p)`，即 `p | a^L-1`。
- 取 `L = lcm(1,2,...,B)`（实现上等价于把所有不超过 B 的素数幂乘起来），只要 p-1 的所有素因子都不超过 B（B-光滑），就有 `p-1 | L`。
- 令 `a=2`，计算 `a^L mod N`；由于 `N=pq`，`gcd(a^L-1, N)` 会包含 p（可能还包含 q，若 q-1 也光滑）。若结果落在 (1,N) 即得到非平凡因子。
- 实际实现不必一次算完 L：从小到大枚举素数 p_i，把 a 反复自乘到 `p_i^k ≤ B` 的最大幂，每步后检查 `gcd(a-1,N)`；一旦 p-1 的所有因子都被覆盖，gcd 就会命中。
- 安全性前提是 p-1 有大素因子，使 B 需要大到计算不可行。本题 p-1 完全 B-光滑，B=100000 即可；原文在枚举到素数 15767 时取出 512 bit 因子，说明 p-1 的最大素因子不超过该量级。

## 触发条件

- RSA 素数生成时只保证 p 是素数，未检查 p-1 是否有大素因子（非 safe prime）。
- p-1 的最大素因子小于攻击者可承受的 B（本题 100000）。
- 攻击者能拿到 N；e、c 正常公开。
- 有足够的计算资源做 B 次模幂/素数枚举（本题规模很小）。

## 利用步骤

1. 对 N 运行 Pollard p-1，B 从较小值（如 10^4、10^5）开始；每步枚举素数幂并更新 `a`，检查 `gcd(a-1,N)`。
2. 命中非平凡因子 g 后，令 p=g、q=N//g，验证 p*q==N 且均为素数。
3. 计算 `phi=(p-1)(q-1)`、`d=e^{-1} mod phi`，解密密文。
4. 若小 B 失败，增大 B 或改用 Pollard rho/ECM；对每个新连接重新读取 N/e/c，不能硬编码某次参数。

## PoC

```python
import math

def primes_upto(n):
    sieve = bytearray(b"\x01") * (n + 1)
    sieve[:2] = b"\x00\x00"
    for i in range(2, int(n ** 0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = b"\x00" * len(sieve[i*i::i])
    return [i for i in range(n + 1) if sieve[i]]

def pollard_pm1(n, bound=100000):
    a = 2
    for p in primes_upto(bound):
        pk = p
        while pk * p <= bound:
            pk *= p
        a = pow(a, pk, n)
        g = math.gcd(a - 1, n)
        if 1 < g < n:
            return g
    return None

g = pollard_pm1(N, 100000)
p, q = g, N // g
phi = (p - 1) * (q - 1)
m = pow(c, pow(e, -1, phi), N)
print(m.to_bytes((m.bit_length() + 7) // 8, "big"))
```

```python
# 服务端每次连接重新生成密钥时，从 socket 实时解析 N/e/c
N, e, c = parse_rsa_params(recv_until(b"c = "))
```

## 变体与关联

- 变体：p+1 光滑可用 Williams p+1；p-1 有大素因子但整体较小可用 ECM；两个素数共享部分比特可用 Coppersmith。
- 变体：B 的选择可自适应（先 10^4，再 10^5、10^6），或对每个素数幂检查 gcd 以尽早命中。
- 关联：[[crypto-rsa-pell-equation-prime-generation]]（生成规律导致弱素数）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（部分密钥泄露）。
- 边界：p-1 含大素因子时 Pollard p-1 失效；B 过大计算量爆炸；N 位数过大时模幂仍可行但素数枚举成为瓶颈。

## 检测与防御

- 检测：密钥生成代码是否只调用 `next_prime`/`generate_prime` 而未检查 p-1 的因子；对公钥做 p-1 光滑性预检（小 B 试除）；监控异常短的密钥生成时间。
- 修复：使用安全素数（p=2q+1，q 为素数）或确保 p-1 含足够大的素因子；使用成熟库生成 RSA 密钥；密钥生成后做自检。
- 加固：定期轮换密钥；对高价值密钥使用 HSM/安全随机源；避免自写素数生成器；对导出公钥做弱密钥扫描。
