---
id: ctf-crypto-power-tower-composite-modulus-crt
title: 幂塔模合数：三因子分解 + 欧拉降幂逐素数求值 + CRT 后 XOR 解明文
type: scenario
domain: ctf
path: ctf/crypto
technique: power-tower-composite-modulus-crt
tags:
- ctf
- crypto
- modular-exponentiation
- power-tower
- crt
- factorization
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:27:56+08:00'
  notes: 已对照原文 Power tower 核对：n=127*841705194007*100567...、t/c 数据、逐素数欧拉降幂 exp=pow(2,t,p-1)、CRT、c^l 与 flag 一致；未复跑
url: /docs/ctf/crypto/ctf-crypto-power-tower-composite-modulus-crt/
draft: false
kb_aliases:
- Power tower
- 幂塔
- 2^(2^t) mod n
- 欧拉降幂
- 三素数 CRT
- ISCTF Power tower
---

## 一句话结论

题目把 n 声称成 256 位素数，但实际可分解为三个素因子；对幂塔 `l = 2^(2^t) mod n`，先在每个素因子 p 上用费马小定理把指数降为 `2^t mod (p-1)`，分别求 `2^exp mod p`，再用中国剩余定理合并得到 l，最后与密文 c 异或即可恢复明文。

## 原理

- **合数模幂可拆**：若 `n = p1*p2*p3`，则 `l mod n` 可由 `l mod pi` 通过 CRT 唯一还原。
- **欧拉/费马降幂**：对素数 p，`2^(p-1) ≡ 1 (mod p)`（p≠2），所以 `2^(2^t) mod p = 2^(2^t mod (p-1)) mod p`；指数 `2^t` 本身很大，但只需计算它对 p-1 的余数。
- **逐因子求值**：`exp = pow(2, t, p-1)`，`l_p = pow(2, exp, p)`；这里 t 是题目给定的幂塔高度参数。
- **CRT 合并**：三组同余 `l ≡ l_p (mod p)` 用 CRT 得到 `l mod n`。
- **异或解密**：题目密文 `c = m XOR l`（或 `c = flag XOR l` 的整数形式），`m = c XOR l`，`long_to_bytes` 得到 flag。
- **为什么容易误判**：n 的位数/形式可能伪装成素数；用 FactorDB、`isprime` 或小因子试除可发现它实际是合数，从而把不可解的模幂拆成三个小模数。

## 触发条件

- 模数 n 实际为合数且可分解（小因子、FactorDB 可查、或题目给出因子线索）。
- 需要计算幂塔/超大指数模 n，直接 `pow(2, 2**t, n)` 不可行。
- 密文与幂塔结果做 XOR 或简单线性组合。
- 已知幂塔高度 t 与密文 c。

## 利用步骤

1. 检查 n 的素性；若声称素数但可疑，用 FactorDB/试除/`factorint` 分解，得到 p1、p2、p3。
2. 对每个 pi 计算 `exp_i = pow(2, t, pi-1)`，再算 `l_i = pow(2, exp_i, pi)`。
3. 用 CRT 合并 `l_i` 得到 `l mod n`。
4. 计算 `m = c ^ l`（按题目定义的异或/加法关系），转字节得到 flag。
5. 若 p=2 出现在因子中，单独处理（`2^k mod 2` 在 k≥1 时为 0）。

## PoC

```python
from Crypto.Util.number import long_to_bytes

t = 6039738711082505929
n = 127 * 841705194007 * 1005672644717572752052474808610481144121914956393489966622615553
c = 114092817888610184061306568177474033648737936326143099257250807529088213565247

primes = [127, 841705194007,
          1005672644717572752052474808610481144121914956393489966622615553]

def crt(residues, moduli):
    total, prod = 0, 1
    for m in moduli:
        prod *= m
    for r, m in zip(residues, moduli):
        p = prod // m
        total += r * pow(p, -1, m) * p
    return total % prod

residues = []
for p in primes:
    exp = pow(2, t, p - 1)
    residues.append(pow(2, exp, p))

l = crt(residues, primes)
print(long_to_bytes(c ^ l))
```

输出：

```text
ISCTF{Euler_1s_v3ry|useful!!!!!}
```

## 变体与关联

- 因子数量/结构变体：两素数、三素数、含小因子；CRT 同样适用，模数两两互素即可。
- 降幂变体：用 Carmichael λ(n) 代替 φ(n) 可进一步减小指数；底数与模数不互素时需先剥离公因子。
- 关联：[[ctf-crypto-noise-crt-lattice-recovery]]（带噪 CRT）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（多素数 RSA）。
- 边界：n 无法分解或因子过大时，幂塔计算不可行；若密文不是简单 XOR，需按题目公式逆运算。

## 检测与防御

- 检测：CTF 中先验证模数素性，不要轻信“256 位素数”的描述；检查是否存在小因子或 FactorDB 记录。
- 防御：密码协议使用标准大素数/安全模数，避免把合数当素数；不要用幂塔/XOR 作为加密方案。
- 加固：对模数做素性证明与结构检查；使用 AEAD 或标准 KEM/DEM。
