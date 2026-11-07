---
id: crypto-rsa-schmidt-samoa-known-d-factor
title: Schmidt-Samoa 密码系统：已知 N、c、d 用 gcd(a^{Nd}-a,N) 恢复 pq 并解密
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-schmidt-samoa-known-private-exponent
aliases:
- Schmidt-Samoa
- Schmidt-Samoa 密码系统
- N=p^2q
- 已知 d 分解 N
- gcd(a^{Nd}-a,N)
tags:
- rsa
- schmidt-samoa
- cryptosystem
- key-recovery
- gcd
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:51+08:00'
  notes: 已对照原文核对：N=p^2·q、d=N^{-1} mod lcm(p-1,q-1)、c=m^N mod N、gcd(pow(a,N*d,N)-a,N) 得 pq、m=pow(c,d,pq) 与原文代码一致；已修正卡片原理中“公钥是 (N,d)”的错误表述为公钥 N、私钥 d。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

Schmidt-Samoa 密码系统使用 `N=p^2·q`、私钥 `d=N^{-1} mod λ(pq)`、加密 `c=m^N mod N`、解密 `m=c^d mod pq`。一旦攻击者同时拿到 `N`、`c`、`d`，由 `N·d ≡ 1 (mod λ(pq))` 可知 `a^{N·d} ≡ a (mod pq)`，于是 `gcd(N, a^{N·d}-a)` 给出 `pq`，再用 `c^d mod pq` 即可恢复明文。

## 原理

- 密钥生成：`N=p^2·q`，`d = N^{-1} mod lcm(p-1,q-1)`；公钥是 `N`（加密指数即 `N`），私钥是 `d`，加密 `c = m^N mod N`，解密 `m = c^d mod pq`。
- 因为 `N·d ≡ 1 (mod λ(pq))`，对任意与 `pq` 互素的 `a`，由 Carmichael 定理 `a^{λ(pq)} ≡ 1 (mod pq)`，所以 `a^{N·d} = a·(a^{λ(pq)})^t ≡ a (mod pq)`。
- 因此 `pq | a^{N·d}-a`；而 `N=p^2·q` 也包含因子 `pq`。计算 `g = gcd(N, a^{N·d}-a)`，结果通常是 `pq`（若同时被 `p^2` 整除则可能是 `N`，换一个底数 `a` 重试即可）。
- 得到 `pq` 后，`c^d = m^{N·d} ≡ m (mod pq)`，直接解出明文 `m`。
- 私钥 `d` 本应保密；该场景说明在 Schmidt-Samoa 中泄露 `d` 等价于泄露 `pq`，系统随即被完全解密，而不是像标准 RSA 那样只泄露一个指数。

## 触发条件

- 目标使用 Schmidt-Samoa 密码系统：`N=p^2·q`，加密指数为 `N`，解密模数为 `pq`。
- 攻击者已知 `N`、目标密文 `c`，以及私钥 `d`（例如密钥文件泄露、调试接口返回、CTF 题目直接给出）。
- 能计算大整数模幂与 gcd；`N` 的规模在可计算范围内。
- `a` 与 `pq` 互素（取 2、3、5 等小素数通常满足）。

## 利用步骤

1. 确认 `N` 的结构为 `p^2·q`（可通过题目描述或 `N` 的因子分布判断），并确认加密/解密公式。
2. 取小底数 `a=2`，计算 `mid = pow(a, N*d, N) - a`。
3. 计算 `g = gcd(N, mid)`；若 `g` 等于 `N`，换 `a=3,5,7…` 重试，直到 `1 < g < N`。
4. 令 `n = g`（应为 `pq`），计算 `m = pow(c, d, n)`。
5. 将 `m` 转字节得到明文；用 `pow(m, N, N) == c` 或题目格式校验。

## PoC

```python
import math
from Crypto.Util.number import long_to_bytes

c = ...
N = ...
d = ...

a = 2
mid = pow(a, N * d, N) - a
n = math.gcd(N, mid)
m = pow(c, d, n)
print(long_to_bytes(m))
```

> 若 `gcd` 返回 `N`，说明该底数同时命中了 `p^2` 因子，换 `a=3,5,…` 再试；也可以对多个底数的 gcd 结果取交/比较。

## 变体与关联

- 变体：若只泄露 `d` 而不泄露 `c`，仍可用 `gcd` 恢复 `pq`，进而分解 `N=p^2·q`，之后可解密任意密文。
- 变体：Schmidt-Samoa 的签名/加密变体可能使用不同的指数关系，但“`d` 泄露 → `pq` 泄露”的核心不变。
- 关联：[[crypto-rsa-rabin-random-square-root-oracle]]（解密预言机导致分解）、[[crypto-rsa-common-modulus]]（RSA 参数复用）、[[crypto-rsa-partial-prime-high-bits-coppersmith]]（分解 `N` 的其他路径）。

## 检测与防御

- 防御：Schmidt-Samoa 的私钥 `d` 必须与标准 RSA 私钥同等保护，绝不能出现在日志、调试接口或客户端。
- 防御：优先使用标准 RSA-OAEP 等经过广泛分析的方案；自制密码系统需经过形式化安全证明与代码审计。
- 检测：审计 `N` 是否为完全平方因子结构（`N` 可被 `p^2` 整除）、私钥材料是否泄露、接口是否返回 `d` 或可推导 `d` 的字段。
- 响应：确认 `d` 泄露后立即轮换密钥，并假定该密钥下所有历史密文均可被解密。
