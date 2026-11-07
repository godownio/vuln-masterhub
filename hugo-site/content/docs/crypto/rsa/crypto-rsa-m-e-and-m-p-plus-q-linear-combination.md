---
id: crypto-rsa-m-e-and-m-p-plus-q-linear-combination
title: RSA 已知 m^e 与 m^(p+q)：扩展欧几里得线性组合直接恢复明文
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-two-exponent-linear-combination-recovery
tags:
- crypto
- rsa
- linear-combination
- extended-euclidean
- euler-theorem
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:27:27+08:00'
  notes: 已对照原文 easy_RSA 核对：φ=N+1-(p+q)、m^(N+1)≡ct2、扩展欧几里得 a*e+b*(N+1)=1、msg=ct1^a*ct2^b 与原文推导/代码及 flag 一致；PoC 未复跑
url: /docs/crypto/rsa/crypto-rsa-m-e-and-m-p-plus-q-linear-combination/
draft: false
kb_aliases:
- RSA 线性组合恢复明文
- m^(p+q) 与 m^e
- 扩展欧几里得 RSA
- ct2 = m^(p+q)
- phi = N+1-(p+q)
---

## 一句话结论

同一 RSA 模数下若同时给出 `ct1 = m^e mod N` 和 `ct2 = m^(p+q) mod N`，由 `φ(N)=N+1-(p+q)` 与欧拉定理可得 `m^(N+1) ≡ ct2 (mod N)`；再用扩展欧几里得求 `a*e + b*(N+1) = 1`，即可用 `ct1^a * ct2^b mod N` 直接还原 `m`，无需分解 N。

## 原理

- RSA 中 `φ(N) = (p-1)(q-1) = N + 1 - (p+q)`。
- 若 `gcd(m,N)=1`，欧拉定理给出 `m^φ(N) ≡ 1 (mod N)`，即 `m^(N+1-(p+q)) ≡ 1`，两边乘 `m^(p+q)` 得 `m^(N+1) ≡ m^(p+q) = ct2 (mod N)`。
- 已知 `ct1 = m^e`，且 `ct2 = m^(N+1)`；只要 `gcd(e, N+1)=1`，扩展欧几里得可求整数 `a,b` 使 `a*e + b*(N+1) = 1`。
- 于是 `m = m^(a*e + b*(N+1)) = ct1^a * ct2^b mod N`；指数为负时用模逆（Python 3.8+ 的 `pow(base, -exp, N)` 直接支持）。
- 更一般地：只要拿到同一明文的两个幂 `m^x`、`m^y` 且 `gcd(x,y)=1`，就能用 Bézout 系数把 `m^1` 线性组合出来；本题 `x=e`、`y=N+1`。
- 边界：若 `gcd(m,N)>1`，欧拉定理不再直接成立，但此时 `gcd(m,N)` 已经泄露 N 的因子，可改用分解路线。

## 触发条件

- 同一 RSA 模数 N 下加密同一明文两次，分别泄露 `m^e` 与 `m^(p+q)`（或 `m^φ`、`m^(N+1)` 等等价幂）。
- `gcd(e, N+1)=1`（本题 e=65537 与 N+1 互素）。
- 明文未使用随机填充，两次输出对应同一 m。
- 目标未对同态线性组合做防护（纯 textbook RSA）。

## 利用步骤

1. 确认两组密文 `ct1`、`ct2` 对应同一明文与同一 N，且指数分别为 e 与 p+q。
2. 由 `φ=N+1-(p+q)` 推出 `m^(N+1) ≡ ct2`。
3. 用扩展欧几里得求 `a*e + b*(N+1) = 1`。
4. 计算 `m = ct1^a * ct2^b mod N`（负指数转模逆）。
5. `long_to_bytes(m)` 得到 flag；若结果异常，检查 gcd(m,N) 是否泄露因子。

## PoC

```python
from Crypto.Util.number import long_to_bytes

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, x1, y1 = egcd(b % a, a)
    return (g, y1 - (b // a) * x1, x1)

g, a, b = egcd(e, N + 1)          # a*e + b*(N+1) = 1
msg = (pow(ct1, a, N) * pow(ct2, b, N)) % N
print(long_to_bytes(msg).decode())
```

完整数据代入（原文 N、ct1、ct2、e=65537）可解出：

```text
ISCTF{Congratulations_you_master_Mathematical_ability}
```

## 变体与关联

- 指数变体：`m^(p-q)`、`m^φ`、`m^(N-1)` 等只要与 `e` 互素，都能用同一 Bézout 组合恢复；若两个指数不互素，只能得到 `m^gcd(x,y)`。
- 若第二个幂未知但知道 φ 或 p+q，可先按 [[crypto-rsa-known-prime-sum-quadratic-factorization]] 分解 N，再常规解密。
- 关联：[[crypto-rsa-common-modulus]]（同模数不同指数）、[[crypto-rsa-franklin-reiter-affine-related-message]]（相关明文）。
- 边界：带随机填充或两次明文不同（如 OAEP）时攻击失效。

## 检测与防御

- 检测：同一 N 下出现两个相关幂的密文；CTF 中检查 `ct2` 是否等于 `m^(p+q)`、`m^φ` 等。
- 防御：使用 OAEP/PKCS#1 v1.5 等随机化填充；不要泄露同一明文的多个幂；避免 textbook RSA 直接加密。
- 加固：若必须多 exponent，使用互素指数并加随机化；轮换密钥，避免 p+q/φ 通过侧信道或调试输出泄漏。
