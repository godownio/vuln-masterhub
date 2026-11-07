---
id: crypto-rsa-fermat-close-prime-factorization
title: RSA next_prime 近邻素数：费马分解用平方差快速分解 N
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-fermat-close-primes-factorization
aliases:
- RSA 费马分解
- 相邻素数 RSA
- next_prime 生成素数
- 平方差分解
- 近邻素数攻击
tags:
- crypto
- rsa
- fermat
- factorization
- close-primes
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:27:02+08:00'
  notes: 已对照原文与图11核对：q 由 p 多次 next_prime 生成、p/q 差值约 1135、费马平方差分解与求 d 解密步骤正确；CTF 题，无产品版本；PoC 为等价 Python 脚本未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

RSA 的 `p`、`q` 若由 `next_prime` 连续生成、彼此非常接近，费马分解只需很少次迭代即可把 `N` 分解：令 `a = ceil(sqrt(N))` 逐步自增，直到 `a² - N = b²` 为完全平方数，则 `p = a - b`、`q = a + b`，随后可求 `φ(N)`、私钥 `d` 并解密。

## 原理

- 费马分解基于平方差：若 `N = p·q` 且 `p`、`q` 接近，则存在 `a = (p+q)/2`、`b = (q-p)/2`，满足 `a² - b² = N`，即 `a² - N = b²`。
- 从 `a = ceil(sqrt(N))` 开始自增，每次检查 `a² - N` 是否为完全平方数；当 `p`、`q` 的差值很小时，迭代次数约为 `(q-p)² / (8·sqrt(N))`，收敛极快。
- 出题脚本先选素数 `p`，再多次调用 `next_prime(p)` 得到 `q`，导致 `q - p` 很小；原文实测两者差值约 1135，`a` 只需很少次迭代。
- 分解得到 `p`、`q` 后：`φ(N) = (p-1)(q-1)`，用扩展欧几里得求 `d = e^(-1) mod φ(N)`，再 `m = c^d mod N` 还原明文。
- 与 Pollard p-1、共模等攻击的区别：费马不依赖 `p-1` 光滑或两个模数相同，只依赖 `p`、`q` 距离近；反过来说，素数间距足够大时费马分解不可行。

## 触发条件

- RSA 的 `p`、`q` 由相邻/近邻素数生成（如 `q = next_prime(p)`、`p` 与 `q` 差值很小）；
- 攻击者拿到 `N`、`e` 与密文 `c`；
- `N` 的位长在可计算范围内，`a` 的迭代次数可接受（差值越小数百到数万次）。

## 利用步骤

1. 从公钥/题目附件读取 `N`、`e`、`c`。
2. 计算 `a = isqrt(N)`；若 `a*a < N` 则 `a += 1`。
3. 循环：计算 `b2 = a*a - N`，判断 `b2` 是否为完全平方数（`isqrt(b2)**2 == b2`）；是则 `b = isqrt(b2)`，`p = a - b`、`q = a + b`，结束；否则 `a += 1`。
4. 验证 `p*q == N`。
5. 计算 `φ(N) = (p-1)(q-1)`，`d = pow(e, -1, φ)`，`m = pow(c, d, N)`，`long_to_bytes(m)` 得到明文。

## PoC

```python
from math import isqrt
from Crypto.Util.number import long_to_bytes

N = ...
e = ...
c = ...

a = isqrt(N)
if a * a < N:
    a += 1

while True:
    b2 = a * a - N
    b = isqrt(b2)
    if b * b == b2:
        p = a - b
        q = a + b
        break
    a += 1

assert p * q == N
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, N)
print(long_to_bytes(m))
```

原文实测：分解出的 `p`、`q` 差值约 1135，完全符合“邻居素数”设定，随后求出 `d` 并恢复明文 flag。

## 变体与关联

- 变体：`p`、`q` 差值稍大时，费马迭代次数增加；可先用小范围试算评估可行性，或改用其他分解方法。
- 变体：多素数 RSA 中若有两个因子接近，也可对相应子模数使用费马分解。
- 关联 [[crypto-rsa-pollard-pminus1-smooth-prime]]：另一种素数生成缺陷（`p-1` 光滑），可与费马分解并列作为“弱素数生成”检查项。
- 关联 [[crypto-rsa-pell-equation-prime-generation]]：同为 `next_prime` 相关生成缺陷，该卡利用 Pell 方程解空间，本卡利用平方差。
- 边界：`p`、`q` 差值很大（例如随机独立生成）时费马分解不可行；`N` 过大且差值不够小时迭代成本可能不可接受。

## 检测与防御

- **素数生成**：`p`、`q` 必须独立随机生成，禁止用 `next_prime(p)` 或固定偏移从 `p` 推导 `q`；使用经过审计的密码库。
- **间距检查**：生成后检查 `|p - q|` 是否足够大（相对于 `N` 的位长），并检查 `p-1`、`q-1` 是否光滑。
- **检测**：对 RSA 公钥做弱密钥扫描（费马分解试算、小间距、共模、低指数等）；CTF/教学场景中可用费马分解快速验证题目是否使用近邻素数。
- **响应**：发现弱素数立即更换密钥对并重签/重加密，排查历史密文是否已被解密。
