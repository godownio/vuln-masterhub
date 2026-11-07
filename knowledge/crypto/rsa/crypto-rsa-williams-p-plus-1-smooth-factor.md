---
id: crypto-rsa-williams-p-plus-1-smooth-factor
title: RSA p+1 光滑：Williams p+1 用 Lucas 序列分解 p+1 光滑素数
type: scenario
domain: crypto
path: crypto/rsa
technique: williams-p-plus-1-smooth-factorization
aliases:
- Williams p+1
- p+1 光滑
- Lucas 序列分解 RSA
- p+1 factorization
- Pollard p-1 失败时
- 光滑数 p+1
tags:
- rsa
- factorization
- williams-p1
- lucas-sequence
- smooth-number
- gmpy2
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:10+08:00'
  notes: 已对照原文 §ezRSA3 核对：p=2*prod(sample(sops,10))-1、sops 10000 个 50-bit 素数、M=2*prod(所有 sops)、gmpy2.lucasv_mod、gcd(V_M-2,N)、P=5 成功、flag 均一致；未本机复跑。注意：本卡与 92543 批次 ctf-crypto-rsa-williams-p-plus-one-smooth-prime 为同场景近重复（两批并发导致），建议合并或保留其一。
---

## 一句话结论

当 RSA 的素数满足 `p + 1` 光滑（例如 `p = 2 * 从固定集合中抽 10 个素数之积 - 1`）时，Pollard p-1 会失败，但 Williams p+1 可以用 Lucas 序列 `V_M(P, 1) mod N` 计算 `gcd(V_M - 2, N)` 直接分解 `N`；案例中 `M = 2 * 所有候选素数之积`，P 从 3 试到 5 即拿到因子。

## 原理

- Pollard p-1 依赖 `p - 1` 光滑：若 `p-1 | M`，则 `a^M ≡ 1 (mod p)`，`gcd(a^M - 1, N)` 得到 p。
- Williams p+1 依赖 `p + 1` 光滑：在二次扩域上使用 Lucas 序列 `V_k(P, 1)`，当 `p + 1 | M` 时 `V_M(P, 1) ≡ 2 (mod p)`，因此 `gcd(V_M(P,1) - 2, N)` 得到 p。
- 案例生成逻辑：`p = 2 * prod(sample(sops, k)) - 1`，其中 `sops` 是 10000 个 50 位素数的排序列表，`k=10`。因此 `p + 1 = 2 * 10 个素数之积`，一定整除 `M = 2 * prod(所有 sops)`。
- 由于 `p - 1` 没有同样的小素数结构，Pollard p-1 会失败；这正是题目把光滑性放在 `p+1` 的原因。
- 计算 `V_M(P,1) mod N` 可用快速 Lucas 序列算法（`gmpy2.lucasv_mod`），复杂度与模幂相当，不需要展开巨大的 M。

## 触发条件

- RSA 模数 `N = p*q`，其中至少一个素数的 `p + 1` 是 B-smooth，且 B 在可接受范围内。
- 已知或可构造一个被 `p + 1` 整除的光滑数 `M`（案例直接给出所有候选素数乘积）。
- `p - 1` 不光滑，Pollard p-1 无效。
- 有 `gmpy2`/PARI 等支持 Lucas 序列或大数运算的库。

## 利用步骤

1. 从题目附件/生成脚本中提取候选素数集合 `sops` 与参数 `k`，计算 `M = 2 * prod(sops)`（或只取必要的素数子集）。
2. 对 `P = 3, 4, 5, ...` 计算 `V = lucasv_mod(P, 1, M, N)`。
3. 计算 `g = gcd(V - 2, N)`；若 `1 < g < N`，则 `g` 就是 `p`。
4. 若所有 P 都失败，检查 `M` 是否漏乘、是否应对 `p-1` 改用 Pollard p-1、或扩大候选素数集合。
5. 得到 `p` 后计算 `q = N // p`、`phi = (p-1)(q-1)`、`d = e^{-1} mod phi`，解密 `m = c^d mod N`。
6. 用 `long_to_bytes` 还原明文并校验格式。

## PoC

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

ns = {}
exec(open("out.py", "r", encoding="utf-8").read(), ns)
sops, N, c, e = ns["sops"], ns["N"], ns["c"], 65537

M = 2
for r in sops:
    M *= r

Nmp, Mmp = gmpy2.mpz(N), gmpy2.mpz(M)
p = None
for P in range(3, 5000):
    V = gmpy2.lucasv_mod(P, 1, Mmp, Nmp)
    g = int(gmpy2.gcd(V - 2, Nmp))
    if 1 < g < N:
        p = g
        print("found P =", P)
        break

assert p is not None
q = N // p
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, N)
print(long_to_bytes(m).decode())
```

案例输出：`found P = 5`，明文为 `NepCTF{5m0o7h_m4k3s_w1lliam_gr34t}`。

## 变体与关联

- 变体：只已知 `p+1` 的部分因子时，可用分段/逐步的 Williams p+1，或结合 Pollard rho/ECM。
- 变体：`p-1` 与 `p+1` 都部分光滑时，可先后尝试 Pollard p-1、Williams p+1、ECM。
- 变体：`p+1` 光滑但 `M` 过大时，可只取小于某个界的素数构造 `M`，多次尝试不同上界。
- 关联：[[crypto-rsa-pollard-pminus1-smooth-prime]]（p-1 光滑对照）、[[crypto-rsa-nested-smooth-prime-p1-known-factor]]（已知因子加速）、[[crypto-rsa-fermat-close-prime-factorization]]（近邻素数）。

## 检测与防御

- 防御：RSA 素数应使用密码学安全随机数生成，确保 `p-1` 与 `p+1` 都含有足够大的素因子；优先使用标准库生成的 2048 位以上密钥。
- 防御：避免用“从固定小素数集合抽样相乘 ±1”的方式构造素数；这类结构会被 p-1/p+1 分解直接命中。
- 检测：密钥生成脚本中出现 `prod(sample(primes)) ± 1`、固定素数表、`getPrime(50)` 等模式；对 N 做 p-1/p+1 光滑性预检。
- 响应：发现弱素数后立即更换密钥对，撤销相关证书/会话，审计历史密文是否可被解密。
