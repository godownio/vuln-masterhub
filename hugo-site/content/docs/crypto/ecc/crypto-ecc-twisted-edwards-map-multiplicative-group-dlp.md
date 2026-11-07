---
id: crypto-ecc-twisted-edwards-map-multiplicative-group-dlp
title: 扭曲爱德华曲线 DLP 归约：Add 即 F_p(√D) 乘法，映射到 F_p^* 后用 discrete_log 恢复共享密钥
type: scenario
domain: crypto
path: crypto/ecc
technique: twisted-edwards-map-multiplicative-group-dlp
tags:
- ecc
- twisted-edwards
- dlp
- multiplicative-group
- pohlig-hellman
- sage
- aes-ecb
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:38:55+08:00'
  notes: 已对照原文核对：Add 公式、gcd 恢复 p、f(P)=(x+dy)/(x-dy)、discrete_log、共享密钥取 x 坐标、AES-ECB 解密均一致；已复算 gcd/2 为素数且 G/A 满足范数 1；未在本机跑 Sage discrete_log 全链。
url: /docs/crypto/ecc/crypto-ecc-twisted-edwards-map-multiplicative-group-dlp/
draft: false
kb_aliases:
- Curve
- 扭曲爱德华曲线
- F_p(√D) 乘法
- 映射到乘法群
- discrete_log
- Pohlig-Hellman
---

## 一句话结论

题目给的曲线加法 `Add((x1,y1),(x2,y2)) = (x1x2 + D y1y2, x1y2 + y1x2)` 实际是 `F_p(√D)` 中“范数为 1”元素的乘法；把所有点映射到 `f(P) = (x + d·y)/(x − d·y)`（`d² = D`）后，曲线上的离散对数变为 `F_p^*` 中的离散对数，用 Sage `discrete_log`（Pohlig-Hellman）求出私钥，再标量乘对方公钥得到共享密钥的 x 坐标，`sha256` 派生 AES-ECB 密钥即可解密 flag。

## 原理

- **加法公式的代数含义**：把点 `(x,y)` 视为 `x + y√D`，则 `(x1 + y1√D)(x2 + y2√D) = (x1x2 + D y1y2) + (x1y2 + y1x2)√D`，正是题目 `Add` 的两个坐标。因此“点”就是 `F_p(√D)` 中的元素，“加法”就是乘法；单位元 `(1,0)` 对应 `1`。
- **曲线方程**：这类元素满足范数 `N(x + y√D) = x² − D y² = 1`。题目给出的 G、A、B 都在该集合上；对每个点都有 `p | (x² − D y² − 1)`。
- **恢复模数 p**：取两个点 G、A，计算 `gcd(gx² − D·gy² − 1, ax² − D·ay² − 1)`，得到 `p` 的倍数（本题 `g = 2p`），除以 2 并检验素数即可。即使题目没给 p，也能从两个点恢复。
- **映射到乘法群**：令 `d = √D mod p`（本题 D=841，d=29），`f(P) = (x + d·y)/(x − d·y)`。因为 `(x + y√D)(x − y√D) = 1`，`f(P)` 在 `F_p^*` 中；且 `f(P+Q) = f(P)·f(Q)`（同态）。于是 `A = n_a·G` 变为 `f(A) = f(G)^{n_a}`，曲线 DLP 降为 `F_p^*` 的 DLP。
- **求私钥与共享密钥**：`n_a = discrete_log(f(A), f(G))`；共享密钥是 `n_a·B` 的 x 坐标（也可用 `f(B)^{n_a}` 反查，但题目直接用 x 坐标）。`key = sha256(long_to_bytes(shared_secret))`，AES-ECB 解密 C 并去 PKCS#7 填充。
- **为什么可解**：`F_p^*` 的阶为 `p−1`，若其光滑或 Sage 的 `discrete_log` 能在可接受时间内分解，就能求出私钥；本题 p 的规模与光滑性满足 Sage 求解。
- **成立条件**：能恢复 p；`D` 是模 p 的二次剩余（否则 `√D` 不在 F_p，映射需在扩域中理解）；曲线点确实满足范数 1；共享密钥取 x 坐标的约定与加密端一致。

## 触发条件

- 题目给出 `D`、生成元 G、双方公钥 A/B、AES-ECB 密文；加法公式形如 `(x1x2 + D y1y2, x1y2 + y1x2)`。
- 未直接给出模数 p，但给出至少两个曲线点；或 p 已知但曲线不是标准椭圆曲线。
- 曲线群可同态映射到 `F_p^*`（存在 `d² = D`），且 `p−1` 的离散对数可解。

## 利用步骤

1. 确认加法公式对应 `F_p(√D)` 乘法，点满足 `x² − D y² = 1`。
2. 用两个点恢复 p：`g = gcd(gx²−D·gy²−1, ax²−D·ay²−1)`，取 `p = g // 2`（或按实际倍数调整），验证 `isPrime(p)`。
3. 计算 `d = sqrt(D) mod p`（本题 `d=29`），定义 `f(P) = (x + d*y)/(x − d*y) mod p`。
4. 计算 `u=f(G)`、`v=f(A)`，用 Sage `discrete_log(v, u)` 求 `n_a`；若阶光滑，也可用 Pohlig-Hellman/BSGS。
5. 用题目 `Add`/标量乘计算 `S = n_a · B`，取 `S[0]` 作为共享密钥。
6. `key = sha256(long_to_bytes(shared_secret)).digest()`，AES-ECB 解密并 unpad，得到 flag。
7. 闭环验证：用 `f` 检查 `f(S) == f(B)^{n_a}`，或用恢复的 key 重新加密明文确认。

## PoC

```python
from hashlib import sha256
from math import gcd
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes, isPrime
from sage.all import GF, discrete_log

D = 841
gx, gy = 1100598635269059922265259097431205826869659019985617812588900225256796699368319232, 269583433230904539404618502954816143916504972586573484672290485092817854594102981
ax, ay = 522493413431164541763578890114416187756743905387601370337657937604705331138537817, 1508871699477090073528276437418263853138631109882880455850153282479682759269308568
bx, by = 775700026584506740810283787673112405277484661261929762130750879159326080315752049, 164554371563691962332379023518848094645187895772638009983860665200242350372953279
C = bytes.fromhex("7727ceae1edbfa37f913e09b44c10e6fa846891f4b520c87d829fc55299b1f02621af77a1f1f1107d1159c4088250834")

g = gcd(gx**2 - D*gy**2 - 1, ax**2 - D*ay**2 - 1)
p = g // 2
assert isPrime(p)
F = GF(p)
d = F(29)  # 29^2 = D

def f(P):
    x, y = F(P[0]), F(P[1])
    return (x + d*y) / (x - d*y)

n_a = discrete_log(f((ax, ay)), f((gx, gy)))

def add(P, Q):
    return ((P[0]*Q[0] + D*P[1]*Q[1]) % p, (P[0]*Q[1] + P[1]*Q[0]) % p)

def mul(P, n):
    Q = (1, 0)
    while n:
        if n & 1: Q = add(Q, P)
        P = add(P, P); n >>= 1
    return Q

S = mul((bx, by), n_a)
key = sha256(long_to_bytes(S[0])).digest()
flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(C), 16)
print(flag.decode())
```

## 变体与关联

- **p 的恢复**：若 `gcd` 得到的是 `k·p`，可尝试用两个以上点、或对结果做小因子剥离；若 k 很大，可检查 `g` 的因子中哪个使 `d²=D` 有解且所有点满足范数 1。
- **不同曲线形式**：标准 Twisted Edwards `a x² + y² = 1 + d x² y²` 的加法有分母；本题的无分母形式对应 `F_p(√D)` 乘法，映射公式不同，需先确认群结构。
- **DLP 求解**：`p−1` 光滑时用 Pohlig-Hellman；否则用 BSGS/Pollard rho；Sage `discrete_log` 会自动选择。
- **共享密钥约定**：有的题用 `f(S)` 而非 `S[0]` 作为共享密钥，需按加密端代码确认；本卡按题目 `get_shared_secret(P,n)=C_multiplication(P,n)[0]`。
- 关联：[[ctf-crypto-quaternion-norm-dlp-bsgs]]（范数同态把 DLP 降到素域）、[[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]（光滑阶 DLP）、[[crypto-ecc-unknown-curve-projective-cubic-fit-weierstrass-dlp]]（未知曲线恢复）。
- **边界**：若 `D` 非二次剩余、或群中存在非范数 1 的点、或 p 的离散对数不可解，该方法不成立；自定义曲线不应作为安全设计。

## 检测与防御

- **题目/设计侧**：自定义 Edwards 曲线的加法若等价于 `F_p(√D)` 乘法，DLP 会退化到乘法群，不能提供预期安全强度；应使用标准曲线（如 Curve25519/Ed25519）与标准 ECDH。
- **分析侧**：看到 `(x1x2 + D y1y2, x1y2 + y1x2)` 这种无分母加法，先尝试 `x² − D y² = 1` 与 `f(P)=(x+dy)/(x−dy)` 同态；优先恢复 p 再用 `discrete_log`。
- **检测思路**：自定义曲线参数、`D` 为平方数、点满足范数 1、共享密钥取 x 坐标、`sha256(long_to_bytes(secret))` 派生 AES 密钥等特征。
