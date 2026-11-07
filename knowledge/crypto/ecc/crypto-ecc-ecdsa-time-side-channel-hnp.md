---
id: crypto-ecc-ecdsa-time-side-channel-hnp
title: ECDSA 时间侧信道：两种 k 位长 + HNP 格 CVP 恢复私钥并伪造 token
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdsa-timing-side-channel-hnp
aliases:
- ECDSA 侧信道
- 时间侧信道 HNP
- 两种 k 位长
- k 位长泄露
- 格 CVP 恢复私钥
- 2025 强网杯 ECDSA
tags:
- ecdsa
- ecc
- side-channel
- timing
- hnp
- lattice
- cvp
- token-forgery
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:43:53+08:00'
  notes: 已对照原文核对：公式、PoC 与原文一致；原文无受影响版本，frontmatter 无 sources/source_url；PoC 未本机复跑。
---

## 一句话结论

服务端签名时以两种方式生成 `k`（256 位安全值，或 240–256 位的短值），短 `k` 的签名耗时明显更短；攻击者收集大量签名并按耗时筛选短 `k` 样本，把 `k_i = A_i + d*T_i mod q` 视为隐藏数问题，构造 `diag(q)` + `T` 行 + `B/q` 的格并解 CVP，即可恢复私钥 `d`，再伪造 admin token。

## 原理

- ECDSA：`s_i = k_i^{-1}(z + r_i*d) mod q`，其中 `z=Hash(msg)`、`q` 为曲线阶。
- 若服务端有两种 `k` 生成路径：256 位随机（安全）与 240–256 位随机（较短），后者的标量乘法/签名的耗时通常更短；时间侧信道可把短 `k` 样本筛出来。
- 对短 `k` 样本，`k_i < B = 2^240`（或更小的界）。由签名式：
  - `k_i = z*s_i^{-1} + d*r_i*s_i^{-1} mod q`
  - 记 `A_i = z*s_i^{-1} mod q`、`T_i = r_i*s_i^{-1} mod q`，则 `k_i = A_i + d*T_i mod q`，且 `0 <= k_i < B`。
- 构造 `(m+1)x(m+1)` 格：前 `m` 行 `diag(q)`，最后一行前 `m` 列为 `T_i`，最后一列为 `B/q`。
- 目标向量 `u = (A_1,...,A_m,0)`；格点 `v = (y_i*q - d*T_i, -d*B/q)`；`v - u` 的前 `m` 位为 `k_i`（短），最后一位为 `d*B/q`。用 LLL/BKZ 约减后做 CVP/Babai，取最近向量。
- 从 `v[m]` 反推 `d = round(±v[m]*q/B) mod q`，验证所有 `k_i = (A_i + d*T_i) mod q` 都 `< B`；噪声/误差可能导致一次失败，可多组样本重试。

## 触发条件

- 服务端签名接口使用两种 `k` 位长/两种随机数路径，且短 `k` 的耗时统计上明显更低。
- 攻击者能获取大量 `(r,s)` 与足够精确的耗时；能重算消息哈希 `z`。
- 短 `k` 的上界 `B` 已知（如 2^240），且样本数 `m` 足够（案例 24 个/组，多组重试）。
- 有 LLL/BKZ/CVP 工具（Sage）。

## 利用步骤

1. 调用签名接口，记录每条的 `(r,s)`、耗时 `cost` 与消息哈希 `z`。
2. 按耗时排序，取最短的一批样本（案例每组 24 个，尝试多组）；必要时用统计/聚类区分两种分布。
3. 计算 `A_i = z*s_i^{-1} mod q`、`T_i = r_i*s_i^{-1} mod q`。
4. 构造格 `diag(q)` + `T` 行 + `B/q`，做 LLL/BKZ。
5. 以 `u=(A_i,0)` 为目标做 CVP/Babai，得到 `v`；从 `v[m]` 反推 `d` 候选（正负号都试）。
6. 验证 `k_i=(A_i+d*T_i) mod q` 全部 `< B`；成功后用 `d` 伪造 admin token/签名。
7. 若失败，换样本子集/增加样本/调整 `B`，重复。

## PoC

```python
# Sage
q = Integer(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
B = Integer(2) ** 240
z = Integer(int.from_bytes(hashlib.sha256(MSG).digest(), "big"))
samples = [(r1, s1), (r2, s2), ...]   # 按耗时筛出的短 k 样本

T, A = [], []
for r, s in samples:
    sinv = inverse_mod(Integer(s), q)
    T.append(QQ((Integer(r) * sinv) % q))
    A.append(QQ((z * sinv) % q))

m = len(T)
M = Matrix(QQ, m + 1, m + 1)
for i in range(m):
    M[i, i] = q
for j in range(m):
    M[m, j] = T[j]
M[m, m] = QQ(B) / QQ(q)

u = vector(QQ, A + [0])
Bred = M.LLL()
try:
    Bred = Bred.BKZ(block_size=20)
except Exception:
    pass

def babai_row(Bmat, target):
    rows = [vector(QQ, Bmat.row(i)) for i in range(Bmat.nrows())]
    Gs = Bmat.gram_schmidt()[0]
    y = vector(QQ, target)
    for i in reversed(range(Bmat.nrows())):
        den = Gs[i].dot_product(Gs[i])
        if den == 0: continue
        mu = y.dot_product(Gs[i]) / den
        y -= ZZ(round(mu)) * rows[i]
    return vector(QQ, target) - y

v = babai_row(Bred, u)
for sign in (1, -1):
    d = ZZ(round(sign * v[m] * q / B)) % q
    ks = [ZZ((A[i] + T[i] * d) % q) for i in range(m)]
    if all(0 <= kk < B for kk in ks):
        print("d =", int(d))
        break
```

案例用 80 轮、每轮取 3 个最短耗时样本，最终恢复 `d` 并伪造 admin token 访问 `/welcome`。

## 变体与关联

- 变体：侧信道可能是功耗/电磁/缓存而非时间；同样把“短 k/部分位泄露”转成 HNP。
- 变体：短 `k` 的位长不同（如 240/248/252）时，分别设 `B` 并尝试。
- 变体：噪声导致 CVP 失败时，增加样本、剔除异常值、用 BKZ 更强约减或多组投票。
- 关联：[[crypto-ecc-ecdsa-partial-nonce-leak-lattice]]（部分 nonce 格攻击）、[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]（完全复用）、[[crypto-prng-truncated-lcg-coppersmith-lattice-cvp]]（CVP 格方法）。

## 检测与防御

- 防御：所有 `k` 必须使用同一安全位长与 CSPRNG/RFC6979，禁止“短 k”路径；签名实现应常量时间。
- 防御：对签名接口做速率限制，避免攻击者收集大量样本；使用 HSM/远程签名服务隔离时序。
- 检测：签名耗时分布出现双峰/短尾；同一接口大量签名请求；异常 token 伪造尝试。
- 响应：发现侧信道后轮换私钥/证书，统一 nonce 生成路径，审计历史签名是否可恢复。
