---
id: ctf-crypto-hnp-msb-oracle-babai-nearest-plane
title: Hidden Number Problem（HNP）MSB 泄露：pI 与 t 行构造格，Babai 最近平面恢复 α
type: scenario
domain: ctf
path: ctf/crypto
technique: hnp-msb-oracle-babai-nearest-plane
aliases:
- HNP
- Hidden Number Problem
- 隐藏数问题
- MSB oracle
- Babai 最近平面
- nearest plane
- 高位泄露
tags:
- crypto
- ctf
- lattice
- hnp
- msb
- babai
- cvp
- lll
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:48:28+08:00'
  notes: 已对照原文与图02核对：构造、公式与原文一致；PoC 按原文重写未复跑。注意：AGCD 卡称原文实测恢复 p/q0/e0，但原文仅给脚本未展示运行输出；HNP PoC 沿用原文 matrix(ZZ) 赋 1/2^(l+1) 有理缩放，实际运行需改用 QQ 或等价整数缩放；原文无受影响版本，frontmatter 无 sources/source_url。
---

## 一句话结论

当神谕对任意 `t` 返回 `MSB_k(α·t mod p)`（即知道 `αt mod p` 落在长度 `p/2^k` 的区间内）时，可写成 `αt_i ≡ u_i + e_i (mod p)`，`|e_i|≤p/2^{k+1}`；用 `pI_n` 与最后一行 `(t_1,…,t_n, 1/2^{l+1})` 构造格，目标点 `u=(u_1,…,u_n,0)`，用 Babai 最近平面找到最近格向量 `v=(αt_i mod p, α/2^{l+1})`，最后一维即恢复 `α`。

## 原理

- **MSB 泄露转成近似线性方程**：`u_i = MSB_k(α t_i mod p)` 意味着 `α t_i mod p` 与 `u_i` 的差 `e_i` 很小（`|e_i| ≤ p/2^{k+1}`）。于是 `α t_i ≡ u_i + e_i (mod p)`，未知量是 `α`，误差是 `e_i`。
- **格构造**：取 `n` 组样本，构造 `(n+1)×(n+1)` 格，基为
  ```text
  [ p    0   ... 0   0
    0    p   ... 0   0
    ...  ... ... ... ...
    0    0   ... p   0
    t_1  t_2 ... t_n 1/2^{l+1} ]
  ```
  其中 `l` 是泄露的高位数（与 `k` 对应，缩放因子 `1/2^{l+1}` 用于把最后一维压小）。
- **目标向量**：`u=(u_1,…,u_n,0)`。格中存在向量 `v=(αt_1 mod p,…,αt_n mod p, α/2^{l+1})`，它与 `u` 的差为 `(e_1,…,e_n, α/2^{l+1})`，各分量都很小，因此 `v` 是格中离 `u` 最近的向量（CVP）。
- **Babai 最近平面**：对格基做 LLL 约减后，用 Babai 的 nearest plane 算法求 `u` 的近似最近向量；最后一维 `v_{n+1}=α/2^{l+1}`，乘以 `2^{l+1}` 即得 `α`。
- **参数条件**：`l ≈ log^{1/2}(p)` 量级的泄露位数、足够多的样本、误差界足够小；样本太少或噪声太大时 CVP 不唯一/最近向量错误。
- **为什么成立**：HNP 把“高位已知、低位未知”的乘法关系转成“格中带小误差的最近向量”；LLL + Babai 在维数/误差合适时能有效求解。
- **CVP→SVP**：也可把目标点嵌入格中（Kannan embedding）转成 SVP，用 LLL/BKZ 求短向量；Babai 是最直接的 CVP 近似算法。

## 触发条件

- 有 MSB/高位泄露神谕：已知 `α t_i mod p` 的高 `k` 位，误差 `|e_i| ≤ p/2^{k+1}`。
- 样本数 `n` 足够，泄露位数 `l` 与 `p` 的关系满足 `l ≈ log^{1/2}(p)` 或更宽松；误差足够小。
- 能运行 Sage/LLL；需要构造 `pI` 与 `t` 行、选择缩放因子 `1/2^{l+1}`。
- 常见于 ECDSA nonce 高位泄露、截断 LCG、乘法掩码/侧信道等场景。

## 利用步骤

1. 收集 `(t_i, u_i)` 样本，估计泄露位数 `l`/误差界；确认 `α t_i ≡ u_i + e_i (mod p)`。
2. 构造 `n+1` 维格：前 `n` 行 `p` 在对角，最后一行前 `n` 列为 `t_i`、最后一列为 `1/2^{l+1}`。
3. 对格基做 LLL 约减；用 Babai nearest plane 求目标 `u=(u_1,…,u_n,0)` 的最近向量。
4. 取最近向量最后一维 `v_last`，`α = v_last * 2^{l+1}`（或按缩放因子调整）；验证 `α t_i mod p` 的高位与 `u_i` 一致。
5. 若失败，增加样本数、调整 `l`/缩放因子、改用 BKZ 或 Kannan embedding。

## PoC

```python
# Sage
n = len(t)
l = ...  # 泄露位数
M = matrix(ZZ, n + 1, n + 1)
for i in range(n):
    M[i, i] = p
for j in range(n):
    M[n, j] = t[j]
M[n, n] = 1 / (2 ** (l + 1))

# LLL 约减后 Babai nearest plane
L = M.LLL()
target = vector(ZZ, list(u) + [0])
# Sage 可用 L.babai(target) 或 fpylll 的 CVP.closest_vector
v = L.babai(target)
alpha = v[-1] * (2 ** (l + 1))
print(alpha)
```

原文用该构造 + Babai 最近平面恢复 `α`；未在本库复跑。

## 变体与关联

- **CVP→SVP**：Kannan embedding 把目标点嵌入格，转成短向量问题；LLL/BKZ 求短向量。
- **泄露类型**：MSB、LSB、中间位、带错误的高位；不同泄露对应不同的缩放/嵌入方式。
- **应用场景**：ECDSA nonce 高位泄露（`crypto-prng-truncated-lcg-coppersmith-lattice-cvp` 类）、截断 LCG、乘法掩码侧信道。
- **关联卡片**：[[crypto-prng-truncated-lcg-coppersmith-lattice-cvp]]（截断 LCG 的 Coppersmith/lattice）、[[ctf-crypto-coppersmith-msb-lcg-truncated-cvp]]（MSB 截断 LCG 的 CVP）、[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（LLL/Kannan embedding）。

## 检测与防御

- **不要泄露高位**：ECDSA/签名 nonce 的 MSB/LSB 不能暴露；使用 RFC 6979 确定性 nonce 或强随机。
- **参数评估**：对 HNP 类场景，用格攻击脚本评估泄露位数/样本数是否足以恢复密钥；`l ≈ log^{1/2}(p)` 是危险阈值。
- **检测**：签名/随机数接口是否存在高位截断、侧信道泄露、可重复的 `t` 采样；对异常签名做格攻击可行性评估。
