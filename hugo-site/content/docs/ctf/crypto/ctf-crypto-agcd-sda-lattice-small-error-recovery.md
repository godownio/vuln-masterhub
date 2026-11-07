---
id: ctf-crypto-agcd-sda-lattice-small-error-recovery
title: 近似 GCD（AGCD）SDA 格攻击：x_i=pq_i+e_i 用小误差差分构造短向量恢复 p
type: scenario
domain: ctf
path: ctf/crypto
technique: agcd-sda-lattice-small-error-recovery
tags:
- crypto
- ctf
- lattice
- lll
- agcd
- approximate-gcd
- dghv
- small-error
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:48:22+08:00'
  notes: 已对照原文与图02核对：构造、公式与原文一致；PoC 按原文重写未复跑。注意：AGCD 卡称原文实测恢复 p/q0/e0，但原文仅给脚本未展示运行输出；HNP PoC 沿用原文 matrix(ZZ) 赋 1/2^(l+1) 有理缩放，实际运行需改用 QQ 或等价整数缩放；原文无受影响版本，frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-agcd-sda-lattice-small-error-recovery/
draft: false
kb_aliases:
- AGCD
- 近似 GCD
- Approximate GCD
- DGHV 参数恢复
- SDA 格
- 丢番图近似
- q0x1-q1x0
---

## 一句话结论

当样本形如 `x_i = p·q_i + e_i`（`p` 为 η 位、`q_i` 为 γ−η 位、`e_i` 为 ρ 位的小噪声）时，先取两个样本做差消去 `p`：`q_0x_1 − q_1x_0 = q_0e_1 − q_1e_0`；把 `(q_0, q_1, …, q_l)` 作为系数、以 `2^{ρ+1}` 和 `x_i`/`−x_0` 构造 SDA 格，LLL 求出的最短向量第一分量可恢复 `q_0`，再由 `e_0 = x_0 mod q_0`、`p = (x_0−e_0)/q_0` 恢复 `p`。

## 原理

- **消去 p**：`x_i = p q_i + e_i`；取 `q_0 x_1 − q_1 x_0 = q_0(q_1p+e_1) − q_1(q_0p+e_0) = q_0e_1 − q_1e_0`。右边只含小噪声，量级约 `γ + ρ`，远小于 `p q_i` 的 `γ` 位主项（相对而言仍是“短”的差分）。
- **SDA 格构造**：以 `(q_0,q_1,…,q_l)` 为系数，基矩阵为
  ```text
  [ 2^{ρ+1}   x_1      x_2    ...  x_l
      0       -x_0      0     ...   0
      0        0       -x_0   ...   0
      ...      ...      ...   ...  ...
      0        0        0     ...  -x_0 ]
  ```
  线性组合得到 `(q_0·2^{ρ+1}, q_0e_1−q_1e_0, …, q_0e_l−q_le_0)`。第一分量 `q_0·2^{ρ+1}` 约 `γ−η+ρ+1` 位，其余分量约 `γ+ρ` 位；在合适的参数下这是格中很短的非零向量。
- **恢复顺序**：LLL 约减后取第一分量除以 `2^{ρ+1}` 得 `q_0`（取绝对值）；`e_0 = x_0 mod q_0`（要求 `e_0` 小且非负/取最小余数）；`p = (x_0 − e_0)/q_0`。
- **参数条件**：SDA 攻击需要 `l+1 > (γ−ρ)/(η−ρ)`（样本数足够多）；正交格（OL）变体条件为 `l > (γ−ρ)/(η−ρ)`，构造类似但用正交关系。
- **小噪声捷径**：如果 `e_i` 很小、可爆破，直接枚举 `e_1,e_2` 并 `gcd(x_1−e_1, x_2−e_2)` 即可得到 `p`；格方法用于噪声不可爆破的情况。
- **为什么成立**：AGCD 把“带噪声的整除关系”转成“格中短向量”；LLL 能在多项式时间找到短向量，从而把噪声从主项中剥离。

## 触发条件

- 样本满足 `x_i = p q_i + e_i`，`p`、`q_i` 大小关系符合 η/γ，噪声 `e_i` 远小于 `p q_i`。
- 有足够多的样本满足 `l+1 > (γ−ρ)/(η−ρ)`（SDA）或 `l > (γ−ρ)/(η−ρ)`（OL）。
- 能运行 Sage/LLL；参数需要配平（`2^{ρ+1}` 的指数选择很关键）。
- 噪声不是可爆破的极小值，或爆破成本过高。

## 利用步骤

1. 估计 η、γ、ρ：`p` 的位数为 η，`x_i` 的位数为 γ，噪声位数为 ρ；确认样本数满足范围条件。
2. 若噪声极小，先尝试枚举 `e_1,e_2` 并 `gcd(x_1−e_1,x_2−e_2)`；不行再上格。
3. 按 SDA 构造基矩阵：第一行 `[2^{ρ+1}, x_1, …, x_l]`，其余行在对角放 `−x_0`。
4. LLL 约减，取第一分量 `A·q_0`，`q_0=|L[0,0]//2^{ρ+1}|`；若不对，调整 `2` 的指数/样本数/行顺序。
5. `e_0 = x_0 % q_0`，`p=(x_0−e_0)//q_0`；用其它样本验证 `x_i % p` 是否等于小噪声。
6. 若 SDA 失败，尝试 OL 正交格变体或 BKZ 加强。

## PoC

```python
k = 5
rho = 256
xs = [...]  # x_i = p*q_i + e_i

A = ZZ(pow(2, rho + 1))
B = matrix(xs[1:])
C = matrix.diagonal([-xs[0]] * (k - 1))
M = matrix.block([[A, B], [ZZ(0), C]])
L = M.LLL()
q0 = ZZ(L[0, 0] / A).abs()
e0 = ZZ(xs[0] % q0)
p = ZZ((xs[0] - e0) / q0)
print(e0, q0, p)
```

原文实测 `k=5, eta=768, gamma=1024+eta, rho=256` 能恢复 `p/q0/e0`；未在本库复跑。

## 变体与关联

- **OL 正交格**：构造与 SDA 类似，条件为 `l > (γ−ρ)/(η−ρ)`；适合 SDA 参数不满足时。
- **爆破捷径**：噪声极小时枚举 `e_i` 后 GCD；与格方法在构造上区别不大。
- **DGHV/同态加密参数**：AGCD 是全同态加密的参数恢复问题；同样的格方法可用于攻击参数选择不当的 DGHV 实例。
- **关联卡片**：[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（LLL/Kannan embedding）、[[ctf-crypto-rsa-shared-prime-batch-gcd]]（批量 GCD/共享素数）。

## 检测与防御

- **参数选择**：AGCD/DGHV 类方案要保证噪声相对 `p` 足够大、样本数不足以满足格攻击范围；不要用小噪声 + 少量样本。
- **检测**：密钥生成时检查 `l+1 > (γ−ρ)/(η−ρ)` 是否成立；对公开样本做 LLL 短向量探测。
- **密码设计**：不要把“近似整除”当作安全假设；使用经过证明的 LWE/RLWE 参数与安全估计工具。
