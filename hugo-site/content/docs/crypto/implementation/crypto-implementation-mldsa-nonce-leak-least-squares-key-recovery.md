---
id: crypto-implementation-mldsa-nonce-leak-least-squares-key-recovery
title: ML-DSA/Dilithium 签名 nonce 泄露：z-r=c·s1-noise 最小二乘恢复私钥
type: scenario
domain: crypto
path: crypto/implementation
technique: mldsa-nonce-leak-least-squares
tags:
- crypto
- dilithium
- ml-dsa
- post-quantum
- nonce-leak
- least-squares
- signature
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:29+08:00'
  notes: 已对照原文 §easyDilithium 核对：z=y+c*s1、r=y+noise、z-r=c*s1-noise、s1∈[-2,2]、noise∈[-15,15]、环 x^64+1、卷积矩阵+lstsq、160 签名、残差与伪造流程、flag 均一致；未本机复跑。卡片关联段自引本卡（crypto-implementation-mldsa-nonce-leak-least-squares-key-recovery）为冗余，不影响技术内容。
url: /docs/crypto/implementation/crypto-implementation-mldsa-nonce-leak-least-squares-key-recovery/
draft: false
kb_aliases:
- easyDilithium
- Dilithium nonce leak
- z-r = c*s1 - noise
- ML-DSA 私钥恢复
- 最小二乘恢复 s1
- 签名噪声泄露
---

## 一句话结论

签名实现返回 `c, z, r`，其中 `z = y + c*s1`、`r = y + noise`，因此 `z - r = c*s1 - noise`；`s1` 的系数只有 `[-2,2]`、`noise` 只有 `[-15,15]`，把每个 challenge 多项式 `c` 展开成卷积矩阵 `M_c`，收集约 100–160 个签名做最小二乘，噪声被平均掉后四舍五入即可恢复 `s1`，再按正常签名流程伪造目标消息签名。

## 原理

- Dilithium/ML-DSA 的签名中 `z = y + c*s1`，其中 `y` 是掩码向量，`c` 是 challenge 多项式，`s1` 是私钥向量。
- 题目额外返回 `r = y + noise`，于是 `z - r = c*s1 - noise`。`noise` 的系数范围 `[-15,15]`，`s1` 的系数范围 `[-2,2]`，后者是稀疏小量。
- 环为 `Z_q[x]/(x^64+1)`；多项式乘法 `c*s1_i` 可以写成卷积矩阵 `M_c * s1_i`。每个签名给出 64 条方程，而 `s1_i` 只有 64 个未知系数。
- 单个签名被噪声污染，但多个签名的噪声独立；把 `K` 个 `M_c` 纵向堆叠、`K` 组 `(z_i - r_i)` 拼接，做最小二乘 `solve(M, y)`，噪声的均值趋近 0。
- 对解四舍五入并裁剪到 `[-2,2]`，即可恢复 `s1`（案例 160 个签名，残差约 0.36/0.40，仍能正确舍入）。
- 恢复 `s1` 后，按正常签名流程对目标消息生成 `c, z`，通过 `verify` 即可获取 flag；不需要破解 ML-DSA 的格难题。

## 触发条件

- 签名接口返回 `z` 与 `r`（或任何泄露 `y + noise` 的中间值），且 `r` 与 `z` 使用同一个 `y`。
- `s1` 系数范围很小（如 `[-2,2]`），噪声范围有界且独立。
- 攻击者能收集足够多的签名（案例 100–160 个），且 challenge 多项式 `c` 已知。
- 环维度 `n=64`、模数 `q` 已知；签名验证接口可用于最终验证。

## 利用步骤

1. 请求大量非目标消息的签名，记录每个 `(c, z, r)`。
2. 对每个 challenge 多项式 `c` 构造 `n x n` 卷积矩阵 `M_c`（注意 `x^n = -1` 的符号）。
3. 对每个私钥分量 `i`，把所有 `M_c` 纵向堆叠，把所有 `(z_i - r_i)` 拼接为右端向量。
4. 用 `numpy.linalg.lstsq` 求解，得到带噪的 `s1_i` 估计；四舍五入并裁剪到 `[-eta, eta]`（案例 eta=2）。
5. 用恢复的 `s1` 对目标消息签名：采样 `y`、计算 `w=A*y`、`c=H(msg,w1)`、`z=y+c*s1`，检查 `z` 的范数约束后提交。
6. 若验证失败，增加签名数量、检查卷积矩阵符号/系数顺序、确认 `r` 的采样范围与 `z` 的编码。

## PoC

```python
import numpy as np

def conv_matrix(c_coeffs, n):
    c = challenge.Poly(c_coeffs).centered_list()
    mat = np.zeros((n, n), dtype=float)
    for out_idx in range(n):
        for secret_idx in range(n):
            if secret_idx <= out_idx:
                c_idx, sign = out_idx - secret_idx, 1
            else:
                c_idx, sign = out_idx + n - secret_idx, -1
            mat[out_idx, secret_idx] = sign * c[c_idx]
    return mat

def recover_s1(samples):
    matrices = []
    rhs = [[] for _ in range(challenge.l)]
    for c_coeffs, z_lists, r_lists in samples:
        matrices.append(conv_matrix(c_coeffs, challenge.n))
        for i in range(challenge.l):
            rhs[i].append(np.array(z_lists[i]) - np.array(r_lists[i]))
    big = np.vstack(matrices)
    recovered = []
    for i in range(challenge.l):
        y = np.concatenate(rhs[i])
        sol, *_ = np.linalg.lstsq(big, y, rcond=None)
        rounded = np.clip(np.rint(sol).astype(int), -challenge.eta, challenge.eta)
        recovered.append(challenge.Poly(rounded.tolist()))
    return recovered
```

案例收集 160 个签名后恢复 `s1`，并成功伪造目标签名，得到 `NepCTF{ML_DSA_n0nse_l34k_4tt4ck}`。

## 变体与关联

- 变体：只泄露 `y` 的部分低位/高位时，可把已知部分代入，构造类似的线性系统或格。
- 变体：噪声更大时，最小二乘可能不足以舍入，需要把问题建模为 LWE/CVP 并做格约减。
- 变体：`s1` 系数范围更大或分布不均匀时，可用最大似然/整数规划替代简单舍入。
- 关联：[[ctf-crypto-dilithium-like-exact-t-as-linear-system-secret-recovery]]（无噪声精确线性方程版本）、[[crypto-prng-truncated-lcg-coppersmith-lattice-cvp]]（格/CVP 方法）、[[crypto-implementation-mldsa-nonce-leak-least-squares-key-recovery]]（本卡）。

## 检测与防御

- 防御：签名实现绝不能返回 `y`、`r` 或任何 `y` 的线性函数；只返回标准 `(c, z)`。
- 防御：使用标准库/经过审计的 ML-DSA 实现，严格遵循拒绝采样与范数检查；不要为了调试输出中间值。
- 防御：对签名接口做速率限制与鉴权，避免攻击者收集大量样本。
- 检测：签名响应中出现额外字段（`r`、`y`、`w` 等）；同一私钥在短时间内产生大量签名；验证失败率异常。
- 响应：发现 nonce/中间值泄露后立即轮换密钥，审计历史签名是否可恢复私钥，修复接口字段并重新编译。
