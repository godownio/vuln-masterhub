---
id: ctf-crypto-hnp-2h-continued-fraction-kannan-embedding
title: HNP-2H 连分数降维 + Kannan Embedding：双小未知量模方程恢复大 secret
type: scenario
domain: ctf
path: ctf/crypto
technique: hnp-2h-continued-fraction-kannan-embedding
tags:
- crypto
- ctf
- lattice
- hnp
- hnp-2h
- continued-fraction
- kannan-embedding
- lll
- sage
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:53:12+08:00'
  notes: 已对照原文核对：消元 C̄/Q̄/A、A_i/p 连分数取 Bmin≈√p、k_i=λ_i r_i+Δ_i s_i、t_i=λ_i Q̄_i/a_i=λ_i C̄_i、Kannan (n+2) 维嵌入、候选提取与残差验证均一致；卡片正确指出原文正文 B≈2^50 与代码 isqrt(512-bit p)·2^34≈2^290 的矛盾，并给出 mB 上界。未验证点：原文无运行输出/flag，PoC 未本机执行；小笔误：触发条件中 n≈2√bitlen 应为 n≈√(2·bitlen)（原文 d=int(sqrt(nbit<<1))，512-bit 时 n=32 本身正确）。
url: /docs/ctf/crypto/ctf-crypto-hnp-2h-continued-fraction-kannan-embedding/
draft: false
kb_aliases:
- HNP-2H
- HNP with Two Holes
- HNP-2D
- Honey
- Crypto CTF 2024 Honey
- 连分数逼近
- 二维 hole 降维
- Kannan embedding
---

## 一句话结论

当每条模方程形如 `C_i ≡ Q_i·m + R_i·r_i + S_i·s_i (mod p)`、其中 `m` 是大 secret、`r_i, s_i` 是两个有界小未知量（HNP-2H）时，可先用 `R_i^{-1}` 消元，再用 `A_i/p` 的连分数逼近找到 `λ_i/ u_i` 使 `Δ_i = λ_i A_i - u_i p` 很小，把二维小向量 `(r_i, s_i)` 投影成一维短量 `k_i = λ_i r_i + Δ_i s_i`，最后用 Kannan embedding + LLL 恢复 `m`。

## 原理

- **标准 HNP**：给定 `t_i·x ≡ a_i + e_i (mod p)`，`e_i` 有界，可用格（`pI` + `t` 行）加 Babai/Kannan 恢复 `x`；DSA 部分 nonce 泄露是典型来源。
- **HNP-2H**：每条方程有两个小未知量 `r_i, s_i`，直接构造格需要同时恢复 `m` 和所有 `r_i, s_i`，维度过高；关键是找一个线性变换把二维小向量压成一维可界定短量。
- **第一步消元**：令 `C̄_i = R_i^{-1} C_i`、`Q̄_i = R_i^{-1} Q_i`、`A_i = R_i^{-1} S_i (mod p)`，方程变为
  `C̄_i - Q̄_i·m ≡ r_i + A_i·s_i (mod p)`。
- **第二步连分数逼近**：对 `A_i/p` 做连分数展开，取分母上界 `Bmin ≈ √p`，找到第一个分母超过 `Bmin` 的渐近分数，取其前一项 `u_i/λ_i`；由最佳逼近性质
  `|A_i/p - u_i/λ_i| < 1/(λ_i·Bmin)`，两边乘 `pλ_i` 得 `|Δ_i| = |λ_i A_i - u_i p| < p/Bmin ≈ √p`，同时 `λ_i < Bmin`。于是 `λ_i` 与 `Δ_i` 都在 `√p` 量级，二者平衡。
- **第三步投影**：原式乘 `λ_i`，并用 `λ_i A_i = u_i p + Δ_i`、`u_i p s_i ≡ 0 (mod p)` 得
  `λ_i(C̄_i - Q̄_i m) ≡ λ_i r_i + Δ_i s_i = k_i (mod p)`。
  取 `t_i = λ_i Q̄_i`、`a_i = λ_i C̄_i`，则 `t_i m - a_i ≡ -k_i (mod p)`，其中 `|k_i| ≲ √p·2^{noise}`。HNP-2H 被约化成标准 HNP。
- **第四步 Kannan embedding**：构造 `(n+2)×(n+2)` 格：
  - 前 `n` 行对角为 `p`（模运算的整数倍）；
  - 第 `n` 行前 `n` 列为 `t_i`，第 `n` 列为误差尺度 `B`；
  - 第 `n+1` 行前 `n` 列为 `a_i`，最后一列为 `M`。
  取组合 `(q_0,…,q_{n-1}, m, -1)`，得到向量
  `(q_i p + m t_i - a_i, mB, -M)`；前 `n` 个坐标正是 `-k_i`，都很小。若 `mB` 与 `M` 也控制在随机向量范数之下，该向量就是格中短向量，LLL 可把它找出来；从 `r[n] // B` 或 `r[n] % B == 0` 提取 `m`，再用原始残差验证。
- **参数关键（原文数值有笔误）**：对于 512-bit 的 `p`，`√p ≈ 2^256`，`B = isqrt(p)·2^{noise_bits+slack}` 约为 `2^290`，不是原文正文写的 `2^50`；`k_i` 的界也约为 `2^288`。嵌入向量最后一维是 `mB`，要让它仍短于随机向量（约 `√n·p`），需要 `mB ≲ p`，即 `m ≲ p/B ≈ 2^256/2^34 ≈ 2^222`（约 27 字节的 flag）。若 `m` 更长，`mB` 会盖过随机向量，LLL 可能找不到目标向量，需要调整尺度、增加维度或改用 BKZ/其他嵌入。
- **候选提取与验证**：LLL 约减后，检查每行最后两维：若 `|r[n+1]| == M` 或 `r[n] % B == 0`，取 `x = r[n] // B`；再回到原方程计算 `u_i = λ_i R_i^{-1}(C_i - Q_i m) mod p`，映射到 `(-p/2, p/2)`，要求所有 `|u_i| < B` 才接受。

## 触发条件

- 题目给出 `p, Q, R, S, C`，每条满足 `C_i ≡ Q_i m + R_i r_i + S_i s_i (mod p)`；`m` 为大 secret，`r_i, s_i` 为已知界的小量（如 32-bit）。
- `p` 为大素数，`R_i` 可逆；方程数量 `n` 足够（原文 `n ≈ 2√bitlen`，512-bit 时 n=32）。
- 能运行 SageMath（`continued_fraction`、`Matrix(ZZ).LLL()`）或 fpylll。
- `mB` 不超过随机向量范数（或可通过 BKZ/调参补救）；flag 长度较短时最稳。

## 利用步骤

1. 读取 `p, Q, R, S, C`，确认 `n`、噪声位数与 flag 长度量级。
2. 对每个 `i` 计算 `invR = R_i^{-1} mod p`、`A_i = invR·S_i`、`Q̄_i = invR·Q_i`、`C̄_i = invR·C_i`。
3. 对 `A_i/p` 做连分数，取 `Bmin = isqrt(p)`，找第一个分母 `> Bmin` 的渐近分数，取前一项 `(λ_i, u_i)`；计算 `Δ_i = λ_i A_i - u_i p`（应约为 `√p`）。
4. 计算 `t_i = λ_i Q̄_i mod p`、`a_i = λ_i C̄_i mod p`；设 `B = Bmin·2^{noise_bits+slack}`（32-bit 噪声、slack 2–4），`M = B`。
5. 构造 `(n+2)` 维 Kannan 嵌入矩阵，做 LLL（必要时 BKZ）；从短向量提取候选 `m`。
6. 用原始方程验证残差 `|λ_i(C̄_i - Q̄_i m)|`（中心化）是否都 `< B`；通过后转字节串检查 flag 格式。
7. 若失败：增大 `B`/`slack`、增加样本、改用 BKZ、检查 `mB` 是否过大（flag 太长时需换嵌入或分块）。

## PoC

```python
# SageMath 示意；参数/噪声界按题目调整，未在本机执行
def cf_lambda(A, Bmin, p):
    cf = (QQ(A) / QQ(p)).continued_fraction()
    for i in range(cf.length() - 1):
        di, dj = Integer(cf.denominator(i)), Integer(cf.denominator(i + 1))
        if di < Bmin <= dj:
            return di, Integer(cf.numerator(i))
    return Integer(cf.denominator(cf.length() - 1)), Integer(cf.numerator(cf.length() - 1))

def build_embedding(p, t, a, B, M):
    n = len(t)
    Mtx = Matrix(ZZ, n + 2, n + 2)
    for i in range(n):
        Mtx[i, i] = p
    for j in range(n):
        Mtx[n, j] = t[j]
    Mtx[n, n] = B
    for j in range(n):
        Mtx[n + 1, j] = a[j]
    Mtx[n + 1, n + 1] = M
    return Mtx

def centered(x, p):
    x = Integer(x) % p
    return x - p if x > p // 2 else x

def solve(p, Q, R, S, C, noise_bits=32, slack=3):
    n = len(Q)
    Bmin = isqrt(p)
    lam, t, a = [], [], []
    for i in range(n):
        invR = inverse_mod(Integer(R[i]), p)
        A = (invR * Integer(S[i])) % p
        li, _ = cf_lambda(A, Bmin, p)
        lam.append(li)
        t.append((li * invR * Integer(Q[i])) % p)
        a.append((li * invR * Integer(C[i])) % p)

    B = Integer(Bmin) * (Integer(2) ** (noise_bits + slack))
    red = build_embedding(p, t, a, B, B).LLL()

    cands = set()
    for r in red.rows():
        if abs(Integer(r[n + 1])) == B:
            cands.add(Integer(r[n]) // B)
        if Integer(r[n]) % B == 0:
            cands.add(abs(Integer(r[n]) // B))

    for m in cands:
        if not (0 <= m < p):
            continue
        if all(abs(centered(Integer(lam[i]) * inverse_mod(Integer(R[i]), p) *
                          (Integer(C[i]) - Integer(Q[i]) * m), p)) < B
               for i in range(n)):
            return m
    return None
```

说明：原文完整脚本还包含参数读取、flag 格式检查；上述为最小结构示意，未在本机复跑。原文正文把 `B` 写成 `≈2^50`，与其代码 `isqrt(512-bit p)·2^34 ≈ 2^290` 不一致，卡片按代码/量级修正；实际题目需先算 `mB` 与 `√n·p` 再决定是否可行。

## 变体与关联

- 变体：噪声界不是 32-bit 时调整 `slack`；方程数少时用 BKZ 或增加样本；`m` 太长时改用分块/其他嵌入或三变量 lattice。
- 变体：标准 HNP（1-hole）用 `pI` + `t` 行 + Babai；三个及以上小未知量需要多变量格方法，连分数降维不够。
- 关联：[[ctf-crypto-hnp-msb-oracle-babai-nearest-plane]]（标准 HNP/Babai）、[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（Kannan embedding 解 LWE）、[[crypto-ecc-ecdsa-partial-nonce-leak-lattice]]（ECDSA 部分 nonce 泄露）、[[ctf-crypto-agcd-sda-lattice-small-error-recovery]]（小误差格攻击）。
- 边界：`R_i` 不可逆、噪声界估计错误、`mB` 过大、样本不足、LLL 找不到短向量时失败；需要 BKZ/调尺度/换构造。

## 检测与防御

- CTF 识别：多个系数数组 `Q/R/S`、每条方程两个小未知量、模大素数、目标 secret 为 flag；优先尝试消元 + 连分数降维 + HNP 格。
- 真实系统防御：不要泄露 nonce 的部分比特/小误差；使用 CSPRNG、足够大的 nonce、常数时间实现；签名/加密方案避免让攻击者获得带小噪声的线性方程。
- 审计：检查协议是否把 `r,s` 之类的小随机量与其系数一起输出；若必须输出，增大噪声空间或做掩码。
