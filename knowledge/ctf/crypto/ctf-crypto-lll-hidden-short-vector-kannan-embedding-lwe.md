---
id: ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe
title: LLL 恢复打乱基中的短向量 + Kannan embedding 解小误差 LWE
type: scenario
domain: ctf
path: ctf/crypto
technique: lll-hidden-short-vector-kannan-embedding-lwe
aliases:
- LLL 短向量
- Kannan embedding
- LWE 格攻击
- BKZ
- 隐藏短向量
- 单位上三角变换
tags:
- crypto
- ctf
- lattice
- lll
- bkz
- lwe
- kannan
- fpylll
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:50:00+08:00'
  notes: 已对照原文核对；单位上三角基 LLL 取短向量、Kannan embedding 2n+1 维与 e/s 验证一致
---

## 一句话结论

当格基 `H` 是原始基 `mt` 经过单位上三角随机矩阵 `U`（`det=1`）打乱得到时，`H` 与 `mt` 生成同一个格，LLL 可直接从 `H` 中恢复 `mt` 的短向量 `secret`；有了多项式 `F` 后，把 `B=M_A·s+e mod p, |e_i|≤3` 转成 Kannan embedding 格，LLL+BKZ 可同时解出 `s` 和 `e`。

## 原理

- **格基等价**：`H=U·mt`，`U` 为单位上三角（对角线 1，上三角随机 0..256），`det(U)=1`，所以 `H` 与 `mt` 生成同一个格。`secret` 是 `mt` 的第一行，元素很小（`f_coeffs` 小，第 24 位为 1），是格中短向量；LLL 约减 `H` 后，短向量会出现在约减基中。
- **恢复短向量**：LLL 结果中找 `x^24` 系数绝对值为 1、且最大绝对值 <1000 的行；取反使 `x^24` 系数为 +1，得到 `f_coeffs`。本题得到 `F(x)=x^24+2x^3+2x+4`。
- **构造 LWE**：题面 `B=(M_A·s_coeffs+error) mod p`，其中 `M_A` 由 `a(x)·x^j mod F` 的系数矩阵给出，误差 `|e_i|≤3`，维度 24，模 `p=2^31-1`。这是小误差 LWE。
- **Kannan embedding**：构造 `(2n+1)×(2n+1)` 格，基矩阵为
  `L = [[pI_n, 0, 0], [M_A^T, I_n, 0], [-B^T, 0, c]]`；
  格中存在短向量 `(-e, s, c)`（`c` 为嵌入因子，常取 1/3/10/100）。LLL+BKZ(20) 约减后，取最后一维为 `c` 的行，归一化得到 `e/s`，验证 `M_A·s+e ≡ B (mod p)` 且 `|e_i|≤3`。
- **为什么成立**：LLL 能在多项式时间找到格中较短向量；Kannan embedding 把“带误差的线性方程”转成“格中短向量”问题，误差小、维数低（24）时 BKZ 很容易解。
- **参数**：`d=64`（隐藏短向量维度）、`n=24`（LWE 维度）、`scale=2^44`（mt 随机行上界）、`p=2147483647`、误差界 3。

## 触发条件

- 格基是原基的单位上三角随机变换（`det=1`），短向量仍在格中；短向量系数足够小，LLL 能恢复。
- LWE 维数低（24）、模数 31 bit、误差界小（3），Kannan embedding + BKZ 可解。
- 有足够的 `(M_A, B, p)` 数据；能运行 Sage/fpylll（LLL 至少，BKZ 更稳）。
- 题目给出的 `A` 向量、`F` 的构造方式、`B` 输出完整；否则需先补全。

## 利用步骤

1. 对 `H` 做 LLL，找 `x^24` 系数为 ±1 且最大绝对值 <1000 的行，取反使 `x^24` 系数为 +1，得到 `f_coeffs`。
2. 构造 `F=x^24+Σ f_i x^i`，计算 `a(x)=Σ A_i x^i`，构造 `M_A[i,j]=(a·x^j mod F)` 的系数。
3. 构造 Kannan embedding 格 `L`（如上），对 `c∈{1,3,10,100}` 逐个尝试；LLL 后用 fpylll 的 `BKZ.reduction(block_size=20)` 加强。
4. 遍历约减基行，取最后一维 `w`；若 `w!=0` 且 `c % w == 0`，令 `mul=c//w`，得到 `e=[-row[i]*mul]`、`s=[row[n+i]*mul]`。
5. 验证 `|e_i|≤3` 且 `M_A·s+e ≡ B (mod p)`；成功则 `s` 的字节即 flag（`0xGame{kiss then kill}`）。
6. 若 LLL 失败，尝试不同 `c`、提高 BKZ block size 或调整格基排列。

## PoC

```python
# H 为题目给出的 64x64 格基
Hr = H.LLL()
secret = None
for row in Hr.rows():
    if abs(row[24]) == 1 and max(abs(x) for x in row) < 1000:
        secret = [-x for x in row]      # 令 x^24 系数为 +1
        break
assert secret is not None
f = [int(secret[i]) for i in range(24)]

R.<x> = PolynomialRing(ZZ)
F = x^24 + sum(f[i] * x^i for i in range(24))
a = sum(A[i] * x^i for i in range(24))
M = matrix(ZZ, 24, 24)
for j in range(24):
    col = (a * x^j) % F
    for i in range(24):
        M[i, j] = col[i]

def solve_lwe(c=1, block=20):
    n = 24
    dim = 2 * n + 1
    L = matrix(ZZ, dim)
    for i in range(n):
        L[i, i] = p
    for i in range(n):
        for j in range(n):
            L[n + i, j] = M[j, i]       # M^T
        L[n + i, n + i] = 1
    for j in range(n):
        L[2 * n, j] = -B[j]
    L[2 * n, 2 * n] = c
    Lr = L.LLL()
    # 可选：fpylll BKZ(block_size=20) 再约减
    for row in Lr.rows():
        w = row[2 * n]
        if w == 0 or c % w:
            continue
        mul = c // w
        e = [-row[i] * mul for i in range(n)]
        s = [row[n + i] * mul for i in range(n)]
        if all(abs(v) <= 3 for v in e):
            if all((sum(M[i, j] * s[j] for j in range(n)) + e[i] - B[i]) % p == 0
                   for i in range(n)):
                return s, e
    return None

for c in (1, 3, 10, 100):
    res = solve_lwe(c)
    if res:
        s, e = res
        print(bytes([v & 0xFF for v in s]).rstrip(b"\x00"))
        break
```

## 变体与关联

- **变体（LLL 子集和）**：低密度背包用 CJLOSS 格还原选择向量，思路同样是“把组合问题嵌入格中找短向量”。
- **变体（LWE 参数）**：误差界增大、维数增大时需要 BKZ 更高 block size 或更多样本；Kannan embedding 也可换成 primal/dual 攻击。
- **变体（Babai）**：若误差更小且格基良好，可直接用 Babai 最近平面/最近向量。
- **关联卡片**：[[ctf-reverse-apk-knapsack-chacha20-vault]]（LLL 子集和）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（Coppersmith 格）、[[ctf-crypto-simon-period-measurement-gf2-nullspace]]（线性代数攻击）。
- **边界**：`U` 的行列式不为 1、短向量不够短、维数/误差过大时 LLL 失败；需要按目标环境调整 `c`/BKZ 参数；没有 `fpylll` 时 LLL 可能不够。

## 检测与防御

- **CTF 识别**：看到“打乱的格基”“secret 短向量”“B=M·s+e mod p”“误差很小”时，先做 LLL 找短向量，再构造 Kannan embedding。
- **密码设计**：LWE 参数需满足安全估计（维数、模数、误差分布），不要用 24 维/误差 3 的玩具参数；格基变换不能替代密钥保护。
- **实现**：使用标准 PQC 库与参数；不要把原始短向量/误差暴露在输出中；对格基做随机化时注意不要保留短向量。
