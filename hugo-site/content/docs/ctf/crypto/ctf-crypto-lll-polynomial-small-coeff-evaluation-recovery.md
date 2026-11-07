---
id: ctf-crypto-lll-polynomial-small-coeff-evaluation-recovery
title: LLL 恢复小系数多项式：偏移 B 构造短向量，8 组精确求值还原后 SHA-256 派生 AES-CTR key
type: scenario
domain: ctf
path: ctf/crypto
technique: lll-polynomial-small-coefficient-evaluation-recovery
tags:
- ctf
- crypto
- lll
- lattice
- polynomial
- coefficient-recovery
- aes-ctr
- sha256
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V182
  verified_at: '2026-11-06T20:13:44+08:00'
  notes: 已对照原文核对（含11张图片）；SageMath 未本机执行；矩阵构造与 LLL 取行逻辑匹配，已修正矩阵规模 130×138 与“加偏移 B”表述
url: /docs/ctf/crypto/ctf-crypto-lll-polynomial-small-coeff-evaluation-recovery/
draft: false
kb_aliases:
- 多项式系数格恢复
- LLL 多项式求值
- 小系数多项式攻击
- 偏移 B 短向量
- 评估点隐藏多项式
- Sage LLL 多项式
---

## 一句话结论

当密钥来自一个次数已知、系数都在已知偏移 B 附近（`a_i = B + 小量`）的多项式 `f(x)=Σa_i x^i`，且题目给出若干组精确求值 `(x_j, y_j=f(x_j))` 时，可以把“系数向量 + 求值约束”编码进一个格：目标向量是 `(a_i−B, 1, 0, …, 0)`，前段小、后段（求值误差）为零；LLL 找到该短向量后加上偏移 B 即恢复全部系数，再计算 `f(0x65537)`、SHA-256 派生 AES-CTR key 解密密文。

## 原理

### 问题结构

- 设未知多项式 `f(x) = a_0 + a_1 x + … + a_N x^N`，次数 `N=128`；系数满足 `a_i = B + e_i`，其中 `B=2^63`、`e_i` 是小量（相对 B 很小）。
- 题目给出 `M=8` 组精确求值 `y_j = f(x_j)`（`j=0..M−1`），没有噪声；未知的是 129 个系数 `a_i`，已知的是 8 个方程和“系数接近 B”这一强约束。
- 直接解 8 个方程无法确定 129 个未知数；但“系数接近 B”把问题变成格中的短向量问题：把所有系数同时减去 B 后，得到一个很短的向量，而求值方程则要求这些短系数与已知 y 的线性组合为零。

### 格的构造

对每个系数下标 `i=0..N` 建一行：

```text
row_i = [0,...,1,...,0 | K*x_0^i, K*x_1^i, ..., K*x_{M-1}^i]
```

即前 `N+1` 列是单位矩阵（系数坐标），后 `M` 列是各求值点的 `K*x_j^i`（`K=2^100` 用于放大约束）。

再加一行常数行：

```text
row_const = [0,...,0, 1, 0,...,0 | -K*(y_j - B*Σ_i x_j^i) for each j]
```

其中第 `N+1` 列（常数坐标）为 1，后 `M` 列是 `-K*(y_j − B*Σ_i x_j^i)`。

取格向量：

```text
v = Σ_i (a_i − B) * row_i + 1 * row_const
```

- 前 `N+1` 个坐标就是 `a_i − B`，因为 `a_i` 接近 B，这些都是小量。
- 后 `M` 个坐标：
  ```text
  K * [ Σ_i (a_i−B)x_j^i − (y_j − B*Σ_i x_j^i) ]
  = K * [ Σ_i a_i x_j^i − y_j ]
  = 0
  ```
  因为 `y_j = f(x_j)` 是精确求值。
- 常数坐标为 1。因此 `v` 是一个“前段小、后段全零、常数项为 1”的短向量；在格中做 LLL 约简，最短向量很可能就是它（或其相反数）。

### 从短向量恢复系数

- LLL 输出一行若后 `M` 个坐标全为 0，且常数坐标为 `1` 或 `-1`，就是目标向量：
  - 常数坐标为 `1`：`a_i = row[i] + B`；
  - 常数坐标为 `-1`：先取负，再 `a_i = -row[i] + B`。
- 恢复系数后，题目用 `ep = f(0x65537)`（即 `Σ a_i * 0x65537^i`）作为秘密；`key = SHA-256(str(ep))[:16]`，再用 AES-CTR 解密 `ct`。
- 该构造之所以有效，是因为“系数接近 B”提供了比方程数更强的先验；8 个方程足以在 129 维格中把目标向量压到最短，而精确求值保证后段严格为零。

## 触发条件

- 已知多项式次数 N（或可估计），未知系数都在已知偏移 B 附近且偏差远小于 B；求值点 x_j 与结果 y_j 已知。
- 求值是精确的（无噪声）；若有小噪声，后段不会严格为零，需要调整 K/用近似格或 CVP，成功率下降。
- 有足够的求值组数把目标向量与格中其它短向量区分开；组数太少可能找到伪短向量，需要用 `f(x_j)=y_j` 回代校验。
- 能运行 LLL（SageMath/FPLLL），矩阵规模在可处理范围内；本例 130×138，系数为大整数，需注意 LLL 精度/时间。
- 密钥派生方式已知（SHA-256 前 16 字节）且 AES 模式/IV 已知。

## 利用步骤

1. 解析题目给出的 `(x_j, y_j)`、密文 `ct`、nonce；确定次数 N（本例 128）、系数偏移 B（2^63）、缩放 K（2^100）。
2. 按上述布局构造 `(N+2) × (N+2+M)` 的整数矩阵：前 N+1 行为单位系数 + `K*x_j^i`；最后一行常数 + `-K*(y_j − B*Σ x_j^i)`。
3. 对矩阵做 LLL；遍历约简后的行，找后 M 列全为 0、常数列为 ±1 的行。
4. 按常数列符号恢复 `a_i = ±row[i] + B`；用所有 `(x_j,y_j)` 回代验证 `f(x_j)==y_j`，排除伪短向量。
5. 计算 `ep = Σ a_i * 0x65537^i`；`key = SHA-256(str(ep).encode()).digest()[:16]`。
6. 用 key 和题目 nonce 构造 AES-CTR 的 16 字节 IV，解密密文；检查明文是否为 flag 格式。

## PoC

SageMath（矩阵构造与 LLL；`poly_list` 为题目给出的 `(x, y)` 列表）：

```python
from sage.all import *
from hashlib import sha256

N = 128
M = 8
B = 2**63
K = 2**100
X = [p[0] for p in poly_list]
Y = [p[1] for p in poly_list]

rows = N + 2
cols = N + 2 + M
mat = Matrix(ZZ, rows, cols)

# 系数坐标 + 求值约束
for i in range(N + 1):
    mat[i, i] = 1
    for j in range(M):
        mat[i, N + 2 + j] = K * (X[j] ** i)

# 常数行：1 * f(x_j) - y_j 的偏移形式
mat[N + 1, N + 1] = 1
for j in range(M):
    sum_x_pow = sum(X[j] ** i for i in range(N + 1))
    mat[N + 1, N + 2 + j] = -K * (Y[j] - B * sum_x_pow)

L = mat.LLL()
coeffs = None
for row in L:
    if all(row[N + 2 + j] == 0 for j in range(M)):
        if row[N + 1] == 1:
            coeffs = [row[i] + B for i in range(N + 1)]
            break
        if row[N + 1] == -1:
            coeffs = [-row[i] + B for i in range(N + 1)]
            break

assert coeffs is not None
assert all(sum(coeffs[i] * X[j] ** i for i in range(N + 1)) == Y[j]
           for j in range(M))

ep = sum(c * (0x65537 ** i) for i, c in enumerate(coeffs))
key = sha256(str(ep).encode()).digest()[:16]
print(key.hex())
# 再用 key + nonce 做 AES-CTR 解密 ct
```

案例解出的 key 为 `6ba291ac100d770ebe0fb1220f793fde`，AES-CTR 解密得到 `DASCTF{Y0u_r3@11y_Kn0w_what_your_3V@lu@t3_pO1ynOmi@1!}`。

## 变体与关联

- **有噪声求值**：若 `y_j = f(x_j) + noise`，后段不再严格为零；可将噪声界纳入格（近似公因子/Coppersmith 风格），或增大 K 并接受近似短向量，再用回代筛选。
- **系数范围未知**：B 未知时可以先估计系数上界，或用多个候选 B 跑 LLL；目标向量仍会出现“后段为零、常数 ±1”的特征。
- **模意义求值**：若 `y_j = f(x_j) mod p`，需要把等式改为 `f(x_j) - y_j - k_j p = 0`，把商 k_j 也作为未知量放入格。
- **多变量多项式**：把每个单项式作为一格坐标，构造多变量 Coppersmith/LLL；矩阵更大，但“系数小 + 求值约束”思路相同。
- **关联：LLL 短向量/隐藏数问题**。`ctf/crypto` 下已有 LLL hidden short vector、Kannan embedding、HNP 等卡；本卡是“多项式求值 + 小系数偏移”的具体构造。
- **关联：Coppersmith 小根**。两者都用格找短向量；Coppersmith 针对模未知因子的根，本卡针对精确求值下的系数向量。
- **防御/设计**：不要把密钥直接绑定到“小系数多项式在公开点的值”；使用 CSPRNG/HKDF 生成密钥；若必须用多项式承诺/评估，采用密码学安全的方案并避免泄露足够的精确求值。

## 检测与防御

- **CTF/审计特征**：题目给出多组 `(x, y)`、一个大次数、密钥由 `hash(str(poly(x)))` 派生；检查系数是否集中在某个偏移附近。
- **求解校验**：LLL 结果必须回代所有 `(x_j,y_j)`；只检查“后段为零”可能拿到伪向量。
- **参数选择**：矩阵中 K 要足够大以压制求值误差，但不能大到让 LLL 精度/规模失控；先小规模试跑，再逐步增大 N。
- **防御**：密钥派生使用 HKDF/PBKDF2 并加入随机 salt；不要公开多项式在秘密点的精确值；对公开求值点做盲化/加噪；避免使用可被格攻击的小系数结构。
- **监控**：在 CTF 之外，这类结构常见于白盒密码/混淆实现；若发现密钥由低熵多项式评估派生，应视为可恢复。
