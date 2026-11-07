---
id: ctf-crypto-ring-convolution-linear-system-sparse-vector
title: 环卷积线性系统恢复稀疏向量：F_65537[x]/(x^70+1) 上的 NTRU 类方程
type: scenario
domain: ctf
path: ctf/crypto
technique: ring-convolution-linear-system-sparse-vector
tags:
- ctf
- crypto
- ntru
- convolution
- linear-algebra
- sparse-vector
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:50:31+08:00'
  notes: 已对照原文 ntru_ghost 一节核对：F_65537[x]/(x^70+1)、卷积规则 k=i+j 越界减 N 取负、A·s=v 的 70×70 线性系统、s∈{0,±1} 分组每组一个非零、path 以 i:s 拼接、layer-02 KDF 均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-ring-convolution-linear-system-sparse-vector/
draft: false
kb_aliases:
- NTRU 线性化
- 环卷积
- 稀疏向量恢复
- x^70+1
- 系数矩阵求解
---

## 一句话结论

当服务端在环 `F_65537[x]/(x^70+1)` 上给出 `a` 与 `v=a·s`，且 `s` 是 0/±1 的稀疏向量时，可以把每个 `s[j]` 对输出的贡献写成矩阵的一列，构造 `A·s=v (mod 65537)` 并解线性系统，从而恢复 `s`；本题再按分组取每组唯一非零项得到 `path`，派生密钥解密 flag。

## 原理

- **环乘法**：卷积规则 `k=i+j; if k>=N: k-=N, sign=-1; out[k]+=sign*a[i]*s[j]` 等价于在 `R=F_P[x]/(x^N+1)` 中计算 `v=a·s`（`x^N=-1`）。
- **线性化**：固定 `a` 时，映射 `s ↦ a·s` 是线性的。对每个 `j`，把 `s[j]=1` 时的输出向量作为矩阵 `A` 的第 `j` 列；则 `A·s=v mod P`。`s` 的每个分量是 0/±1，但线性系统不依赖稀疏性，直接解出唯一向量。
- **稀疏/分组约束**：本题 `s` 的取值只有 0、1、-1（`P-1`），且按 `shape=[groups,width]` 分组，每组恰好一个非零项；解出 `s` 后按组检查，得到 `path=[(index, sign)]`。
- **派生密钥**：`raw=",".join(f"{i}:{s}" for i,s in path)`，`key=sha256(b"layer-02:"+raw)`，HMAC-SHA256 计数器流与 `box` 异或得到 flag。
- **为什么成立**：环乘法的线性性 + 足够多的输出分量（70 个方程、70 个未知数）使 `A` 可逆或列满秩；`s` 的稀疏性只是用来校验/分组，不是求解必需。
- **边界**：如果 `a` 与 `x^N+1` 不互素，`A` 可能奇异；需要更多样本/不同 `a`。本题 `a` 随机，矩阵通常可逆。

## 触发条件

- 已知环参数 `N`、模数 `P`、`a` 与 `v=a·s`；`s` 维度为 `N`。
- `A` 列满秩（或至少解唯一）；`P` 为素数，元素可求逆。
- `s` 的取值/分组约束已知（本题 0/±1、每组一个非零），用于校验和恢复 `path`。
- 能实现 GF(P) 高斯消元/矩阵求逆。

## 利用步骤

1. 读取 `u`（即 `a`）、`v`、`shape=[groups,width]`，确认 `N=len(a)=70`、`P=65537`。
2. 构造 `A`：对每个 `j`，模拟 `s[j]=1`、其余为 0 的卷积，得到列向量；注意 `k>=N` 时减 `N` 且符号取负。
3. 解 `A·s=v mod P`（高斯消元/矩阵求逆）；检查每个分量是否为 0/1/P-1。
4. 按 `groups/width` 分组，每组应恰好一个非零；记录 `(index, +1/-1)` 组成 `path`。
5. 用 `sha256(b"layer-02:"+raw)` 派生 HMAC-SHA256 流，异或 `box` 得到 flag。
6. 用 `flag{` 前缀/可打印性验证。

## PoC

```python
P = 65537
N = 70

def conv_matrix(a):
    A = [[0] * N for _ in range(N)]
    for j in range(N):
        for i, x in enumerate(a):
            k = i + j
            sign = 1
            if k >= N:
                k -= N
                sign = -1
            A[k][j] = (sign * x) % P
    return A

def solve_linear_mod(A, b, p=P):
    n = len(b)
    M = [[A[i][j] % p for j in range(n)] + [b[i] % p] for i in range(n)]
    row, pivots = 0, []
    for col in range(n):
        pivot = next((r for r in range(row, n) if M[r][col] % p), None)
        if pivot is None:
            continue
        M[row], M[pivot] = M[pivot], M[row]
        inv = pow(M[row][col], -1, p)
        M[row] = [(x * inv) % p for x in M[row]]
        for r in range(n):
            if r != row and M[r][col] % p:
                f = M[r][col] % p
                M[r] = [(M[r][c] - f * M[row][c]) % p for c in range(n + 1)]
        pivots.append(col)
        row += 1
        if row == n:
            break
    if len(pivots) != n:
        raise RuntimeError("singular matrix")
    x = [0] * n
    for r, col in enumerate(pivots):
        x[col] = M[r][-1] % p
    return x

s = solve_linear_mod(conv_matrix(u), v)

path = []
_, groups, width = shape
for g in range(groups):
    picked = []
    for i in range(g * width, (g + 1) * width):
        if s[i] == 1:
            picked.append((i, 1))
        elif s[i] == P - 1:
            picked.append((i, -1))
    assert len(picked) == 1
    path.append(picked[0])
```

## 变体与关联

- **变体（NTRU 真实参数）**：大 `N`/大 `q` 时矩阵求逆不可行，需要格攻击/理想格结构；本题是玩具参数。
- **变体（稀疏性利用）**：若 `N` 很大但 `s` 极稀疏，可用压缩感知/格方法而不是满矩阵。
- **变体（多组 a,v）**：多个样本可联立提高秩/恢复不同密钥。
- **关联卡片**：[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（格方法解 LWE）、[[ctf-crypto-sparse-error-linear-system-nullspace-enumeration]]（稀疏错误线性系统）、[[crypto-implementation-dirichlet-convolution-parameter-inversion]]（卷积参数反演）。
- **边界**：`A` 奇异、`P` 非素数、`s` 分量超出 0/±1 时需调整；大参数下高斯消元复杂度 `O(N^3)`。

## 检测与防御

- **CTF 识别**：看到 `x^N+1`、卷积规则、`a` 与 `a*s`、稀疏 0/±1 向量，优先线性化求逆。
- **密码设计**：NTRU 类方案的安全依赖大维数/格困难性；玩具参数（N=70, q=65537）可被线性代数直接攻破。
- **实现**：卷积矩阵构造注意 `x^N=-1` 的符号；高斯消元要处理奇异与模逆。
