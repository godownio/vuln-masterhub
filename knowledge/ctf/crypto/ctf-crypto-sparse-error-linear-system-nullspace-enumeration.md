---
id: ctf-crypto-sparse-error-linear-system-nullspace-enumeration
title: 稀疏错误线性系统：校验矩阵枚举 4 个错误位置并恢复单项式向量
type: scenario
domain: ctf
path: ctf/crypto
technique: sparse-error-linear-system-nullspace-enumeration
aliases:
- 稀疏错误
- 校验矩阵
- 错误位置枚举
- 单项式向量
- quadratic_vine
tags:
- ctf
- crypto
- linear-algebra
- sparse-error
- nullspace
- finite-field
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:50:29+08:00'
  notes: 已对照原文 quadratic_vine 一节核对：82 条记录/4 条错误、65 维单项式 m、A 为 82×65、H·A=0 的校验矩阵、枚举 4 支撑解 H_S·e_S=syndrome、修正后解 A·m 取前 10 项、layer-03 KDF 均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

当 `y = A·m + e (mod P)` 中 `e` 只有少量（本题 4 个）非零位置时，先求 `A` 的左零空间/校验矩阵 `H`（`H·A=0`），得到 `H·y=H·e`；枚举 `e` 的 4 个非零下标，用 `H` 的对应列解出错误值，修正 `y` 后再解 `A·m=y`，即可恢复单项式向量 `m`。

## 原理

- **问题形式**：服务端随机生成 10 维 `x`，构造 65 维单项式向量 `m=[x0..x9, x0², x0x1, ..., x9²] mod 65537`；82 条记录中只有 4 条的 `y_i` 被替换为随机值。即 `y=A·m+e`，`e` 是 4-稀疏错误向量。
- **校验矩阵消去未知数**：对 `A`（82×65）求左零空间 `H`（满足 `H·A=0`），则 `H·y=H·e`。这一步把“未知的 m”消掉，只剩错误向量。
- **稀疏错误枚举**：`e` 只有 4 个非零位置；枚举 4 个下标的组合 `C(82,4)` 较大，但可以用 `H` 的列构造小线性系统：对每个候选支撑 `S`，解 `H_S·e_S = H·y`（`|S|=4`，`H` 行数足够时唯一）。若解出的 4 个值都非零，则候选正确；否则继续。
- **修正与求解**：用 `e` 修正 `y' = y - e`，再解 `A·m=y'`；由于 `A` 列满秩，直接高斯消元得到 `m`，前 10 项就是 `x`。
- **派生密钥**：`raw=",".join(map(str,x))`，`key=sha256(b"layer-03:"+raw)`，HMAC-SHA256 计数器流与 `box` 异或得到 flag。
- **为什么成立**：线性系统的冗余（82 行 > 65 列）提供了 17 个校验方程；4 个稀疏错误只影响 4 个分量，校验方程足以定位并纠正。枚举的复杂度取决于错误数量，而不是整个向量空间。

## 触发条件

- 已知矩阵 `A`（82×65）、右端 `y`、模数 `P=65537`；错误数量 `e` 的上界已知（本题 4）。
- `A` 列满秩（或至少 `A` 的列空间秩足够），且 `H` 的行数 ≥ 错误数量。
- 错误位置是稀疏的，错误值在有限域内任意；没有其他结构性噪声。
- 能实现 GF(P) 上的 RREF/零空间与线性求解。

## 利用步骤

1. 读取 `trace` 的 82 条 `(row, y_i)`，构造矩阵 `A` 与向量 `y`。
2. 对 `A^T` 求零空间得到校验矩阵 `H`（`H·A=0`）；计算 `syndrome=H·y`。
3. 枚举错误数量 `weight=1..max_weight` 与支撑 `S`（本题 4）：取 `H` 的列 `H_S`，解 `H_S·e_S=syndrome`；若解存在且每个分量非零，则找到错误。
4. 用 `e` 修正 `y`，解 `A·m=y_corrected`；取前 `shape[0]=10` 项作为 `x`。
5. 按 `sha256(b"layer-03:"+raw)` 派生 HMAC-SHA256 流，异或 `box` 得到 flag；用 `flag{` 前缀验证。

## PoC

```python
import itertools

P = 65537

def rref(mat, ncols):
    a = [row[:] for row in mat]
    pivots, r = [], 0
    for c in range(ncols):
        pivot = next((i for i in range(r, len(a)) if a[i][c] % P), None)
        if pivot is None:
            continue
        a[r], a[pivot] = a[pivot], a[r]
        inv = pow(a[r][c], -1, P)
        a[r] = [(v * inv) % P for v in a[r]]
        for i in range(len(a)):
            if i != r and a[i][c] % P:
                f = a[i][c]
                a[i] = [(a[i][j] - f * a[r][j]) % P for j in range(ncols)]
        pivots.append(c)
        r += 1
    return a, pivots

def nullspace(mat, ncols):
    red, pivots = rref(mat, ncols)
    pivot_set = set(pivots)
    basis = []
    for f in range(ncols):
        if f in pivot_set:
            continue
        v = [0] * ncols
        v[f] = 1
        for row, pc in enumerate(pivots):
            v[pc] = (-red[row][f]) % P
        basis.append(v)
    return basis

def solve_tall(columns, target):
    rows, width = len(target), len(columns)
    a = [[columns[c][r] % P for c in range(width)] + [target[r] % P] for r in range(rows)]
    pivots, r = [], 0
    for c in range(width):
        pivot = next((i for i in range(r, rows) if a[i][c]), None)
        if pivot is None:
            continue
        a[r], a[pivot] = a[pivot], a[r]
        inv = pow(a[r][c], -1, P)
        a[r] = [(v * inv) % P for v in a[r]]
        for i in range(rows):
            if i != r and a[i][c]:
                f = a[i][c]
                a[i] = [(a[i][j] - f * a[r][j]) % P for j in range(width + 1)]
        pivots.append(c)
        r += 1
    for i in range(r, rows):
        if all(a[i][c] == 0 for c in range(width)) and a[i][width]:
            return None
    sol = [0] * width
    for row, c in enumerate(pivots):
        sol[c] = a[row][width]
    return sol

def decode_sparse_error(a, y, max_weight):
    at = [[a[row][col] for row in range(len(a))] for col in range(len(a[0]))]
    h = nullspace(at, len(a))
    syndrome = [sum(hrow[i] * y[i] for i in range(len(y))) % P for hrow in h]
    columns = [[hrow[i] for hrow in h] for i in range(len(y))]

    for weight in range(1, max_weight + 1):
        for support in itertools.combinations(range(len(y)), weight):
            sol = solve_tall([columns[i] for i in support], syndrome)
            if sol is not None and all(v % P for v in sol):
                return dict(zip(support, sol))
    raise RuntimeError("no sparse error")

# 读取 a, y 后：
bad = decode_sparse_error(a, y, 4)
corrected = y[:]
for idx, err in bad.items():
    corrected[idx] = (corrected[idx] - err) % P
m = solve_tall([[a[r][c] for r in range(len(a))] for c in range(len(a[0]))], corrected)
x = m[:10]
```

## 变体与关联

- **变体（错误数量未知）**：从小到大枚举 `weight`，用“解出的错误值非零 + 修正后方程一致”验证。
- **变体（错误值受限）**：若错误值来自小集合，可先枚举值再定位；或使用 Berlekamp-Welch/Reed-Solomon 解码。
- **变体（矩阵结构）**：`A` 可能是范德蒙/单项式矩阵，可利用结构快速求校验矩阵；本题直接对 `A^T` 求零空间。
- **关联卡片**：[[ctf-crypto-berlekamp-welch-rational-function-interpolation]]（带错误点插值）、[[ctf-crypto-simon-period-measurement-gf2-nullspace]]（GF(2) 零空间）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（格/线性代数）。
- **边界**：错误数超过校验冗余、`A` 列不满秩、错误值恰好为 0（与无错误不可区分）时枚举可能失败；需要更多记录/先验。

## 检测与防御

- **CTF 识别**：看到“82 条记录只有 4 条错误”“校验矩阵/零空间”，优先本卡；先求 `H` 再枚举稀疏错误。
- **密码设计**：不要用低冗余线性系统 + 稀疏错误作为安全编码；使用标准纠错码与足够校验位。
- **实现**：有限域 RREF 要处理主元选择、模逆与零行；枚举支撑时用 `H` 的列而不是原矩阵，规模更小。
