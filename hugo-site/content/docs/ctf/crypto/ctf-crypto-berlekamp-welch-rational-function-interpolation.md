---
id: ctf-crypto-berlekamp-welch-rational-function-interpolation
title: Berlekamp-Welch 有理函数插值：从带 30 个噪声点的 98 个样本恢复分子分母
type: scenario
domain: ctf
path: ctf/crypto
technique: berlekamp-welch-rational-function-interpolation
tags:
- ctf
- crypto
- interpolation
- berlekamp-welch
- error-correction
- finite-field
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:50:27+08:00'
  notes: 已对照原文 rational_echo 一节核对：98 点/68 真点/30 噪声、shape=[13,12,30]、N=up·E（43 次）/D=down·E（42 次）、86 未知数 98 方程、gcd 去 E、layer-01 KDF 与解密均一致；01.png 与 02.png 为八卦题与合川斜影（不在本卡范围）。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-berlekamp-welch-rational-function-interpolation/
draft: false
kb_aliases:
- Berlekamp-Welch
- 有理函数插值
- 带错误点插值
- 错误定位多项式
- 噪声点恢复
---

## 一句话结论

当 98 个有限域样本中只有 68 个来自同一个有理函数 `y=up(x)/down(x)`、另外 30 个是随机噪声点时，可以设错误定位多项式 `E(x)` 在所有噪声横坐标处为零，构造 `N=up·E`、`D=down·E`，把“找噪声点”转成线性方程组 `N(x_i)=y_i·D(x_i)`；解出 `N/D` 后取 gcd 去掉 `E`，即可恢复原始 `up/down`。

## 原理

- **有理函数插值**：目标是恢复 `y = up(x)/down(x) mod P`，其中 `deg(up)≤13`、`deg(down)=12` 且最高次系数为 1。无噪声时 26 个点就够；本题有 30 个随机噪声点，直接插值会被带偏。
- **错误定位多项式**：设 `E(x)` 的次数为 30（等于噪声点数量），且在所有噪声点的 `x_i` 处取 0。定义 `N(x)=up(x)·E(x)`（次数 43）、`D(x)=down(x)·E(x)`（次数 42，最高次仍为 1）。
- **关键等式**：对任意给出的点 `(x_i,y_i)`：
  - 真点：`y_i=up(x_i)/down(x_i)`，两边乘 `down·E` 后 `N(x_i)=y_i·D(x_i)`；
  - 噪声点：`E(x_i)=0`，两边都为 0，等式仍成立。
  因此**所有** 98 个点都满足同一个线性方程，不需要先知道哪些是噪声。
- **解线性系统**：未知数是 `N` 的 44 个系数与 `D` 的 42 个低次系数（最高次固定为 1），共 86 个未知数；98 个点给出 98 个方程，超定但一致，解出 `N,D`。
- **去掉 E**：`N` 与 `D` 的公共因子就是 `E`（以及可能的其他公共因子），对 `N,D` 做多项式 gcd，再分别除以 gcd，得到 `up,down`；`vec = up + down[:-1]` 派生密钥解密 flag。
- **为什么成立**：错误定位多项式把“噪声点不满足有理函数”变成“噪声点使两边同时为零”，从而把非线性/组合问题转成线性代数；噪声数量必须小于等于冗余方程能容忍的上限（本题 30 个噪声、98 个点、86 个未知数，刚好可解）。

## 触发条件

- 有限域 `P`（本题 65537）上的样本点，真点来自同一个有理函数，噪声点数量已知/可估。
- 分子/分母的次数上界已知（本题 13/12），分母最高次系数固定（可消去整体倍数）。
- 样本数量 > 未知数数量（本题 98 > 86），保证线性系统可解。
- 有有限域多项式运算（加减乘除、gcd）与高斯消元实现。

## 利用步骤

1. 读取 `trace` 的 98 个 `(x,y)`、`shape=[13,12,30]`；确认噪声数 `EXTRA=30`。
2. 设 `num_deg=13+30=43`、`den_deg=12+30=42`；未知数为 `D` 的低 42 个系数 + `N` 的 44 个系数。
3. 对每个点构造方程 `Σ N_j x^j - y·Σ D_j x^j = y·x^den_deg`（`D` 最高次系数为 1，移项到右边）。
4. 高斯消元解出 `D`（补最高次 1）与 `N`。
5. 对 `N,D` 做多项式 gcd，分别除以 gcd 得到 `up,down`；验证 `deg` 与 `down` 首项。
6. `vec=up+down[:-1]`，按题目 KDF（`sha256(b"layer-01:"+raw)` + HMAC-SHA256 流）解密 `box`，得到 flag。

## PoC

```python
P = 65537
DN, DD, EXTRA = 13, 12, 30

def trim(poly):
    while len(poly) > 1 and poly[-1] % P == 0:
        poly.pop()
    return [c % P for c in poly]

def poly_divmod(a, b):
    a, b = trim(a[:]), trim(b[:])
    q = [0] * max(1, len(a) - len(b) + 1)
    ib = pow(b[-1], -1, P)
    while len(a) >= len(b) and a != [0]:
        shift = len(a) - len(b)
        coef = a[-1] * ib % P
        q[shift] = coef
        for i in range(len(b)):
            a[shift + i] = (a[shift + i] - coef * b[i]) % P
        trim(a)
    return trim(q), trim(a)

def poly_gcd(a, b):
    while trim(b[:]) != [0]:
        _, r = poly_divmod(a, b)
        a, b = b, r
    inv = pow(a[-1], -1, P)
    return [(c * inv) % P for c in a]

def solve_linear(rows, rhs, nvars):
    aug = [r[:] + [b % P] for r, b in zip(rows, rhs)]
    where = [-1] * nvars
    row = 0
    for col in range(nvars):
        pivot = next((r for r in range(row, len(aug)) if aug[r][col] % P), None)
        if pivot is None:
            continue
        aug[row], aug[pivot] = aug[pivot], aug[row]
        scale = pow(aug[row][col], -1, P)
        aug[row] = [(v * scale) % P for v in aug[row]]
        for r in range(len(aug)):
            if r != row and aug[r][col] % P:
                f = aug[r][col]
                aug[r] = [(a - f * b) % P for a, b in zip(aug[r], aug[row])]
        where[col] = row
        row += 1
    sol = [0] * nvars
    for c, r in enumerate(where):
        if r != -1:
            sol[c] = aug[r][-1] % P
    return sol

num_deg, den_deg = DN + EXTRA, DD + EXTRA
rows, rhs = [], []
for x, y in trace:
    xp = [1]
    for _ in range(max(num_deg, den_deg)):
        xp.append(xp[-1] * x % P)
    row = [y * xp[j] % P for j in range(den_deg)]
    row += [(-xp[j]) % P for j in range(num_deg + 1)]
    rows.append(row)
    rhs.append((-y * xp[den_deg]) % P)

sol = solve_linear(rows, rhs, den_deg + num_deg + 1)
d = sol[:den_deg] + [1]
n = sol[den_deg:]

g = poly_gcd(n, d)
up, _ = poly_divmod(n, g)
down, _ = poly_divmod(d, g)
vec = trim(up) + trim(down)[:-1]
```

## 变体与关联

- **变体（噪声数量未知）**：从小到大尝试 `EXTRA`，用解出的 `up/down` 验证真点数量/多项式次数；或使用 Welch-Berlekamp 的迭代版本。
- **变体（多项式而非有理函数）**：`down=1` 时退化为带错误点的多项式插值；Reed-Solomon 解码同理。
- **变体（有限域/次数）**：模数、分子/分母次数、噪声数可替换；未知数数量必须 ≤ 样本数。
- **关联卡片**：[[crypto-rsa-multiprime-partial-key-coppersmith]]（Coppersmith 格）、[[ctf-crypto-simon-period-measurement-gf2-nullspace]]（GF(2) 线性代数）、[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（格方法）。
- **边界**：噪声数超过可纠错界、分母最高次不固定、样本不足时线性系统无唯一解；有限域运算需保证 `P` 为素数/可逆。

## 检测与防御

- **CTF 识别**：题目给“98 个点、其中 30 个噪声、分子 13 次/分母 12 次”，优先 Berlekamp-Welch；先构造错误定位多项式。
- **密码设计**：不要用低次数有理函数 + 少量噪声点作为秘密共享/编码；使用标准 Reed-Solomon/纠错码与足够冗余。
- **实现**：有限域多项式 gcd/高斯消元要处理零多项式、首一化与模逆；解出后必须验证所有真点与次数。
