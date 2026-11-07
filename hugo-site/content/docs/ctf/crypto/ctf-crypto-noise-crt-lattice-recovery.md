---
id: ctf-crypto-noise-crt-lattice-recovery
title: Noise CRT：带噪 CRT 余数用 Pi·inv(Pi) 系数与 2^nbits 对角构造格恢复 N
type: scenario
domain: ctf
path: ctf/crypto
technique: noise-crt-lattice-recovery
tags:
- crypto
- ctf
- lattice
- crt
- lll
- flatter
- noise
- hidden-number
severity: info
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:48:34+08:00'
  notes: 已对照原文与图02核对：构造、公式与原文一致；PoC 按原文重写未复跑。注意：AGCD 卡称原文实测恢复 p/q0/e0，但原文仅给脚本未展示运行输出；HNP PoC 沿用原文 matrix(ZZ) 赋 1/2^(l+1) 有理缩放，实际运行需改用 QQ 或等价整数缩放；原文无受影响版本，frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-noise-crt-lattice-recovery/
draft: false
kb_aliases:
- Noise CRT
- 噪声 CRT
- 带噪中国剩余定理
- CRT 余数格攻击
- flatter CRT
- N_j mod p_i
---

## 一句话结论

当题目给出多个模数 `p_i` 下 `N_j` 的带噪余数（矩阵 `A[i][j] = N_j mod p_i`）时，用 CRT 系数 `T_i = S[i][j]·(P/p_i)·inv(P/p_i mod p_i)` 把各余数组合起来，再以 `P` 和 `2^{nbits}` 对角构造格 `M = [[P,0],[T,B]]`，用 LLL/flatter 找到短向量剥离噪声，即可恢复 `N`（`N` 的位数为 `nbits`）。

## 原理

- **无噪 CRT**：若 `S[i][j]` 是 `N_j mod p_i` 且无误差，则 `N_j = Σ_i S[i][j]·P_i·inv(P_i mod p_i) mod P`，其中 `P=∏ p_i`、`P_i=P/p_i`；这是标准 CRT 重构。
- **带噪情形**：每个余数带小噪声 `e_{i,j}`，直接 CRT 重构会得到 `N_j + 噪声组合`；噪声经 CRT 系数放大后可能仍远小于 `P`，因此可以把“找 `N_j`”转成“在格中找接近 CRT 组合的短向量”。
- **格构造**：按列 `j` 计算 `T_i = S[i][j]·P_i·inv(P_i,p_i)`，组成列向量 `T`；令 `B = diag(2^{nbits})`，构造
  ```text
  M = [ P    0
        T    B ]
  ```
  其中 `P` 是 CRT 模数，`2^{nbits}` 是 `N` 的位数量级缩放。对 `M` 做 LLL/flatter 约减，短向量对应噪声/误差，从中恢复 `N_j`。
- **参数**：`m` 为模数个数/轮数，`nbits` 为 `N` 的位数；`P` 必须大于 `N`，`2^{nbits}` 的缩放要与 `N` 的量级匹配；噪声不能大到淹没 `N`。
- **为什么用 flatter**：flatter 是 LLL 的高效实现/改进，适合这种高维、系数巨大的 CRT 格；Sage 的 `M.LLL()` 也可，但可能较慢/需要调参。
- **与 HNP 的关系**：Noise CRT 可看作“CRT 域上的隐藏数问题”；都是把带噪线性关系转成格中短向量。

## 触发条件

- 题目给出多个模数 `p_i` 与 `N_j` 的余数矩阵，余数带小噪声。
- `P=∏ p_i` 大于 `N`，`N` 的位数 `nbits` 已知或可估；模数个数 `m`/列数 `n` 足够。
- 能运行 Sage + flatter/LLL；参数（`2^{nbits}`、行/列排列）可调。
- 噪声相对 `P` 足够小，短向量能与其他格向量区分。

## 利用步骤

1. 读取模数列表 `p`、余数矩阵 `S`（`m` 行、`n` 列），确定 `nbits`。
2. 计算 `P=∏ p_i`；对每个 `i`，`P_i=P/p_i`、`invPi=inv(P_i mod p_i, p_i)`；按列 `j` 生成 `T_i = S[i][j]*P_i*invPi`。
3. 组装 `T=column_matrix(Ti)`、`B=diagonal_matrix([2^nbits]*len(Ti))`、`M=block_matrix([[matrix([P]),0],[T,B]])`。
4. 用 flatter（或 LLL/BKZ）约减 `M`；检查短向量，提取 `N_j` 的候选。
5. 用原始余数验证 `N_j mod p_i` 与 `S[i][j]` 的差是否等于小噪声；成功则输出 `N`。
6. 若失败，调整 `2^nbits` 的指数、增加模数/列数、换 flatter 参数或 BKZ。

## PoC

```python
m = 15       # 模数个数/轮数
nbits = 3211 # N 的位数
P = prod(p)

Ti = []
for i, pi in enumerate(p):
    Pi = P // pi
    invPi = inverse_mod(Pi, pi)
    Ti.extend(S[i][j] * Pi * invPi for j in range(m))

T = column_matrix(Ti)
B = diagonal_matrix([2 ** nbits] * len(Ti))
M = block_matrix([[matrix([P]), 0], [T, B]])

def flatter(M):
    from subprocess import check_output
    import re
    inputM = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    outputM = check_output(["flatter"], input=inputM.encode())
    return matrix(M.nrows(), M.ncols(), map(int, re.findall(rb"-?\d+", outputM)))

flatter(M)
```

原文用该构造恢复 `N`；未在本库复跑。

## 变体与关联

- **无噪 CRT**：直接 CRT 重构，不需要格；只有噪声存在时才需要格。
- **HNP 变体**：`αt_i ≡ u_i+e_i mod p` 用 `pI` + `t` 行构造格，与 Noise CRT 同属“带噪线性关系”。
- **AGCD 变体**：`x_i=pq_i+e_i` 用 SDA/OL 格，同样是把噪声从主项剥离。
- **关联卡片**：[[ctf-crypto-hnp-msb-oracle-babai-nearest-plane]]（HNP/Babai）、[[ctf-crypto-agcd-sda-lattice-small-error-recovery]]（AGCD/SDA）、[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（LLL/Kannan embedding）。

## 检测与防御

- **参数选择**：CRT 模数个数/噪声/`N` 位数要满足格攻击不可行；不要让 `P` 远大于 `N` 且噪声过小。
- **密码设计**：不要把带噪 CRT 当作安全假设；需要时使用经过分析的 LWE/RLWE 或带认证的编码。
- **检测**：对公开的 CRT 余数做 LLL/flatter 短向量探测；评估 `m`、`nbits`、噪声界是否落入攻击范围。
