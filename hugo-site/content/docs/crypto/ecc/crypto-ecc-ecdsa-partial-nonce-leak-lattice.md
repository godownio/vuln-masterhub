---
id: crypto-ecc-ecdsa-partial-nonce-leak-lattice
title: ECDSA 部分 nonce 泄露：k=h+l 线性关系用 LLL/CVP 恢复私钥
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdsa-partial-nonce-lattice
tags:
- ecdsa
- ecc
- lattice
- lll
- cvp
- hnp
- nonce-leak
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:43:51+08:00'
  notes: 已对照原文核对：公式、PoC 与原文一致；原文无受影响版本，frontmatter 无 sources/source_url；PoC 未本机复跑。
url: /docs/crypto/ecc/crypto-ecc-ecdsa-partial-nonce-leak-lattice/
draft: false
kb_aliases:
- ECDSA 部分 k 泄露
- k 高位已知
- 隐藏数问题 HNP
- LLL 恢复私钥
- CVP ECDSA
- 线性关系 nonce
---

## 一句话结论

若多个 ECDSA 签名的 `k_i` 只有低 `X` 位未知（`k_i = h_i + l_i`、`0 <= l_i < X`），或 `k_i` 之间存在已知线性关系，可把 `s_i = k_i^{-1}(e_i + d*r_i)` 改写为 `t_i*d + u_i ≡ -l_i (mod n)`，构造 `diag(n,...,n)` + `t` 行 + `u` 行的格，用 LLL/CVP 求出短向量，从最后一位恢复私钥 `d`。

## 原理

- ECDSA：`s_i = k_i^{-1}(e_i + d*r_i) mod n`，等价于 `k_i = e_i*s_i^{-1} + d*r_i*s_i^{-1} mod n`。
- 记 `T_i = r_i*s_i^{-1} mod n`、`A_i = e_i*s_i^{-1} mod n`，则 `k_i = A_i + d*T_i mod n`。
- 若 `k_i = h_i + l_i`，`l_i < X`，则 `l_i = A_i + d*T_i - h_i - y_i*n`（某个整数 `y_i`）。把 `u_i = A_i - h_i` 记入，得到 `u_i + d*T_i ≡ l_i (mod n)`。
- 构造 `(m+2) x (m+2)` 格：前 `m` 行 `diag(n)`，第 `m` 行前 `m` 列为 `T_i`，第 `m+1` 行前 `m` 列为 `u_i`；右下角分别为 `X/n` 与 `X`。
- 格中存在短向量，其前 `m` 个坐标对应 `l_i`（或带符号），最后坐标与 `d` 相关；LLL 后按 `d ≈ row[m]*n/X` 提取候选，验证所有 `l_i` 是否落在 `[0,X)`。
- 若 `k_i` 之间是线性关系（`k_i = a_i*k_0 + b_i`），可先消元把未知量减少到一个，再用同样的格/HNP。

## 触发条件

- 多个 ECDSA 签名使用同一私钥，且每个 `k_i` 的未知部分 `l_i` 有共同上界 `X`（如低 128 位未知）。
- 已知每个 `k_i` 的已知部分 `h_i` 或线性关系；消息哈希与签名可获取。
- `X` 相对 `n` 足够小，格维数/样本数足够（通常 3 个以上签名即可尝试）。
- 有 LLL/BKZ/CVP 工具（Sage/fpylll）。

## 利用步骤

1. 收集 `m` 组 `(r_i,s_i,e_i,h_i)`，确认 `k_i = h_i + l_i`、`l_i < X`。
2. 计算 `T_i = r_i*s_i^{-1} mod n`、`u_i = e_i*s_i^{-1} - h_i mod n`。
3. 按上述构造 `(m+2)x(m+2)` 格，设置 `X` 与 `X/n`。
4. LLL/BKZ 约减，检查短向量；从最后坐标提取 `d` 候选（注意符号/取模）。
5. 用候选 `d` 计算 `k_i = (A_i + d*T_i) mod n`，检查是否都 `< X`；若失败，增加样本/调整 `X`/换向量。
6. 用 `d*G == Q` 或伪造签名验证私钥。

## PoC

```python
# Sage
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
X = 2**128
sigs = [{"r": ..., "s": ..., "e": ..., "h": ...}, ...]
m = len(sigs)
M = Matrix(QQ, m + 2, m + 2)
for i, sig in enumerate(sigs):
    s_inv = pow(sig["s"], -1, n)
    t = (sig["r"] * s_inv) % n
    u = (sig["e"] * s_inv - sig["h"]) % n
    M[i, i] = n
    M[m, i] = t
    M[m + 1, i] = u
M[m, m] = X / n
M[m + 1, m + 1] = X
M_lll = M.LLL()
for row in M_lll:
    d = abs(int(row[m] * n / X))
    if 0 < d < n:
        ks = [(sigs[i]["e"] * pow(sigs[i]["s"], -1, n) + d * sigs[i]["r"] * pow(sigs[i]["s"], -1, n)) % n for i in range(m)]
        if all(0 <= k < X for k in ks):
            print("d =", d)
            break
```

## 变体与关联

- 变体：`k_i` 之间满足 `k_i = a_i*k_0 + b_i` 时，先代入消元，再按单未知量 HNP 构造格。
- 变体：未知部分是高位而非低位时，把 `h_i` 与 `l_i` 的角色互换，等式仍成立。
- 变体：样本带噪声/部分位错误时，用 CVP/BKZ 或枚举异常样本剔除。
- 关联：[[crypto-ecc-ecdsa-time-side-channel-hnp]]（时间侧信道 HNP）、[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]（完全复用）、[[crypto-prng-truncated-lcg-coppersmith-lattice-cvp]]（格/CVP 方法）。

## 检测与防御

- 防御：使用 RFC6979/CSPRNG 生成 full-size nonce，不要截断/复用；签名实现不要泄露 `k` 的高位/低位。
- 防御：对签名接口做速率限制，避免攻击者收集大量样本；使用 HSM 保护私钥与 nonce。
- 检测：签名日志中出现 `k` 的部分位、固定高位、线性关系；大量签名样本被收集。
- 响应：发现 nonce 泄露后立即轮换私钥，审计历史签名是否可恢复，修复随机数生成。
