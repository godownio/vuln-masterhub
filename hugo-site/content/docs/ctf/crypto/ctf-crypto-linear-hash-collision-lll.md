---
id: ctf-crypto-linear-hash-collision-lll
title: 线性模哈希碰撞：把 Σ(2g)^{i-k}g·e_k≡0 mod N 转成 [E|R;0|N] 格，LLL 求短差分向量
type: scenario
domain: ctf
path: ctf/crypto
technique: linear-modular-hash-collision-lll
tags:
- crypto
- ctf
- lattice
- lll
- hash
- collision
- linear-hash
- modular
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:48:37+08:00'
  notes: 已对照原文与图02核对：构造、公式与原文一致；PoC 按原文重写未复跑。注意：AGCD 卡称原文实测恢复 p/q0/e0，但原文仅给脚本未展示运行输出；HNP PoC 沿用原文 matrix(ZZ) 赋 1/2^(l+1) 有理缩放，实际运行需改用 QQ 或等价整数缩放；原文无受影响版本，frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-linear-hash-collision-lll/
draft: false
kb_aliases:
- 线性哈希碰撞
- LLL 哈希碰撞
- 线性同余哈希
- 格攻击哈希
- n_{i+1}=g(2n_i+m_i)
- 短差分向量
---

## 一句话结论

哈希若按 `n_{i+1} = g·(2n_i + m_i) mod N` 迭代，展开后是消息字节的线性函数；两条消息 `s`、`t` 碰撞等价于 `Σ_k (2g)^{i-k}g·(s_k−t_k) ≡ 0 (mod N)`。把 `R=[(2g)^i g,…,(2g)^0g]`、单位阵 `E` 与 `N` 拼成格 `M=[[E,R],[0,N]]`，LLL 找到短向量 `(e_0,…,e_i,k)`，用 `e_k` 调整一条消息即可构造碰撞。

## 原理

- **展开迭代**：`n_{i+1}=(2g)^{i+1}n_0+Σ_{k=0}^i (2g)^{i-k}g·m_k mod N`；哈希输出再减去常量 `0xdeedbeef114514`，不影响碰撞条件。
- **碰撞条件**：两条消息 `s`、`t` 的哈希差为 `Σ_k (2g)^{i-k}g·(s_k−t_k) mod N`；要碰撞，需要这个和 `≡0 mod N`。令 `e_k=s_k−t_k`，就是找一个短向量 `e` 满足线性同余。
- **格构造**：令 `R` 为列向量 `[(2g)^i g, (2g)^{i-1} g, …, g]^T`，`E` 为 `msize×msize` 单位阵，构造
  ```text
  M = [ E   R
        0   N ]
  ```
  格中向量 `(e_0,…,e_i, k)`（`k` 为整数）满足 `e·R + k·N ≡ 0 mod N`，即碰撞条件。LLL 会找到短向量 `e`（消息差分）和对应的 `k`。
- **构造碰撞**：取一条消息 `s`（如全 `a`），另一条 `t=s−e`（逐字节减，注意字节范围/模 256）；由于 `e` 小，`t` 仍在合法字节范围内时即可得到碰撞对。
- **为什么成立**：线性哈希没有非线性混淆，碰撞问题退化为“找短整数向量满足一个模线性方程”；LLL 能在多项式时间找到短向量，从而构造碰撞。
- **参数**：消息长度 `msize`、`g`、`N`；`R` 的指数按消息长度取 `(2g)^i` 到 `(2g)^0`，方向不要反。

## 触发条件

- 哈希/校验函数是消息字节的线性/仿射函数（迭代式为 `n = a·n + b·m + c mod N` 等）。
- 已知 `g`、`N`、消息长度；需要构造两条不同消息但相同哈希值。
- 能运行 Sage/LLL；短向量 `e` 的每个分量落在可调整的字节范围内（或可通过多次尝试/加 Padding 调整）。
- 哈希没有强非线性/压缩函数（如 MD5/SHA 的 ARX/布尔混淆）。

## 利用步骤

1. 逆出哈希迭代式与常量：确认 `n_{i+1}=g(2n_i+m_i) mod N`，并展开成线性形式。
2. 取消息长度 `msize`，构造 `R=[(2g)^i g, …, (2g)^0 g]`（列向量，注意顺序），`E=identity_matrix(msize)`。
3. 构造 `M=block_matrix([[E,R],[0,matrix([N])]])`，LLL 约减。
4. 在约减基中找最后一维非零且向量分量较小的行 `X`；短向量给出 `e`（前 `msize` 个分量）与 `k`（最后一维）。
5. 取 `s`（如 `b'a'*msize`），令 `t=s−e`（逐字节，必要时模 256/加偏移），计算 `hash(s)` 与 `hash(t)` 验证相等。
6. 若 `t` 字节越界，调整 `s`、`msize`、`R` 顺序或换 LLL 基向量重试。

## PoC

```python
# Sage
msize = ...
R = [(2 * g) ** i * g for i in range(msize)]
R = column_matrix(R[::-1]) % N
E = identity_matrix(msize)
M = block_matrix([[E, R], [0, matrix([N])]])
X = M.LLL()

sbytes = b'a' * msize
print(sbytes, hash(sbytes))
tbytes = list(b'a' * msize)
for i in range(msize):
    tbytes[i] -= X[2][i]   # 取 LLL 约减基中的短差分向量
tbytes = bytes(tbytes)
print(tbytes, hash(tbytes))
```

原文用该构造得到相同哈希的两条不同字节流；未在本库复跑。

## 变体与关联

- **线性变体**：`n=a·n+b·m+c mod N`、多字节/多轮、带 XOR 的线性化；先展开成消息字节的线性组合。
- **格变体**：`[E|R;0|N]`、`[I|R;0|N]`、Kannan embedding；LLL/BKZ 找短向量。
- **哈希变体**：CRC/Adler32 等线性校验、多项式哈希、滚动哈希；非线性哈希（MD5/SHA）不适用。
- **关联卡片**：[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（LLL 短向量）、[[ctf-crypto-noise-crt-lattice-recovery]]（线性同余 + 格）。

## 检测与防御

- **哈希设计**：不要用线性/仿射模哈希做安全校验；使用 SHA-2/SHA-3/BLAKE 等带非线性压缩的哈希，或 HMAC。
- **参数**：若必须用滚动哈希，至少加入密钥化/非线性混淆，并限制消息长度/差分空间。
- **检测**：检查哈希实现是否为 `a*n+b*m+c mod N` 形式；对公开参数做 LLL 短向量探测，评估碰撞可行性。
