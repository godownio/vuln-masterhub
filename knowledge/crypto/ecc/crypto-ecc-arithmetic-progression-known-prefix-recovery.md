---
id: crypto-ecc-arithmetic-progression-known-prefix-recovery
title: ECC 等差点列 + 已知 flag 前缀：反推每字节乘数恢复明文
type: scenario
domain: crypto
path: crypto/ecc
technique: ecc-arithmetic-progression-known-prefix
aliases:
- ECC 已知前缀攻击
- 等差数列点列
- brainpoolP320r1
- m_i = a_i / x_i
- 椭圆曲线 CTF
tags:
- crypto
- ecc
- known-plaintext
- arithmetic-progression
- brainpool
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V214
  verified_at: '2026-11-07T04:21:11+08:00'
  notes: 已对照原文 ecn 段与 exp 核对：a_i=(n_i·P).x·m_i、Q_i=n_i·G 等差、flag{ 前缀、2^5 符号枚举求 X/K、逐字节 m_i 恢复与 flag 均一致；与现有 ECC 未知曲线卡非同一原语。未在本机执行 exp。
---

## 一句话结论

当题目给出 `a_i = (n_i·P).x · m_i mod p` 和点 `Q_i = n_i·G`，其中 `n_i` 是等差数列、`m_i` 是 flag 的每个字节时，利用已知前缀 `flag{` 可解出前 5 个 `(d·Q_i).x`，再按“点列仍为等差数列”恢复 `d·Q_0` 与步长 `d·H`，即可对每个 i 计算 `m_i = a_i · (d·Q_i).x^{-1} mod p`，还原完整 flag。

## 原理

- 题目结构：`a_i = (n_i · P).x * m_i mod p`；同时给出 `Q_i = n_i · G` 的坐标；`P = d·G` 是公钥，`n_i = start + i·step` 是等差数列，`m_i` 为 flag 字节。
- 因为 `n_i·P = n_i·(d·G) = d·(n_i·G) = d·Q_i`，所以 `(n_i·P).x = (d·Q_i).x`。
- 已知 flag 前缀（如 `flag{`）时，前 5 个 `m_i` 已知，可算出 `T_i = a_i · m_i^{-1} mod p = (d·Q_i).x`。
- `Q_i = Q_0 + i·H`（H = step·G）是等差数列；乘以标量 d 后 `d·Q_i = d·Q_0 + i·(d·H)` 仍是等差数列。每个 x 坐标对应两个可能的 y（±y），对前 5 个 T_i 枚举 `2^5` 种符号组合，找出满足“相邻差相同”的点列，即得 `X = d·Q_0` 与 `K = d·H`。
- 之后对任意 i，`R_i = X + i·K = d·Q_i`，其 x 坐标已知；`m_i = a_i · R_i.x^{-1} mod p`，若结果在 0–255 即为明文字节；逐字节恢复 flag。

## 触发条件

- 曲线参数已知（文章为 `brainpoolP320r1`，p、q、G、a、b 已知）。
- 给出至少 5 组 `(a_i, x_i, y_i)`，且 flag 前缀已知（`flag{` 5 字节）。
- `n_i` 为等差数列，`m_i` 为小整数（flag 字节），保证 `m_i` 在模 p 下可逆。
- p 满足可开平方（文章 p ≡ 3 mod 4，用 `(p+1)//4` 求 y），且 `a_i` 非零。

## 利用步骤

1. 解析 `output.txt` 的 `(a, x, y)` 列表，构造 `Q_i = Point(x,y)`。
2. 用已知前缀 `flag{` 计算 `T_i = a_i * pow(m_i, -1, p) % p`（i=0..4）。
3. 对每个 `T_i` 解 `y^2 = x^3 + a*x + b mod p` 得到两个候选点（±y）。
4. 枚举 `2^5` 种组合，检查相邻点差 `Q_i - Q_{i-1}` 是否全部相同；找到 `X` 与 `K`。
5. 对 i=5..len-1 计算 `R_i = X + i*K`，`m_i = a_i * pow(R_i.x, -1, p) % p`，转成字符拼接。
6. 验证 flag 格式/可打印性。

## PoC

文章 exp 关键代码：

```python
from fastecdsa.curve import brainpoolP320r1
from fastecdsa.point import Point
from itertools import product
import ast

curve = brainpoolP320r1
p, G = curve.p, curve.G
data = ast.literal_eval(open('output.txt').read())
known = [ord(c) for c in "flag{"]

T = []
for i in range(5):
    a_val, x, y = data[i]
    T.append((a_val * pow(known[i], -1, p)) % p)

def points_with_x(x):
    y2 = (x**3 + curve.a * x + curve.b) % p
    y = pow(y2, (p + 1) // 4, p)
    return [Point(x, y, curve=curve), Point(x, (-y) % p, curve=curve)]

for combo in product(*[points_with_x(t) for t in T]):
    diffs = [combo[i] - combo[i-1] for i in range(1, 5)]
    if all(d == diffs[0] for d in diffs):
        X, K = combo[0], diffs[0]
        break

flag = "flag{"
for i in range(5, len(data)):
    a_val, x, y = data[i]
    R = X + i * K
    m = (a_val * pow(R.x, -1, p)) % p
    flag += chr(m) if 0 <= m <= 255 else "?"
print(flag)
```

## 变体与关联

- 变体：前缀未知但格式可猜（`flag{`、`ctf{`、`DASCTF{`）；可用前 1–2 字节先试，或枚举常见前缀。
- 变体：`n_i` 为等比/多项式序列时，`d·Q_i` 也保持同样线性关系，可推广为“点列线性关系 + 已知前缀”。
- 变体：只给 x 坐标时，需处理 ±y 的符号歧义；用多组点的一致性筛选。
- 关联：[[crypto-ecc-unknown-curve-point-halving-recover-flag]]、[[crypto-ecc-unknown-curve-projective-cubic-fit-weierstrass-dlp]]（未知曲线参数恢复）。
- 边界：flag 前缀未知、`a_i` 为 0、`m_i` 不是小整数、点列不满足等差关系时，该攻击不成立。

## 检测与防御

- 检测：CTF/审计中看到“每字节乘数 + 点坐标 + 等差 n”的 ECC 题，即可尝试已知前缀攻击。
- 防御：不要把明文逐字节乘到点坐标上；使用标准 ECIES/ECDH + KDF + AEAD；对明文做填充/随机化。
- 加固：避免泄露同一私钥下等差数列倍点的坐标；对侧信道/已知明文攻击做盲化。
