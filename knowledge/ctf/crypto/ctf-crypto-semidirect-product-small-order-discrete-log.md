---
id: ctf-crypto-semidirect-product-small-order-discrete-log
title: 半直积群小阶共轭元：枚举 c 的阶后用 BSGS 解离散对数
type: scenario
domain: ctf
path: ctf/crypto
technique: semidirect-product-small-order-bsgs
aliases:
- sporadiclogarithms
- 半直积离散对数
- 共轭作用离散对数
- 小阶 c BSGS
tags:
- ctf
- crypto
- group-theory
- semidirect-product
- discrete-log
- bsgs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:22+08:00'
  notes: 已对照原文 sporadiclogarithms 段核对：phi(a)=cac^-1、半直积 (gc)^x=h c^x、ord(c)≤8 枚举 r、化为 (a^m)^t=(h c^r)a^-r 后 BSGS、BOUND=262144 均一致；未连远端复跑。
---

## 一句话结论

要求解 `h = g·φ(g)·φ²(g)···φ^{x-1}(g)`（`φ(a)=cac^{-1}`）时，可把 `(g,c)` 放进半直积：`(gc)^x = h·c^x`；当 `c` 的阶 `m` 很小（≤8）时，枚举 `r = x mod m`，令 `a=gc`，把方程化为 `(a^m)^t = (h c^r) a^{-r}`，再用 BSGS 求 `t`，即可在少量黑盒查询内得到 `x`。

## 原理

- 半直积中 `(g,c)^2 = g(cgc^{-1})c^2 = gφ(g)c^2`，归纳得 `(gc)^x = s_{g,φ}(x)·c^x = h·c^x`。
- 设 `a=gc`，则 `a^x = h c^x`；右边也含 `x`，不能直接做普通离散对数。
- 设 `m=ord(c)`、`x=r+mt`，因 `c^m=1` 有 `c^x=c^r`；两边右乘 `a^{-r}` 得 `(a^m)^t = (h c^r) a^{-r}`。
- 对每个 `r∈[0,m)`，右边是已知群元素，左边底数为 `a^m`，转化为求 `t` 的离散对数；`t` 的范围约 `BOUND/m`，用 BSGS 可在 `O(sqrt(BOUND/m))` 次群乘内求解。
- 黑盒只提供 `mul`、`inv`、`phi`、`eq`，因此需先通过反复乘 `c` 恢复 `ord(c)`，并预计算 `c^r`、`a^{-r}`。

## 触发条件

- 群元素以黑盒形式提供，允许乘法、求逆、共轭、相等判断。
- `c` 的阶很小（本例 ≤8），`x` 有已知上界（本例 262144）。
- 每轮查询预算足够完成 BSGS（本例每轮 <10000 次）。

## 利用步骤

1. 反复 `mul(cur, c)` 直到回到单位元，得到 `ord(c)=m` 与 `c^r` 表。
2. 计算 `a = mul(g,c)`、`a_inv = inv(a)`，预计算 `a^{-r}`。
3. 计算 `b = a^m`，对 `b^t = y` 做 BSGS：baby steps 存 `b^j`，giant steps 用 `b^{-m}`。
4. 对每个 `r` 构造 `y = (h c^r) a^{-r}`，查表得到 `t`，检查 `x=r+mt ≤ BOUND`。
5. 提交 `x`。

## PoC

```python
# 核心步骤（黑盒 bb 提供 mul/inv）
cpows = [one]; cur = one
while True:
    cur = bb.mul(cur, c)
    if cur == one: break
    cpows.append(cur)
m = len(cpows)

a = bb.mul(g, c); a_inv = bb.inv(a)
a_inv_pows = [one]; cur = one
for _ in range(1, m):
    cur = bb.mul(cur, a_inv); a_inv_pows.append(cur)

b = one
for _ in range(m): b = bb.mul(b, a)
# BSGS on b^t = y for each r ...
```

## 变体与关联

- `c` 的阶较大时可用 Pohlig-Hellman 分解或 Pollard rho。
- 共轭作用可换成其他自同构；关键是把它写成半直积的幂。
- 关联：[[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]（光滑阶离散对数）、[[ctf-crypto-small-discrete-log-crt-channel-selection]]（小模数离散对数）。

## 检测与防御

- 这是数学结构导致的攻击，防御上应避免使用小阶共轭元/可预测的自同构，并选择足够大的群与阶。
- 检测：黑盒查询中出现大量 `mul` 与 `inv` 交替、接近 BSGS 模式的查询量。
