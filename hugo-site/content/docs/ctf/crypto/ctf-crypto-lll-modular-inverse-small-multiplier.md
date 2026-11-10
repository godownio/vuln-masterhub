---
id: ctf-crypto-lll-modular-inverse-small-multiplier
title: 模逆隐藏数：data = t·m⁻¹ mod g，2×2 格配平缩放恢复短 t 与明文 m
type: scenario
domain: ctf
path: ctf/crypto
technique: lll-modular-inverse-small-multiplier-2d
tags:
- ctf
- lattice
- lll
- modular-inverse
- rsa
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-24
  verified_at: '2026-11-08T13:27:54+08:00'
  notes: 已对照原文核对：题目脚本/参数与卡一致，dedup top候选均related非同链，dedup_review理由成立；卡无sources字段(库内约定)；未验证点：PoC未在本机Sage环境执行
url: /docs/ctf/crypto/ctf-crypto-lll-modular-inverse-small-multiplier/
draft: false
kb_aliases:
- 模逆藏数
- data = t * inverse(m, g)
- 2x2 格约减恢复 m
- LLL 求模逆明文
---

## 一句话结论

当 `data ≡ t·m^{-1} (mod g)`，`g` 是 512 bit 素数、`t` 只有 150 bit 而 `m` 是较短的明文时，`(k, m)·[[g·2^150, 0], [data·2^150, 1]]` 得到向量 `(t·2^150, m)`；用缩放因子 `2^150` 把两个分量配到同一量级后，`LLL` 会把这个短向量直接约出来，从而同时恢复 `t` 与明文 `m`。

## 原理

- 由 `data ≡ t·m^{-1} (mod g)` 两边乘 `m`：`data·m ≡ t (mod g)`，即存在整数 `k` 使 `k·g + data·m = t`。
- 构造二维格基 `M = [[g·2^150, 0], [data·2^150, 1]]`。整数系数向量 `(k, m)` 在 `M` 上的像为
  `(k·g·2^150 + m·data·2^150, m) = (t·2^150, m)`。
- 该像向量长度：`t` 150 bit 乘 `2^150` 后约 300 bit，`m`（短明文）也约 300 bit，两个分量同量级，整体远短于格的行范数（约 `g·2^150`，600+ bit）。
- LLL 在多维格中寻找短向量，二维格上等价于高斯约减，因此会直接返回 `±(t·2^150, m)`；取绝对值、去掉缩放、`long_to_bytes` 即得 flag。
- 为什么缩放是必需的：不配平时第一分量 `t` 只有 150 bit 而第二分量 `m` 有 300 bit，短向量的判据被第一分量主导，`m` 可能被约成非明文值；乘 `2^150` 让两者平衡，是把「数值大小」对齐到「格的几何长度」的标准做法。

## 触发条件

- 给出 `g`（素数或大整数）与 `data = t·m^{-1} mod g`；
- 未知乘子 `t` 与明文 `m` 的比特长度之和明显小于 `g`（本卡 `150 + ~300 < 512`），目标向量相对格基足够短；
- `m` 与 `g` 互素（否则 `invert` 不存在，题目不会这样出）。

## 利用步骤

1. 估计 `t` 的位长 `n`（由生成脚本 `getPrime(n)` 得知，本卡 150）。
2. 构造 `M = matrix(ZZ, [[g << n, 0], [data << n, 1]])`。
3. `M.LLL()`，检查返回向量的两个分量：第一分量应能被 `2^n` 整除，第二分量绝对值即 `m`。
4. 对候选分量逐个 `long_to_bytes` 并过滤可打印/含 flag 格式的结果。

## PoC

```python
from Crypto.Util.number import long_to_bytes
from sage.all import matrix, ZZ

g = 7835965640896798834809247993719156202474265737048568647376673642017466116106914666363462292416077666356578469725971587858259708356557157689066968453881547
data = 2966297990428234518470018601566644093790837230283136733660201036837070852272380968379055636436886428180671888655884680666354402224746495312632530221228498
n = 150  # t 的位长

M = matrix(ZZ, [[g << n, 0], [data << n, 1]]).LLL()
for row in M:
    for v in row:
        b = long_to_bytes(int(abs(v)))
        if b.isprintable():
            print(b)
```

## 变体与关联

- 变体：`data = t·m^{-1} mod g` 中 `t` 未知且较长时，可改成三维格加入 `t` 的界，或用 `gcd(data·m - t, g)` 反推。
- 变体：`data = (a·m + b) mod g`（线性同余）时，用二维格 `[[g,0],[a,1]]` 直接求短向量（HNP 的最简形式）。
- 关联：[[ctf-crypto-hnp-2h-continued-fraction-kannan-embedding]]（HNP 的连分数/Kannan 嵌入）、[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（Kannan 嵌入求短向量）。
- 边界：`t`、`m` 都接近 `g` 的位长时目标向量不再显著短于格基，LLL 无法保证约出；此时需要更多样本（多组 `data`）做联立。

## 检测与防御

- 检测（CTF 视角）：看到形如 `t * inverse(m, g) % g` 的密文生成，且 `t` 位长明显小于 `g`，优先试二维格。
- 防御（实现视角）：不要把「短随机数 × 明文的模逆」当加密；随机数需与模数同量级或做哈希绑定，否则本质上是可约减的短向量问题。
