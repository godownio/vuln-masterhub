---
id: crypto-prng-lcg-parameter-recovery-delta-gcd
title: LCG 参数恢复：连续输出差分 gcd 求模数、乘数与种子
type: scenario
domain: crypto
path: crypto/prng
technique: lcg-parameter-recovery-delta-gcd
tags:
- crypto
- prng
- lcg
- parameter-recovery
- gcd
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:48:50+08:00'
  notes: 已对照原文「LCG4.0」核对并复算 PoC：10 个状态、差分 d_{i+2}d_i-d_{i+1}^2 的 gcd 得 m=1321686059169464686504334539368898634722771，a=864627827635375530732233567562343956520897，b=1158343860852874514750980020186868343571703，反解 seed=42008170895622552782693455202459542710141 => b'{solvethelastlag}'，全状态回代通过，与原文一致。未验证点：未持附件复跑；无版本/CVE；frontmatter 无 sources/source_url。
url: /docs/crypto/prng/crypto-prng-lcg-parameter-recovery-delta-gcd/
draft: false
kb_aliases:
- LCG 参数恢复
- 线性同余生成器
- 差分 gcd
- 模数恢复
- 种子反推
---

## 一句话结论

当拿到 LCG 的连续输出 `s_i` 时，相邻差 `d_i=s_{i+1}-s_i` 满足 `d_{i+2}·d_i - d_{i+1}^2 ≡ 0 (mod m)`；对所有项取最大公约数即可恢复模数 `m`，再用首两个差分求乘数 `a`、用首两个状态求增量 `b`，最后反解 `seed`。

## 原理

- **LCG 递推**：`s_{i+1} = (a·s_i + b) mod m`。相邻差 `d_i = s_{i+1}-s_i = a·(s_i-s_{i-1}) = a·d_{i-1} mod m`，所以 `d_i` 本身也是一个乘数为 `a` 的 LCG（无增量）。
- **消去 a**：`d_{i+1} ≡ a·d_i (mod m)`，`d_{i+2} ≡ a·d_{i+1} (mod m)`；两式相乘/相除消去 `a` 得 `d_{i+2}·d_i ≡ d_{i+1}^2 (mod m)`。因此 `m` 整除 `d_{i+2}·d_i - d_{i+1}^2`。
- **恢复 m**：对所有 `i` 计算该差值并取 `gcd`（含 0 时跳过）；`gcd` 可能是 `m` 的倍数/小因子，需要结合多个样本和验证。本题 gcd 直接给出 1321...771。
- **恢复 a/b**：`a = d_1 · d_0^{-1} mod m`（要求 `gcd(d_0,m)=1`）；`b = (s_1 - a·s_0) mod m`。
- **恢复 seed**：题目给出的第一个状态是 `seed` 迭代一次后的结果，`s_0 = (a·seed + b) mod m`，所以 `seed = (s_0-b)·a^{-1} mod m`。
- **为什么成立**：LCG 是线性递推，差分把仿射项消掉，剩下纯乘性关系；连续输出足够多时，模数可被差分关系唯一确定（最多差一个因子）。

## 触发条件

- 拿到至少 4 个连续 LCG 输出（本题 10 个），且输出没有截断/取高位。
- `m` 未知但为常数；`a`、`b` 未知；`gcd(d_0,m)=1` 以保证可求逆（否则需用其他差分/扩展欧几里得）。
- 已知递推形式与输出顺序；第一个输出是否等于 seed 需按题目确认。
- 输出是精确整数（不是 `% 2^k` 截断），否则差分关系不完整。

## 利用步骤

1. 计算相邻差分 `d_i = s_{i+1} - s_i`。
2. 对每个 `i` 计算 `d_{i+2}·d_i - d_{i+1}^2`，与当前 `g` 取 `gcd`；忽略 0。
3. 把 `g` 作为候选 `m`，用更多项验证 `d_{i+1} ≡ a·d_i mod m`；若失败，尝试 `g` 的因子/倍数。
4. 求 `a = d_1·d_0^{-1} mod m`，`b = (s_1 - a·s_0) mod m`。
5. 反解 `seed = (s_0-b)·a^{-1} mod m`；按题目要求转字节/十六进制。
6. 用 `s_{i+1} == (a·s_i+b) mod m` 回代验证全部状态；本题 `seed` 转字节得到 `b'{solvethelastlag}'`。

## PoC

```python
from math import gcd

states = [
    421212310892931870090770823648461624975774,
    862129767917451191679336928145552691547367,
    1079761070727277937369386910846268488929766,
    40605969152837342975500589521586616251762,
    439006148938366452242502948541061704411062,
    954155169757201085402176495152430057621156,
    563168879613345685512623653387438510002584,
    561093487257447844384066670581505915222992,
    368958647863543275592990859614306474308863,
    197354019925819894610192413469597110533773,
]

delta = [b - a for a, b in zip(states, states[1:])]
m = 0
for i in range(len(delta) - 2):
    relation = delta[i + 2] * delta[i] - delta[i + 1] ** 2
    m = gcd(m, abs(relation))

a = delta[1] * pow(delta[0], -1, m) % m
b = (states[1] - a * states[0]) % m
seed = (states[0] - b) * pow(a, -1, m) % m
plain = seed.to_bytes((seed.bit_length() + 7) // 8, "big")

print("m =", m)
print("a =", a)
print("b =", b)
print("seed =", seed)
print(plain)          # b'{solvethelastlag}'

assert all((a * x + b) % m == y for x, y in zip(states, states[1:]))
```

## 变体与关联

- **变体（截断输出）**：只给 `s_i mod 2^k` 或高位时，差分关系被破坏，需要 HNP/格方法或更多信息。
- **变体（未知增量/乘数）**：已知 `m` 时用两组方程解 `a,b`；未知 `m` 时先恢复 `m`。
- **变体（多组 LCG/交错）**：不同 LCG 输出混在一起时，先按周期/统计分离。
- **关联卡片**：[[crypto-prng-mt19937-seed-recovery-lfsr-noise-batch-alignment]]（MT19937 状态恢复）、[[crypto-prng-glibc-rand-output-sequence-prediction]]（线性递推预测）、[[crypto-prng-srand-time-seed-2fa-code-prediction]]（弱种子）。
- **边界**：输出不足、`gcd(d_0,m)>1`、模数不唯一时需要额外验证；浮点/截断输出不适用。

## 检测与防御

- **不要用 LCG 做安全随机数**：LCG 线性可预测，连续输出即可恢复参数与种子；密钥/token 使用 CSPRNG。
- **种子管理**：即使种子随机，LCG 状态泄露也会导致后续输出可预测；输出应经过加密/哈希。
- **CTF 识别**：看到连续大整数、递推关系、模数未知，优先尝试差分 gcd；用回代验证。
