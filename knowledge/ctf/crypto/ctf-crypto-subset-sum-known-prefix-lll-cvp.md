---
id: ctf-crypto-subset-sum-known-prefix-lll-cvp
title: 已知格式前后缀的子集和：CVP 格约减恢复 64 位二进制明文
type: scenario
domain: ctf
path: ctf/crypto
technique: subset-sum-known-prefix-lll-cvp
aliases:
- 子集和问题
- subset sum LLL
- 背包加密 0/1 恢复
- new_bag
- 已知 flag 前缀的格攻击
tags:
- ctf
- lattice
- lll
- cvp
- subset-sum
- knapsack
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-24
  verified_at: '2026-11-08T13:27:59+08:00'
  notes: 已对照原文核对：题目脚本/参数与卡一致，dedup top候选均related非同链，dedup_review理由成立；卡无sources字段(库内约定)；未验证点：PoC未在本机Sage环境执行
---

## 一句话结论

`enc = Σ pubkey[i]·bit[i] mod p` 且明文二进制位是 0/1、flag 的固定前缀 `LitCTF{` 与后缀 `}` 已知时，把已知位的贡献从 `enc` 中扣除，剩余未知位构成标准子集和；用「单位阵 + 加权向量」构造格并把常数项配成 `1/2` 的 CVP 嵌入后 `LLL`，即可直接读出 64 位 0/1 解。

## 原理

- 子集和（背包）问题是 NP 难的，但当维数不大且解是 0/1 短向量时，格约减能在多项式时间内找到它（Lagarias-Odlyzko 攻击）。
- 已知前缀/后缀的比特后，把它们对应的 `pubkey[i]` 从 `enc` 中减掉，未知位只剩 64 个；同时 `enc` 与 `Σ pubkey[i]·bit[i]` 相差整数倍 `p`，需枚举商 `k`（`s = enc + k·p`），`k` 的取值由已知位贡献的量级估出初值 `k0`，只需在其附近小范围搜索。
- 构造格
  `L = [[I_n, N·W^T], [1/2·1_n, N·s]]`，
  其中 `W = pubkey[未知位]`、`N ≈ sqrt(n)` 为放大系数、`1/2·1_n` 一行用于把「解向量」平移到 `±1/2` 的对称位置。
- 若 `x` 是 0/1 解，则向量 `(x - 1/2·1, 0)` 属于格：`(x - 1/2·1)·1_n = ±1/2` 之和只有 `n/2` 个 `±1/2`；格中该向量长度为 `O(sqrt(n))`，而随机向量长度约为 `N·|pubkey|`，相差悬殊。LLL 约减后取前 `n` 个分量，把 `±1/2` 还原成 0/1 即得明文位。
- 为什么用 `1/2` 平移：0/1 向量没有「短」的几何特征（长度为 `sqrt(64)`），但 `x - 1/2` 各分量恒为 `±1/2`，方差最小，LLL 才能稳定约出；这是把 CVP 转成 SVP 的标准技巧。

## 触发条件

- 背包向量 `pubkey` 个数（位长）与模数 `p` 已知，明文位数不超过约 100（维数过高时 LLL 失效）；
- 明文的固定格式（flag 前后缀）已知，可扣除对应比特；
- 解是严格 0/1 且无噪声（`enc` 精确等于加权和模 `p`）。

## 利用步骤

1. 把已知前缀/后缀转成比特串，计算其对 `enc` 的贡献 `sum_known`，并估计商 `k0 = sum_known // p`。
2. 对 `k` 在 `k0` 附近小范围枚举（几十次内），令 `s_ = enc + (k + k0)·p - sum_known`。
3. 取未知位对应的 `pubkey` 子集 `W`，构造上面的格 `L` 并 `LLL`。
4. 对每个约减基向量取前 `n` 个分量，分别尝试 `x + 1/2` 与 `1/2 - x`，若结果集合为 `{0,1}` 则按 8 位一组转 ASCII，拼回前缀/后缀即为 flag。
5. 若一次 LLL 未命中，调整 `N`（如 `ceil(sqrt(n))`）或扩大 `k` 的搜索范围。

## PoC

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.all import matrix, identity_matrix, ones_matrix, ZZ, QQ, ceil, sqrt

p = 173537234562263850990112795836487093439
s = 82516114905258351634653446232397085739       # enc
pubkey = [...]                                    # 长度 = flag 位数
w = pubkey[8 * 7 - 1:-8]                          # 去掉已知前缀/后缀后的未知位
n = len(w)
N = ceil(sqrt(n))

front = bin(bytes_to_long(b'LitCTF{'))[2:]
end = bin(bytes_to_long(b'}'))[2:]
sum_front = sum(pubkey[i] * int(front[i]) for i in range(len(front)))
sum_end = sum(pubkey[i + 127 - 7] * int(end[i]) for i in range(len(end)))
k0 = (sum_front + sum_end) // p

E = identity_matrix(ZZ, n)
W = matrix(QQ, 1, n, w)
for k in range(70):
    s_ = s + (k + k0) * p - (sum_front + sum_end)
    L = block_matrix([[E, N * W.T], [ones_matrix(QQ, 1, n) / 2, N * s_]])
    M = L.LLL()
    for i in range(65):
        for sign in (1, -1):
            bits = [(v + sign * QQ(1, 2)) for v in M[i][:n]]
            if set(bits).issubset({0, 1}):
                bs = ''.join(str(int(b)) for b in bits)
                print('LitCTF{' + ''.join(chr(int(bs[j:j+8], 2)) for j in range(0, len(bs), 8)) + '}')
```

## 变体与关联

- 变体：明文含噪声或非 0/1 小系数时，用「小系数背包」并通过 `N` 调参；维数更大时可分批（分块）求解再利用已知前缀拼接。
- 变体：`enc` 不是模 `p` 而是整数（无模约减）时是纯 SVP，直接对 `[[I, N·W^T]]` 约减即可。
- 关联：[[ctf-crypto-hnp-2h-continued-fraction-kannan-embedding]]（同类 CVP→SVP 嵌入）、[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（Kannan 嵌入）。
- 边界：维数过大（>150）或明文位分布无结构（无法估 `k`）时需改用 BKZ 或更多已知信息。

## 检测与防御

- 检测（CTF 视角）：看到「每位乘一个大素数再求和取模」且明文字符集已知，直接套格攻击而不是爆搜。
- 防御（实现视角）：不要用低维背包做加密；若必须，使用带随机化的背包（Merkle-Hellman 已被攻破），维数需远高于可约减范围并加入噪声。
