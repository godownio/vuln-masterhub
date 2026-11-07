---
id: ctf-crypto-mt19937-truncated-output-gf2-linear-recovery
title: MT19937 截断输出 GF(2) 线性恢复：624×19968 状态矩阵、6 维零空间枚举与 shuffle 逆置换
type: scenario
domain: ctf
path: ctf/crypto
technique: mt19937-truncated-output-gf2-linear-recovery
tags:
- ctf
- crypto
- mt19937
- prng
- gf2
- linear-algebra
- shuffle
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:27+08:00'
  notes: 已对照 ezran 原代码核对：19968 基状态、每 2 字节采样、30 个状态位约束后 6 维零空间→64 候选、shuffle 逆置换一致；已修正秩亏表述；未复跑附件。
url: /docs/ctf/crypto/ctf-crypto-mt19937-truncated-output-gf2-linear-recovery/
draft: false
kb_aliases:
- MT19937 截断输出
- getrandbits 高位恢复
- setstate 基向量矩阵
- 左零空间枚举
- shuffle 逆置换
- ezran
---

## 一句话结论

Python `random` 的每个输出位都是 19968 位初始状态的 GF(2) 线性函数；即使只拿到 `getrandbits(16)` 的高 15 位或高 8 位，也能对 19968 个基状态各跑一遍同样的采样流程建立矩阵，解线性方程组恢复 MT19937 状态；加入状态位固定约束后矩阵仍秩亏 6 维时枚举 64 个候选，再用后续 `shuffle` 的逆置换筛出正确状态并还原明文。

## 原理

- Python `random` 是 MT19937，内部状态为 624 个 32-bit 字，共 `624*32=19968` bit。tempering 只含 XOR 与移位，是 GF(2) 上的线性变换；`getrandbits(16)` 返回 16 个输出位，`>>1`/`>>8` 取高 15/8 位，仍然是状态位的线性组合。
- 题目给出的 gift 按 2 字节一块采样：每块先丢弃一个 `getrandbits(8)`，再取一个 `getrandbits(16)`，第 `i` 块若 `i % 64 == 0` 取高 15 位，否则取高 8 位。把这些位按顺序拼起来就是观测向量 `R`。
- 对 19968 个基状态分别 `setstate` 并执行完全相同的采样流程，每一行就是“该基状态对观测位的贡献”，组成 `19968 × L` 的 GF(2) 矩阵 `M`。真实初始状态 `s` 满足 `M*s = R`。
- 用 `solve_left` 得到一个特解；再求左零空间。原文实测观测矩阵秩为 19932（19968 个未知位，零空间 36 维）；题目又加入 30 个“部分状态位固定为 0”的增广约束，把零空间压到 6 维，因此有 `2^6=64` 个候选状态，需要逐一回放验证。
- 对每个候选重新 `setstate`，先按题目代码消耗 3108 组 `(8+16)` bit，再执行 2025 次 `shuffle`，就得到打乱后的下标序列 `x`。原程序用 `c[x.index(i)]` 生成密文，所以逆置换就是按 `x` 把字符还原。
- 正确候选会输出可读 flag；错误候选只产生乱码，以此完成筛选。

## 触发条件

- 目标使用 Python `random`（MT19937）生成“礼物”输出，且这些输出被截断（只暴露 `getrandbits(k)` 的高位）。
- 同一个 RNG 状态随后被用于加密、洗牌等可验证操作；攻击者知道消耗次数、`shuffle` 次数与密文结构。
- 观测位数量足以建立线性系统（本题约 16 万位对应 19968 个未知状态位）。
- 可在本地复现 `setstate`/`getrandbits`/`shuffle` 行为，并知道是否有额外的状态固定约束。

## 利用步骤

1. 读源码确认采样格式：每次丢弃多少 bit、取多少位、每 64 次是否有分支。
2. 把 gift 按位展开成观测向量 `R`；用同样的采样函数对每个基状态 `1 << i` 生成矩阵行。
3. 在 GF(2) 上解 `M*s = R`，得到特解与左零空间；按题目约束（如部分状态位为 0）增广方程。
4. 枚举零空间的所有组合（本题 64 个），把候选位串切成 624 个 32-bit 字并 `setstate`。
5. 按源码回放：消耗固定数量的 `getrandbits`，执行已知次数的 `shuffle`。
6. 用逆置换还原密文；保留可打印/匹配 flag 格式的候选。

## PoC

```python
from sage.all import *
from random import Random
from Crypto.Util.number import long_to_bytes

def sample_bits(rng, n=19968):
    out = []
    for i in range(n):
        rng.getrandbits(8)
        v = rng.getrandbits(16)
        if i % 64 == 0:
            out += [(v >> 1 >> b) & 1 for b in range(14, -1, -1)]
        else:
            out += [(v >> 8 >> b) & 1 for b in range(7, -1, -1)]
    return out

# 1) 观测位（由 gift 按同样的 2 字节分块展开）
R = vector(GF(2), observed_bits)

# 2) 每个基状态一行
rows = []
for i in range(19968):
    st = [0] * 624
    st[i // 32] = 1 << (i % 32)
    rng = Random()
    rng.setstate((3, tuple(st + [624]), None))
    rows.append(sample_bits(rng))
M = Matrix(GF(2), rows)

# 3) 特解 + 零空间枚举
s = M.solve_left(R)
K = M.left_kernel().basis()
for mask in range(1 << len(K)):
    cand = s + sum((K[j] for j in range(len(K)) if mask >> j & 1), vector(GF(2), [0] * 19968))
    bits = ''.join(map(str, cand))
    state = [int(bits[32 * j:32 * j + 32], 2) for j in range(624)]
    rng = Random()
    rng.setstate((3, tuple(state + [624]), None))
    for _ in range(3108):
        rng.getrandbits(8); rng.getrandbits(16)
    x = list(range(len(ct)))
    for _ in range(2025):
        rng.shuffle(x)
    pt = ''.join(ct[x.index(i)] for i in range(len(ct)))
    if 'flag{' in pt:
        print(pt)
```

说明：这是原文思路的最小骨架；`observed_bits`、`ct` 和增广约束需按题目数据替换。未在本机复跑原题附件。

## 变体与关联

- **完整 32-bit 输出**：直接 `untemper` 624 个输出即可，不需要线性系统；见 [[ctf-crypto-mt19937-bitstream-chinese-alignment-state-recovery]]。
- **截断/错位输出**：用基向量建矩阵是通用方法；未知位数、位序（MSB/LSB）或丢弃次数会改变矩阵形状。
- **`shuffle` 逆置换**：`x.index(i)` 与 `shuffle` 次数必须精确回放；少一次/多一次都会得到完全不同的置换。
- **种子恢复**：若状态由 32-bit 种子初始化，也可只枚举种子；本题状态维度过大，故走线性系统。

## 检测与防御

- 不要用 `random` 生成任何密钥、令牌或可验证的随机序列；使用 `secrets`/`os.urandom` 或 CSPRNG。
- 若必须用 `random`，输出经密码学哈希（如 SHA-256）后再使用，避免输出位直接暴露状态线性关系。
- 检测：同一进程的随机输出与后续加密/洗牌存在可验证关联、输出位数被截断等特征。
