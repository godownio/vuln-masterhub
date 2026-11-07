---
id: crypto-prng-truncated-lcg-coppersmith-lattice-cvp
title: 截断 LCG 状态恢复：Coppersmith 求 p 高位缺失 + 格 CVP 求低 256 位
type: scenario
domain: crypto
path: crypto/prng
technique: truncated-lcg-coppersmith-lattice-cvp
tags:
- prng
- lcg
- coppersmith
- lattice
- cvp
- hnp
- fpylll
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:13+08:00'
  notes: 已对照原文 §LGC Attack 核对：p_high=p>>502、zncoppersmith、s_{i+1}=a(s_i-c) mod p、output=s>>256、e_i=A_i e0+D_i、diag(p)+系数行+scale=2^250、CVP 目标 -D、seed 拼回、flag 均一致；未本机复跑。注意：本卡与 92543 批次 ctf-crypto-coppersmith-msb-lcg-truncated-cvp 为同场景近重复（两批并发导致），建议合并或保留其一。
url: /docs/crypto/prng/crypto-prng-truncated-lcg-coppersmith-lattice-cvp/
draft: false
kb_aliases:
- LGC Attack
- 截断 LCG
- LCG 高位输出恢复
- Coppersmith zncoppersmith
- HNP CVP 格
- 低 256 位恢复
---

## 一句话结论

当 LCG 只输出状态的高位（`output_i = s_i >> 256`）且模数 `p` 的高 502 位已知、`p | N` 时，可以先用 Coppersmith 小根求出 `p` 的低 502 位，再把 `s_i = output_i * 2^256 + e_i` 代入递推，得到 `e_{i+1} = a*e_i + const_i mod p`；所有 `e_i < 2^256`，构造格用 CVP 求最近向量即可恢复全部低位，拼回 `s_0` 即 seed。

## 原理

- 题目给出 `p_high = p >> 502`，即 `p = p_high * 2^502 + x`，`0 <= x < 2^502`。由于 `p | N`，`x` 是多项式 `f(x) = p_high * 2^502 + x` 模 `N` 的小根；`2^502` 接近 `N^(1/4)` 边界，可用 Coppersmith（`zncoppersmith`）求小根。
- LCG 递推：`s_{i+1} = a * (s_i - c) mod p`，输出 `output_i = s_i >> 256`。
- 令 `s_i = output_i * 2^256 + e_i`，`0 <= e_i < 2^256`。代入递推并整理可得 `e_{i+1} = a * e_i + const_i mod p`，其中 `const_i = a*(output_i*2^256 - c) - output_{i+1}*2^256`。
- 继续展开：`e_i = A_i * e_0 + D_i mod p`，`A_i = a^i`，`D_i` 由常数累积得到。所有 `e_i` 都是 256 位小量，而 `p` 是 1024 位左右，这是典型 Hidden Number Problem。
- 构造 `(dim+1) x (dim+1)` 格：左上 `dim x dim` 为 `diag(p, ..., p)`，最后一行前 `dim` 列为 `A_i`，最后一列 `scale`；对目标 `(-D_0, ..., -D_{dim-1}, 0)` 做 CVP 最近向量，得到 `e_i` 的候选（符号可能整体取反），检查是否都落在 `[0, 2^256)`。
- 恢复 `e_0` 后 `seed = (output_0 << 256) + e_0`，再按 LCG 递推验证所有输出，最后把 seed 转字节即 flag/密钥。

## 触发条件

- LCG 参数 `a`、`c`、`p` 已知或部分已知；模数 `p` 的高位泄露且 `p | N`（或可通过其他方式恢复 p）。
- 输出为状态的高位截断，且截断位数 `k` 使低位 `e_i < 2^k` 相对 `p` 足够小。
- 有足够多的连续输出（案例 6 个）构造格；维数越高越稳定。
- 有 Coppersmith 实现（PARI `zncoppersmith`）与格工具（fpylll/sage）。

## 利用步骤

1. 从附件读取 `N`、`p_high`、`a`、`c`、`outputs`。
2. 设 `p = p_high * 2^502 + x`，用 `zncoppersmith(x + p0, N, X, sqrtint(N))` 求小根，得到 `p`；验证 `N % p == 0`。
3. 计算每步常数 `const_i = a*(output_i*2^256 - c) - output_{i+1}*2^256`。
4. 迭代 `A_i = A_{i-1}*a mod p`、`D_i = a*D_{i-1} + const_{i-1} mod p`，得到 `e_i = A_i*e_0 + D_i`。
5. 构造格并做 LLL + CVP，目标为 `(-D_i)`；从最近向量差得到 `e_i` 候选，检查范围与符号。
6. 拼回 `seed`，按 LCG 验证所有 `output_i`，转字节输出 flag。

## PoC

```python
from fpylll import CVP, IntegerMatrix, LLL
from Crypto.Util.number import long_to_bytes

# N, p_high, a, c, outputs 来自题目
p0 = p_high << 502
# 1) Coppersmith（需在 gp 中运行）：
#    roots = zncoppersmith(x + p0, N, 2^502, sqrtint(N))
#    p = p0 + roots[1]
p = ...  # 由 zncoppersmith 得到
assert N % p == 0

k, base = 256, 1 << 256
dim = len(outputs)
consts = [a * (outputs[i] * base - c) - outputs[i + 1] * base
          for i in range(dim - 1)]

coeffs, offsets = [1], [0]
for const in consts:
    coeffs.append((coeffs[-1] * a) % p)
    offsets.append((a * offsets[-1] + const) % p)

scale = 1 << 250
mat = IntegerMatrix(dim + 1, dim + 1)
for i in range(dim):
    mat[i, i] = p
for j, value in enumerate(coeffs):
    mat[dim, j] = value
mat[dim, dim] = scale
LLL.reduction(mat)

target = tuple([(-d) % p for d in offsets] + [0])
closest = CVP.closest_vector(mat, target)
diffs = [target[i] - closest[i] for i in range(dim)]

for sign in (1, -1):
    lows = [sign * d for d in diffs]
    if all(0 <= low < base for low in lows):
        seed = (outputs[0] << 256) + lows[0]
        print(long_to_bytes(seed, 64).rstrip(b"\x00"))
        break
```

案例输出：`Nepctf{C0pp3rsm1th_m33ts_LLL_in_Latt1c3_w0rld!}`。

## 变体与关联

- 变体：截断位数不同（`>> k`）时把 `2^256` 换成 `2^k`，并相应调整 `scale` 与格维度。
- 变体：`a`、`c` 未知时，先用连续输出差分/gcd 恢复参数（参考 LCG 参数恢复卡），再做 HNP。
- 变体：输出为低位截断或高位+低位组合时，重新推导线性关系，构造相应的 HNP/Coppersmith 格。
- 变体：`p` 完全未知但 `N` 已知时，可先用 Coppersmith 求 `p` 的小根或结合其他泄露。
- 关联：[[crypto-prng-lcg-parameter-recovery-delta-gcd]]（LCG 参数恢复）、[[crypto-prng-mt19937-seed-recovery-lfsr-noise-batch-alignment]]（PRNG 种子恢复）、[[crypto-rsa-williams-p-plus-1-smooth-factor]]（同题其他 RSA 分解）。

## 检测与防御

- 防御：不要用 LCG 生成密钥/种子；使用 CSPRNG（`secrets`、`os.urandom`）并避免输出内部状态的高位/低位。
- 防御：若必须用 LCG，输出前对状态做密码学哈希，且不要连续泄露多个输出的截断值。
- 检测：代码中出现 `s = (a*(s-c)) % p`、`s >> k` 连续输出、固定 `a/c/p`；对密钥生成做统计随机性检测。
- 响应：发现状态泄露后立即更换密钥/种子，评估历史输出是否可恢复，审计依赖该 PRNG 的协议。
