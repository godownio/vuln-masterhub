---
id: ctf-crypto-gf3-lfsr-known-plaintext-state-mask-recovery
title: GF(3) LFSR 已知明文恢复：前 40 输出取初态，模 3 高斯消元解 mask 并解密
type: scenario
domain: ctf
path: ctf/crypto
technique: gf3-lfsr-known-plaintext-state-mask-recovery
aliases:
- GF(3) LFSR
- 模 3 线性反馈移位寄存器
- myLFSR
- 三进制 LFSR
- 已知明文恢复 mask
- 模 3 高斯消元
tags:
- ctf
- crypto
- lfsr
- stream-cipher
- known-plaintext
- gf3
- gaussian-elimination
- base3
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:18+08:00'
  notes: 已对照原文核对：GF(3)、40 trit 状态、state[0] 输出、模 3 反馈、gift 已知明文得 81 个密钥流、前 40 为初态、后 40 建 40x40 模 3 方程解 mask、推进 L 步、base-3 LSB-first 还原，与原文 exp 一致。dedup top 候选 ctf-crypto-lfsr-known-plaintext-state-recovery 为 likely_duplicate，但其为 GF(2)/64 位/比特输出，本卡为 GF(3)/40 trit/模 3 消元，不构成同一链，理由成立。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

在 GF(3) 上的 LFSR 中，每次输出 `state[0]` 后状态右移并在末尾追加 `b = Σ state[i]·mask[i] mod 3`；题目给出的已知明文 `gift` 足以反推出前 40 个输出（即 40 个 trit 的初始状态）和接下来的 40 个输出，用模 3 高斯消元解出 40 个 mask 系数，即可推进状态到 flag 密文起点并生成密钥流，逐 trit 还原明文。

## 原理

- **三进制 LFSR**：状态向量长度 `n=40`，每个分量取值 `{0,1,2}`。每次 `output = state[0]`，随后 `state = state[1:] + [sum(state[i]*mask[i]) mod 3]`。这是 GF(3) 上的线性递推：新状态分量是旧状态的线性组合。
- **已知明文得到密钥流**：加密为逐 trit `ct = pt ^ stream`（题面用 Python 的 `^` 实现，脚本按同样运算对齐）。`gift` 是已知明文 `b'\xff'*k` 的密文；把已知明文展开成 base-3（LSB-first）后与 `gift` 逐位异或，即得一段连续密钥流（本例 81 个 trit）。
- **前 n 个输出就是初始状态**：因为每次先输出 `state[0]` 再移位，前 40 个输出恰好对应初始状态的 40 个分量，无需解方程。
- **后 n 个输出建立 mask 方程**：第 `t` 个输出是当时状态的 `state[0]`，而状态由初始状态和未知 mask 线性决定；把观察到的 40 个输出作为 `b`、对应状态向量作为矩阵行，解 `A·mask = b (mod 3)` 即可。40 个方程解 40 个未知数，gift 提供 81 个输出，满足 `2n` 的最低要求。
- **推进到 flag 起点**：gift 消耗了前 `L` 个密钥流 trit（本例 `L=81`），要先把恢复出的状态推进 `L` 步，再为 flag 密文生成长度相同的密钥流；flag 密文也是 base-3 trit 序列，异或后按 LSB-first 还原整数，再按大端转字节。
- **为什么成立**：LFSR 的线性性使已知明文攻击从暴力搜索 `3^40` 降为解 40×40 的模 3 线性方程组；mask 与状态都只需多项式时间。

## 触发条件

- LFSR 工作在 GF(3)（或一般小素数域），状态长度 `n` 已知（本例题目首行给出 40）。
- 加密是逐 trit 组合（异或/模 3 加），且提供一段已知明文的密文 `gift`。
- 已知明文展开后的 trit 数至少 `2n`（本例 81 ≥ 80），能同时覆盖初态与 mask 方程。
- 需要恢复 flag 密文 `ct` 起始位置对应的密钥流（需知道 gift 消耗的 trit 数或能推断）。
- 有模 3 高斯消元/线性代数实现，能处理非域元素（3 为素数，1/2 的逆分别为 1/2）。

## 利用步骤

1. 读取题目代码/参数，确认 LFSR 的状态长度 `n`、输出位（`state[0]`）、移位方向和反馈公式。
2. 把 `gift` 的已知明文按 base-3 LSB-first 展开；与 `gift` 密文逐位异或得到密钥流 `stream`。
3. 取 `stream[:n]` 作为初始状态；对 `t=0..n-1`，用 `stream[t:t+n]` 构造矩阵行、`stream[n+t]` 作为 `b`，建立 `A·mask = b (mod 3)`。
4. 模 3 高斯消元（主元为 1 或 2，2 的逆为 2）解出 `mask`；用 `mask` 重放前 `2n` 个输出，验证与 `stream` 一致。
5. 从初始状态模拟推进 `L` 步（gift 消耗的 trit 数），再为 `ct` 生成等长密钥流。
6. 逐 trit 异或得到 flag 明文 trits；按 `flag_int += d*3^i` 还原整数，再 `to_bytes(...,'big')` 解码；用 `QnQSec{`/`flag{` 前缀校验。

## PoC

```python
def expand(n, base=3):
    res = []
    while n:
        res.append(n % base); n //= base
    return res or [0]

def solve_mod3(A, b):
    n, m = len(A), len(A[0])
    M = [row[:] + [bv] for row, bv in zip(A, b)]
    r = 0
    for c in range(m):
        piv = next((i for i in range(r, n) if M[i][c] % 3), None)
        if piv is None: continue
        M[r], M[piv] = M[piv], M[r]
        if M[r][c] % 3 == 2:
            M[r] = [(v * 2) % 3 for v in M[r]]
        for i in range(n):
            if i != r and M[i][c] % 3:
                f = M[i][c] % 3
                M[i] = [(M[i][j] - f * M[r][j]) % 3 for j in range(m + 1)]
        r += 1
    x = [0] * m
    for row in M:
        lead = next((j for j in range(m) if row[j] % 3), None)
        if lead is not None:
            x[lead] = row[-1] % 3
    return x

gift_ct = bytes.fromhex(GIFT_HEX)
flag_ct = bytes.fromhex(CT_HEX)
gift_pt = expand(int.from_bytes(b"\xff" * 16, "big"), 3)
L = min(len(gift_pt), len(gift_ct))
stream = [gift_pt[i] ^ gift_ct[i] for i in range(L)]

n = 40
init = stream[:n]
A = [[stream[t + i] % 3 for i in range(n)] for t in range(n)]
b = [stream[n + t] % 3 for t in range(n)]
mask = solve_mod3(A, b)

state = init[:]
def step(state):
    out = state[0]
    fb = sum(s * m for s, m in zip(state, mask)) % 3
    return out, state[1:] + [fb]

for _ in range(L):
    _, state = step(state)
ks = []
for _ in range(len(flag_ct)):
    out, state = step(state)
    ks.append(out)

digits = [ks[i] ^ flag_ct[i] for i in range(len(flag_ct))]
val, p = 0, 1
for d in digits:
    val += d * p; p *= 3
print(val.to_bytes((val.bit_length() + 7) // 8, "big"))
```

## 变体与关联

- 变体：GF(2) 的 LFSR 用比特异或与 GF(2) 高斯消元，见 [[ctf-crypto-lfsr-known-plaintext-state-recovery]]；已知 mask 求初态见 [[ctf-crypto-lfsr-mask-recovery-output-state]]。
- 变体：输出位不一定是 `state[0]`；若输出是状态某一位的线性组合，矩阵行需按实际输出方程构造。
- 变体：反馈可能是模 3 加法/乘法混合、状态长度更大；只要保持线性，仍可用同一套模素数高斯消元。
- 边界：若 gift 的 trit 数小于 `2n`，方程不足；若加密不是逐 trit 线性组合（如先转字节再异或），需要按题目实际运算重建模型。

## 检测与防御

- 检测（CTF）：题目给出 GF(3)/模 3 参数、状态长度与一段已知明文密文；密钥流长度至少为状态长度的 2 倍。
- 修复（真实设计）：LFSR 不是密码学安全流密码；应使用 AES-CTR/ChaCha20 等带 nonce 的认证加密，避免线性反馈结构。
- 加固：若必须用 LFSR，至少叠加非线性滤波函数并定期重播种；不要复用密钥流。
