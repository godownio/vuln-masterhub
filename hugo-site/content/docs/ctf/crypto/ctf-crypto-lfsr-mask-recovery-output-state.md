---
id: ctf-crypto-lfsr-mask-recovery-output-state
title: LFSR 抽头 mask 恢复：initState 与 outputState 前 128 位建 GF(2) 方程
type: scenario
domain: ctf
path: ctf/crypto
technique: lfsr-mask-recovery-gf2-linear-system
tags:
- ctf
- crypto
- lfsr
- stream-cipher
- gf2
- gaussian-elimination
- mask-recovery
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:28:19+08:00'
  notes: 已对照原文小蓝鲨的LFSR系统核对：initState 128 位、outputState 256 位、矩阵行取状态、b 取输出、GF(2) 高斯消元、mask→16 字节 key 重复异或与 flag 一致；原文代码移位模型不一致已按原文说明；长数据未重复已注明；未复跑
url: /docs/ctf/crypto/ctf-crypto-lfsr-mask-recovery-output-state/
draft: false
kb_aliases:
- LFSR mask 恢复
- 小蓝鲨的LFSR系统
- 抽头 mask
- GF(2) 高斯消元
- initState outputState
- 线性反馈移位寄存器
---

## 一句话结论

已知 LFSR 的 128 位初始状态和输出比特流时，每个输出比特都是当前状态与未知抽头 mask 的点积（GF(2) 线性方程）；用前 128 个输出建立 128×128 方程组，高斯消元得到唯一的 128 位 mask，再把 mask 转成 16 字节密钥重复异或即可解密 flag。

## 原理

- **LFSR 的线性性**：状态长度为 n 的 LFSR 每次左移一位，新比特为 `feedback = dot(mask, state)`（GF(2) 点积）；输出比特通常就是该反馈位或状态某一位。
- **未知量是 mask**：若 initState 与 outputState 都已知，则第 t 个输出满足 `dot(mask, state_t) = output_t`，其中 `state_t` 由初始状态和先前输出递推得到，是已知向量；未知量只有 n 个 mask 位。
- **建立方程组**：收集 n 个时刻的 `state_t` 作为矩阵 A 的行，`output_t` 作为 b，解 `A·mask = b (mod 2)`。本题 n=128、输出 256 位，矩阵满秩，解唯一。
- **递推细节**：按题目实现，状态更新为 `state = state[1:] + [output_t]`（左移并塞入新输出位）。原文指出题目代码存在“直接附加而非移位”的不一致，求解时按循环左移修正；若模型不匹配，前 128 位解出的 mask 无法复现后 128 位输出。
- **验证**：用解出的 mask 重新生成全部 256 位输出，与 outputState 完全一致才说明模型正确；否则调整移位方向/输出位/抽头定义。
- **解密**：mask 的 128 位按 8 位分组转成 16 字节 key，重复成与密文等长的 keystream，逐字节 XOR 得到明文。

## 触发条件

- LFSR 的初始状态与一段输出比特流均已知（或可由已知明文反推）。
- 反馈函数是线性的，未知抽头 mask 固定，状态长度 n 不超过可用输出比特数。
- 输出比特与状态位的关系明确（反馈位/某状态位），移位方向与更新规则可推断。
- 密文用该 LFSR 密钥流异或加密。

## 利用步骤

1. 确认 LFSR 位宽 n、初始状态、输出比特顺序与状态更新规则；收集至少 n 个输出比特。
2. 从 initState 开始，对 t=0..n-1：把当前 state 作为矩阵 A 的第 t 行，`output_t` 作为 b 的第 t 项；然后按规则更新 state（左移并追加 output_t）。
3. 在 GF(2) 上做高斯消元，检查秩是否为 n；满秩则 mask 唯一。
4. 用 mask 重新生成 128/256 位输出，与已知 outputState 对比验证。
5. mask 按 8 位转字节得到 16 字节 key，重复成 keystream，与密文 XOR 得到 flag。
6. 若验证失败，尝试相反移位方向、输出位改为状态最高/最低位、或把 mask 位序反转。

## PoC

```python
def gaussian_elimination_mod2(A, b):
    n, m = len(A[0]), len(A)
    M = [A[i][:] + [b[i]] for i in range(m)]
    row = 0
    for col in range(n):
        if row >= m: break
        pivot = next((r for r in range(row, m) if M[r][col]), None)
        if pivot is None: continue
        M[row], M[pivot] = M[pivot], M[row]
        for r in range(m):
            if r != row and M[r][col]:
                M[r] = [M[r][c] ^ M[row][c] for c in range(n + 1)]
        row += 1
    sol = [0] * n
    for r in range(row):
        for c in range(n):
            if M[r][c]:
                sol[c] = M[r][n]
                break
    return sol

def recover_mask(init_state, output_state):
    n = len(init_state)
    m = min(len(output_state), n)
    A, state = [], init_state.copy()
    for t in range(m):
        A.append(state.copy())
        state = state[1:] + [output_state[t]]   # 左移并塞入新 bit
    return gaussian_elimination_mod2(A, output_state[:m])

mask = recover_mask(initState, outputState)
key = bytes(int(''.join(str(b) for b in mask[i*8:(i+1)*8]), 2) for i in range(16))
keystream = (key * (len(ciphertext)//16 + 1))[:len(ciphertext)]
print(bytes(p ^ k for p, k in zip(ciphertext, keystream)))
```

`initState`（128 位）、`outputState`（256 位）与 `ciphertext_hex` 为原文题目数据，受篇幅限制未在此重复；需先 `ciphertext = bytes.fromhex(ciphertext_hex)`。按原文数据运行，恢复 mask 后解密得到：

```text
ISCTF{lf5R_jUst_So_s0}
```

## 变体与关联

- 已知明文变体：若只知明文前缀，先用 `C XOR P` 得到输出比特，再按本卡恢复 mask；见 [[ctf-crypto-lfsr-known-plaintext-state-recovery]]。
- 模型变体：Galois 结构、右移、输出状态某一位、非线性滤波/组合生成器；线性方程只适用于纯线性反馈。
- 输出不足变体：只有 2n 位输出时可用 Berlekamp-Massey 求线性复杂度/反馈多项式，再推 mask。
- 关联：[[ctf-crypto-single-byte-seed-recurrence-stream-cipher-bruteforce]]（递推流密码）、[[ctf-crypto-mt19937-bitstream-chinese-alignment-state-recovery]]（PRNG 状态恢复）。
- 边界：若输出经过非线性滤波或每步注入随机数，GF(2) 线性模型不成立；状态更新规则判断错误会解出错误 mask。

## 检测与防御

- 检测：CTF 中看到 initState/outputState 或密钥流比特，先判断是否线性；用解出的 mask 复现全部输出验证。
- 防御：不要用 LFSR 作为密码学密钥流；使用 CSPRNG/AES-CTR/ChaCha20，并为每帧使用唯一 nonce。
- 加固：避免泄露初始状态与长输出流；若必须用 LFSR，加入非线性滤波并限制输出长度。
