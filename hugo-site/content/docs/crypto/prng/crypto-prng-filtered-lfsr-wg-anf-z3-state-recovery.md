---
id: crypto-prng-filtered-lfsr-wg-anf-z3-state-recovery
title: 滤波 LFSR 非线性输出状态恢复：48 位状态 + 80 位密钥流建模为 Z3 布尔约束
type: scenario
domain: crypto
path: crypto/prng
technique: filtered-lfsr-wg-anf-z3-state-recovery
tags:
- crypto
- prng
- lfsr
- z3
- sat
- stream-cipher
- state-recovery
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T10:04:34+08:00'
  notes: V161 指出的 PoC 不可运行问题已修正（z3 移位取位 / forbiddenfruit 绕过内置类型限制）
url: /docs/crypto/prng/crypto-prng-filtered-lfsr-wg-anf-z3-state-recovery/
draft: false
kb_aliases:
- 滤波 LFSR 状态恢复
- WG 滤波器
- ANF 真值表 Z3
- LFSR SAT 求解
- 非线性滤波流密码
- UofT LFSR Labyrinth
---

## 一句话结论

LFSR 本身是线性的，但输出经过非线性滤波器（如 WG 的 ANF 组合函数）后，经典 Berlekamp–Massey/线性方程组失效；只要结构（反馈抽头、滤波抽头、ANF）已知且有足够长的连续密钥流（示例 80 位），就可以把 48 位初始状态当作布尔未知量，把 LFSR 时钟更新与每位滤波输出建模成 Z3 约束，求解初始状态后解密。

## 原理

- **LFSR 时钟**：状态 `s[0..L-1]` 每个时钟按反馈抽头异或得到 `fb`，状态左移/右移并插入 `fb`：`state = [fb] + state[:-1]`（具体方向按题目）。这一步是 GF(2) 线性变换，可逐位表示为 XOR 约束。
- **非线性滤波**：输出不是单个抽头，而是取 7 个滤波抽头的位组成 7-bit 索引，再查 ANF（代数正规型）真值表 `f: {0,1}^7 → {0,1}`。ANF 是若干单项式（变量子集的 AND）的 XOR；例如 `x1x2x3 ⊕ x0x2 ⊕ ...`。非线性来自 AND 项，使输出对状态不是线性的。
- **建模**：为初始 48 位建 `Bool` 变量；每个时钟：
  1. 用 `If(state[tap], 1<<j, 0)` 拼出 7-bit 索引（`BitVecVal`）；
  2. 预计算 7-bit ANF 真值表为 128-bit 常量 `TT`，用 `LShR(TT, ZeroExt(121, idx)) & 1` 取第 idx 位作为输出（z3py 的 `Extract` 只接受常量索引）；
  3. `solver.add(outbit == keystream[i])`；
  4. 按反馈抽头更新状态（XOR）。
- **求解**：80 位密钥流提供 80 个约束，未知量 48 个，通常可唯一确定初始状态；Z3 的 SAT 求解器能处理这种布尔/位向量混合约束。
- **为什么 BM 失效**：BM 只适用于线性递推序列；滤波输出是非线性序列，线性复杂度可能接近状态长度但无法直接恢复状态；SAT 建模直接利用已知非线性结构。
- **解密**：拿到初始状态后，重建 LFSR 密钥流，按题目 `decrypt(nonce, ct, init_state)` 解出 flag。

## 触发条件

- 目标使用 LFSR + 非线性滤波器的流密码/PRNG，且结构（长度 L、反馈抽头、滤波抽头、ANF/真值表）已知或可从代码逆出。
- 可获得足够长的连续密钥流（至少约 L 位，示例 80 位 > 48 状态）；密钥流与状态一一对应、无噪声。
- 状态空间大（2^48）无法暴力；但约束系统可满足。
- 有 Z3/其它 SAT/SMT 求解器与建模脚本。

## 利用步骤

1. **逆出结构**：从代码/题目数据获取 L（48）、`feedback_taps`、`filter_taps`、WG ANF 项或 7-bit 真值表。
2. **预计算真值表**：遍历 0..127，按 ANF 计算 `f(bits)`，拼成 128-bit 常量 `TT`。
3. **建 Z3 模型**：初始状态 48 个 Bool；对每位密钥流，拼索引、移位取位、加约束、更新 LFSR。
4. **求解**：`solver.check()==sat`，从 model 取 48 位初始状态。
5. **重建密钥流/解密**：用初始状态生成密钥流，调用题目解密函数或自行实现流密码解密。
6. **验证**：用求解状态重算前 80 位密钥流，应与给定序列一致；再解 flag。
7. **优化**：若求解慢，可增加约束/固定已知前缀、用 `BitVec` 整体建模、或分块求解。

## PoC

```python
from z3 import *

L = 48
feedback_taps = [...]          # 反馈抽头
filter_taps = [...]            # 7 个滤波抽头
keystream = [...]              # 0/1 序列

WG_ANF_TERMS = [(1,2,3,4,5,6), (0,1,2,3,5), ...]  # 题目给定

def eval_anf(bits):
    res = 0
    for mon in WG_ANF_TERMS:
        prod = 1
        for i in mon:
            prod &= bits[i]
        res ^= prod
    return res

TT = 0
for x in range(128):
    bits = [(x >> i) & 1 for i in range(7)]
    if eval_anf(bits):
        TT |= (1 << x)
TT = BitVecVal(TT, 128)

solver = Solver()
state0 = [Bool(f"s{i}") for i in range(L)]
state = state0[:]

for ks in keystream:
    idx = BitVecVal(0, 7)
    for j, tap in enumerate(filter_taps):
        idx = idx | If(state[tap], BitVecVal(1 << j, 7), BitVecVal(0, 7))
    outbit = LShR(TT, ZeroExt(121, idx)) & 1
    solver.add(outbit == BitVecVal(ks, 1))

    fb = False
    for t in feedback_taps:
        fb = Xor(fb, state[t])
    state = [fb] + state[:-1]

assert solver.check() == sat
model = solver.model()
init_state = [1 if model.eval(b) else 0 for b in state0]
print(init_state)
```

原文用该模型恢复 48 位状态并调用题目 `decrypt` 解出 flag；`WG_ANF_TERMS`/抽头需按目标实现补全。本卡不执行 PoC。

## 变体与关联

- **其它滤波器**：WG、Geffe、求和生成器、门限函数等；只要能把输出写成状态位的布尔函数，都可 SAT 建模。
- **状态更大**：2^64/2^128 无法暴力，但约束系统仍可能可解；可加入已知明文/密钥流前缀、分块、或用 CryptoMiniSat/专用代数攻击。
- **相关攻击**：代数攻击（解多元非线性方程组）、快速相关攻击、线性掩码；SAT 是通用但可能较慢的路线。
- **关联**：[[crypto-prng-conditional-lfsr-sat-onehot-counter]]（条件更新 LFSR SAT）、[[ctf-crypto-lfsr-known-plaintext-state-recovery]]（线性 LFSR 已知明文）、[[crypto-prng-mt19937-untemper-state-recovery-predict]]（MT19937 状态恢复）。
- **边界**：需要已知完整结构与非线性函数；若滤波器/抽头保密、密钥流有噪声或长度不足，SAT 可能无解/多解；真实密码应使用 CSPRNG 而非滤波 LFSR。

## 检测与防御

- **不要用滤波 LFSR 作为密码**：使用 AES/ChaCha 等经过审查的 CSPRNG/流密码；LFSR 只适合测试/扩频等非安全场景。
- **增加非线性/状态**：若必须用，增加状态长度、非线性度、输出抽头保密，并限制密钥流暴露长度；但这只是提高门槛。
- **检测**：大量连续密钥流被采集、异常 SAT 求解资源消耗无法从外部直接检测；协议层应限制输出速率/长度。
- **响应**：一旦怀疑状态恢复，立即轮换密钥/种子，停止使用该生成器。
