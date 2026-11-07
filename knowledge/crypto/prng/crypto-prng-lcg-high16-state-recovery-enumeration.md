---
id: crypto-prng-lcg-high16-state-recovery-enumeration
title: LCG 高 16 位输出恢复初始状态：枚举低 16 位并用下一输出验证，预测第 100 位
type: scenario
domain: crypto
path: crypto/prng
technique: lcg-high16-state-recovery-enumeration
aliases:
- Genome LCG
- 高 16 位输出
- 低 16 位枚举
- LCG 状态恢复
- 位置 100 预测
tags:
- crypto
- prng
- lcg
- truncated-output
- state-recovery
- brute-force
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:22:59+08:00'
  notes: 已对照原文与图26核对：LCG a=1664525/c=1013904223/m=2^32、output=state>>>16、观测 50383/18563/20506/8072/48125/3917/7486/21992/42234/50464、枚举 low16 用 output1 验证、state0=0xC4CFC551、迭代到位置 100 得 50019、提交后认证并 claim SDG{4607fa424c02d98dd4e13ea1740ef428} 均一致。未验证点：PoC 未本机复跑（已手工核对参数与序列）；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

已知 LCG 参数 `a=1664525,c=1013904223,m=2^32`，输出只给 state 高 16 位；由 `output0` 枚举低 16 位，用 `output1` 验证唯一 `state0`，迭代到第 100 位预测。

## 原理

- **截断输出**：`output_n = state_n >>> 16`，只泄露高 16 位；`state_n = (output_n << 16) | low16`，low16 只有 2^16 种可能。
- **连续输出验证**：对每个 low16 候选，按 LCG 推进一步，检查 `(state1 >>> 16) == output1`；通常唯一。
- **全状态预测**：恢复 `state0` 后可迭代任意步；位置 100 的 `output_100 = state_100 >>> 16`。
- **参数公开**：题目把 LCG 参数写在协议里用于“可复现性验证”，反而让攻击者只需恢复初始状态。

## 触发条件

- 已知 LCG 参数（a/c/m）与输出截断方式（高 16 位）。
- 有至少两个连续输出（越多越稳）。
- 预测位置可迭代到达。

## 利用步骤

1. 收集 `output_0..output_9`。
2. 对 `low16 in 0..65535` 构造 `state0`，推进一步验证 `output1`。
3. 得到唯一 `state0`；继续迭代到位置 100。
4. 取 `state_100 >>> 16` 作为预测，提交认证。
5. 若多个候选，用 `output2` 进一步过滤。

## PoC

```python
a, c, m = 1664525, 1013904223, 2**32
outs = [50383, 18563, 20506, 8072, 48125, 3917, 7486, 21992, 42234, 50464]

def nxt(s): return (a * s + c) % m

state0 = None
for low in range(1 << 16):
    s = (outs[0] << 16) | low
    if (nxt(s) >> 16) == outs[1]:
        state0 = s
        break

s = state0
for _ in range(100):
    s = nxt(s)
print(s >> 16)
```

## 变体与关联

- **截断变体**：高 8/12 位、低 16 位、输出取模 2^k；候选空间与验证输出数变化。
- **参数未知**：先用差分 gcd 恢复 a/c/m（见关联卡）；或用格/Coppersmith 处理更大截断。
- **输出变体**：`state % n`、多输出组合、带噪声；可能需要 HNP/格。
- **关联卡片**：[[crypto-prng-lcg-parameter-recovery-delta-gcd]]（参数恢复）、[[crypto-prng-truncated-lcg-coppersmith-lattice-cvp]]（截断 LCG 格攻击）、[[crypto-prng-glibc-rand-output-sequence-prediction]]（glibc rand 预测）。
- **边界**：若只泄露 1 位/输出有随机噪声，2^16 枚举不再唯一；若 m 不是 2 的幂，需按实际模数枚举。

## 检测与防御

- **CTF/验证**：恢复的 state0 应能重现全部观测输出；预测值提交后应通过认证。
- **防御**：不要用 LCG 做安全随机；使用 CSPRNG（`secrets`/`os.urandom`/ChaCha20）；不要泄露连续输出；对认证接口做限速。
- **检测信号**：协议公开 LCG 参数与截断方式；接口按 position 返回输出；可预测的随机分配/抽签。
