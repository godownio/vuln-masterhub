---
id: crypto-prng-mt19937-seed-recovery-lfsr-noise-batch-alignment
title: MT19937 种子恢复：输出混入 LFSR 干扰与随机批次起点
type: scenario
domain: crypto
path: crypto/prng
technique: mt19937-seed-recovery-lfsr-noise-batch-alignment
tags:
- crypto
- prng
- mt19937
- seed-recovery
- lfsr
- gf2
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T02:17:12+08:00'
  notes: V118 指出的 PoC/代码错误已修正并重新 verify
url: /docs/crypto/prng/crypto-prng-mt19937-seed-recovery-lfsr-noise-batch-alignment/
draft: false
kb_aliases:
- MT19937 状态恢复
- MT19937 种子还原
- LFSR 干扰
- 批次对齐
- init_by_array
- 逆 temper
---

## 一句话结论

当服务端每批返回 312 行、每行 50% 概率是 MT19937 输出、50% 是 LFSR 输出时，先按“226 个高频值”把 LFSR 行筛掉，再对 MT 行逆 temper 得到状态词；利用批次间重叠对齐起点，按 MT 的线性递推建立 GF(2) 方程组解出 624 词状态，逆推初始状态与 `init_by_array` 种子，枚举初始位置补缺失的 31 bit，即可恢复 128 位 `static_seed`。

## 原理

- **MT19937 输出可逆**：每个 32 位输出经过 temper：`y ^= y>>11; y ^= (y<<7)&0x9d2c5680; y ^= (y<<15)&0xefc60000; y ^= y>>18`。这些操作可逆，逆 temper 后得到内部状态词 `s[p]`。
- **LFSR 干扰可筛除**：LFSR 的 SBox 有 256 项但只有 226 个不同的输出值；MT 输出是 32 位随机数，落入这 226 个值的概率极低（约 `226/2^32`）。统计所有批次中每个值出现的次数，出现次数特别多的 226 个值就是 LFSR 的值域：值在集合内 → LFSR 行，丢弃；否则 → MT 行，保留。
- **批次随机起点对齐**：每批 312 行，起点随机。若两批起点相差小于 312，它们有重叠；重叠区内同一绝对位置的 MT 输出相同。利用这些相同值可以算出两批起点差，把所有批次拼成连续序列/簇。
- **GF(2) 状态恢复**：MT 递推为
  `s[p] = s[p-227] ⊕ ((s[p-624]>>31 || s[p-623]&0x7fffffff)>>1) ⊕ (A·(s[p-623]&1))`，
  对状态是线性的。取 624 个词作为未知数（共 19968 bit），把每个观测词展开成这些未知数的线性方程，用 GF(2) 消元求解。解出后可能缺 31 bit（恰好是第一个词的低 31 位），可用已知区域/初始状态首词固定值 `0x80000000` 补齐。
- **逆推种子**：从已知状态按递推反推，直到种子刚生成时的初始状态 `S0`；`init_by_array` 的初始状态首词有固定值 `0x80000000`。初始状态的绝对位置未知，枚举 `[0,2^20)`；对每个候选位置逆 `init_by_array` 得到 4 个 key 字，真正的种子会让 4 个 key 槽完全一致，错误位置只会得到随机噪声。
- **为什么成立**：MT19937 是线性状态机，输出足够多且可对齐时，状态可被线性代数完全恢复；`init_by_array` 也是可逆的，所以能从状态回到 128 位种子。

## 触发条件

- 能获得足够多的 MT19937 输出（本题多批 312 行），且能区分/过滤干扰输出（LFSR 值域 226）。
- 批次起点随机但有重叠，可用于对齐；或已知输出绝对位置。
- 种子为 128 位并走 `init_by_array`；初始状态首词有固定值 `0x80000000`。
- 有 GF(2) 线性方程求解器（Sage/bitvector）与逆推实现；采样时间足够（本题主要耗时在采集样本）。

## 利用步骤

1. 采集多批 312 行输出，统计值频次，取高频的 226 个值作为 LFSR 值域。
2. 丢弃值在 LFSR 值域内的行；对剩余 MT 行逆 temper，得到状态词。
3. 用批次重叠（相同绝对位置的输出相同）求起点差，拼成连续序列/簇；若重叠不足，增加批次。
4. 以 624 个词为未知数，按 MT 递推建立 GF(2) 方程，消元求状态；补齐缺失的 31 bit。
5. 从状态逆推到初始状态 `S0`，利用首词 `0x80000000` 定位；枚举初始位置 `[0,2^20)`，逆 `init_by_array`，检查 4 个 key 槽一致，得到 128 位种子。
6. 用种子重现 MT 输出，验证与观测一致；按题目要求提交种子/flag。

## PoC

原文未给出完整可执行脚本（作者称 AI 脚本太长未附），但给出了完整方法。逆 temper 片段：

```python
def untemper(y: int) -> int:
    y ^= y >> 18
    y ^= (y << 15) & 0xefc60000
    y ^= (y << 7) & 0x9d2c5680
    y ^= y >> 11
    y ^= y >> 22          # 右移异或需两段还原，单次会残留 x>>22
    return y & 0xffffffff
```

MT 递推（用于建立 GF(2) 方程）：

```text
s[p] = s[p-227]
     ^ ((s[p-624] >> 31) | ((s[p-623] & 0x7fffffff) << 1)) >> 1   # 按位拼接后右移
     ^ (A * (s[p-623] & 1))
A = 0x9908b0df
```

核心判定：初始状态首词为 `0x80000000`；错误初始位置逆 `init_by_array` 后 4 个 key 槽不一致。

## 变体与关联

- **变体（弱种子）**：若种子是 32 位时钟/进程 ID，直接枚举种子比恢复状态更快；见 MT19937 时钟种子钱包卡。
- **变体（输出截断/高位泄露）**：只泄露部分位时，方程仍是线性的，但需要更多观测；temper 逆变换需按截断位调整。
- **变体（干扰源）**：任何有限值域/低熵干扰都可用频率/集合筛除；若干扰与 MT 输出不可区分，则需要其他侧信道。
- **关联卡片**：[[crypto-prng-mt19937-clock-seed-wallet-key-recovery]]（32 位时钟种子枚举）、[[crypto-prng-glibc-rand-output-sequence-prediction]]（线性递推恢复）、[[crypto-prng-srand-time-seed-2fa-code-prediction]]（时间种子预测）。
- **边界**：观测不足、批次无重叠、状态方程秩不足时无法恢复；`init_by_array` 的实现/端序需与目标一致；采样成本可能很高。

## 检测与防御

- **不要用 MT19937 产生安全随机数**：密钥、token、验证码等使用 `secrets`/`os.urandom`/CSPRNG（如 ChaCha20-DRBG）；MT19937 只适合模拟/统计。
- **不要暴露原始 PRNG 输出**：即使种子是 128 位，泄露 624 个连续状态词即可恢复内部状态；输出应经过加密/哈希等不可逆变换。
- **种子管理**：使用足熵种子并定期轮换；不要把种子与输出放在同一可观测通道。
- **检测**：CTF/审计中看到批量 32 位随机数、值域异常集中（226 个高频值）、批次重叠，优先尝试本卡；生产环境监控异常随机数输出接口。
