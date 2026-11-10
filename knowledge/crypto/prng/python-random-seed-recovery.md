---
id: python-random-seed-recovery
title: 从 Python random 内部状态逆推种子（init_by_array 逆向）
type: scenario
domain: crypto
path: crypto/prng
technique: 逆向 Python random 库 init_by_array 初始化过程从状态数组恢复种子
aliases:
- random seed 逆向
- init_by_array 逆向
tags:
- prng
- mt19937
- python-random
- seed-recovery
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-32
  verified_at: '2026-11-08T16:07:02+08:00'
  notes: 已对照原文核对：init_by_array 两段混合逆向公式与原文 re_init_by_array 一致，低32位种子限制、str/bytes 多key变体均出自原文；dedup_review 成立（候选卡为 LFSR 干扰+批次对齐的 CTF 特化链，本卡为通用 624 状态字逆推种子）；未验证点：未实际运行原文脚本复现 predict_seed 断言
---

## 一句话结论

拿到 Python `random` 库 MT19937 的完整内部状态数组后，可逆向其 `init_by_array` 两段初始化过程，从状态末位元素倒推出原种子的低 32 位。

## 原理

Python `random` 的种子初始化分两步：先用固定常量 19650218 调 `init_genrand` 预处理状态数组（该数组完全已知），再用种子经 `init_by_array` 做两段非线性混合。两段混合均为 `mt[i] = f(mt[i], mt[i-1])` 形式：第二段只用已知常量 1566083941，且处理完 `mt[623]` 后立即将 `mt[0]` 固定为 `0x80000000`，因此取 i=622、623 两个位置可先按第二段公式逆算出第二段处理前的值；第一段混入种子且使用已知预处理数组，公式可解出 `init_key` 项即种子：`seed = mt[i] - (prev ^ (prev>>30))*1664525 - j`（模 2^32）。乘法有模逆元、加减法可逆，混合操作只依赖"当前值+上个值"，上个值已知，故整条链可逆。

## 触发条件

- 已通过任意手段（状态逆推、调试、内存读取、`getstate()` 泄露等）获得 Python `random.Random` 实例的 624 个状态字；
- 目标种子源自时间戳、低熵值等值得恢复的场景。

## 利用步骤

1. 由 `getstate()` 取 `(version, state, gauss)` 中的 state（624+1 个字，末位为 index）；
2. 用 i=622、623 两位置按第二段公式 `_int32((mt[i]+i) ^ (mt[i-1] ^ (mt[i-1]>>30)) * 1566083941)` 逆算第二段处理前的 `tmp` 值；
3. 用固定种子 19650218 重建预处理数组 original_mt；
4. `predict_seed = _int32(tmp[623] - _int32((tmp[622] ^ (tmp[622]>>30)) * 1664525 ^ original_mt[623]))`；
5. 得到 32 位以内的种子值。

## PoC

无 PoC（原文给出可验证的 Python 实现：随机生成种子 → 取 getstate → 按上述步骤逆推 → 断言 `predict_seed == seed % 2**32`）。

## 变体与关联

- 只能恢复种子的低 32 位：32 位 MT19937 中 seed 真正参与 `init_by_array` 的只有低 32 位，高位无效；
- `random.seed()` 传入 str/bytes 时会先经 `init_by_array` 以多个 key 字混合，此时恢复出的是 key 数组而非单一整数，需按多 key 形式解；
- 与「MT19937 状态恢复与输出预测」场景衔接：先由输出恢复状态，再由状态逆推 seed，可破解 seed 源自弱熵（时间戳等）的系统并回溯历史输出。

## 检测与防御

- 同「MT19937 状态恢复」防御：敏感场景使用 `secrets` 等 CSPRNG；
- 避免以时间戳等低熵值作为 `random.seed`，因其可被上述逆推验证与穷举。
