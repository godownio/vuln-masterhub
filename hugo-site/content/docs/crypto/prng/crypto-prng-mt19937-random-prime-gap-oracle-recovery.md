---
id: crypto-prng-mt19937-random-prime-gap-oracle-recovery
title: MT19937 状态恢复：异常 oracle 排序 + random_prime 消耗间隙与 B0/B1 约束
type: scenario
domain: crypto
path: crypto/prng
technique: mt19937-state-recovery-random-prime-gaps-exception-oracle
tags:
- crypto
- prng
- mt19937
- state-recovery
- oracle
- z3
- random-prime
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:19:40+08:00'
  notes: 已对照原文核对：同一 SEED 重放、option1 36 组 getrandbits(988)+random_prime、option2 异常 oracle（cand^get_limit(k)^1 命中时 random_prime(1) 抛 ValueError）、random_prime 消耗与 getrandbits 共用 MT 流、B0 提供 top31/B1 提供间隙、第 10 轮 get_limit 砍 1/3 与 extra10=1、Z3 恢复 624 状态词后 SHA256(str(next256)) 派生 AES key、next256 数值均一致。未验证点：PoC 未连接远程复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/crypto/prng/crypto-prng-mt19937-random-prime-gap-oracle-recovery/
draft: false
kb_aliases:
- polarisCTF ez_random
- getrandbits(988)
- random_prime 异常 oracle
- Key Part A/B0/B1
- extra10
- MT19937 Z3 状态恢复
- 随机流间隙
---

## 一句话结论

服务端用同一 `SEED` 重放随机链，`option 1` 输出 36 个乱序的 `getrandbits(988)` 与 `random_prime` 结果，`option 2` 逐位询问并最终用 `getrandbits(256)` 派生 AES 密钥；利用 `random_prime(1)` 抛异常的 oracle 可把 36 个值排回顺序，再把 `random_prime` 内部消耗的随机数（由 B0/B1 给出）与 988-bit 输出的 `full32/top28` 观测一起送入 Z3，恢复 MT19937 状态并预测下一次 `getrandbits(256)`。

## 原理

- **随机链复用**：`option 1` 和 `option 2` 都用同一个 `SEED` 播种 Python `random`（MT19937）。`option 1` 生成 36 组 `(getrandbits(988), random_prime(...))`；`option 2` 重跑同一条链，最后再取一次 `getrandbits(256)`，转字符串做 SHA256 得到 AES-ECB 密钥。
- **异常 oracle**：`option 2` 每轮计算 `random_prime(int(input()) ^ (getrandbits(988) ^ get_limit(k)))`。若括号整体为 1，`random_prime(1)` 抛 `ValueError`。`get_limit(k)` 已知，所以对第 k 轮的候选 `cand` 发送 `cand ^ get_limit(k) ^ 1`：若 `cand` 等于真实 `getrandbits(988)`，服务端异常；否则继续询问下一轮。用这个信号可把乱序的 `Key Part A` 逐位排回。
- **随机流不连续**：`random_prime` 不是只消耗一次 `getrandbits`；它内部通过 `Zmod(n).random_element()` 反复取候选，消耗的随机数与 `getrandbits(988)` 共用同一条 MT 流。只按 36 个 988-bit 输出恢复状态会把中间消耗当成不存在，位置错位。
- **B0/B1 补洞**：`Key Part B0[i]` 是第 i 轮最终成功的素数（可提供 `top31` 观测），`B1[i]` 是该轮尝试次数（即额外消耗的候选数）。离线恢复时把每个 988-bit 输出拆成 30 个 `full32` + 1 个 `top28`，在每个输出后插入 `B1[i]` 个未观测的 MT 输出，并把 `B0[i]` 作为 `top31` 约束放在第 `B1[i]` 个间隙位置。
- **第 10 轮特殊**：`get_limit(i)` 在 `i==10` 时把上界砍掉三分之一，`randbelow` 的 rejection 行为改变；需要额外枚举 `extra10`（案例 0–7，命中 1）来补齐消耗。
- **Z3 恢复**：用 624 个 32 位 BitVec 表示 MT 状态，符号化 twist/temper；把 `full32`、`top28`、`top31` 观测作为约束；求解后 `random.Random().setstate(...)`，按已消耗的输出数前进，取下一次 `getrandbits(256)`，再 `SHA256(str(next256))` 派生 AES key 解密 flag。
- **为什么可行**：MT19937 是线性状态机，观测足够多时可唯一确定 624 个状态词；异常 oracle 解决了顺序问题，B0/B1 解决了随机流间隙问题，二者缺一不可。

## 触发条件

- 服务端使用 Python `random`/MT19937，且同一 seed 被多次重放。
- 攻击者能获得乱序的 `getrandbits` 输出、`random_prime` 结果与尝试次数（B0/B1），并能反复交互。
- `random_prime` 对参数 1 抛异常，且错误/异常信号可被攻击者区分。
- 攻击者能进行大量连接/并发（oracle 排序较慢），并有 Z3 求解环境。
- 最终密钥由 `SHA256(str(getrandbits(256)))` 派生，且密文可获取。

## 利用步骤

1. 用 `option 1` 拉取 `Key Part A`（乱序的 36 个 988-bit 值）、`B0`、`B1`。
2. 对每个位置 k，枚举剩余候选 `cand`，向 `option 2` 发送 `cand ^ get_limit(k) ^ 1`；若收到 `ValueError`/`n must be greater`/traceback，则该候选为当前位置的值。逐位确认并 checkpoint。
3. 把有序的 36 个 988-bit 值拆成 `full32`（30 个/值）与 `top28`（最后 28 bit）。
4. 按 `B1[i]` 在每轮后插入间隙；把 `B0[i]` 作为 `top31` 约束放在第 `B1[i]` 个间隙位置；对第 10 轮枚举 `extra10`。
5. 用 Z3 建立 MT19937 状态/ twist / temper 模型，加入上述观测约束；求解 624 个状态词。
6. `setstate` 后按总输出数前进，取 `getrandbits(256)`；`SHA256(str(next256))` 派生 AES key，解密最终密文。
7. 若某实例求解失败，重连换实例（不同 seed/布局）重试。

## PoC

```python
# 异常 oracle：候选 cand 命中当前真实 getrandbits(988) 时，服务端 random_prime(1) 抛错
send_value = cand ^ get_limit(k) ^ 1

# 988-bit 输出拆块
def split_988(v):
    return [(v >> (32 * i)) & 0xFFFFFFFF for i in range(30)] + [(v >> 960) & ((1 << 28) - 1)]

# Z3 约束（示意）
# full32: temper(state[pos]) == val
# top28:  LShR(temper(state[pos]), 4) == val
# top31:  LShR(temper(state[pos + gap - 1]), 1) == b0
# 求解后：
# rr = random.Random(); rr.setstate((3, tuple(state + [total % 624]), None))
# next256 = rr.getrandbits(256)
# key = sha256(str(next256).encode()).digest()
```

```text
# 案例：extra10=1, total_outputs=1956
# next256 = 10008324236482032701298949755825802170892553192271055426143845860770670696738
```

## 变体与关联

- oracle 变体：异常信号可换成超时、不同错误码、返回长度差异；核心是“让某个候选触发可区分分支”。
- 间隙变体：`random_prime` 可换成 `randbelow`、`shuffle`、`choice` 等消耗随机数的函数；需要知道每次消耗的数量或可从输出反推。
- 求解器变体：Z3、GF(2) 线性消元、pycryptosat；MT19937 的 twist/temper 可符号化，也可用 untemper + 线性方程。
- 关联：[[crypto-prng-mt19937-untemper-state-recovery-predict]]（基础 untemper 恢复）、[[ctf-crypto-mt19937-buggy-randbelow-z3-shuffle]]（截断 randbelow 的 Z3 恢复）、[[crypto-prng-mt19937-seed-recovery-lfsr-noise-batch-alignment]]（带干扰/批次对齐的恢复）。

## 检测与防御

- 检测：同一进程/种子重复生成随机数并暴露给客户端；异常输入触发 `random_prime`/`ValueError` 的可区分响应；大量短连接枚举候选；`getrandbits` 输出被直接返回。
- 防御：不要用 MT19937 生成密钥/令牌；使用 `secrets`/CSPRNG；每次会话使用独立随机种子；不要暴露原始随机输出或其哈希；对异常统一响应，避免 oracle。
- 加固：对敏感随机数做 HKDF 派生；限制交互频率与并发；密钥材料不落日志；定期轮换 seed。
