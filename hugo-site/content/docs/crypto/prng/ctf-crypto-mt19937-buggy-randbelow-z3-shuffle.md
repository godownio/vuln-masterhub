---
id: ctf-crypto-mt19937-buggy-randbelow-z3-shuffle
title: 魔改 _randbelow k=bit_length-1 导致输出截断：Z3 恢复 MT19937 状态并逆转 shuffle
type: scenario
domain: crypto
path: crypto/prng
technique: mt19937-buggy-randbelow-z3-shuffle
tags:
- ctf
- crypto
- prng
- mt19937
- z3
- symbolic-execution
- randbelow
- shuffle
- state-recovery
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:02:24+08:00'
  notes: 已对照原文全文核对：MT19937 结构/temper 逆转/625 输出索引修正/ExtendMT19937Predictor/GF(2) 矩阵法与文中代码一致；魔改 _randbelow k=bit_length-1、高 4/7 bit 泄露、Z3 约束与 Fisher-Yates 逆序均与文中 exp 一致。PoC 按原文重写未复跑；原文无图片、无受影响版本，未设置 versions；两卡 frontmatter 无 sources/source_url。
url: /docs/crypto/prng/ctf-crypto-mt19937-buggy-randbelow-z3-shuffle/
draft: false
kb_aliases:
- 魔改 random
- _randbelow_with_getrandbits
- k = bit_length - 1
- 高 4/7 bit 截断
- Z3 twist_z3
- 逆转 Fisher-Yates shuffle
---

## 一句话结论

题目把 Python `random._randbelow_with_getrandbits` 的 `k = n.bit_length()` 改成 `k = n.bit_length() - 1`，导致 `randrange(18)` 实际只取 `getrandbits(4)`（0..15）、`randrange(130)` 实际取 `getrandbits(7)`（0..127）；也就是说每次只泄露 MT19937 连续输出的高 4 bit 与高 7 bit。用 Z3 把 624 个状态词建成 32 位 BitVec，符号化 twist/temper 生成输出，再对每个 gift 字节枚举 `a`、推出 `b`，把 `out_a` 高 4 位与 `out_b` 高 7 位的约束用 `Or` 注入求解器；解出状态后重放魔改 `randbelow` 消耗随机数，并记录/逆序执行 Fisher-Yates 的交换，还原被 shuffle 的密文得到 flag。

## 原理

- **魔改 `_randbelow`**：原版 `k = n.bit_length()`，`getrandbits(k)` 覆盖 `[0, 2^k)` 并用拒绝采样保证 `< n`；改成 `k = n.bit_length() - 1` 后，`randrange(18)` 的 `k=4`，结果只有 0..15，`randrange(130)` 的 `k=7`，结果只有 0..127，永远满足 `< n`，不会拒绝。
- **截断泄露**：`a_i = randrange(18)` 等价于一次 `getrandbits(4)`，即 MT19937 输出 `out_a` 的高 4 bit；`b_i = randrange(130)` 是下一次输出 `out_b` 的高 7 bit。
- **Z3 建模**：用 624 个 32 位 BitVec `s_0..s_623` 表示初始状态；`twist_z3` 按 MT 的 `upper|lower`、`>>1`、条件异或 `MATRIX_A` 生成新状态；`temper_z3` 做四步 temper；`build_outputs` 按需 twist/extract，生成 2×len(gift) 个输出表达式。
- **约束**：每个 gift 字节 `value` 满足 `value = a ^ mask`，其中 `mask = pow(a, 2*i, 17) & 0xF`（题目自定义混合），`b = value ^ mask` 必须在 0..127；对每个合法 `a`（0..15）生成 `And(top4(out_a)==a, top7(out_b)==b)`，全部用 `Or` 连接加入 solver。
- **求解与重放**：`solver.check()` 得到 624 个状态词，`setstate((3, tuple(state+[624]), None))`；先重放 `len(gift)` 次魔改 `randbelow(18/130)` 消耗已用输出，再按 Fisher-Yates 生成 2024 轮交换；把交换按逆序应用回密文字符数组，得到明文 flag。
- **为什么有效**：截断只丢失低位，仍保留足够线性/非线性约束；Z3 能处理 twist 的位运算与条件异或，几千个输出足以唯一确定 624 个 32 位状态。

## 触发条件

- 目标使用 Python `random`/MT19937，且 `_randbelow_with_getrandbits` 被魔改为 `bit_length()-1` 或等价截断。
- 攻击者可获得大量 `randrange(n)` 结果（如 gift 字节、游戏输出），且知道 `n` 与混合公式。
- 输出位数虽被截断，但多个连续输出仍能提供足够约束。
- 后续操作（shuffle/加密）可由恢复的状态重放。

## 利用步骤

1. 确认 `randrange(n)` 的实际范围（如 18 -> 0..15），推断 `k=n.bit_length()-1` 与截断位数。
2. 收集 gift 字节与对应索引 i；确认 `value = a ^ (pow(a,2i,17)&0xf)` 等混合关系。
3. 用 Z3 建立 624 个 32 位状态、符号化 twist/temper/outputs；对每个 gift 枚举 a、计算 b，加入 `Or` 约束。
4. `solver.check()` 取模型，构造 `random.Random().setstate`；重放已消耗的 `randbelow` 调用。
5. 记录 Fisher-Yates 的 `(i,j)` 交换，逆序应用回密文，得到 flag。

## PoC

```python
from z3 import *

N, M, MATRIX_A = 624, 397, 0x9908B0DF
UPPER_MASK, LOWER_MASK = 0x80000000, 0x7FFFFFFF

def temper_z3(y):
    y = y ^ LShR(y, 11)
    y = y ^ ((y << 7) & BitVecVal(0x9D2C5680, 32))
    y = y ^ ((y << 15) & BitVecVal(0xEFC60000, 32))
    y = y ^ LShR(y, 18)
    return y

def twist_z3(mt):
    new_mt = []
    for i in range(N):
        y = (mt[i] & BitVecVal(UPPER_MASK, 32)) | (mt[(i + 1) % N] & BitVecVal(LOWER_MASK, 32))
        v = mt[(i + M) % N] ^ LShR(y, 1)
        v = If((y & BitVecVal(1, 32)) == BitVecVal(1, 32), v ^ BitVecVal(MATRIX_A, 32), v)
        new_mt.append(v)
    return new_mt

def build_outputs(initial_state, count):
    outputs, mt, idx = [], initial_state, N
    for _ in range(count):
        if idx >= N:
            mt = twist_z3(mt); idx = 0
        outputs.append(temper_z3(mt[idx])); idx += 1
    return outputs

def recover_state(gift):
    state = [BitVec(f"s_{i}", 32) for i in range(N)]
    outputs = build_outputs(state, len(gift) * 2)
    solver = Solver()
    for i, value in enumerate(gift):
        out_a, out_b = outputs[2 * i], outputs[2 * i + 1]
        a_top4 = Extract(31, 28, out_a)
        b_top7 = Extract(31, 25, out_b)
        cases = []
        for a in range(16):
            mask = pow(a, 2 * i, 17) & 0xF
            b = value ^ mask
            if 0 <= b < 128:
                cases.append(And(a_top4 == BitVecVal(a, 4), b_top7 == BitVecVal(b, 7)))
        if not cases:
            raise RuntimeError(f"no case at {i}")
        solver.add(Or(*cases))
        if i >= 2500:
            break
    assert solver.check() == sat
    model = solver.model()
    return [model.evaluate(x).as_long() for x in state]
```

重放与逆 shuffle：

```python
def buggy_randbelow(r, n):
    k = n.bit_length() - 1
    value = r.getrandbits(k)
    while value >= n:
        value = r.getrandbits(k)
    return value

r = random.Random()
r.setstate((3, tuple(recovered_state + [624]), None))
for _ in range(len(gift)):
    buggy_randbelow(r, 18)
    buggy_randbelow(r, 130)

swaps = []
for _ in range(2024):
    for i in reversed(range(1, len(c))):
        swaps.append((i, buggy_randbelow(r, i + 1)))

arr = list(c)
for i, j in reversed(swaps):
    arr[i], arr[j] = arr[j], arr[i]
print("".join(arr))
```

## 变体与关联

- 其他魔改：`k = bit_length` 但去掉拒绝采样、`getrandbits(k-1)`、取低位/取模；按实际泄露位建约束。
- 若截断位数更多（如只留 2 bit），需要更多样本或额外泄露；Z3 规模可能增大。
- 若 shuffle 使用 `random.shuffle` 而非手写 Fisher-Yates，注意其交换顺序/实现细节，按实际算法逆向。
- 关联：MT19937 untemper 状态恢复、PRNG 截断攻击、Z3 符号执行卡。

## 检测与防御

- 不要魔改 PRNG 内部函数；安全场景直接使用 `secrets`/`os.urandom`。
- 不要把随机数输出/截断结果成批暴露；对随机数派生值加 HMAC/加密。
- 若必须使用 `random`，使用官方实现并避免输出可预测的连续位；对 shuffle 密钥使用 CSPRNG。
