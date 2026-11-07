---
id: crypto-prng-mt19937-untemper-state-recovery-predict
title: MT19937 624 输出 untemper 恢复内部状态并预测后续随机数（含 GF(2) 矩阵法）
type: scenario
domain: crypto
path: crypto/prng
technique: mt19937-untemper-state-recovery
aliases:
- MT19937 状态恢复
- 梅森旋转预测
- untemper
- setstate
- ExtendMT19937Predictor
- GF(2) 矩阵求逆 temper
tags:
- crypto
- prng
- mt19937
- mersenne-twister
- untemper
- state-recovery
- prediction
- gf2
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:02:22+08:00'
  notes: 已对照原文全文核对：MT19937 结构/temper 逆转/625 输出索引修正/ExtendMT19937Predictor/GF(2) 矩阵法与文中代码一致；魔改 _randbelow k=bit_length-1、高 4/7 bit 泄露、Z3 约束与 Fisher-Yates 逆序均与文中 exp 一致。PoC 按原文重写未复跑；原文无图片、无受影响版本，未设置 versions；两卡 frontmatter 无 sources/source_url。
---

## 一句话结论

MT19937 的输出是内部 624 个 32 位状态词经过可逆 temper 变换得到的；收集连续 624 个 32 位输出，对每个输出逆 temper（unshiftRight 18 / unshiftLeft 15&0xefc60000 / unshiftLeft 7&0x9d2c5680 / unshiftRight 11）即可恢复完整状态，`random.Random().setstate((3, tuple(state+[624]), None))` 后即可预测后续所有输出；若有第 625 个输出，可枚举索引修正状态；自定义 temper 参数可用 GF(2) 矩阵求逆。

## 原理

- **MT19937 结构**：`n=624, m=397, a=0x9908b0df`；初始化 `register[i] = 0x6c078965 * (register[i-1] ^ (register[i-1] >> 30)) + i`；twist 把状态按 `(upper(i) | lower(i+1))` 旋转并异或 `a`；extract 对状态词做 temper：
  - `x ^= x >> 11`
  - `x ^= (x << 7) & 0x9d2c5680`
  - `x ^= (x << 15) & 0xefc60000`
  - `x ^= x >> 18`
- **可逆性**：每个 temper 步骤都是可逆的异或移位；`unshiftRight(x, shift)` 迭代 `res = x ^ (res >> shift)` 32 次；`unshiftLeft(x, shift, mask)` 迭代 `res = x ^ ((res << shift) & mask)` 32 次。按 temper 的逆序依次调用即可得到原始状态词。
- **状态恢复**：624 个输出对应一个完整周期；恢复后 `setstate` 的 state tuple 为 `(3, tuple(624 个 state + [624]), None)`，其中 `624` 是索引。
- **625 输出修正**：若第 625 个输出可用，可对候选索引 `i=1..625` 设置 state 并检查 `getrandbits(32)` 是否匹配，定位当前索引，避免状态偏移。
- **非 32 位输出**：`extend_mt19937_predictor.ExtendMT19937Predictor` 的 `setrandbits(x, bits)` 可处理 `getrandbits(128)` 等大块输出；按块恢复后 `predict_getrandbits(bits)` 预测后续。
- **自定义 temper**：把 32 个基向量 `1 << (31-i)` 过一遍 `extract_number`，组成 32×32 GF(2) 矩阵 `T`；对泄露值 `Z` 解 `T.solve_left(Z)` 即得状态位。适用于魔改移位/掩码但仍是线性变换的情况。
- **为什么有效**：temper 是 GF(2) 上的可逆线性变换，没有密钥；MT19937 不是密码学安全 PRNG。

## 触发条件

- 应用使用 Python `random`/MT19937 生成安全相关值（token、密钥、shuffle、验证码），且攻击者能获得连续/足够多的输出。
- 输出为 32 位或可拆成 32 位块；若输出经过截断/取模，需要更多样本或约束求解。
- 可预测后续输出或逆向依赖该随机数的操作（如 shuffle）。

## 利用步骤

1. 收集至少 624 个连续的 32 位输出（或等价位数的 `getrandbits` 块）。
2. 对每个输出调用 `untemper`，得到 624 个状态词；若状态索引未知，用第 625 个输出枚举修正。
3. `random.Random().setstate((3, tuple(state + [624]), None))`，向前验证已知输出。
4. 预测后续随机数，或逆向依赖它的算法（shuffle、token 生成）。
5. 若 temper 被魔改，构造 GF(2) 矩阵 `T` 并对每个泄露值 `solve_left`。

## PoC

```python
class MT19937Recover:
    def unshiftRight(self, x, shift):
        res = x
        for _ in range(32):
            res = x ^ (res >> shift)
        return res

    def unshiftLeft(self, x, shift, mask):
        res = x
        for _ in range(32):
            res = x ^ ((res << shift) & mask)
        return res

    def untemper(self, v):
        v = self.unshiftRight(v, 18)
        v = self.unshiftLeft(v, 15, 0xefc60000)
        v = self.unshiftLeft(v, 7, 0x9d2c5680)
        v = self.unshiftRight(v, 11)
        return v

    def go(self, outputs, forward=True):
        assert len(outputs) >= 624
        ivals = [self.untemper(outputs[i]) for i in range(624)]
        if len(outputs) >= 625:
            challenge = outputs[624]
            for i in range(1, 626):
                state = (3, tuple(ivals + [i]), None)
                r = random.Random(); r.setstate(state)
                if challenge == r.getrandbits(32):
                    result_state = state
                    break
        else:
            result_state = (3, tuple(ivals + [624]), None)
        rand = random.Random(); rand.setstate(result_state)
        if forward:
            for i in range(624, len(outputs)):
                assert rand.getrandbits(32) == outputs[i]
        return rand
```

GF(2) 矩阵法：

```python
def extract_number(x):
    x ^= x >> 11
    x ^= (x << 7) & 2636928640
    x ^= (x << 15) & 4022730752
    x ^= x >> 18
    return x & 0xffffffff

T = []
for i in range(32):
    x = 1 << (31 - i)
    x = extract_number(x)
    T.append(x.digits(2, padto=32)[::-1])
T = matrix(GF(2), T)

def untemper(leak):
    Z = matrix(GF(2), ZZ(leak).digits(2, padto=32)[::-1])
    X = T.solve_left(Z)
    return reduce(lambda x, y: (ZZ(x) << 1) + ZZ(y), list(X[0]))
```

## 变体与关联

- 输出不足 624：用 Z3/SMT、GF(2) 线性方程、或利用同进程其他泄露补齐。
- 输出被截断/取模：按截断位数建立约束；如只取高 4/7 bit，需要更多样本和求解器。
- 种子可枚举（时间戳、pid/uptime）时，优先做种子恢复而非状态恢复。
- 关联：MT19937 种子恢复、LCG 参数恢复、PRNG 预测卡。

## 检测与防御

- 安全场景不要用 `random`/MT19937；使用 `secrets`/`os.urandom`/CSPRNG。
- 不要向外暴露连续随机数输出；对 token/验证码/密钥使用带密钥的 PRF。
- 若必须用 MT19937，定期重新播种并混入高熵，避免输出可被收集。
