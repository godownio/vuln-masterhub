---
id: crypto-prng-custom-arx-state-recovery-predict
title: 自定义 4-word ARX PRNG 状态恢复：untemper 逆变换 + 连续输出反推并预测下一次
type: scenario
domain: crypto
path: crypto/prng
technique: custom-arx-prng-state-recovery-predict
aliases:
- 4-word ARX PRNG
- 自定义 PRNG 状态恢复
- untemper 逆变换
- 连续输出反推状态
- 预测下一次随机数
- rand.step 逆向
tags:
- prng
- state-recovery
- arx
- untemper
- prediction
- aes
- md5
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V182
  verified_at: '2026-11-06T20:13:42+08:00'
  notes: 已对照原文核对（含11张图片）；未运行 PoC；untemper 逆变换、状态反推公式与 gift 断言逐行匹配文中 exp
---

## 一句话结论

一个自定义 PRNG 用 4 个 64-bit 状态字做“异或 + 移位 + 循环左移”的 ARX 更新，每次返回旧 `s1` 再经过可逆的 `temper`（乘 13、rol 9、乘 11）；由于 temper 可逆、step 的更新关系是线性的，拿到连续 4 个输出即可 untemper 得到 4 个 `s1`，解出某一轮的状态并实例化，随后 `assert` 复现后续输出、再调用一次预测 AES key 所用的下一个随机数。

## 原理

### 状态更新与输出

题目实现（简化）：

```python
MASK64 = (1 << 64) - 1

def rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64

class rand:
    inv11 = pow(11, -1, 1 << 64)
    inv13 = pow(13, -1, 1 << 64)

    def __init__(self, s):
        self.s = s  # 4 个 64-bit word

    @staticmethod
    def temper(s1):
        return (rotl64((s1 * 13) & MASK64, 9) * 11) & MASK64

    @staticmethod
    def untemper(y):
        x = (y * rand.inv11) & MASK64
        x = rotl64(x, 64 - 9)
        x = (x * rand.inv13) & MASK64
        return x

    def step(self):
        s0, s1, s2, s3 = self.s
        result = s1
        x = (s1 >> 13) & MASK64
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3
        s2 ^= x
        s3 = rotl64(s3, 23)
        self.s = [s0, s1, s2, s3]
        return result

    def __call__(self):
        return rand.temper(self.step())
```

- `step()` 先保存 `result = s1`，然后按固定顺序更新 4 个状态字；`__call__` 返回 `temper(result)`。
- `temper` 是 `s1 → ((s1*13 mod 2^64) rol 9)*11 mod 2^64`。乘 13、乘 11 在模 2^64 下都有逆元（`inv13`、`inv11`），rol 9 的逆是 rol(64−9)，所以 `untemper` 可以精确还原每个输出对应的旧 `s1`。
- 攻击者拿到 `gift = [r(), r(), r(), r()]` 后，先 `raw = [untemper(g) for g in gift]`，得到 4 个连续的旧 `s1`（记为 r0,r1,r2,r3）。

### 反推状态

- `step()` 的更新只含异或、右移、循环左移，全部是 GF(2) 上的线性/仿射运算；给定 r0..r3，可以按更新顺序逐项消元，恢复某一轮的状态。
- 一种可行解（由连续输出解出 step 1 开始的状态）：

```text
s2_1 = r1 ^ r0 ^ (r0 >> 13)
s2_2 = r2 ^ r1 ^ (r1 >> 13)
s0_1 = s2_1 ^ r2 ^ r1
s0_2 = s2_2 ^ r3 ^ r2
s3_1 = s0_2 ^ s0_1 ^ r1
state_1 = [s0_1, r1, s2_1, s3_1]
```

- 用 `state_1` 实例化 `rand`，从它开始调用应依次得到 `gift[1], gift[2], gift[3]`；这三个等式就是校验解是否正确的最直接方式（错误的状态会在第一步就不匹配）。
- 校验通过后再调用一次 `r()`，得到题目用 `hashlib.md5(str(r()).encode()).digest()` 生成 AES key 的那个随机数。

### 为什么能预测

- PRNG 的全部状态只有 4×64=256 bit；每个输出虽然经过 temper，但 temper 是双射，等价于直接泄露旧 `s1`。4 个输出足以确定 4 个状态字之间的关系，从而恢复完整状态。
- 更新函数是确定性的、无外部熵输入；一旦状态恢复，后续所有输出都可预测。这与 MT19937 的 untemper/state recovery 思路相同，只是状态更小、更新函数是自定义 ARX。
- 题目用 `secrets.randbits(64)` 初始化，种子本身不可预测；但状态一旦通过输出泄露，种子就不重要了。

## 触发条件

- 目标使用自定义 PRNG（4 个 64-bit 状态字、线性 ARX 更新），输出经过可逆的 temper 变换。
- 攻击者能获得连续至少 4 个完整输出（本案例 `gift` 正好 4 个），且知道 PRNG 的更新/输出算法（源码或逆向）。
- 后续敏感值（AES key、token、验证码）由该 PRNG 的下一次或下几次输出派生。
- 64-bit 运算在模 2^64 下可逆，temper 的乘数 11、13 与 2^64 互素。

## 利用步骤

1. 从题目源码/逆向得到 `step`、`temper`、`untemper`；确认输出是 `temper(旧 s1)`。
2. 收集连续输出 `gift`；对每个输出调用 `untemper` 得到 `raw`。
3. 按 `step` 的更新顺序推导/使用状态恢复公式，构造某一轮的 `state`；用 `rand(state)` 复现 `gift[1..]` 做断言。
4. 断言通过后调用一次 `rand()`，得到下一个随机值；按题目派生方式（如 `md5(str(next).encode()).digest()`）生成密钥。
5. 用该密钥解密密文（案例为 AES-128-ECB），得到 flag。
6. 若输出有截断/只泄露部分位，需要更多输出并用格/SAT 求解；本例输出完整，直接代数恢复。

## PoC

```python
import hashlib
from Crypto.Cipher import AES

MASK64 = (1 << 64) - 1

def rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64

class rand:
    inv11 = pow(11, -1, 1 << 64)
    inv13 = pow(13, -1, 1 << 64)

    def __init__(self, s):
        self.s = s

    @staticmethod
    def temper(s1):
        return (rotl64((s1 * 13) & MASK64, 9) * 11) & MASK64

    @staticmethod
    def untemper(y):
        x = (y * rand.inv11) & MASK64
        x = rotl64(x, 64 - 9)
        x = (x * rand.inv13) & MASK64
        return x

    def step(self):
        s0, s1, s2, s3 = self.s
        result = s1
        x = (s1 >> 13) & MASK64
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3
        s2 ^= x
        s3 = rotl64(s3, 23)
        self.s = [s0, s1, s2, s3]
        return result

    def __call__(self):
        return rand.temper(self.step())

gift = [10985600798761172310, 3345325618133513476,
        2722881897911525365, 1527608446272288228]
enc_hex = ("55614b00a3e68ff9b53787f487ccf3c1"
           "92af93e0eaf55445fc5cdf9580d6ac64")

r = [rand.untemper(g) for g in gift]
s2_1 = r[1] ^ r[0] ^ (r[0] >> 13)
s2_2 = r[2] ^ r[1] ^ (r[1] >> 13)
s0_1 = s2_1 ^ r[2] ^ r[1]
s0_2 = s2_2 ^ r[3] ^ r[2]
s3_1 = s0_2 ^ s0_1 ^ r[1]
state = [s0_1, r[1], s2_1, s3_1]

prng = rand(state)
assert prng() == gift[1]
assert prng() == gift[2]
assert prng() == gift[3]

next_val = prng()
key = hashlib.md5(str(next_val).encode()).digest()
pt = AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(enc_hex))
print(pt.decode("utf-8", "ignore"))
```

案例解出 `DASCTF{fuNn9_r@nd_in_l1n3@r!!!!}`。

## 变体与关联

- **输出经过更多层变换**：若 `__call__` 在 temper 外再叠加 XOR/加法，先逆外层再 untemper；只要每层可逆，状态恢复思路不变。
- **只泄露部分位**：若输出被截断（例如只给低 32 位），4 个输出不足以直接解出 256-bit 状态；需要收集更多输出，用 GF(2) 线性方程/格/SAT 求解，或利用 `temper` 的乘法和移位约束做位级推理。
- **状态字更多/更新更复杂**：ARX 更新仍是 GF(2) 线性（异或、移位、循环移位），可用矩阵形式建立 256×256 的线性系统；非线性部分（如加法进位）才需要 SAT/SMT。
- **关联：MT19937 untemper**。`crypto/prng` 下已有 MT19937 untemper 状态恢复卡；本卡的状态更小，但“可逆输出变换 + 线性状态更新”的方法一致。
- **关联：LCG 状态恢复**。LCG 用模运算线性关系恢复；本卡用 XOR/移位线性关系恢复，二者都属于“输出泄露状态”的 PRNG 预测。
- **防御**：不要把 PRNG 输出直接当密钥/令牌；使用 CSPRNG（`secrets`/`os.urandom`/AES-CTR DRBG）；不要在输出中泄露完整内部状态；对令牌使用带密钥的 MAC/HMAC，而不是仅靠 PRNG 不可预测性。

## 检测与防御

- **代码审计**：搜索自定义 `class rand`、`temper/untemper`、`rotl64`、`step`、`secrets.randbits` 等实现；确认输出是否直接作为 key/token。
- **密码学评估**：任何非标准 PRNG 都应视为可预测；用连续输出做状态恢复测试（本卡 PoC），检查 4 个输出能否复现后续值。
- **CTF/审计检测**：拿到 `gift` 后先 untemper，再按更新顺序解线性方程；用 assert 复现后续输出，避免“公式对了但状态轮次错一位”。
- **修复**：改用标准 CSPRNG；若必须自定义，至少使用密码学安全的构造（如 ChaCha20/AES-CTR DRBG），并确保输出不泄露完整状态；密钥派生用 HKDF/PBKDF2，不要 `md5(str(rand()))`。
- **监控**：在协议中检测异常可预测的 token/验证码序列；对重复/线性相关的随机值告警。
