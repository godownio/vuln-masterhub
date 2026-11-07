---
id: crypto-prng-lcg-digit-charset-bytewise-state-recovery
title: LCG 状态逐字节恢复：利用后续消息只含数字字符的约束
type: scenario
domain: crypto
path: crypto/prng
technique: lcg-digit-charset-bytewise-state-recovery
aliases:
- LCG 状态恢复
- 线性同余生成器
- 数字字符串约束
- 模 2 的幂逐字节提升
- boringRNG
tags:
- crypto
- prng
- lcg
- state-recovery
- known-plaintext
- charset-constraint
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V214
  verified_at: '2026-11-07T04:21:07+08:00'
  notes: 已对照原文 boringRNG 段核对：M/A/C 常数、5 条密文、逐字节 lift_S1 算法与 flag{boring_challenge_3214a47a44} 均一致。未在本机执行 exp。
---

## 一句话结论

当 LCG 的模数 `M=2^n`、乘数 `A`、增量 `C` 已知，密文为 `m_i XOR S_i`，且后续若干条消息被约束为只含 ASCII 数字（`0x30`–`0x39`）时，可以从最低字节开始逐字节枚举初始状态 `S_1` 的候选，利用数字字符约束剪枝，最终唯一恢复 `S_1` 并解密全部消息（包括 flag）。

## 原理

- LCG 递推：`S_{i+1} = (A·S_i + C) mod M`，`M = 2^n`（文章 n = flag 长度 × 8，模数为 2 的幂）。
- 加密：`cipher_i = m_i XOR S_i`。已知 `cipher_i` 时，若知道 `S_i` 就能得到 `m_i`；反之，已知 `m_i` 的部分字符集可反过来约束 `S_i`。
- 关键性质：模 `2^k` 的运算只依赖低 k 字节。对 `S_1 mod 2^{8k}` 的每个候选，都能递推得到 `S_i mod 2^{8k}`，进而得到 `m_i mod 2^{8k}`（即消息的低 k 字节）。
- 逐字节提升：先枚举 `S_1` 的最低字节（256 种），用“第 2–5 条消息的低 1 字节必须是 `'0'..'9'`”过滤；保留下来的候选再扩展下一字节（每个候选 ×256），继续用低 2 字节的数字字符约束过滤；重复到 n 字节，候选收敛为唯一 `S_1`。
- 为什么约束足够强：每条随机消息的每个字节都必须落在 10 个数字字符上，5 条消息 × 每字节的 10/256 概率，能在很少的字节后把候选压到唯一；flag 消息不参与约束（只用于最后解密）。
- 恢复 `S_1` 后按完整 `M` 递推生成所有 `S_i`，与密文异或即得明文。

## 触发条件

- 已知 LCG 参数 `M`（2 的幂）、`A`、`C`，以及至少 2–5 条密文。
- 除 flag 外的消息格式已知且字符集受限（如纯十进制数字字符串），能对每个字节做 `0x30..0x39` 检查。
- flag 长度已知或等于最短密文长度；所有消息按同一 LCG 状态序列加密。
- 约束足够强（消息条数 × 长度）使候选唯一；否则需要更多已知明文/额外约束。

## 利用步骤

1. 从题目获取 `M`、`A`、`C` 与密文列表；确认 `M` 是 2 的幂（`n` 字节）。
2. 令 `mod_k = 256`，初始化候选 `S_1` 低字节集合为 0..255。
3. 对每个候选，按 `S_{i+1} = (A·S_i + C) mod mod_k` 递推得到各条消息的低 k 字节；检查第 2–5 条消息的每个字节是否都在 `0x30..0x39`，不满足则淘汰。
4. `mod_k *= 256`，把保留下来的候选扩展一个字节（`base + b<<(8*(k-1))`），重复步骤 3，直到 k=n。
5. 用唯一候选 `S_1` 在完整模 `M` 下递推，异或所有密文得到明文；第一条即 flag。

## PoC

文章 exp 的核心逻辑（简化）：

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes

M = 105312291668557186697918027683670432318895095400549111254310977536
A = 88374959429094291779410031678823825774338019588313091797786329067
C = 96051380126051117777593583876658604814834203814405720083455837449
ciphers = [bytes.fromhex(x) for x in [
    "674c6ac59d0703753f7ccd89e563d732866af287e3bb0a1abe92c0",
    "76791d13292326ad2e86ae69b9493aed416d8f71cd4a080164e3c3",
    "75e03966148fd58fe623ed5fc76f62e67c8ec4be72bb6ca4b057c9",
    "99201d1bd01631ce3a26687c14014030e0c2a6c01e8c1f2c115668",
    "e12611c1b6f104e2f9dd18fe10e688c2e4d9c1555b57c88959b38f",
]]
n = len(ciphers[0])

def lift_S1(M, A, C, ciphers):
    cs = [bytes_to_long(c) for c in ciphers]
    candidates = [0]
    mod_k = 1
    for k in range(1, n + 1):
        mod_k *= 256
        A_k, C_k = A % mod_k, C % mod_k
        new_cands = []
        for base in candidates:
            for b in range(256):
                S1 = base + (b << (8 * (k - 1)))
                S = S1
                ok = True
                for i, c in enumerate(cs):
                    m_low = (c ^ S) % mod_k
                    if i > 0:  # 后续消息必须是数字字符串
                        if any(not (0x30 <= bb <= 0x39) for bb in m_low.to_bytes(k, "big")):
                            ok = False
                            break
                    S = (A_k * S + C_k) % mod_k
                if ok:
                    new_cands.append(S1)
        candidates = list(set(new_cands))
    return candidates[0]

S1 = lift_S1(M, A, C, ciphers)
S = S1
for c in ciphers:
    print(long_to_bytes(bytes_to_long(c) ^ S))
    S = (A * S + C) % M
```

## 变体与关联

- 变体：消息约束可以是纯字母、十六进制、Base64 字符集、固定前缀；约束越强，恢复越快。
- 变体：若 `A`/`C` 未知但模数已知且前若干输出公开，可先恢复参数；见 [[crypto-prng-lcg-known-modulus-xor-keystream]]。
- 变体：模数不是 2 的幂时，逐字节提升不成立，需要格/Coppersmith 或分支定界；见 [[crypto-prng-truncated-lcg-coppersmith-lattice-cvp]]。
- 关联：[[crypto-prng-lcg-high16-state-recovery-enumeration]]、[[crypto-prng-lcg-parameter-recovery-delta-gcd]]。
- 边界：约束太弱（消息条数少、字符集大）时候选不唯一；密文长度/消息长度未知时需先确定字节数。

## 检测与防御

- 检测：CTF/审计中看到 `M=2^n`、`cipher = m XOR S`、后续消息为固定字符集的 LCG 题，即可套用逐字节恢复。
- 防御：不要用 LCG 直接做加密/密钥流；对状态/输出做密码学安全的 KDF 或使用 CSPRNG；避免让攻击者获得同一状态序列下的多条结构化明文。
- 加固：需要可证明安全时使用 AES-GCM/ChaCha20-Poly1305 等认证加密，而不是异或线性同余输出。
