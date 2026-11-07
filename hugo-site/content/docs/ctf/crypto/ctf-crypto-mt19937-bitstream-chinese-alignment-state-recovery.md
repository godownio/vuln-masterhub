---
id: ctf-crypto-mt19937-bitstream-chinese-alignment-state-recovery
title: MT19937 位流状态恢复：中文位才消耗 bit 的错位修正与 getrandbits(50000) 预测
type: scenario
domain: ctf
path: ctf/crypto
technique: mt19937-bitstream-chinese-alignment-state-recovery
tags:
- ctf
- crypto
- mt19937
- bitstream
- state-recovery
- prng
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:48:05+08:00'
  notes: 已对照原文 Noisy Forest 节核对：getrandbits(50000)、32-bit MSB-first 拼流、仅中文位消耗 bit、bit=1 码点 +9997、19968 bit=624 words、untemper/setstate、按非标点对齐会错位，均与原文 exp 一致。未验证点：PoC 未本机复跑（缺 ciphertext/ans 附件）；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-mt19937-bitstream-chinese-alignment-state-recovery/
draft: false
kb_aliases:
- MT19937 位流
- 中文位消耗
- getrandbits(50000)
- 位流错位修正
- Noisy Forest
---

## 一句话结论

题目用 `random.getrandbits(50000)` 生成位流，但**只有明文中文字符才消耗 1 bit**（bit=1 时码点 `+9997`，bit=0 不变，非中文不消耗）；因此不能按“每个非标点字符”对齐，而要用已知明文段提取出 624×32=19968 个 bit、untemper 恢复 MT19937 状态、克隆 RNG 预测剩余 bit，再按“中文位”规则还原全文并计算 SHA-256。

## 原理

- **位流生成**：`huge = random.getrandbits(50000)`；把 `huge` 按 32-bit 切块，每块 `format(v,'032b')` 拼成 `full_bit_stream`（MSB-first），等价于把 MT19937 连续 32-bit 输出按位展开。
- **加密规则**：遍历明文每个字符；只有“中文字符”（本题自定义范围 `'一' <= ch <= '龥'`）才消耗 1 个 bit：
  - bit=0：字符不变；
  - bit=1：字符码点 `+9997`；
  - 非中文：原样输出，**不消耗 bit**。
- **错位陷阱**：若按“除逗号句号外的所有字符都消耗 bit”来对齐，遇到非中文（数字、英文、标点）时不会消耗 bit，但错误实现会消耗，导致从某处开始整体错位，后续全盘乱码、SHA-256 对不上。
- **状态恢复**：Python `random` 是 MT19937，内部 624 个 32-bit 状态；拿到连续 624 个 `getrandbits(32)` 的 **tempered** 输出即可 `untemper` 还原状态。本题 19968 个 bit 正好对应 624 个 32-bit 输出。
- **预测**：`random.Random().setstate((3, tuple(state + [624]), None))` 克隆状态；继续 `getrandbits(32)` 补齐剩余 bit；再按“中文位”规则解密全文。
- **验证**：对还原明文计算 `sha256`，按题目格式 `LilacCTF{<sha256>}` 提交。

## 触发条件

- 题目给出密文与部分已知明文（或可猜的 flag 前缀/固定文本），加密逻辑是“按明文字符类型决定是否消耗 PRNG bit”。
- 明文以中文为主，非中文字符不消耗 bit；已知明文段包含足够多中文字符（≥19968 个 bit）。
- 程序使用 Python `random`/MT19937 且输出未做额外混淆；位流按 32-bit MSB-first 拼接。
- 可离线运行 Python `random` 并 `setstate`。

## 利用步骤

1. 读程序逻辑，确认 `getrandbits(50000)`、32-bit 切块、`format(v,'032b')` 的位序，以及“只有中文消耗 bit”的规则。
2. 用已知明文与密文逐字符对齐：对每个中文字符，比较 `ord(c)-ord(p)`：0→bit 0，9997→bit 1；非中文跳过、不消耗 bit。
3. 收集 `624*32=19968` 个 bit，按 32 位一组转成整数（MSB-first），得到 624 个 tempered 输出。
4. 对每个输出 `untemper`（逆向 `y ^= y>>11`、`y ^= (y<<7)&0x9d2c5680`、`y ^= (y<<15)&0xefc60000`、`y ^= y>>18`）得到状态。
5. `rng.setstate((3, tuple(state + [624]), None))`，继续生成剩余 `getrandbits(32)`，补齐 50000 bit。
6. 按“中文位”规则解密：对每个密文字符，若 `chr(ord(c)-9997)` 是中文或 `c` 本身是中文，则消耗一个 bit；bit=1 取 `-9997`，bit=0 保持原字符；非中文原样输出、不消耗。
7. 计算 `sha256(plain).hexdigest()`，拼成 flag；若 hash 不匹配，检查中文范围/位序/对齐起点。

## PoC

```python
import hashlib, random

MASK32 = 0xFFFFFFFF
def unshift_right_xor(y, shift):
    x = 0
    for _ in range(0, 32, shift):
        x = y ^ (x >> shift)
    return x & MASK32

def unshift_left_xor_and(y, shift, mask):
    x = 0
    for _ in range(0, 32, shift):
        x = y ^ ((x << shift) & mask)
    return x & MASK32

def untemper(y):
    y = unshift_right_xor(y, 18)
    y = unshift_left_xor_and(y, 15, 0xefc60000)
    y = unshift_left_xor_and(y, 7, 0x9d2c5680)
    y = unshift_right_xor(y, 11)
    return y & MASK32

def recover_state(outputs):
    st = [untemper(v) for v in outputs[:624]]
    rng = random.Random()
    rng.setstate((3, tuple(st + [624]), None))
    return rng

# 1) 从已知明文段提取中文位（示例：known_plain/ciphertext 已对齐）
bits = []
for p, c in zip(known_plain, ciphertext):
    if '一' <= p <= '龥':
        d = ord(c) - ord(p)
        if d == 0: bits.append('0')
        elif d == 9997: bits.append('1')
        else: raise ValueError("alignment error")
words = [int("".join(bits[i:i+32]), 2) for i in range(0, 624*32, 32)]
rng = recover_state(words)

# 2) 补齐剩余 bit（50000 bit 共 1563 个 32-bit 块）
full = "".join(bits[:624*32]) + "".join(f"{rng.getrandbits(32):032b}"
        for _ in range((50000 + 31)//32 - 624))
full = full[:50000]

# 3) 按中文位规则解密
out, bi = [], 0
for ch in ciphertext:
    back = chr(ord(ch) - 9997) if ord(ch) >= 9997 else None
    if back and '一' <= back <= '龥':
        b = int(full[bi]); bi += 1
        out.append(back if b else ch)
    elif '一' <= ch <= '龥':
        b = int(full[bi]); bi += 1
        out.append(chr(ord(ch) - 9997) if b else ch)
    else:
        out.append(ch)
plain = "".join(out)
print("LilacCTF{" + hashlib.sha256(plain.encode()).hexdigest() + "}")
```

说明：PoC 按原文的 `getrandbits(50000)`/中文位规则重写；`known_plain` 需足够长（≥19968 个中文 bit）。未在本机对附件复跑。

## 变体与关联

- **MT19937 其他恢复**：`getrandbits(k)` 的非 32 位输出、`randrange` 截断、`shuffle` 等需要额外建模；见 [[crypto-prng-mt19937-untemper-state-recovery-predict]]。
- **位序**：`format(v,'032b')` 是 MSB-first；若程序用 `int.to_bytes`/LSB-first，需反转每组 32 位。
- **字符规则**：中文范围可能不同（GB2312、Unicode 区间、正则 `一-鿿`）；按程序实际判断。
- **偏移**：`+9997` 可能换成其他常量；用已知明文差值确定。
- **关联**：[[ctf-crypto-mt19937-buggy-randbelow-z3-shuffle]]（MT19937 变体）、[[crypto-prng-mt19937-seed-recovery-lfsr-noise-batch-alignment]]（位流对齐）。

## 检测与防御

- **不要用 `random` 做密码学**：Python `random` 是 MT19937，可预测；密钥/令牌应使用 `secrets`/`os.urandom` 或 CSPRNG。
- **检测**：大量结构化明文、按字符类型条件消耗随机数、固定位流拼接等特征；CTF 中属于 PRNG 预测题。
- **防御**：加密前对 PRNG 输出做密码学哈希/HKDF，或直接使用流密码（ChaCha20）并保密 key/nonce。
