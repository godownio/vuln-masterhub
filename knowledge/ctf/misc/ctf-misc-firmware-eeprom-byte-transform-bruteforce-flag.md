---
id: ctf-misc-firmware-eeprom-byte-transform-bruteforce-flag
title: 固件 EEPROM 33 字节混淆串：单字节 XOR/ADD/SUB + ROL/ROR + NOT 组合爆破定位 flag
type: scenario
domain: ctf
path: ctf/misc
technique: firmware-eeprom-single-byte-transform-bruteforce
aliases:
- SmartCoffee
- EEPROM 混淆字符串
- 单字节变换爆破
- XOR/ADD/SUB 暴力
- ROL ROR NOT 组合
- 固件字符串还原
tags:
- ctf
- misc
- firmware
- eeprom
- obfuscation
- bruteforce
- xor
- hardware
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:22+08:00'
  notes: 已对照原文核对：byte_20E0[33] 字节数组、单字节 XOR/ADD/SUB×ROL/ROR×NOT 枚举、key=0x3B/post_not=True/rot=0 命中 QnQSec{...}，与原文反汇编/爆破输出一致。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

固件把 flag 以 33 字节数组存放在 EEPROM 区，运行时仅打印十六进制并提示“bytes are likely obfuscated”；对全数组枚举“单字节 key（0..255）× XOR/ADD/SUB × ROL/ROR(0..7) × 前后可选 NOT”的小变换空间，用可打印率与 flag 前缀评分，即可在约 0x3B 的 key 上还原出明文 flag。

## 原理

- **固件字符串混淆的常见形态**：为了不把 flag/口令以明文留在固件里，开发者常用一次性可逆变换处理整个字节数组：每字节 XOR 常量、加减常量、循环移位、按位取反，或这些操作的组合。它们都不改变数组长度，也不依赖位置/上下文，因此可以被逐字节枚举还原。
- **搜索空间很小**：单字节 key 256 种 × 3 种算术操作（XOR/ADD/SUB）× 8 种旋转（含 0）× 2 种前置 NOT × 2 种后置 NOT ≈ 2.4 万种组合；33 字节数组的每次变换只是 33 次运算，整个空间可在秒级跑完。
- **评分函数**：正确明文通常包含 `flag{`/`QnQSec{` 等前缀，且可打印 ASCII 比例接近 1.0。先按“包含 flag 前缀/关键字”精确命中，再按可打印率降序排列候选；两者结合可避免只靠可打印率误报。
- **位置无关性**：如果变换是逐字节的同一操作，还原后的每个字节独立恢复；若开发者用了两字节重复 key 或位置相关运算，需要把 key 长度与位置纳入搜索（本卡先覆盖单字节，两字节作为变体）。
- **为什么成立**：混淆算法必须可逆且足够简单才能在固件里低成本还原；攻击者不需要逆向出具体分支，只要枚举等价的变换空间并用明文统计特征筛选。

## 触发条件

- 拿到固件/EEPROM dump 或反汇编，能定位到保存密文的字节数组（如 `byte_20E0[33]`）。
- 程序对该数组只做打印/简单处理，提示“obfuscated”或没有明显解密函数；数组长度较短（几十字节）。
- 已知 flag 格式（如 `QnQSec{...}`/`flag{...}`），或可用高可打印率作为启发式。
- 变换是逐字节、位置无关的简单操作；若是多字节 key/位置相关，需要扩展搜索空间。

## 利用步骤

1. 在 IDA/Ghidra 中定位打印函数（如 `sub_11F0`）：循环 `printf("%02x", byte_20E0[n])`，并在末尾提示“bytes are likely obfuscated”。
2. 从 `.rodata`/`.data` 提取完整字节数组（本例 33 字节，起始 `95 AA 95 97 A1 A7 BF F7 ...`），确认没有额外的长度/校验字段。
3. 写爆破脚本：对 key 0..255、op ∈ {xor, add, sub}、rot 0..7（ROL/ROR）、pre_not/post_not ∈ {False,True} 生成变换结果。
4. 评分：优先匹配 `qnqsec{`/`flag{`/`ctf{` 等前缀；否则按可打印 ASCII 比例排序，输出 top 20。
5. 检查命中的候选（本例 key=0x3B、post_not=True、无旋转），确认明文语义与长度；必要时用同一变换验证相邻字符串/校验值。
6. 若单字节无结果，扩展到两字节重复 key、位置相关 XOR（`key[i % len]`）、base64 后再变换等组合。

## PoC

```python
data = [0x95,0xAA,0x95,0x97,0xA1,0xA7,0xBF,0xF7,0xBC,0x9B,
        0xB7,0xF7,0xB7,0xAA,0xB1,0xA9,0x9B,0xA7,0xF0,
        0xAA,0x9B,0xA0,0xF4,0x9B,0xAC,0xF0,0xB6,0xA0,
        0xB3,0xF0,0xB6,0xF7,0xB9]

def rol(b, n): return ((b << n) | (b >> (8 - n))) & 0xFF if n else b
def ror(b, n): return ((b >> n) | (b << (8 - n))) & 0xFF if n else b

def transform(bs, op, key, rot, pre_not, post_not, use_rol):
    out = []
    for b in bs:
        x = (~b) & 0xFF if pre_not else b
        x = (rol(x, rot) if use_rol else ror(x, rot)) if rot else x
        if op == "xor": x ^= key
        elif op == "add": x = (x + key) & 0xFF
        elif op == "sub": x = (x - key) & 0xFF
        if post_not: x = (~x) & 0xFF
        out.append(x)
    return bytes(out)

hits = []
for key in range(256):
    for op in ("xor", "add", "sub"):
        for rot in range(8):
            for pre in (False, True):
                for post in (False, True):
                    for use_rol in (True, False):
                        s = transform(data, op, key, rot, pre, post, use_rol)
                        score = sum(32 <= c <= 126 for c in s) / len(s)
                        low = s.lower()
                        if b"qnqsec{" in low or b"flag{" in low or score > 0.95:
                            hits.append((score, f"{op} key=0x{key:02X} rot={rot} pre={pre} post={post} rol={use_rol}", s))
for score, desc, s in sorted(hits, reverse=True)[:20]:
    print(f"{score:.3f} {desc} -> {s}")
```

```text
# 本例命中：key=0x3B，post_not=True，rot=0，op 为 XOR/ADD/SUB 之一
# 明文：QnQSec{3x_s3snum_c4n_d0_h4rdw4r3}
```

## 变体与关联

- 变体：两字节/多字节重复 key（`key[i % k]`），搜索空间变为 `256^k`，需先用已知明文片段缩小。
- 变体：位置相关 XOR（`key ^ i`、`key + i`）、base64/hex 解码后再变换；可把位置运算加入 `transform`。
- 变体：有校验和/CRC 时，可先用校验约束筛选候选，减少人工查看。
- 关联：[[ctf-reverse-byte-multiply-reverse-26-byte-check-inverse]]（逐字节可逆变换）、[[ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse]]（ROL 组合逆变换）、[[iot-hardware-bes2300-rom-bootloader-uart-dump]]（固件 dump 获取）。
- 边界：若变换依赖全局状态/密钥流/加密算法，简单枚举无效；若数组被压缩/加密，需要先解包。

## 检测与防御

- 检测（CTF）：固件中短字节数组被十六进制打印；字符串区出现高熵/非 ASCII；提示“obfuscated”。
- 修复（固件开发）：不要把 flag/密钥以可逆轻量混淆形式放在固件；至少使用设备唯一密钥的 AEAD 加密，并避免明文比较。
- 加固：对固件做安全启动与加密存储；泄露的字符串应使用 KDF 派生密钥，而不是单字节 XOR/移位。
