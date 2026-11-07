---
id: ctf-crypto-aes-sbox-duplicate-missing-byte-random-block-z3-base64
title: AES S-box 重复/缺失字节侧信道：区分随机块与密文 + z3 解双重 Base64 乱序表
type: scenario
domain: ctf
path: ctf/crypto
technique: aes-sbox-bug-random-block-oracle-z3-base64
aliases:
- AES S-box bug
- S 盒重复字节
- 0xCC 0xCE
- 随机块与密文区分
- 双重 Base64 乱序表
- z3 LShR Base64
tags:
- ctf
- crypto
- aes
- sbox
- side-channel
- z3
- base64
- bitvector
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:17:47+08:00'
  notes: 已对照原文 Crypto-base 段核对：S 盒 0xCC 重复/0xCE 缺失、最后一轮无 MixColumns、按固定位置 4500 样本去重（256 为随机块否则密文块）、两次 Base64+64 项乱序表、z3 LShR/& 拆分、UUID4 约束、md5=ec2783d8262e2621eece6e9e236479dc 均与原文 exp 一致。PoC 未本机复跑；原文未标注组件版本。
---

## 一句话结论

当题目按二进制位输出“纯随机块”或“AES 加密块”时，若 AES 实现的 S 盒把 `0xCC` 写了两次、`0xCE` 缺失，则最后一轮（无 MixColumns）的某个输出字节位置永远不会出现某个特定值；对同一位置取足够多样本（如 4500 个），随机块会覆盖全部 256 个值，AES 块则缺一个值，据此还原二进制串；再用 z3 的 `LShR`/`&` 解双重 Base64 乱序表并用 md5 过滤错误解。

## 原理

- **S 盒非双射**：标准 AES S 盒是 256 字节的置换；题目实现把 `0xCC` 重复、`0xCE` 缺失，导致 S 盒像集少一个值。最后一轮没有 MixColumns，输出字节 = `Sbox(input) XOR round_key`；对固定位置，输出也少一个值（缺失值被 round_key 平移）。
- **随机块 vs 密文块**：随机块在同一字节位置取 4500 个样本，几乎必然覆盖 0..255 全部值；AES 块则始终缺少那个特定值。`len(set(x[0::16])) == 256` 判为随机（bit 0），否则判为 AES 密文（bit 1）。
- **二进制串**：把所有块的判定位按顺序拼成 `c_bin`，再 `long_to_bytes(int(c_bin, 2))` 得到隐藏字符串；注意位序/填充，必要时反转或按字节对齐。
- **双重 Base64 + 乱序表**：隐藏字符串是 flag 经过两次 Base64 的产物，且输出符号表被一个 64 项置换 `V` 打乱。建模时：
  - `flag` 为 42 个 8 位 BitVec；按 UUID4 格式约束（`flag{`、`}`、固定位置的 `-`、版本位 `4`、变体位 `89ab`、十六进制字符）。
  - `B1 = b64_enc(flag)` 得到第一层 6-bit 值；用标准表映射成 56 个 ASCII 字符 `S_ascii`；`B2 = b64_enc(S_ascii)` 得到第二层 75 个 6-bit 值。
  - `V` 为 64 个互不相同的 0..63 BitVec；观测串 `C_STR[i]` 是标准表下标 `table.index(C_STR[i])`，满足 `V[table.index(C_STR[i])] == B2[i]`。
- **为什么用 `LShR`/`&`**：Base64 的 6-bit 拆分本质是逻辑右移和掩码；z3 的 `>>` 对 BitVec 是算术移位，负值会补 1，导致模型卡死/错误。改用 `z3.LShR(x, n)` 和 `x & 0x3f` 才是正确语义。
- **md5 过滤**：z3 可能给出多组满足约束的解；对每个候选算 md5，与题目给的哈希比对，唯一命中即 flag。

## 触发条件

- 题目提供“输出随机块或加密块”的 oracle/数据文件，块大小 16 字节。
- 可拿到加密实现源码（如 `aes.py`），能数出 S 盒重复/缺失；最后一轮无 MixColumns。
- flag 格式已知（UUID4），且经过两次 Base64/符号表打乱；有 md5 校验值。
- 有 z3（BitVec + LShR）环境。

## 利用步骤

1. 审计 AES 实现：统计 S 盒每个值出现次数，找出重复值与缺失值；确认最后一轮是否省略 MixColumns。
2. 对每个块按固定字节位置取样（如 4500 个块），统计该位置出现过的值；256 个值齐全 → 随机块；缺值 → AES 块。
3. 按样本顺序生成二进制串，转成字节串；确认位序（可能需要反转/字节对齐）。
4. 按“flag → Base64 → ASCII → Base64 → 乱序表”建 z3 模型；用 `LShR`/`&` 实现 6-bit 拆分；加 UUID4 格式约束。
5. `solver.check()` 后取模型，重建 flag；对候选算 md5，与目标哈希比对，排除多解。
6. 用原程序/题目校验接口验证。

## PoC

```python
import ast
import hashlib
import lzma
import z3
from Crypto.Util.number import long_to_bytes

# 1) 用 S 盒 bug 区分随机块/密文块
p = ast.literal_eval(lzma.open("output", "rt").read())
c_bin = "".join("0" if len(set(x[0::16])) == 256 else "1" for x in p)
C_STR = long_to_bytes(int(c_bin, 2)).decode()

# 2) z3 建模：flag -> Base64 -> ASCII -> Base64 -> 乱序表
s = z3.Solver()
flag = [z3.BitVec(f"f_{i}", 8) for i in range(42)]
V = [z3.BitVec(f"V_{i}", 8) for i in range(64)]
s.add(z3.Distinct(V))
for i in range(64):
    s.add(V[i] >= 0, V[i] < 64)

for i, c in enumerate(b"flag{"):
    s.add(flag[i] == c)
s.add(flag[41] == ord("}"))
for i in (13, 18, 23, 28):
    s.add(flag[i] == ord("-"))
s.add(flag[19] == ord("4"))
s.add(z3.Or([flag[24] == ord(c) for c in "89ab"]))
hex_idx = list(range(5, 13)) + list(range(14, 18)) + list(range(20, 23)) + \
          list(range(25, 28)) + list(range(29, 41))
for i in hex_idx:
    s.add(z3.Or(z3.And(flag[i] >= ord("0"), flag[i] <= ord("9")),
                z3.And(flag[i] >= ord("a"), flag[i] <= ord("f"))))

def b64_enc(data):
    res = []
    for i in range(0, len(data) - len(data) % 3, 3):
        res.extend([
            z3.LShR(data[i], 2),
            ((data[i] & 3) << 4) | z3.LShR(data[i + 1], 4),
            ((data[i + 1] & 15) << 2) | z3.LShR(data[i + 2], 6),
            data[i + 2] & 63,
        ])
    if len(data) % 3 == 2:
        res.extend([z3.LShR(data[-2], 2),
                    ((data[-2] & 3) << 4) | z3.LShR(data[-1], 4),
                    (data[-1] & 15) << 2])
    return res

table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B1 = b64_enc(flag)
S_ascii = [z3.BitVec(f"Sa_{i}", 8) for i in range(56)]
for i in range(56):
    for j in range(64):
        s.add(z3.Implies(B1[i] == j, S_ascii[i] == table[j]))

B2 = b64_enc(S_ascii)
for i in range(75):
    s.add(V[table.index(C_STR[i].encode())] == B2[i])

if s.check() == z3.sat:
    res = bytes([s.model()[f].as_long() for f in flag])
    if hashlib.md5(res).hexdigest() == "ec2783d8262e2621eece6e9e236479dc":
        print(res.decode())
```

## 变体与关联

- **S 盒异常变体**：重复/缺失值可能不同；用“统计像集大小 + 最后一轮结构”判断，不要硬编码 `0xCE`。
- **块分类变体**：随机源可能是 PRNG/噪声；样本量要足够大（每位置至少数百到数千），否则随机块也可能缺值。
- **Base64 变体**：可能一次/三次 Base64、换表、反转、URL-safe 表；按实际编码函数建模。
- **求解变体**：z3 位向量移位必须用 `LShR`；若仍慢，可手工拆 6-bit 或用 C 枚举部分变量。
- **关联卡片**：[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（AES 常量/ECB 识别）、[[ctf-reverse-base64-table-index-mutation]]（Base64 换表/索引魔改）、[[ctf-reverse-z3-constraint-equation-solve]]（z3 约束求解）。

## 检测与防御

- **检测特征**：自定义 AES 实现、S 盒非置换、最后一轮缺 MixColumns、oracle 返回固定长度块、flag 经过 Base64 换表。
- **修复**：使用标准 AES 库/经过测试的 S 盒；对 S 盒做双射/差分/线性测试；不要用“随机块/密文块”混合输出作为隐藏通道。
- **分析建议**：先验证 S 盒是否双射，再取样分类；z3 建模时先用小规模样例验证 `b64_enc` 与 Python `base64` 一致，再加格式约束。
