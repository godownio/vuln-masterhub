---
id: ctf-reverse-modified-rc5-custom-p32-q32
title: 魔改 RC5 识别与解密：自定义 P32/Q32 轮常量 + 12 轮 + 半块交换逆推
type: scenario
domain: ctf
path: ctf/reverse
technique: modified-rc5-custom-p32-q32-decrypt
tags:
- ctf
- reverse
- rc5
- symmetric-crypto
- key-schedule
- custom-constants
- arx
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:31+08:00'
  notes: 已对照原文脚本核对自定义 P32=1766649740/Q32=1422508807、12轮、s_len=26、密钥打包与 right/left 半块顺序；本地分别运行原文与卡片 PoC，输出明文十六进制一致。修正了卡片把示例密钥/密文说成本题数据的表述（原文为 Example key/ciphertext）。未验证点：未在原始二进制上复现完整逆向。frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-modified-rc5-custom-p32-q32/
draft: false
kb_aliases:
- RC5 魔改
- 自定义 P32 Q32
- RC5 12 轮解密
- Lesscommon
- RC5 key schedule 逆向
---

## 一句话结论

当逆向题里的分组密码呈现出 RC5 的 `S[0]=P`、`S[j]=S[j-1]+Q`、`3*max(s_len,l_len)` 轮密钥混合与 32 位循环移位结构，但 `P32/Q32` 不是标准 `0xB7E15163/0x9E3779B9`、轮数是 12、且解密时左右半块顺序与标准实现相反时，必须按二进制里的自定义常量重建 S 表，并按它的 `ror32(left^right, right) - S[2k+1]` 逆轮逐块解密，才能得到 flag。

## 原理

- **RC5 骨架**：RC5 是 ARX 分组密码，密钥扩展先用两个魔数初始化 S 表（标准 `P=0xB7E15163`、`Q=0x9E3779B9`），再把密钥字 L 与 S 混合 `3*max(s_len,l_len)` 轮；加密轮为 `A = ((A ^ B) <<< B) + S[2i]`、`B = ((B ^ A) <<< A) + S[2i+1]`。
- **识别的关键特征**：
  - `S[0] = P32`、`S[j] = S[j-1] + Q32`；
  - 混合循环里出现 `rol32(A + B + S[i], 3)` 与 `rol32(A + B + L[j], (A+B)&31)`；
  - 轮函数只有异或、循环移位、加法。
- **本题魔改点**：`P32=1766649740`、`Q32=1422508807`（不是标准常量）；轮数 `rounds=12`、`s_len=2+2*rounds=26`；解密时先把密文 `block[0:4]` 解为 `right`、`block[4:8]` 解为 `left`（与常见的 `A/B` 命名顺序相反），逆轮后再交换回来，最后 `right-=S[0]`、`left-=S[1]`，输出 `right||left`。
- **为什么必须重写密钥扩展**：S 表完全由 P/Q 与轮数决定，用标准 RC5 实现会得到不同的轮密钥，解密结果全错；同理，半块顺序/移位方向抄错也会导致全错。
- **可逆性**：每轮 `new_left = ror32(left ^ right, right) - S[2k+1]`、`new_right = ror32(right ^ new_left, new_left) - S[2k]`，因为 RC5 的加法、异或、循环移位都可逆；按 `k=rounds..1` 逆序执行即可。
- **密钥/密文示例**：原文脚本的示例密钥为 `struct.pack('<4I', 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)`（即 MD5 初始状态常量按小端打包）、示例密文 48 字节；实际题目的密钥与密文需按附件和二进制现场提取。脚本按 8 字节分组解密并去 PKCS 式填充。

## 触发条件

- 拿到逆向题二进制或解密脚本骨架，识别出 RC5 的 S 表初始化/混合与 ARX 轮函数。
- 提取自定义 `P32/Q32`、轮数、密钥字节与密文；确认半块顺序与标准实现是否一致。
- 密文长度为 8 的倍数，且末尾可能有 PKCS 式填充。
- 有 Python 环境，可手写密钥扩展与解密。

## 利用步骤

1. 在反编译/汇编中定位 S 表初始化：找 `S[0]` 常量与 `S[j]=S[j-1]+const`，记录 P32/Q32。
2. 找混合循环次数与移位：`rol32(x,3)` 与 `rol32(x,(A+B)&31)` 确认 RC5 结构；记录轮数、`s_len`、`l_len`。
3. 提取密钥字节/字与密文；确认解密端解包顺序（本题 `block[0:4]` 为 right、`block[4:8]` 为 left）。
4. 按自定义常量重建 S 表，按逆轮公式从 `rounds` 到 1 逐块解密，最后减去 `S[0]/S[1]`。
5. 去掉 PKCS 式填充，按 UTF-8 输出明文；用 flag 格式验证。

## PoC

```python
import struct

def rol32(x, n):
    n &= 0x1F
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def ror32(x, n):
    n &= 0x1F
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def key_schedule(key, s_len):
    l_len = max(1, (len(key) + 3) // 4)
    L = [0] * l_len
    for i in range(len(key) - 1, -1, -1):
        L[i // 4] = ((L[i // 4] << 8) + key[i]) & 0xFFFFFFFF

    S = [0] * s_len
    S[0] = 1766649740          # 自定义 P32
    for j in range(1, s_len):
        S[j] = (S[j - 1] + 1422508807) & 0xFFFFFFFF  # 自定义 Q32

    A = B = 0
    i = j = 0
    for _ in range(3 * max(s_len, l_len)):
        A = S[i] = rol32((A + B + S[i]) & 0xFFFFFFFF, 3)
        B = L[j] = rol32((A + B + L[j]) & 0xFFFFFFFF, (A + B) & 0x1F)
        i = (i + 1) % s_len
        j = (j + 1) % l_len
    return S

def decrypt_block(block, S, rounds):
    right = struct.unpack("<I", block[0:4])[0]
    left = struct.unpack("<I", block[4:8])[0]
    for k in range(rounds, 0, -1):
        new_left = (ror32(left ^ right, right) - S[2 * k + 1]) & 0xFFFFFFFF
        new_right = (ror32(right ^ new_left, new_left) - S[2 * k]) & 0xFFFFFFFF
        left, right = new_left, new_right
    right = (right - S[0]) & 0xFFFFFFFF
    left = (left - S[1]) & 0xFFFFFFFF
    return struct.pack("<II", right, left)

key = struct.pack("<4I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
rounds = 12
S = key_schedule(key, 2 + 2 * rounds)
cipher = bytes([
    0x4C,0x6F,0xAB,0xF3,0x13,0x78,0xE2,0xF6,0x86,0x9D,0x1C,0x99,
    0xDE,0x85,0xCC,0x10,0xE8,0x28,0xEE,0x05,0x92,0x21,0x4B,0x34,
    0x43,0x28,0x17,0x3C,0x56,0x5B,0x73,0x51,0x9F,0x8A,0x1D,0x0F,
    0x97,0x34,0x2C,0x56,0x42,0x9F,0x69,0x48,0xA3,0xD5,0x8A,0xF5,
])
plain = b"".join(decrypt_block(cipher[i:i + 8], S, rounds) for i in range(0, len(cipher), 8))
pad = plain[-1]
if 1 <= pad <= 8 and plain.endswith(bytes([pad]) * pad):
    plain = plain[:-pad]
print(plain.decode(errors="replace"))
```

## 变体与关联

- **常量变体**：只改 P/Q 时，密钥扩展与解密结构不变；改轮数需同步 `s_len` 与逆轮起点。
- **结构变体**：RC6 增加乘法与寄存器轮转；RC5 的 `A/B` 顺序、解密端 `right/left` 命名容易被抄错，应以二进制为准。
- **密钥变体**：密钥可来自字符串、MD5/SHA 截断、异或/移位派生；需要从调用点确认。
- **关联**：[[ctf-reverse-vm-tea-interpreter-recovery]]（TEA 魔改 delta）、[[ctf-reverse-aes256-custom-rcon-key-schedule-decrypt]]（AES 自定义轮常量）、[[ctf-reverse-modified-rc4-rounds-sbox]]（RC4 轮数/S 盒改动）。

## 检测与防御

- **CTF 性质**：这是逆向题解法，不是真实漏洞；自定义常量只增加逆向难度。
- **真实场景**：不要自创/魔改分组密码常量来保密；使用标准算法与经过审计的库，密钥通过 KMS 管理。
- **检测**：静态识别 S 表初始化常量与 `rol32(x,3)` 混合循环，可快速判断是否为 RC5 变体。
