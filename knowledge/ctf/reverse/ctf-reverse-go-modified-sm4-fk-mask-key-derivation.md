---
id: ctf-reverse-go-modified-sm4-fk-mask-key-derivation
title: Go 魔改 SM4：FK 异或固定 MASK + 种子派生 16 字节 key 解密 .data 密文
type: scenario
domain: ctf
path: ctf/reverse
technique: go-modified-sm4-fk-mask-seed-key
aliases:
- meddddgo
- Go SM4 魔改
- FK ^ MASK
- SM4 key schedule 变体
- 种子派生 key
- HECTF meddddgo
tags:
- ctf
- reverse
- go
- sm4
- key-schedule
- mask
- key-derivation
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:37:13+08:00'
  notes: 已对照原文与图32-36核对：SM4 S-box/CK、MASK a5a5.../3c3c.../5a5a.../c3c3...、seed 0x1B75B0、密文0x1B77E0、key派生公式与flag一致
---

## 一句话结论

Go 二进制 `meddddgo.exe` 的加密逻辑是标准 SM4 的 32 轮结构，但密钥扩展的 FK 被异或了固定 MASK `[a5a5a5a5, 3c3c3c3c, 5a5a5a5a, c3c3c3c3]`；16 字节 key 不是直接输入，而是由 `.data` 中的 16 字节 seed 按 `k[i]=(11*i) ^ rol8(seed[(5*i+3)&0xF],1) ^ 0xA5` 再迭代 3 轮派生；按同样的 FK^MASK 与逆序轮密钥解密 `.data` 中的 32 字节密文即可得到 flag。

## 原理

- **识别 SM4**：二进制中出现标准 SM4 S-box（`d6 90 e9 fe ...`）、CK 表（32 个 32 位常量）以及 32 轮 `T(x)=L(τ(x))`、`L(b)=b^rol(b,2)^rol(b,10)^rol(b,18)^rol(b,24)` 的结构；Go 符号显示 `main.sbb3YLOJnc4`（轮函数）与 `main.aZ2oh0nY`（key schedule）。
- **魔改点**：标准 SM4 的密钥扩展初始化为 `K[0..3] = MK[0..3] ^ FK[0..3]`，其中 FK 是固定常量 `A3B1BAC6, 56AA3350, 677D9197, B27022DC`。本题在 FK 上再异或 `MASK = A5A5A5A5, 3C3C3C3C, 5A5A5A5A, C3C3C3C3`，即 `K[i] = MK[i] ^ (FK[i] ^ MASK[i])`；其余轮函数、S-box、CK、线性变换均与标准 SM4 一致。
- **key 的派生**：程序不读取用户输入，而是从 `.data:0x1B75B0` 取 16 字节 seed `1023456789abcdef013579bdf0224466`，按 `k[i] = ((11*i) ^ rol8(seed[(5*i+3)&0xF],1) ^ 0xA5) & 0xFF` 生成 16 字节；再重复 3 轮 `k[c] = ((k[(c+5)&0xF] + k[(c+1)&0xF] + 17*a) ^ k[c]) & 0xFF`。
- **密文**：`.data:0x1B77E0` 处 32 字节 `fc66b270e8874c9d734ecd5b766aa5896dda6cc5349d5f3b44b54aaf5ef9ce49`。
- **解密**：按魔改 FK 生成轮密钥，反转 32 个轮密钥，对每个 16 字节块做标准 SM4 解密；输出 `12d8b17b8ae52636a1211299451f9f6c`，套上 `flag{}` 即 flag。
- **为什么可行**：SM4 是对合结构（加密/解密仅轮密钥顺序相反），只要还原 key schedule 的魔改点与 key 派生，就能解密；S-box/CK 未变，说明出题人只改了“密钥进入轮函数”的那一层。

## 触发条件

- 目标是 Go 编译的 PE/ELF，包含 SM4 的 S-box/CK 与 32 轮结构，但 key schedule 常量被修改。
- 能找到 `.data` 中的 seed 与密文，或能从程序逻辑还原 key 派生。
- 已知/可推断 FK 的 MASK 值（通过反编译常量或与标准 FK 对比异或）。
- 密文长度是 16 的倍数，明文为可打印 ASCII/flag 格式。

## 利用步骤

1. **定位 SM4**：在 IDA 中搜索 S-box 字节序列 `d6 90 e9 fe ...`，交叉引用找到轮函数与 key schedule。
2. **对比标准 FK**：读取 key schedule 中使用的 4 个初始常量，与标准 FK 异或得到 MASK；本题 MASK 为 `A5A5A5A5 3C3C3C3C 5A5A5A5A C3C3C3C3`。
3. **提取 seed/密文**：从 `.data` 偏移 `0x1B75B0` 取 16 字节 seed，从 `0x1B77E0` 取 32 字节密文（或按 IDA 交叉引用确认）。
4. **复现 key 派生**：按 `k[i]` 公式生成 16 字节，再迭代 3 轮。
5. **解密**：标准 SM4 轮函数 + `K[i]=MK[i]^(FK[i]^MASK[i])`，轮密钥逆序，解出明文。
6. **验证**：明文可打印/含 flag 格式；必要时尝试 MASK 的字节序变体。

## PoC

```python
from pathlib import Path
import struct

exe = Path("meddddgo.exe").read_bytes()
SEED_OFF, CT_OFF, SBOX_OFF, CK_OFF = 0x1B75B0, 0x1B77E0, 0x1B80E0, 0x1B7C00
seed = exe[SEED_OFF:SEED_OFF+16]
ct = exe[CT_OFF:CT_OFF+32]
SBOX = list(exe[SBOX_OFF:SBOX_OFF+256])
CK = [struct.unpack_from("<I", exe, CK_OFF + i*4)[0] for i in range(32)]

def rol8(x, n=1):
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF

k = [0]*16
for i in range(16):
    k[i] = ((11*i) ^ rol8(seed[(5*i+3) & 0xF], 1) ^ 0xA5) & 0xFF
for a in range(3):
    for c in range(16):
        k[c] = ((k[(c+5) & 0xF] + k[(c+1) & 0xF] + 17*a) ^ k[c]) & 0xFF
key = bytes(k)

FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
MASK = [0xA5A5A5A5, 0x3C3C3C3C, 0x5A5A5A5A, 0xC3C3C3C3]
FKM = [FK[i] ^ MASK[i] for i in range(4)]

def rotl32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def tau(a):
    return ((SBOX[(a >> 24) & 0xFF] << 24) | (SBOX[(a >> 16) & 0xFF] << 16) |
            (SBOX[(a >> 8) & 0xFF] << 8) | SBOX[a & 0xFF])

def L(b):  return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)
def Lp(b): return b ^ rotl32(b, 13) ^ rotl32(b, 23)
def T(x):  return L(tau(x))
def Tp(x): return Lp(tau(x))

def key_schedule(key16):
    MK = [int.from_bytes(key16[i*4:(i+1)*4], "big") for i in range(4)]
    K = [MK[i] ^ FKM[i] for i in range(4)]
    rk = []
    for i in range(32):
        K.append(K[i] ^ Tp(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]))
        rk.append(K[i+4])
    return rk

def crypt_block(block16, rk):
    X = [int.from_bytes(block16[i*4:(i+1)*4], "big") for i in range(4)]
    for i in range(32):
        X.append(X[i] ^ T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]))
    return b"".join(w.to_bytes(4, "big") for w in [X[35], X[34], X[33], X[32]])

rk = key_schedule(key)[::-1]
pt = b"".join(crypt_block(ct[i:i+16], rk) for i in range(0, len(ct), 16))
print("flag{" + pt.decode() + "}")
```

原文输出：`flag{12d8b17b8ae52636a1211299451f9f6c}`。

## 变体与关联

- 变体：只改 FK、只改 CK、改 S-box、改轮数（24/16）、改线性变换旋转常量；key 可能来自环境变量/输入而不是 seed；MASK 可能按字节/字异或。
- 关联：[[ctf-reverse-custom-sm4-24round-native-so-decrypt]]（24 轮 + 自定义 S-box/FK/CK 的 SM4 变体）、[[ctf-reverse-aes256-custom-rcon-key-schedule-decrypt]]（自定义 key schedule 的另一类分组密码）、[[ctf-reverse-cpp-vtable-modified-tea-mask-xor]]（魔改 TEA + mask 的思路）。

## 检测与防御

- **CTF 之外**：不要用魔改标准算法做“安全加固”；算法实现应使用成熟库（Go `crypto/cipher` 无 SM4，需用合规实现）。
- **密钥管理**：不要从二进制中的固定 seed 派生密钥；密钥应随机、可轮换、受保护。
- **逆向对抗**：魔改常量只能增加分析成本；S-box/CK 保留标准值会直接暴露算法，建议出题时同时混淆表与轮函数。
- **检测**：对二进制中出现 SM4 S-box 但 key schedule 常量与标准 FK 不一致的样本，按“魔改 SM4”处理；提取 seed/密文后离线复现。
