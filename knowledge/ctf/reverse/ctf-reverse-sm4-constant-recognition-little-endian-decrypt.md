---
id: ctf-reverse-sm4-constant-recognition-little-endian-decrypt
title: 标准 SM4 逆向识别：FK/CK/Sbox 常量定位与小端字序解密
type: scenario
domain: ctf
path: ctf/reverse
technique: sm4-constant-recognition-little-endian-word-order
aliases:
- SM4 识别
- SM4 逆向
- 小端 SM4
- FK/CK/Sbox 常量
- ezSM4
tags:
- reverse
- sm4
- crypto
- constant-recognition
- endianness
- block-cipher
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V101
  verified_at: '2026-11-05T22:24:43+08:00'
  notes: 已对照原文核对：FK/CK/Sbox常量、固定key 12345678abcdefgh、密文4A5E46359608E930DA28CAA022A6594D、小端装字+逆序轮密钥解出SENSOREDS4Little均一致；未独立复跑。
---

## 一句话结论

逆向遇到 32 轮分组密码时，先在二进制中定位 SM4 的 `FK`、`CK`、`Sbox` 常量确认算法，再按程序实际使用的 32 位字装配字节序实现加/解密；本题的程序用 `memcpy` 风格的小端装字（而非常见教程的大端装字），照搬大端实现会得到错误明文，按小端重写后可直接由固定密钥和密文解出 `SENSOREDS4Little`。

## 原理

- **SM4 参数**：分组 128 bit、密钥 128 bit、32 轮。明文按 4 个 32 位字 `X0..X3` 处理，轮函数为 `X[i+4] = X[i] ^ T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i])`，其中 `T = L(tau(x))`，`tau` 是 4 字节 S-box 替换，`L(b) = b ^ rol(b,2) ^ rol(b,10) ^ rol(b,18) ^ rol(b,24)`。
- **密钥扩展**：`MK` 为主密钥 4 个字，`K[0..3] = MK ^ FK`，`K[i+4] = K[i] ^ T'(K[i+1]^K[i+2]^K[i+3]^CK[i])`，`rk[i] = K[i+4]`；`T' = L'(tau(x))`，`L'(b) = b ^ rol(b,13) ^ rol(b,23)`。加密与解密结构相同，解密只需把 32 个轮密钥逆序使用。
- **常量识别**：SM4 的 `FK` 为 `a3b1bac6 56aa3350 677d9197 b27022dc`；`CK` 从 `00070e15 1c232a31 383f464d 545b6269` 开始共 32 个；`Sbox` 是 256 字节固定表（首字节 `d6 90 e9 fe ...`）。在 IDA/Ghidra 中搜索这些常量、交叉引用到 32 轮循环和 4 字节替换，即可把“未知加密”还原为标准 SM4。
- **字节序陷阱**：标准资料通常把 16 字节明文按大端解释成 4 个 `uint32_t`，但本题的 `bytes_to_dwords_le`/`dwords_to_bytes_le` 直接用 `memcpy` 把字节按小端装入/取出。若密钥扩展、分组输入和输出中任何一处字节序用错，轮密钥与状态都会不同，最终明文错误。正确做法是：密钥扩展用 `little`，密文输入用 `little`，明文输出也用 `little`，且轮密钥逆序。
- **输出字序**：SM4 加密最后输出 `(X35, X34, X33, X32)`（逆序）；解密使用同一 `crypt_block` 并传入逆序轮密钥即可。若实现里输出顺序不同，需要按目标二进制调整，否则会得到字节反转的结果。
- **本题定位链**：字符串 `SM4`、`Correct.`、`Wrong Answer.` 与固定 key 提示 → 主校验函数 `0x140001960`；输入长度检查为 17（16 字符 + NUL）；固定 key `12345678abcdefgh`；目标密文 `4A5E46359608E930DA28CAA022A6594D`；在 `0x1400022d8`、`0x14000235a`、`0x140002490` 分别识别出 `FK`、`CK`、`Sbox`；`0x140002940` 为密钥扩展，`0x140002df0` 为轮函数。按小端实现解密得到 `SENSOREDS4Little`，按题目格式包成 `flag{...}` 提交。

## 触发条件

- CTF Reverse/Crypto 题：程序读取固定长度输入，硬编码密钥，把输入加密后与硬编码密文比较，输出 `Correct`/`Wrong Answer`。
- 二进制中包含 SM4 的 `FK/CK/Sbox` 常量，或可见 32 轮、4 字状态、循环移位等结构特征。
- 程序使用非标准字节序（小端装字）或非标准输出字序，直接套用公开库/教程会失败。
- 攻击者/分析者能静态提取固定 key 与目标密文；无需破解密钥本身。

## 分析步骤

1. 用 `strings`/IDA 搜索 `SM4`、`Correct`、`Wrong Answer`、`flag`，定位主校验函数与输入长度检查。
2. 在主函数附近提取固定密钥与目标密文；确认输入是 16 字节（可能额外要求 NUL 终止）。
3. 在 `.rdata` 搜索 `a3b1bac6`、`00070e15`、`d690e9fe` 等常量；交叉引用确认密钥扩展与轮函数。
4. 判断字节序：查看 `bytes_to_dwords`/`dwords_to_bytes` 是 `memcpy` 还是手工移位；本题为小端 `memcpy` 风格。
5. 实现 SM4：按目标字节序打包 `MK`，执行 32 轮密钥扩展；把密文按同样字节序打包为 `X0..X3`，用逆序轮密钥执行 32 轮；输出 4 个字并按目标字节序转回 16 字节。
6. 验证：用标准向量或程序自身加密路径交叉验证（例如把解出的明文再加密应得到原密文）。
7. 按题目格式提交（本题为 `flag{明文}`）。

## PoC

原文解密脚本（完整常量；未在本机执行）：

```python
SBOX = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
]

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269, 0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249, 0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229, 0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209, 0x10171e25,0x2c333a41,0x484f565d,0x646b7279,
]

def rol(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def tau(a):
    out = 0
    for i in range(4):
        out = (out << 8) | SBOX[(a >> (24 - 8 * i)) & 0xff]
    return out

def L(b):
    return b ^ rol(b, 2) ^ rol(b, 10) ^ rol(b, 18) ^ rol(b, 24)

def Lp(b):
    return b ^ rol(b, 13) ^ rol(b, 23)

def T(x):
    return L(tau(x))

def Tp(x):
    return Lp(tau(x))

def pack_words(bs, endian):
    return [int.from_bytes(bs[i:i+4], endian) for i in range(0, 16, 4)]

def unpack_words(ws, endian):
    return b''.join(w.to_bytes(4, endian) for w in ws)

def expand_key(key_bytes, endian):
    MK = pack_words(key_bytes, endian)
    K = [MK[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        val = K[i] ^ Tp(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i])
        K.append(val)
        rk.append(val)
    return rk

def crypt_block(block_bytes, rk, in_endian, out_endian):
    X = pack_words(block_bytes, in_endian)
    for i in range(32):
        X.append(X[i] ^ T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]))
    Y = X[35:31:-1]                 # 输出 X35..X32
    return unpack_words(Y, out_endian)

key = b"12345678abcdefgh"
ct  = bytes.fromhex("4A5E46359608E930DA28CAA022A6594D")

# 本题关键：小端装字；解密用逆序轮密钥
rk = expand_key(key, "little")
pt = crypt_block(ct, rk[::-1], "little", "little")
print(pt)   # b'SENSOREDS4Little'
```

## 变体与关联

- **算法识别变体**：AES 的 S-box/轮常量、SM4 的 FK/CK、SM3 的 IV、DES 的 IP/PC 表、RC4 的 256 字节 KSA；都可先用常量指纹识别，再处理字节序/填充/模式。
- **字节序变体**：大端装字、小端装字、逐字节替换、16 位字序、输出字逆序；用“已知明文/密文交叉验证”确定正确组合，而不是猜。
- **实现变体**：标准库、硬件指令、白盒 SM4、查表优化；查表实现可能把 S-box 拆成多张表，需按常量/索引关系识别。
- **关联卡片**：[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（固定密钥 AES 与密文复现）、[[code-analysis-reverse-vm-vmprotect-identification-behavior-analysis]]（同为“先识别算法/保护再还原”的逆向策略）。
- **边界**：本题为固定密钥 + 固定密文的 crackme，解出明文即可；真实场景中硬编码密钥可被直接提取，属于密钥管理缺陷而非密码算法破解。

## 检测与防御

- **防御方**：不要把密钥硬编码在客户端/二进制中；使用 KMS/安全元件/白盒密码并配合完整性校验；对敏感算法做混淆只能提高逆向成本，不能替代密钥保护。
- **分析方**：优先用常量指纹识别标准算法，再用标准库或已知向量验证字节序；对可疑的“魔改加密”，先确认是算法变体还是仅数据组织不同。
- **检测**：监控二进制中的高熵常量表、固定密钥字符串、`Correct/Wrong` 校验逻辑；对客户端加密逻辑做动态跟踪（Frida/调试器）确认输入输出字节序。
- **CTF 出题**：若要增加难度，可改字节序、输出字序或轮常量，但需保证题目可解；不要把“非标准字节序”误当成新算法。
