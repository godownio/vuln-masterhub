---
id: defense-forensics-sm4-c2-traffic-seed-prng-key-decrypt
title: SM4 C2 流量解密：4 字节种子经 PRNG 派生密钥字后还原加密命令
type: scenario
domain: defense
path: defense/forensics
technique: sm4-c2-traffic-seed-prng-key-decrypt
tags:
- defense
- forensics
- traffic
- sm4
- c2
- prng
- seed
- key-derivation
- reverse
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:13:45+08:00'
  notes: 已对照原文 SnakeBackdoor-5/6 与图25-29核对；发现并修正原文脚本 seed 笔误：流量字节 46 20 95 34 对应 srand 参数 0x34952046，已复算得 key=ac46fb61... 并解出 flag{6894c9ec-7l9b-46O5-82bf-4felde27738f}（0x46209534 生成不出该 key）。
url: /docs/defense/forensics/defense-forensics-sm4-c2-traffic-seed-prng-key-decrypt/
draft: false
kb_aliases:
- SM4 C2 流量解密
- 4 字节种子派生 SM4 密钥
- PRNG 生成 4 个 32 位密钥字
- 木马通信种子密钥
- SM4 ECB 流量还原
- 自定义 PRNG 密钥派生
---

## 一句话结论

木马与 C2 建连后先由服务端下发 4 字节随机种子，双方用同一套 PRNG（Park-Miller 种子扩展 + 加性滞后斐波那契）生成 4 个 32 位密钥字组成 16 字节 SM4 密钥，再用标准 32 轮 SM4 加密命令与回显；攻击者/取证人员只要在 pcap 中抓到明文种子，复刻 PRNG 即可还原密钥并解密全部通信。

## 原理

- **握手协议**：样本连接 C2（样例 `192.168.1.201:58782`）后，先接收 4 字节种子（样例流量字节为 `46 20 95 34`）；对种子做字节序转换后初始化 PRNG，生成 4 个 32 位随机数作为密钥参数，送入 `sub_13B4()` 按 SM4 的 T 变换与 S 盒扩展成轮密钥。复刻时 `srand` 实际使用 `0x34952046`（按网络字节序读入的 `0x46209534` 再经样本字节交换），WP 脚本中的 `0x46209534` 是读反字节序，按它生成不出后文密钥（已复算：`0x34952046` 才得到 `ac46fb61...`）。
- **PRNG 结构**：初始化 `r[1] = seed`，对 `i=2..31` 计算 `r[i] = 16807 * r[i-1] mod 2147483647`（Park-Miller 最小标准生成器）；随后用加性滞后斐波那契：`v = (r[f] + r[b]) & 0xFFFFFFFF`、`r[f] = v`、`f/b` 循环递增、返回 `(v >> 1) & 0x7FFFFFFF`。先空转 310 次，再取 4 个输出，按小端打包成 16 字节密钥。
- **为什么密钥可还原**：种子在握手阶段明文传输，PRNG 算法与参数固定在样本中；密钥不是硬编码，也不是 DH 协商，而是“种子 → 确定性 PRNG → 密钥字”的单向但可复刻推导。抓到种子即可离线生成同一密钥。
- **SM4 结构**：128 bit 分组、32 轮；密钥扩展 `rk[i] = K[i] ^ T'(K[i+1]^K[i+2]^K[i+3]^CK[i])`，`T'(x)=tau(x)^rol(x,13)^rol(x,23)`；轮函数 `X[i+4]=X[i]^T(X[i+1]^X[i+2]^X[i+3]^rk[i])`，`T(x)=tau(x)^rol(x,2)^rol(x,10)^rol(x,18)^rol(x,24)`；S 盒为 `d6 90 e9 fe ...`，FK 为 `a3b1bac6 56aa3350 677d9197 b27022dc`，CK 从 `00070e15` 起。
- **分组模式**：样例解密函数按 16 字节分组独立解密（ECB 风格），最后按 PKCS#7 去掉填充；若样本改为 CBC，需要在每块解密后与前一块密文异或，首块用 IV。
- **识别特征**：4 字节小包后紧跟 16 字节倍数的高熵数据；二进制中存在 SM4 的 FK/CK/S 盒常量；C2 端口固定、每次连接种子不同。

## 触发条件

- 已获取木马样本与对应 pcap，能定位 C2 的 IP/端口。
- 样本在握手阶段明文发送/接收 4 字节种子（未用 TLS 或额外封装）。
- 能复刻样本的 PRNG 算法与 SM4 参数（标准或从二进制提取的魔改表）。
- 密文为 SM4 分组加密，且知道分组模式/填充（可从样本代码或试解密判断）。

## 利用步骤

1. 在 Wireshark 中按 C2 IP/端口过滤：`ip.addr == <C2> && tcp.port == <PORT> && tcp.len > 0`。
2. 找握手阶段的 4 字节包：`... && tcp.len == 4`，记录种子值；样例为 `46 20 95 34`，复刻 PRNG 时用 `0x34952046`（不是把它直接读成 `0x46209534`）。
3. 按样本 PRNG 复刻：Park-Miller 初始化 32 个状态字，空转 310 次，再取 4 个输出，小端打包为 16 字节密钥。
4. 从样本二进制提取/确认 SM4 的 S 盒、FK、CK 与轮数；标准 SM4 可直接用现成实现。
5. 按 16 字节分组解密密文；ECB 直接解，CBC 先异或前块；去掉 PKCS#7 填充。
6. 解出的明文通常是命令或回显，按协议继续解析。

## PoC

```python
import struct

class Rand:
    def __init__(s, seed):
        s.r = [0] * 32
        s.r[1] = seed & 0xFFFFFFFF
        for i in range(2, 32):
            s.r[i] = (16807 * s.r[i-1]) % 2147483647
        s.f, s.b = 4, 1
        for _ in range(310):
            s.rand()

    def rand(s):
        v = (s.r[s.f] + s.r[s.b]) & 0xFFFFFFFF
        s.r[s.f] = v
        s.f = 1 if s.f >= 31 else s.f + 1
        s.b = 1 if s.b >= 31 else s.b + 1
        return (v >> 1) & 0x7FFFFFFF

def gen_key(seed: int) -> bytes:
    rng = Rand(seed)
    return b''.join(struct.pack('<I', rng.rand()) for _ in range(4))

seed = 0x34952046          # 流量字节 46 20 95 34 经样本字节交换后的 srand 参数
key = gen_key(seed)
print(key.hex())   # ac46fb610b313b4f32fc642d8834b456
```

```python
# SM4 解密核心（标准 S 盒/FK/CK）
import struct

SBOX = bytes([
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
    0xd5,0xdb,0x39,0xb8,0x31,0x11,0x0c,0x5a,0xcb,0x3e,0x0a,0x45,0xe5,0x94,0x77,0x5b,
    0x8d,0x6d,0x48,0x41,0x10,0xbd,0x09,0xc1,0x4a,0x89,0x0d,0x6e,0x97,0xa1,0x1d,0x16,
    0x0a,0xd9,0x88,0x6a,0x96,0xd1,0x6b,0x32,0x02,0x35,0x46,0x06,0x7d,0x65,0x49,0x8c,
    0xf0,0x3e,0x2d,0x7a,0x15,0xff,0x05,0x8e,0x01,0x84,0x3c,0x3a,0x38,0x53,0x87,0x7b,
    0x0b,0x2b,0x7e,0x0f,0xf6,0x69,0xa8,0x5a,0xb5,0x4c,0x1b,0x39,0x7f,0x08,0x8d,0x1c,
])
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
      0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
      0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
      0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
      0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
      0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
      0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
      0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279]

rot = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xffffffff
tau = lambda x: (SBOX[x & 0xff] << 24) | (SBOX[(x >> 8) & 0xff] << 16) | \
                (SBOX[(x >> 16) & 0xff] << 8) | SBOX[x >> 24]
L = lambda x: x ^ rot(x, 2) ^ rot(x, 10) ^ rot(x, 18) ^ rot(x, 24)
Lp = lambda x: x ^ rot(x, 13) ^ rot(x, 23)

def sm4_dec(ct: bytes, key: bytes) -> bytes:
    mk = [struct.unpack('>I', key[i*4:i*4+4])[0] for i in range(4)]
    k = [mk[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        rk.append(k[0] ^ Lp(tau(k[1] ^ k[2] ^ k[3] ^ CK[i])))
        k = k[1:] + [rk[-1]]
    pt = b''
    for blk in range(0, len(ct), 16):
        x = [struct.unpack('>I', ct[blk+i*4:blk+i*4+4])[0] for i in range(4)]
        for i in range(31, -1, -1):
            x = x[1:] + [x[0] ^ L(tau(x[1] ^ x[2] ^ x[3] ^ rk[i]))]
        pt += b''.join(struct.pack('>I', x[3-i]) for i in range(4))
    pad = pt[-1]
    return pt[:-pad] if 1 <= pad <= 16 else pt

key = bytes.fromhex("ac46fb610b313b4f32fc642d8834b456")
ct = bytes.fromhex("7f4b0ef4806983f164af6f46b71d3fce1e3c0bd00c4dd162b72c156f0f3aecd2afcabf551e08380db6fd20316f8a2729")
print(sm4_dec(ct, key).decode())
# flag{6894c9ec-7l9b-46O5-82bf-4felde27738f}
```

## 变体与关联

- 变体：种子可能大端/小端、PRNG 空转次数不同；以样本反编译为准。
- 变体：SM4 的 S 盒/FK/CK/轮数可能被魔改，需要从二进制 `.rodata` 提取；参见自定义 SM4 卡。
- 变体：分组模式为 CBC 时，首块用 IV，后续块与前一块密文异或。
- 关联卡片：[[ctf-reverse-custom-sm4-24round-native-so-decrypt]]、[[ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt]]、[[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]、[[defense-forensics-winos4-c2-frame-xor-decrypt]]。

## 检测与防御

- 检测：C2 连接建立后出现 4 字节明文种子，随后数据包长度为 16 的倍数且高熵。
- 检测：二进制中存在 SM4 的 FK/CK/S 盒常量，或在握手后调用 PRNG/密钥扩展。
- 检测：同一 C2 端口每次连接的种子不同，但密文均可由种子推导密钥解密。
- 防御：边界阻断 C2 地址/端口；对出站连接做 TLS 指纹与协议异常检测；监控“短握手 + 固定分组长度”的加密信道。
