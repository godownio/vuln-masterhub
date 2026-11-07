---
id: ctf-reverse-twofish-table-dump-decrypt
title: Twofish 逆向：Q-box/MDS 查表识别、dump 表与逆向 16 轮 Feistel
type: scenario
domain: ctf
path: ctf/reverse
technique: twofish-reverse-table-dump-decrypt
tags:
- ctf
- reverse
- twofish
- feistel
- mds
- qbox
- block-cipher
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:47:41+08:00'
  notes: 已对照原文 C++++ 节核对：128-bit/16 轮 Feistel/4×uint32/前后 whitening、Q/SBOX+MDS 4×256 uint32、RS 编码、key WONDERFUL&&PEACE、密文 A204...FBD4、R12/RAX 表 dump 与 +0x20 对象头，均与原文 exp 一致。未验证点：PoC 未本机复跑，表 dump 依赖调试环境；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-twofish-table-dump-decrypt/
draft: false
kb_aliases:
- Twofish 逆向
- Twofish-128 解密
- Q-box MDS 表
- 16 轮 Feistel
- WONDERFUL&&PEACE
---

## 一句话结论

当逆向里看到 128-bit 分组、16 轮 Feistel、4 个 uint32 状态、轮间 swap、前后 whitening，以及 Q0/Q1 字节替换 + 4×256 uint32 MDS 查表 + RS 编码时，应识别为 Twofish；在调试时 dump MDS/Q 表、从内存取 key，再用逆向轮序（去输出 whitening → 15..0 轮 → 去输入 whitening）即可解密两段 16 字节密文。

## 原理

- **Twofish 结构**：128-bit block、16 轮 Feistel；每轮把状态分成 4 个 32-bit 字，轮函数 `g` 由 Q0/Q1 字节置换、MDS 矩阵乘法和 PHT 组成；key schedule 用 RS 编码生成 S-key，并派生 40 个 32-bit 子密钥（含输入/输出 whitening）。
- **识别特征**：
  - 4 个 uint32 组成状态，轮间交换两半（最后一轮不 swap）；
  - 轮内出现 `rol/ror`、`+ subkey`、`^`；
  - 轮函数 `gFunc` 是查表型：S-box/Q-box（256 字节）+ MDS（4×256 uint32）；
  - key schedule 出现 RS 编码、`0x0A0A0A0A`/`0x0D0D0D0D` 等常量。
- **本题**：外层是 .NET AOT/多维数组访问，产生大量边界检查噪声；真正逻辑是 Twofish-128。调试到 key schedule/加密初始化时，内存中能看到 key `WONDERFUL&&PEACE`（16 字节）。`R12` 指向 MDS 大表（0x1000 字节 = 1024 个 uint32），`RAX` 指向 Q/Sbox（0x200 字节 = 前 256 SBOX、后 256 INV_SBOX），跳过对象头（常见 +0x20）dump。
- **解密**：Twofish/Feistel 的轮函数不需要可逆；解密只需反向轮序：先 XOR 输出 whitening `K[4..7]`，然后 `j=15..0` 逆轮（注意还原 swap），最后 XOR 输入 whitening `K[0..3]`。
- **本题密文**：`A20492152735B4F6ECBAA359DB64417BDF277A73B085666034CF38E748D8FBD4`（32 字节，2 个 block），解密后去尾部 `0x00` 得到 flag。

## 触发条件

- 逆向程序出现 16 轮 Feistel + 4×uint32 状态 + Q/MDS 查表 + RS 编码/key schedule。
- 密文为 16 字节的整数倍（常见 32 字节）；输入被 padding 到固定长度。
- 能在调试器中定位并 dump MDS/Q 表（或从二进制数据区提取）。
- key 可从内存/字符串/调试断点取得。

## 利用步骤

1. 动态调试到 key schedule/加密初始化，定位 key 明文；本题为 `WONDERFUL&&PEACE`。
2. 在暂停时从 `R12`/`RAX` 指向的对象 dump 表：MDS 0x1000 字节、Q/Sbox 0x200 字节；跳过对象头（常见 +0x20）。
3. 用 key + RS 编码生成 S-key/ctx，派生 40 个子密钥 K（20 对）。
4. 对每个 16 字节 block：
   - `d = ct XOR K[4..7]`（去输出 whitening）；
   - `for j=15..0`：还原 swap（除最后一轮），计算 `F0=K[8+2j]+t0+t1`、`F1=K[8+2j+1]+t0+2*t1`，`d2=ror(d2,27)^F0`、`d3=ror(d3^F1,5)`；
   - `pt = d XOR K[0..3]`（去输入 whitening）。
5. 拼接所有 block，`rstrip(b"\x00")` 去 padding，解码得到 flag。
6. 用已知明文/加密函数复验（可选）。

## PoC

```python
import struct
from pathlib import Path

Q = Path("v31_q.bin").read_bytes()
SBOX, INV_SBOX = list(Q[:256]), list(Q[256:])
mds = list(struct.unpack("<1024I", Path("v30_mds.bin").read_bytes()))
MDS = [mds[i*256:(i+1)*256] for i in range(4)]

def rol32(x, r):
    r &= 31; x &= 0xFFFFFFFF
    return ((x << r) & 0xFFFFFFFF) | (x >> (32-r) if r else 0)

def ror32(x, r):
    r &= 31; x &= 0xFFFFFFFF
    return (x >> r) | (((x << (32-r)) & 0xFFFFFFFF) if r else 0)

def g_func(ctx_s, x, L_words=None):
    b0, b1, b2, b3 = x & 0xFF, (x>>8)&0xFF, (x>>16)&0xFF, (x>>24)&0xFF
    w0, w1 = (ctx_s[0], ctx_s[1]) if L_words is None else (L_words[0], L_words[1])
    a = SBOX[b0]; b = INV_SBOX[(a ^ (w1 & 0xFF)) & 0xFF]
    t = MDS[0][((w0 & 0xFF) ^ b) & 0xFF]
    a = INV_SBOX[b1]; b = INV_SBOX[(a ^ ((w1>>8)&0xFF)) & 0xFF]
    t ^= MDS[1][(((w0>>8)&0xFF) ^ b) & 0xFF]
    a = SBOX[b2]; b = SBOX[(a ^ ((w1>>16)&0xFF)) & 0xFF]
    t ^= MDS[2][(((w0>>16)&0xFF) ^ b) & 0xFF]
    a = INV_SBOX[b3]; b = SBOX[(a ^ ((w1>>24)&0xFF)) & 0xFF]
    t ^= MDS[3][(((w0>>24)&0xFF) ^ b) & 0xFF]
    return t & 0xFFFFFFFF

def decrypt_block(ct16, K, ctx_s):
    d0, d1, d2, d3 = struct.unpack("<4I", ct16)
    d0 ^= K[4]; d1 ^= K[5]; d2 ^= K[6]; d3 ^= K[7]
    for j in range(15, -1, -1):
        if j < 15:
            d0, d1, d2, d3 = d2, d3, d0, d1
        t0 = g_func(ctx_s, d0)
        t1 = g_func(ctx_s, rol32(d1, 8))
        F0 = (K[8+2*j] + t0 + t1) & 0xFFFFFFFF
        F1 = (K[8+2*j+1] + t0 + 2*t1) & 0xFFFFFFFF
        d2 = ror32(d2, 27) ^ F0
        d3 = ror32(d3 ^ F1, 5)
    return struct.pack("<4I", d0 ^ K[0], d1 ^ K[1], d2 ^ K[2], d3 ^ K[3])

# key schedule（RS encode + g_func 生成 40 个子密钥）按原文实现；
# 这里只展示解密轮，完整 make_ctx_and_subkeys 见原文脚本。
```

说明：PoC 展示表加载、g 函数与逆轮核心；RS 编码/密钥编排需按原文的 `rs_encode` + `make_ctx_and_subkeys` 补全。未在本机复跑。

## 变体与关联

- **Twofish-192/256**：key 长度不同，RS/key schedule 分支不同；128 位 key 用 even/odd 2 字路径。
- **Q0/Q1 顺序**：g 函数中 Q 置换的顺序（Q0/Q1、Q1/Q0）随 key 字节位置变化，dump 的 SBOX/INV_SBOX 要按题目实现对应。
- **MDS 表布局**：4×256 uint32，可能按列/行主序；dump 后先用已知测试向量验证。
- **AES/Blowfish 区分**：AES 是 SPN/10-14 轮、无 Feistel swap；Blowfish 是 16 轮 Feistel 但 key schedule 用 P/S 数组、无 Q/MDS/RS。
- **关联**：[[ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt]]（自定义 S-box AES）、[[ctf-crypto-self-referential-key-tea-variant]]（TEA/Feistel 变体）。

## 检测与防御

- 识别：二进制中出现 Twofish 的 Q/MDS 表、RS 编码常量、16 轮 Feistel；`findcrypt`/Ghidra 可辅助。
- 防护：对关键算法做白盒/混淆、把 key 放在安全硬件/服务端，不要硬编码在可调试进程里；CTF 中即使混淆，仍可通过内存 dump 还原。
- 取证：dump 表时注意对象头与字节序；保留原始二进制与表文件，记录 key 来源。
