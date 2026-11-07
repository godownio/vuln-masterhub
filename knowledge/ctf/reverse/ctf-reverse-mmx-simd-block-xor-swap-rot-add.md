---
id: ctf-reverse-mmx-simd-block-xor-swap-rot-add
title: MMX/SIMD 字节级块加密逆运算：XOR→奇偶交换→循环左移→逐字节加 key
type: scenario
domain: ctf
path: ctf/reverse
technique: mmx-simd-block-xor-swap-rot-add
aliases:
- MMXEncod
- pxor/psllq/psrlq/paddb
- 字节块加密
- butterfly
tags:
- ctf
- reverse
- simd
- mmx
- custom-cipher
- xor
- rotate
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:41+08:00'
  notes: 已对照原文与图 17 核对：64-bit 块、key MMXEncod、XOR→奇偶交换→循环左移→paddb 及逆序解密一致；未复跑附件。
---

## 一句话结论

样本把文件按 64-bit 块处理，每块依次与 64-bit key `MMXEncod` 逐字节 XOR、交换奇偶字节、整体循环左移 1 位、再逐字节加 key；这些操作由 SIMD `pxor/psllq/psrlq/por/paddb` 实现。逆运算按相反顺序做“减 key → 循环右移 1 → 交换奇偶字节 → XOR key”即可解密。

## 原理

- 加密每块 8 字节：
  1. `x[i] ^= key[i]`（`pxor`）；
  2. 交换 `x[0]↔x[1]`、`x[2]↔x[3]`、…（`m_psllqi`/`m_psrlqi` 移位后 `por` 拼回，等价于字节交换）；
  3. 64-bit 循环左移 1：`(x << 1) | (x >> 63)`，用 `psllq/psrlq/por` 实现；
  4. `x[i] = (x[i] + key[i]) & 0xff`（`paddb`）。
- 每一步都可逆：XOR 自逆；字节交换自逆；循环左移的逆是循环右移；模 256 加的逆是减。因此解密按相反顺序执行即可。
- 当块大小固定为 8 字节时，尾部不足 8 字节的块保持不变（样本实现如此），解密脚本需原样拼接。
- key 是 8 字节 ASCII `MMXEncod`，在静态分析中可直接从 `m128i` 常量或数据段读取。

## 触发条件

- 样本按 8 字节块处理文件，使用 MMX/SSE 指令做字节级 XOR、字节交换、64-bit 循环移位与加法。
- key 固定且在代码/数据段可见；操作顺序可由 F5 或动态调试确认。
- 有密文文件，且知道尾部不足块的处理方式。

## 利用步骤

1. 在 IDA 中定位主加密循环，确认块大小 8、key `MMXEncod` 以及四步操作顺序。
2. 记录 SIMD 指令对应的语义（`pxor`=XOR、`psllq/psrlq/por`=循环移位/字节交换、`paddb`=逐字节加）。
3. 按相反顺序实现解密：逐字节减 key → 64-bit 循环右移 1 → 交换奇偶字节 → XOR key。
4. 按 8 字节循环处理整个文件；不足 8 字节的尾部原样输出。
5. 输出明文，检查 `flag{` 前缀。

## PoC

```python
from pwn import u64, p64

key = b"MMXEncod"

def decrypt_block(block):
    x = [(block[i] - key[i]) & 0xff for i in range(8)]      # 逆 paddb
    v = u64(bytes(x))
    v = ((v >> 1) | (v << 63)) & 0xffffffffffffffff        # 循环右移 1
    x = list(p64(v))
    for i in range(0, 8, 2):                                # 逆字节交换
        x[i], x[i + 1] = x[i + 1], x[i]
    return [x[i] ^ key[i] for i in range(8)]                # 逆 pxor

buf = open("encode.dat", "rb").read()
out = bytearray()
for pos in range(0, len(buf), 8):
    block = list(buf[pos:pos + 8])
    out += block if len(block) < 8 else decrypt_block(block)
print(bytes(out))
```

说明：`u64/p64` 默认小端；若样本按大端解释块，需要相应调整。未在本机复跑原附件。

## 变体与关联

- **自定义 AES/SM4**：若轮函数是标准算法但 key schedule 被改，应先识别常量；见 [[ctf-reverse-aes128-aux-table-roundkey-recovery]]、[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]。
- **SIMD 混淆**：同样的四则/位运算可能被拆成多条 `psllq/psrlq/por`，关键是归一化成“字节 XOR/交换/循环移位/加法”语义。
- **块大小变化**：16 字节块（SSE）或 4 字节块（MMX 低半）只需改循环与掩码；尾部处理按程序实现。

## 检测与防御

- 检测：二进制中出现 `pxor`、`paddb`、`psllq/psrlq/por` 组合且按固定块循环，通常是自定义块加密。
- 分析：先识别 key 常量与块大小，再按操作逆序写解密器；不要直接套标准算法。
- 防御（对恶意样本）：自定义轻量加密只能提高分析成本；关键密钥不应硬编码在样本中。
