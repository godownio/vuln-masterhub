---
id: ctf-reverse-telink-tc32-crc-aes-qr
title: Telink TC32 固件逆向：CRC-CCITT 约束恢复 AES key + 解密数据区还原双 QR
type: scenario
domain: ctf
path: ctf/reverse
technique: telink-tc32-firmware-crc-aes-qr
aliases:
- REverse1
- unknownfirmware
- Telink TC32
- KNLT 固件
- CRC-CCITT 约束
- 硬件 AES-128-ECB
- 双二维码
tags:
- ctf
- reverse
- firmware
- telink
- tc32
- crc16
- aes
- qr
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:50:57+08:00'
  notes: 已对照原文 REverse1/unknownfirmware 核对：KNLT/Telink TC32、0x26a0 CRC-CCITT(init 0x5B25,poly 0x1021,prime 从 37,变换公式)、16 个 TARGETS、0xdb8 AES、0x3470+0x3d0 AES-128-ECB、2bit 展开 90 宽/双 41x41 QR 均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

固件头部有 `KNLT` 标记，普通 ARM/RISC-V 反汇编不对；识别为 Telink TC32 后使用 TC32 objdump 反汇编，在 `0x26a0` 输入处理函数中找到 16 字节 key 的 CRC-CCITT 逐字节约束，并在 `0xdb8` 附近确认硬件 AES 寄存器调用。按约束逐字节恢复 key 后，对 `0x3470` 开始的 `0x3d0` 字节做 AES-128-ECB 解密，把明文按 2 bit 一组（只允许 `00`/`11`）展开成 90 像素宽的位图，裁出左右两个 41×41 QR 并扫码，得到 flag。

## 原理

- **架构识别**：固件头 `KNLT` 不是常见 ARM/RISC-V；Telink TC32 是 TLSR 系列 SoC 的 32 位 RISC 内核，需用 TC32 工具链/objdump。识别错架构会导致反汇编完全无意义。
- **CRC 约束**：输入处理函数 `0x26a0` 对 key 的每个字节做变换 `transformed = ((prime + c) & 0xff) ^ (prime & 0xff)`，其中 `prime` 是逐字节递增的素数（从 37 开始），然后更新 CRC-CCITT 状态（初值 `0x5B25`，多项式 `0x1021`），要求结果等于 16 个目标常量。对每个字节枚举 0..255，只有一个候选满足目标 CRC，因此可逐字节恢复 key。
- **硬件 AES**：`0xdb8` 附近的代码写 AES 寄存器（key/data/control），确认是 AES-128-ECB；密文区 `0x3470` 长度 `0x3d0`。
- **QR 位图**：解密明文每字节按 2 bit 分组，合法值只有 `00` 或 `11`，映射为 0/1；按 90 像素宽展开成位图，左右两个 41×41 QR 分别位于 `(2,2)` 和 `(47,2)`。渲染成图片后用 pyzbar 解码，两个 QR 内容可能相同或互补，取唯一 flag。

## 触发条件

- 固件使用 Telink TC32 或类似非主流架构，需正确识别工具链。
- 存在逐字节 CRC/哈希约束可枚举恢复密钥（每步候选唯一）。
- 数据区用 AES-ECB 加密，key 由上述约束恢复。
- 明文是二值/QR 位图，可按固定宽度/偏移切分。

## 利用步骤

1. 读取固件头，识别 `KNLT`/Telink TC32；用 TC32 objdump 反汇编。
2. 定位输入处理函数 `0x26a0`，恢复 CRC 初值、素数序列、变换公式与 16 个目标值。
3. 逐字节枚举 0..255，按 CRC 更新匹配目标，恢复 16 字节 key。
4. 定位硬件 AES 调用 `0xdb8`，确认 AES-128-ECB；对 `0x3470 + 0x3d0` 解密。
5. 把明文按 2 bit 分组（只接受 0/3），展开 90 宽位图，裁出两个 41×41 QR，渲染并扫码。
6. 取唯一 flag。

## PoC

```python
from Crypto.Cipher import AES
from PIL import Image
from pyzbar.pyzbar import decode

TARGETS = [0x925B, 0x824C, 0xEB7A, 0xB5FC, 0xA885, 0xC3B4, 0xB230, 0xEDCD,
           0x2CCE, 0xE4B3, 0xCD97, 0x4CFD, 0x0E5E, 0x0834, 0xA3B8, 0xB040]

def crc16_ccitt_update(data, state):
    state &= 0xFFFF
    for b in data:
        state ^= b << 8
        for _ in range(8):
            state = ((state << 1) ^ 0x1021) & 0xFFFF if state & 0x8000 else (state << 1) & 0xFFFF
    return state

def next_prime_gt(n):
    n += 1
    while any(n % d == 0 for d in range(2, int(n ** 0.5) + 1)):
        n += 1
    return n

def recover_key():
    state, prime, key = 0x5B25, 37, bytearray()
    for target in TARGETS:
        prime = next_prime_gt(prime)
        hits = []
        for c in range(256):
            transformed = ((prime + c) & 0xFF) ^ (prime & 0xFF)
            if crc16_ccitt_update(bytes([transformed]), state) == target:
                hits.append(c)
        assert len(hits) == 1
        key.append(hits[0])
        state = target
    return bytes(key)

def render_qr(matrix, path, scale=12, quiet=4):
    h, w = len(matrix), len(matrix[0])
    img = Image.new("1", ((w + 2*quiet)*scale, (h + 2*quiet)*scale), 1)
    px = img.load()
    for y, row in enumerate(matrix):
        for x, bit in enumerate(row):
            color = 0 if bit else 1
            for yy in range(scale):
                for xx in range(scale):
                    px[(x+quiet)*scale+xx, (y+quiet)*scale+yy] = color
    img.convert("L").save(path)

def extract_bits(plain):
    bits = []
    for b in plain:
        for shift in (6, 4, 2, 0):
            pair = (b >> shift) & 3
            assert pair in (0, 3)
            bits.append(1 if pair == 3 else 0)
    width = 90
    height = (len(bits) + width - 1) // width
    bits += [0] * (width * height - len(bits))
    return [bits[i*width:(i+1)*width] for i in range(height)]
```

## 变体与关联

- 其他非主流 MCU 架构：ESP8266/ESP32 Xtensa、8051、MSP430、RISC-V；先看向量表/字符串/工具链签名。
- CRC 约束可换成哈希/校验和/白盒 S-box；逐字节枚举 + 唯一性验证的思路通用。
- AES 可换成硬件 SM4/DES/自定义；先定位寄存器写入序列确认算法。
- 关联：固件逆向、CRC 约束密钥恢复、QR 位图提取卡。

## 检测与防御

- 固件发布时移除调试符号/明文密钥；密钥不要由可枚举的 CRC 约束派生，使用安全 KDF/安全存储。
- 对固件做完整性签名与加密，防止离线提取数据区；敏感数据不要只做 AES-ECB（无完整性）。
- 检测：固件中出现 `KNLT`/硬件 AES 寄存器序列、大量 CRC 查表；二维码/位图在固件数据区中的高熵块。
