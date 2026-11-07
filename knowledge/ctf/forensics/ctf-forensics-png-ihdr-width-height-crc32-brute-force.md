---
id: ctf-forensics-png-ihdr-width-height-crc32-brute-force
title: PNG IHDR 宽高 CRC32 爆破：文件头整体减一还原 + 正确宽高恢复
type: scenario
domain: ctf
path: ctf/forensics
technique: png-ihdr-width-height-crc32-brute-force
aliases:
- PNG 宽高隐写
- IHDR CRC 爆破
- 文件头减一
- 图片改宽高
- 好想吃炸鸡
tags:
- ctf
- forensics
- png
- ihdr
- crc32
- width-height
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:00:43+08:00'
  notes: 已对照原文『好想吃炸鸡』与图11-13核对：8A514F48=89504E47+1、整文件减一、stegsolve 显示 CRC=f4cbf11a 与 Calculated CRC=797d8e75 不一致、脚本以 crcbp[12:16](IHDR)+宽高+crcbp[24:29] 计算、枚举0..1999得 0x12c x 0x15f(300x351)、010改写后得到 sdpcsec{qUickLy_viVo_50}（图13）。卡片 PoC 的 IHDR 偏移16-19/20-23、24-28其他5字节、29-32 CRC 与 binascii.crc32 覆盖 type+data 均正确。未在本机复跑；无组件版本。
---

## 一句话结论

当图片没有扩展名且文件头是 `8A 51 4F 48`（PNG 正常头 `89 50 4E 47` 每字节 +1）时，先对整个文件做减一运算得到 PNG；若解码异常/CRC 不匹配，则用 IHDR 的 CRC32 反推真实宽高：固定其余 IHDR 字段，枚举宽高并计算 `crc32`，匹配当前 CRC 即得到正确尺寸，再改写宽高并重算 CRC。

## 原理

- **整文件字节偏移**：PNG 魔数 `89 50 4E 47 0D 0A 1A 0A`；样本为 `8A 51 4F 48 0E 0B 1B 0B`，每个字节都比正常值大 1。题目提示“加一元换购”暗示 +1，因此对全文件 `-1` 即可还原 PNG。
- **IHDR 结构**：PNG 第一个 chunk 是 `IHDR`，数据为 `width(4 BE) || height(4 BE) || bit depth || color type || compression || filter || interlace`，随后是 4 字节 CRC32。CRC 覆盖 `chunk type + chunk data`（即 `IHDR` 四个字母 + 13 字节数据）。
- **宽高隐写**：题目修改 width/height 但保留原 CRC，或用原 CRC 作为校验；解码器会发现 CRC 不匹配/显示区域被裁剪。已知 CRC 与其余字段时，宽高空间通常不大（本题 ≤2000），可暴力枚举 `(w,h)` 计算 CRC32 匹配。
- **为什么能恢复**：CRC32 是 32 位校验，宽高各 4 字节；在合理尺寸范围内唯一匹配的概率很高。找到后把宽高写回 IHDR，重算 CRC 并写回，PNG 即可正常显示隐藏区域。
- **注意**：CRC 覆盖范围是 `type+data`，不是整个文件；不同库的字节序/初值/异或要按 PNG 标准（zlib CRC32）计算。

## 触发条件

- 图片文件头/内容有固定偏移（如每字节 +1、异或、逆序），可通过魔数比对识别。
- PNG 解码异常、宽高与 IDAT 数据长度不一致、stegsolve/010 显示 CRC 不匹配。
- 已知 IHDR 的 CRC 与除宽高外的其他字段；宽高在可枚举范围内。
- 有 `binascii.crc32`/`zlib.crc32` 与字节编辑工具。

## 利用步骤

1. 用 010/`xxd` 查看文件头；若为 `8A 51 4F 48` 等“PNG 头 +1”，对整个文件每字节减一，保存为 PNG。
2. 打开 PNG；若显示异常/CRC 错误，定位 IHDR：偏移 8 为长度，12 为 `IHDR`，16-19 宽，20-23 高，24-28 其他字段，29-32 CRC。
3. 读取当前 CRC（如 `0xf4cbf11a`），固定 `IHDR` 类型 + 其他 5 字节，枚举 `w,h`（本题 0..2000）计算 `crc32(type+data)`。
4. 匹配到唯一 `(w,h)`（本题 `0x12c × 0x15f` = 300×351）后，把宽高写回 16-23，重算 CRC 写回 29-32。
5. 保存并解码，查看隐藏区域/二维码/flag；若仍异常，检查 IDAT 长度/滤色器/位深。
6. 本题得到 `sdpcsec{...}`。

## PoC

```python
import binascii
import struct
from pathlib import Path

raw = bytearray(Path("FriedChicken.png").read_bytes())

# 1) 文件头整体减一（若尚未还原）
if raw[:4] == bytes([0x8A, 0x51, 0x4F, 0x48]):
    raw = bytearray((b - 1) & 0xFF for b in raw)

# 2) IHDR: 16-19 width, 20-23 height, 24-28 其他 5 字节, 29-32 CRC
crc_target = struct.unpack(">I", raw[29:33])[0]
other = raw[24:29]

for w in range(2000):
    for h in range(2000):
        data = b"IHDR" + struct.pack(">II", w, h) + other
        if (binascii.crc32(data) & 0xFFFFFFFF) == crc_target:
            print("found", w, h)
            raw[16:20] = struct.pack(">I", w)
            raw[20:24] = struct.pack(">I", h)
            raw[29:33] = struct.pack(">I", binascii.crc32(b"IHDR" + bytes(raw[16:29])) & 0xFFFFFFFF)
            Path("fixed.png").write_bytes(raw)
            raise SystemExit
```

## 变体与关联

- **变体（CRC 不匹配但宽高正确）**：只重算 CRC 即可修复；或在 010 中直接改 CRC。
- **变体（宽高改小隐藏内容）**：真实画布比 IHDR 大，IDAT 扫描线长度可反推真实高度；也可用 `pngcheck` 报错定位。
- **变体（文件头变换）**：每字节 +1/-1、异或固定值、逆序、Base64；先用魔数比对确定变换。
- **关联卡片**：[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（伪造 IHDR 高度 + 重算 CRC）、[[ctf-forensics-png-lsb-column-major-scan-order]]（PNG LSB）、[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（其他隐写）。
- **边界**：宽高范围超过枚举上限、多个 `(w,h)` 同 CRC（概率低）时需结合 IDAT 长度/图像内容；CRC 计算范围/字节序错误会找不到。

## 检测与防御

- **CTF 识别**：图片打不开/显示被裁剪、CRC 不匹配、文件头有固定偏移，先试文件头还原 + IHDR CRC 爆破。
- **图像完整性**：真实场景用 PNG 校验工具检查 CRC；不要信任被修改的 IHDR。
- **实现**：CRC32 用 zlib 标准（初值 0xFFFFFFFF、反射、最终异或），覆盖 `type+data`；宽高用大端 32 位。
