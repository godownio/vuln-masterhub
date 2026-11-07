---
id: ctf-forensics-1bpp-qr-row-shift-frame-recovery
title: 1bpp 帧缓冲二维码还原：88x88 位图逐行左移 2y 再整体左移 24 像素
type: scenario
domain: ctf
path: ctf/forensics
technique: 1bpp-framebuffer-qr-row-shift-recovery
aliases:
- UnknownFirmware
- 1bpp 位图
- 88x88 二维码
- 帧缓冲行错位
- 逐行循环移位
- 二维码还原
tags:
- ctf
- forensics
- qr
- 1bpp
- framebuffer
- image-recovery
- row-shift
- telink
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:55:52+08:00'
  notes: 已对照原文 §UnknownFirmware 核对：976B 跳 8B、968*8=88*88、MSB-first、逐行 roll(-2y)、整体 roll(-24)、扫码 flag 均一致；未本机复跑。该题 flag 文本含 Telink 字样，但本卡聚焦 1bpp 图像行移位，与 92543 的 Telink TC32 CRC/AES 卡为同题不同环节，互补非重复。
---

## 一句话结论

976 字节文件跳过前 8 字节后剩 968 字节，`968*8 = 7744 = 88*88`，可按 1bpp 解成 88x88 黑白位图；图像每行相对上一行有固定错位，把第 `y` 行向左循环移动 `2*y` 像素，再整体向左移动 24 像素，即可得到可扫描的二维码并读出 flag。

## 原理

- 1bpp（每像素 1 bit）位图没有文件头时，需要根据数据长度推断宽高：`width * height = payload_bits`。案例 968 字节 = 7744 bit = 88×88，前 8 字节为头部/元数据，跳过。
- 位序需要尝试 MSB-first 与 LSB-first；案例按每字节从高位到低位展开（`for bit in range(7,-1,-1)`）。
- 行错位通常来自渲染时的滚动/偏移：第 y 行被循环左移了 `2*y` 像素，导致整体呈斜向纹理；逐行 `np.roll(row, -2*y)` 可以对齐。
- 对齐后二维码还可能整体偏移，需要再 `np.roll(fixed, -24, axis=1)` 把码图移到可扫描位置；偏移量可通过观察二维码的定位图案（三个角上的方块）估算。
- 渲染时把 1 映射为黑、0 映射为白（或反之），放大并加白边，便于扫码器识别；二维码的纠错能力可以容忍少量残留错位。

## 触发条件

- 拿到一段原始帧缓冲/位图数据，尺寸可由数据长度分解得到（如 `W*H = bits`）。
- 图像呈斜向条纹、二维码定位图案可辨认但整体错位。
- 能尝试不同的位序、行移位方向和偏移量。
- 二维码有足够的纠错级别，允许少量像素错误。

## 利用步骤

1. 读取二进制，检查前几个字节是否为全 0/固定头；跳过头部，计算剩余 bit 数。
2. 分解 `bits = W*H`，优先尝试正方形（如 88×88、128×128、256×256）。
3. 按 MSB-first 展开为 0/1 矩阵；若图像不像二维码，改试 LSB-first 或反色。
4. 观察斜向纹理的斜率，尝试逐行 `roll(row, -k*y)`（k=1,2,3...）以及正负方向。
5. 对齐后观察二维码定位图案，整体平移 `roll` 使码图居中/完整；尝试不同偏移量。
6. 渲染为放大后的黑白 PNG（加白边），用扫码器/`zbarimg`/手机扫描读取 flag；若失败，调整反色、阈值、纠错与偏移。

## PoC

```python
from pathlib import Path
from PIL import Image, ImageOps
import numpy as np

data = Path("decrypted_frame.bin").read_bytes()
payload = data[8:]

bits = []
for byte in payload:
    for bit in range(7, -1, -1):
        bits.append((byte >> bit) & 1)

raw = np.array(bits[:88 * 88], dtype=np.uint8).reshape(88, 88)

fixed = np.zeros((88, 88), dtype=np.uint8)
for y in range(88):
    fixed[y] = np.roll(raw[y], -2 * y)

fixed = np.roll(fixed, -24, axis=1)

img = Image.fromarray(np.where(fixed, 0, 255).astype(np.uint8), "L")
img = ImageOps.expand(img, border=8, fill=255)
img = img.resize((832, 832), Image.Resampling.NEAREST)
img.save("recovered_qr.png")
```

扫码得到 `NepCTF{U_Have_Dec0mpiled_Telink_FirmWareWooooW}`。

## 变体与关联

- 变体：位序可能是 LSB-first；1 可能表示白而不是黑；需要尝试反色。
- 变体：行移位可能是 `k*y + b`（带常数偏移），或按列/对角线错位；用定位图案的斜率估计。
- 变体：二维码可能被裁剪/旋转 90°/镜像；先尝试旋转与翻转，再扫码。
- 关联：[[ctf-forensics-fat16-deleted-noncontiguous-extent-recovery]]（二进制恢复）、[[ctf-forensics-midi-shared-tick-register-stego]]（载体隐写）、[[ctf-reverse-esp32-rf-trigger-frame-reconstruction]]（同场固件逆向）。

## 检测与防御

- 防御：帧缓冲/显示数据不要用固定可预测的行偏移作为“保护”；敏感信息不要仅靠图像错位隐藏。
- 防御：二维码内容应加密/签名，避免被直接扫描读取；显示后及时清屏。
- 检测：固件/文件中出现固定尺寸的 1bpp 位图、斜向纹理、二维码定位图案；提取后按行移位/反色枚举。
- 响应：发现隐藏二维码后按内容敏感性处理，检查同固件其他帧/分区是否还有隐藏图像。
