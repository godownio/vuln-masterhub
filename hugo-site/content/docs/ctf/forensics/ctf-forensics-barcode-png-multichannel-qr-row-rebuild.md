---
id: ctf-forensics-barcode-png-multichannel-qr-row-rebuild
title: PNG 条形码多通道取数重建 21×21 QR：Comment/首行红通道 LSB 与 6 位 hex 低 21 位
type: scenario
domain: ctf
path: ctf/forensics
technique: barcode-png-multichannel-qr-row-rebuild
tags:
- ctf
- forensics
- png
- stego
- lsb
- barcode
- code128
- qr
- png-comment
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:21:05+08:00'
  notes: 已对照原文核对：21 张 Code128 PNG 的 Comment/首行红通道 LSB 给出 A-U+6hex+字母自校验、按字母排序取低 21 位重建 21×21 QR、解出 Wgs6GdF731LwhQz 并解 score.rar、PDF 提示 KEY+numberaboveline、第 3 行上方 4151515，均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-barcode-png-multichannel-qr-row-rebuild/
draft: false
kb_aliases:
- 条形码图片藏 QR 行
- PNG Comment 藏数
- 首行红通道 LSB
- 21x21 QR 重建
- 6 位 hex 低 21 位
- A-U 行号二维码
---

## 一句话结论

一组编号 A–U 的 21 张条形码 PNG 分别通过 Code128 文本、PNG Comment 或首行红色通道 LSB 给出 `AxxxxxxA` 形式的 6 位 hex；按字母排序后取每组低 21 位，即可拼出 21×21 的 QR Version 1，扫描结果就是下一层加密压缩包的口令。

## 原理

- QR Code Version 1 的模块矩阵正好是 21×21。每行 21 个模块可用 21 bit 表示，而 6 位十六进制是 24 bit，题目只用低 21 位承载一行，高 3 位可丢弃。
- 行号用字母 `A`–`U` 标记，且首尾字母相同（`A1fc97fA`），既给出排序键，也可做完整性校验（首尾字母不一致即丢弃）。
- 同一批数据被分散在三种载体里：Code128 条码内容、PNG `tEXt`/Comment 文本块、第 0 行像素红色通道最低位。任一条通道缺失时可用其他通道补齐，因此要同时采集而不是只跑 `zbarimg`。
- 首行 LSB 采用“首字节为长度、后续为 ASCII”的简单分帧；读取时按行优先逐像素取 `r & 1`，每 8 bit 大端打包。

## 触发条件

- 附件是一组同名编号的小图（条形码、色块、二维码碎片），数量为 21 或 21×21。
- PNG 带 Comment/文本块；或图像尺寸足够大、颜色单一，存在 LSB 隐写迹象。
- 题目后续出现“黑白琴弦/乐谱/二维码”等提示，说明第一层结果要用于解密下一层。

## 利用步骤

1. 用 `file`/`7z` 识别并解压外层压缩包，得到 `barcode_*.png` 与二层加密压缩包。
2. 对每张图并行采集三类候选：`zbarimg --raw`、`exiftool`/PIL 的 `img.info["Comment"]`、PIL 读取第 0 行红色通道 LSB。
3. 用正则 `^([A-U])([0-9a-fA-F]{6})\1$` 过滤候选，按首字母存入字典；缺行时回补其他通道。
4. 按 `A`–`U` 排序，对每组 `int(hex6, 16)` 取 `bits[-21:]`，得到 21 行 bit。
5. 以 4 模块 quiet zone、每模块放大若干倍画出 21×21 黑白图，`zbarimg`/pyzbar 扫描得到口令。
6. 用口令解二层压缩包，继续分析内层 PDF/文档中的隐藏提示。

## PoC

```python
from PIL import Image
import re

def first_row_red_lsb(path):
    img = Image.open(path).convert("RGBA")
    bits = [img.getpixel((x, 0))[0] & 1 for x in range(img.width)]
    raw = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for b in bits[i:i+8]:
            v = (v << 1) | b
        raw.append(v)
    if not raw:
        return ""
    return bytes(raw[1:1 + raw[0]]).decode("ascii", "ignore")

pat = re.compile(r"^([A-U])([0-9a-fA-F]{6})\1$")
rows = {}
for p in sorted(Path("outer").glob("barcode_*.png")):
    for text in (Image.open(p).info.get("Comment", ""), first_row_red_lsb(p)):
        m = pat.match(text.strip())
        if m:
            rows[m.group(1)] = m.group(2)

grid = [bin(int(rows[chr(65+i)], 16))[2:].zfill(24)[-21:] for i in range(21)]
# 将 grid 画成 21x21 图后交给 zbarimg 扫描
```

## 变体与关联

- **取数变体**：行数据可能藏在条码文本、PNG Comment、首行/末行/任意通道 LSB、IHDR 后附加块或调色板索引；hex 也可能取高 21 位或做 bit 反转。
- **矩阵尺寸变体**：QR Version n 的边长是 `21 + 4(n-1)`，若行数不是 21 应换算版本；也可能先做行列置换/掩码再扫描。
- **关联卡片**：[[ctf-forensics-1bpp-qr-row-shift-frame-recovery]]（帧缓冲二维码逐行位移还原）、[[ctf-forensics-png-lsb-column-major-scan-order]]（LSB 扫描顺序）、[[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]（PNG 结构修复）。
- **边界**：若图片经过有损压缩或缩放，LSB 会被破坏；条码文本可能只给出口令的一部分。

## 检测与防御

- **CTF 验证**：先确认 21 组数据齐全且首尾字母自校验通过，再重建 QR；扫描失败时检查 quiet zone、缩放与 bit 顺序。
- **防御**：不要把秘密放在 PNG 注释、像素 LSB 或条码文本中；对外图片统一重编码/压缩；DLP 与文件指纹系统检查异常 PNG 文本块和高频 LSB 噪声。
- **检测信号**：大量同尺寸图片、Comment 字段含非业务字符串、像素最低位分布偏离自然图像。
