---
id: ctf-forensics-hex-png-stream-qr-chain-base64
title: 十六进制 PNG 流重组：QR 码链与 base64 解码
type: scenario
domain: ctf
path: ctf/forensics
technique: hex-png-stream-qr-chain-base64
tags:
- ctf
- forensics
- png
- hex
- qr-code
- base64
- image
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:16+08:00'
  notes: 已对照原文 Stomach Bug 核对：循环 hex PNG、|NNN| 编号、QR 链、base64 解码均一致；已修正 PoC 中“去掉编号”的实现（原正则会把 |000| 等编号数字当 hex 保留，导致 PNG 损坏），改为按行解析 |编号|hex；未实际运行。
url: /docs/ctf/forensics/ctf-forensics-hex-png-stream-qr-chain-base64/
draft: false
kb_aliases:
- 十六进制 PNG 流
- QR 码链
- 循环输出图片
- 编号分片标记
- Stomach Bug
---

## 一句话结论

服务端循环输出同一张 PNG 的十六进制文本，每行带 `|NNN|` 编号；按编号取第一组、去掉编号后 hex 解码得到一张大二维码，扫码得到第二张 PNG，再扫码得到 base64，解码即 flag。

## 原理

- PNG 文件头是 `89 50 4e 47 0d 0a 1a 0a`（hex `89504e470d0a1a0a`），文件尾是 `IEND` 块 `49 45 4e 44 ae 42 60 82`；这两个魔数可用于在长文本中定位一张完整 PNG。
- 服务端把 PNG 转成 hex，按固定长度切块并加 `|000|`、`|001|`… 编号；输出是循环的，第一张图结束后重新从文件头开始，所以只需取第一组。
- 重组：按编号排序、去掉前缀、拼接 hex、`bytes.fromhex` 写回 PNG。
- 二维码链：第一张 PNG 是大二维码，扫码内容不是 flag 而是另一张 PNG（可能是 base64/二进制），保存后继续扫码；最后一层是 base64 文本，解码得到 flag。
- 该场景是“编码链”而非加密：hex → PNG → QR → PNG → QR → base64 → flag；每层都要识别魔数/编码特征。

## 触发条件

- 服务端/附件输出大量 hex 文本，含 `|数字|` 分块标记，且周期性重复。
- 文本中出现 PNG/JPEG/ZIP 等文件魔数。
- 重组后的图像是二维码/条形码，扫码内容又是图像或编码文本。
- 题目提示“不断吐东西”“循环”“二维码”等。

## 利用步骤

1. 抓取输出，按行解析 `|编号|hex`；只取第一组编号（从 000 到该图结束）。
2. 按编号排序拼接 hex，`bytes.fromhex` 写入 `frame1.png`；用 `file`/`pngcheck` 确认。
3. 用 `zbarimg`/`pyzbar`/手机扫码识别 `frame1.png`；若内容是 base64 图片，先解码保存为 `frame2.png`。
4. 继续扫码，直到得到纯文本 base64。
5. base64 解码得到 flag。
6. 若扫码失败，检查图片是否被截断、hex 是否含换行/空格、编号是否从 1 开始、是否需取第二组循环。

## PoC

```python
import re
import base64
from pathlib import Path
from PIL import Image
from pyzbar.pyzbar import decode

raw = Path("download.txt").read_text(encoding="utf-8", errors="ignore")

# 1) 按行解析 |编号|hex，去掉编号后按编号拼接（循环输出时同一编号会覆盖，值相同）
parts = {}
for line in raw.splitlines():
    m = re.match(r"^\|(\d+)\|([0-9a-fA-F]+)$", line.strip())
    if m:
        parts[int(m.group(1))] = m.group(2)
hex_blob = "".join(parts[i] for i in sorted(parts))
Path("frame1.png").write_bytes(bytes.fromhex(hex_blob))

# 2) 逐层扫码；内容可能是图片 base64 或最终 base64 文本
data = Path("frame1.png").read_bytes()
for i in range(1, 6):
    Path(f"frame{i}.png").write_bytes(data)
    results = decode(Image.open(f"frame{i}.png"))
    if not results:
        break
    text = results[0].data.decode("utf-8", errors="ignore")
    print(f"layer {i}: {text[:80]}")
    try:
        data = base64.b64decode(text, validate=True)
    except Exception:
        print("FLAG:", text)
        break
```

## 变体与关联

- 变体：hex 换成 base64、原始二进制；分块标记换成 `---`、行号、长度头。
- 变体：QR 内容直接是 URL/文本，或嵌套多层图片/压缩包。
- 变体：PNG 被切片/置乱，需先还原图像再扫码。
- 关联：[[ctf-forensics-1bpp-qr-row-shift-frame-recovery]]（QR 行移位恢复）、[[ctf-forensics-barcode-png-multichannel-qr-row-rebuild]]（多通道 QR 重组）、[[ctf-misc-png-trailing-data-lcg-xor-base62]]（PNG 附加数据）。

## 检测与防御

- 检测：文本中出现 PNG/JPEG 魔数、`|数字|` 分块、周期性重复；图片中出现二维码。
- 防御：该场景是 CTF 编码链；真实系统对上传图片统一重编码/压缩可破坏隐写。
- 响应：若业务流量中出现循环 hex 图片流，按数据外带/隐写排查。
