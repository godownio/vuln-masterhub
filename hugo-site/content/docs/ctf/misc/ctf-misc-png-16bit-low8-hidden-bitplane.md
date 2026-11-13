---
id: ctf-misc-png-16bit-low8-hidden-bitplane
title: PNG 16-bit 通道低位隐藏：取每通道低 8 位重建隐藏图像（funnypng）
type: scenario
domain: ctf
path: ctf/misc
technique: png-16bit-low8-hidden-bitplane
tags:
- ctf
- misc
- stego
- png
- bit-depth
- 16bit
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:20:22+08:00'
  notes: 已对照原文核对：funnypng位深度48bit(每通道16bit)、d%256取低8位重建front.png、再取原图与重建图最低位拼370x370二值图(qr.png)的代码与卡片一致；图10仅为LSB原理示意；与PNG IDAT/LSB等卡载体维度不同非同链；未验证点：无funnypng样本，未实际运行
url: /docs/ctf/misc/ctf-misc-png-16bit-low8-hidden-bitplane/
draft: false
kb_aliases:
- PNG 位深度隐写
- 48bit PNG 低位
- funnypng
- 低 8 位隐藏图像
- png.Reader 位深度提取
---

## 一句话结论

当 PNG 的位深度为 48 bit（RGB 每通道 16 bit）而肉眼/常见查看器只显示每通道高 8 bit 时，隐藏数据可能位于每通道的低 8 位；用 `png.Reader` 读出每个样本后取 `value % 256`，再以 8-bit 重建图像，即可看到被“丢弃”的隐藏画面。

## 原理

- PNG 每通道位深度可为 8 或 16；48-bit RGB 表示每像素每通道 16 bit。普通屏幕与多数看图工具只显示高 8 bit（0–255），低 8 bit 对视觉效果几乎无影响，却可承载完整图像。
- `pypng` 的 `Reader.read()` 会返回 16-bit 原始样本；对每个样本做 `d % 2**8` 取低 8 位，用 `png.Writer(bitdepth=8)` 写出一张新 PNG，即还原隐藏图像。
- 更进一步，原文把原图与低 8 位重建图的每个像素最低位分别拼成上下两半，组合成一张 370×370 的黑白图，用于提取二维码/位图信息。
- 该手法与像素 LSB 类似，但维度是“位深度”而不是“颜色通道最低位”：隐藏的是整幅低字节图像，而非逐 bit 载荷。

## 触发条件

- PNG 的 IHDR 位深度为 16（每通道），文件体积明显大于同尺寸 8-bit 图。
- 直接查看只显示正常/模糊图像，但工具（pngcheck、010）显示 bit depth 48 或样本值超过 255。
- 题目提示“位深度”“低位”“隐藏图”等。

## 利用步骤

1. 用 `pngcheck -v` 或 `png.Reader` 确认位深度为 16、颜色类型为 truecolor。
2. 逐行读取样本，对每通道取 `d % 256`，收集为 8-bit 数据。
3. 用 `png.Writer(bitdepth=8)` 写出新图并查看；若出现二维码/文字，继续解码。
4. 若隐藏信息在最低位而非整字节，分别取原图与重建图每个像素的最低位，拼成二值图（原文拼成 370×370，上半原图、下半重建图）。

## PoC

```python
from PIL import Image
import png

img = png.Reader('funnypng.png')
w, h, imgdata = img.read()[:3]

data = []
for linedata in imgdata:
    data.append([d % (2**8) for d in linedata])   # 取每通道低 8 位

with open('front.png', 'wb') as f:
    png.Writer(width=w, height=h, greyscale=False, bitdepth=8).write(f, data)

img1 = Image.open('funnypng.png')
img2 = Image.open('front.png')
w, h = img1.size
out = Image.new('1', (370, 370))
for i in range(w):
    for j in range(h):
        if i < 370 and j < 185:
            r1, g1, b1 = img1.getpixel((i, j))
            r2, g2, b2 = img2.getpixel((i, j))
            out.putpixel((i, j), int(bin(r1)[-1]))        # 原图最低位
            out.putpixel((i, j + 185), int(bin(r2)[-1]))  # 低位图最低位
out.save('qr.png')
```

- 原文示例：[NSSRound#3 Team]funnypng，位深度 48 bit，取低 8 位并拼最低位后得到二维码。
- 注意 `png.Reader` 对 16-bit 返回的是原始样本，不要先经 Pillow 转 8-bit，否则低位已丢失。

## 变体与关联

- PNG LSB/通道隐写见 [[ctf-forensics-png-lsb-zsteg-download-url-openpgp-payload]]、[[ctf-forensics-png-lsb-column-major-scan-order]]。
- 位图头/尺寸异常见 [[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]、[[ctf-misc-ppm-p6-header-height-tamper-hidden-rows]]。
- 其他“被查看器丢弃的数据”载体：APNG 帧延迟（[[ctf-misc-apng-fctl-delay-num-ascii-stego]]）、GIF 帧时长（[[ctf-misc-gif-frame-duration-ascii-stego]]）。

## 检测与防御

- CTF 技巧，非真实漏洞。出题方可随机化低位或加密隐藏图；解题方优先检查位深度、通道与样本范围。
- 实际图片处理流水线若做格式转换（16→8 bit）会丢失低位数据，可用作隐蔽信道；安全检测应保留原始样本分析。
