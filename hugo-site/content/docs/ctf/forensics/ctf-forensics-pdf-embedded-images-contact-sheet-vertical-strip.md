---
id: ctf-forensics-pdf-embedded-images-contact-sheet-vertical-strip
title: PDF 扫描件嵌入图像批处理：contact sheet 定位竖排低对比 flag 条带
type: scenario
domain: ctf
path: ctf/forensics
technique: pdf-embedded-images-contact-sheet-vertical-strip
tags:
- forensics
- pdf
- image
- stego
- contact-sheet
- ocr
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:29:33+08:00'
  notes: 已对照原文与图08/10/12/14核对：pdfimages -j 导出 409 张嵌入图像、contact sheet 定位第 269 张、左侧灰条裁剪 (48,470,124,778)、旋转 270°、放大/灰度/autocontrast/对比度增强后读出 kashiCTF{1r0nhex_1s_n07_4_m4n} 均一致。未验证点：无 PDF 附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-pdf-embedded-images-contact-sheet-vertical-strip/
draft: false
kb_aliases:
- PDF 图像批量排查
- pdfimages contact sheet
- 扫描件隐藏条带
- 旋转 270 度 增强 flag
---

## 一句话结论

面对图像型 PDF（老扫描书），不要只做文本提取/OCR；用 `pdfimages` 导出全部嵌入图像，拼成 contact sheet 快速浏览，锁定异常灰条/边缘文字，再裁剪、旋转 270°、灰度化与对比度拉伸，即可读出隐藏的竖排 flag。

## 原理

- 扫描书 PDF 常是“每页一张大图”，文本层为空或噪声很大；真正的隐藏信息可能在图像像素里，而不在正文文字层。
- `pdfimages -j` 把 PDF 内所有嵌入图像按编号导出（页数与图像数不一定相同，一页可能有多张图）；contact sheet 把几百张图缩略排列，能快速发现灰块、半透明条带、边缘小字等异常。
- 隐藏条带常被旋转 90°/270°、低对比度、贴在页面边缘；裁剪后旋转回水平，再做灰度化、自动对比度、放大，文字即可读。
- 为什么可行：人眼对整页缩略图的“结构异常”很敏感；批处理把人工翻页成本降到最低，适合数百页扫描件。

## 触发条件

- PDF 以图像为主（文本提取几乎为空），页数/图像数较多。
- 隐藏信息在嵌入图像中，未被压缩/重采样破坏；条带与背景对比度低但可增强。
- 能安装 Poppler（`pdfimages`）与 Pillow。

## 利用步骤

1. `pdfimages -j challenge.pdf out/img` 导出所有嵌入图像，记录数量。
2. 用 Pillow 生成 contact sheet（每行若干张、带编号），快速浏览；重点找灰块、条带、边缘小字、与正文风格不一致的区域。
3. 锁定可疑图（如第 269 张），单独打开，标记可疑区域（左侧中部灰条）。
4. 裁剪条带，顺时针旋转 270° 变横向；放大 3 倍，灰度化 + `autocontrast` + 提高对比度。
5. 读取 flag；若仍模糊，调整裁剪框、旋转角度、阈值/锐化，或尝试其他颜色通道。
6. 若 contact sheet 太大，可按编号分段生成，或按图像尺寸/熵排序优先看异常项。

## PoC

```bash
pdfimages -j challenge.pdf out/img
```

```python
from PIL import Image, ImageOps, ImageEnhance, ImageDraw
import math, pathlib

files = sorted(pathlib.Path("out/img").glob("img-*"))
# 生成 contact sheet（略：按缩略图网格拼接并标注编号）
# 锁定第 269 张后：
img = Image.open(files[268]).convert("RGB")
crop = img.crop((48, 470, 124, 778))
rot = crop.rotate(270, expand=True)
big = rot.resize((rot.width * 3, rot.height * 3), Image.Resampling.LANCZOS)
gray = ImageOps.autocontrast(ImageOps.grayscale(big), cutoff=1)
out = ImageEnhance.Contrast(gray).enhance(2.8)
out.save("flag_revealed.png")
```

说明：PoC 为原文脚本的结构化精简，未在本机执行；原文导出 409 张图，第 269 张左侧灰条旋转增强后读出 `kashiCTF{1r0nhex_1s_n07_4_m4n}`。

## 变体与关联

- 变体（载体）：PDF 内嵌 SVG/字体/注释、XMP 元数据、附件流；`pdfimages` 只覆盖位图，需配合 `pdfdetach`/`mutool`/`exiftool`。
- 变体（增强）：通道分离（R/G/B/alpha）、直方图均衡、局部阈值、去噪/锐化；低对比度条带可用差分/背景估计。
- 关联：[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（多层图像隐写）；[[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]（图像头篡改）；[[ctf-forensics-video-single-pixel-channel-extraction]]（像素通道隐写）。
- 边界：图像被重采样/有损压缩导致文字不可辨、隐藏信息在文本层、或 contact sheet 中异常项过多时，需要 OCR/分区/自动化异常检测。

## 检测与防御

- 检测：PDF 中嵌入图像数量异常、页面边缘存在低对比度条带/旋转文字、contact sheet 中出现结构不一致的灰块。
- 防御：发布前对图像做重编码/裁剪/水印清理；移除不必要的嵌入图像与元数据；对敏感文档做栅格化与审查。
- 取证：保留原始 PDF 与导出图像，记录图像编号/裁剪坐标/旋转角度/增强参数，保证结果可复现。
