---
id: ctf-misc-low-frequency-image-downscale-blur-reveal
title: 低频图像隐写：缩小或高斯模糊恢复隐藏图像
type: scenario
domain: ctf
path: ctf/misc
technique: low-frequency-image-downscale-blur-reveal
tags:
- ctf
- misc
- image
- steganography
- low-frequency
- blur
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:19+08:00'
  notes: 已对照原文 Hiding in Plain Sight 与 img/04 核对：缩小到 32x32 再放大/高斯模糊显现低频人脸（Obama）一致；未实际运行。
url: /docs/ctf/misc/ctf-misc-low-frequency-image-downscale-blur-reveal/
draft: false
kb_aliases:
- 低频隐写
- 缩小看图
- 高斯模糊还原
- Hiding in Plain Sight
- 低通滤波隐写
---

## 一句话结论

图片看起来像噪声/雕像/纹理，但把图像缩小到很低分辨率再放大，或做高斯模糊，高频噪声被滤除后，低频分量中隐藏的人脸/文字/图案就会显现。

## 原理

- 图像可分解为不同空间频率：边缘、纹理、噪声属于高频；大块明暗、轮廓属于低频。
- 如果隐藏图像被编码在低频分量中，而高频噪声/纹理用于掩盖，直接看原图会被高频干扰；缩小（下采样）或高斯模糊都是低通滤波，保留低频、抑制高频。
- 下采样到 32x32 再放大是最简单的低通：每个输出像素平均了一大块区域，噪声被平均掉，低频图案保留。
- 高斯模糊用卷积核加权平均邻域像素，半径越大低通越强；半径需与隐藏图案尺度匹配。
- 变体：FFT 低通滤波、均值滤波、中值滤波、通道分离；隐藏信息可能在某个颜色通道或亮度通道。

## 触发条件

- 图片尺寸较大、细节看似随机/噪声，但整体有微弱明暗结构。
- 题目提示“远看/眯眼/缩小/模糊/低频”等。
- 图片颜色分布或直方图异常，可能存在低频叠加。
- 隐藏内容是人脸、文字、二维码等大尺度图案。

## 利用步骤

1. 用 PIL 打开图片，先做缩小再放大：`resize((32,32))` 后 `resize((800,800))`，保存查看。
2. 若不明显，做高斯模糊：`GaussianBlur(radius=8)`，逐步调整半径 2/4/8/16。
3. 尝试只保留亮度通道（转灰度）或分别查看 R/G/B 通道。
4. 尝试 FFT 低通/均值滤波，观察低频分量。
5. 对显现出的图案做 OCR/人眼识别，得到答案。
6. 若仍无结果，检查图像是否还有 LSB/调色板/附加数据等其它隐写层。

## PoC

```python
from PIL import Image, ImageFilter

img = Image.open("hello.webp").convert("RGB")

# 方法 1：缩小再放大（下采样低通）
small = img.resize((32, 32))
big = small.resize((800, 800))
big.save("reveal_pixelated.png")

# 方法 2：高斯模糊（低通滤波）
blur = img.filter(ImageFilter.GaussianBlur(radius=8))
blur.save("reveal_blur.png")

print("saved reveal_pixelated.png, reveal_blur.png")
```

## 变体与关联

- 变体：不同下采样尺寸（16/32/64）、不同模糊半径、均值/中值滤波。
- 变体：隐藏信息在单个颜色通道、alpha 通道或亮度通道。
- 变体：频域隐写，需 FFT/小波变换提取。
- 关联：[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（多层图像/音频隐写）、[[ctf-forensics-spiral-pixel-scramble-blank-fill]]（像素置乱）、[[ctf-misc-sixel-dcs-image-decode]]（图像编码）。

## 检测与防御

- 检测：图片直方图/频域异常、缩小后出现明显图案、低通滤波后信息熵下降。
- 防御：该场景是 CTF 视觉隐写；真实系统对图片统一重编码/压缩可破坏低频隐写。
- 响应：若业务图片中出现隐藏图案，按隐写/水印/泄露排查。
