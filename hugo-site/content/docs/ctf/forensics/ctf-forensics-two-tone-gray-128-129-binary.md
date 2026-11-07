---
id: ctf-forensics-two-tone-gray-128-129-binary
title: 双灰度像素二值隐写：128/129 映射 0/1 还原 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: two-tone-gray-128-129-binary
tags:
- ctf
- forensics
- pixel
- gray
- binary
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:58:15+08:00'
  notes: 已对照原文CSGO与截图核对：(128,128,128)/(129,129,129)双灰度、置0/1按位解码、末字母r→y一致；未验证点：未对附件复跑。
url: /docs/ctf/forensics/ctf-forensics-two-tone-gray-128-129-binary/
draft: false
kb_aliases:
- 128/129 像素
- 双灰度隐写
- 相邻灰度二值
- 低对比像素隐写
- 两色像素编码
---

## 一句话结论

当图片像素只有 `(128,128,128)` 与 `(129,129,129)` 两种、肉眼几乎看不出差异时，把一种映射为 0、另一种为 1，按行优先每 8 位转 ASCII，即可还原隐藏的 flag。

## 原理

- **相邻灰度差 1 不可见**：人眼对亮度差 1/255 不敏感，尤其在大面积均匀区域；但 PNG/BMP 等无损格式会精确保存 128 与 129。
- **每个像素承载 1 bit**：把 128 映射 0、129 映射 1（或反过来），按扫描顺序（行优先，x 从 0 到 width-1，y 从 0 到 height-1）拼接成 bit 流，每 8 位转一个字节。
- **为什么用两种灰度而不是黑白**：黑白对比强烈、肉眼立刻发现；128/129 在正常亮度的显示器上几乎一致，必须看直方图/像素值才能发现。
- **本题**：StegSolve 的通道视图能看到隐藏图案，`Data Extract` 直接出结果；导出 RGB 值后发现只有 `(128,128,128)` 和 `(129,129,129)`，分别置 0/1 解码得到 flag。最后一位原文按上下文把 `r` 修正为 `y`，说明编码端可能有笔误或校验位。
- **位序/分组**：常见 MSB-first、每 8 位一字节；若不可读，尝试 LSB-first、7 位 ASCII、每像素取反、或先做行列转置。

## 触发条件

- 图片看起来是纯色/渐变/噪声，但直方图只有两个相邻灰度峰（如 128 和 129）。
- 文件是无损 PNG/BMP/TIFF；JPEG 有损压缩会把 128/129 抹平。
- `stegsolve` 的某个通道/位平面显示规律图案；题目提示“像素/RGB/二进制/灰度”。
- 图像尺寸与可疑明文长度满足 `width*height >= len*8`。

## 利用步骤

1. 用 Pillow/OpenCV 统计唯一颜色及数量：
   ```python
   from PIL import Image
   from collections import Counter
   im = Image.open("hidden.png").convert("RGB")
   print(Counter(im.getdata()).most_common(10))
   ```
2. 若只有两种颜色，确定映射（128→0、129→1，或反之）。
3. 按行优先遍历所有像素，生成 bit 串；每 8 位按 MSB-first 转字节，拼成文本。
4. 若不可读，依次尝试：LSB-first、7 位分组、两种映射互换、先列后行、上下/左右翻转、每字节取反。
5. 用 `flag{`、`}`、可打印率验证；若仍有单字符错误，按上下文修正（如本题 `r`→`y`）。
6. 也可用 StegSolve 的 `Analyse > Data Extract` 选择对应通道/位平面直接导出。

## PoC

```python
from PIL import Image
from collections import Counter

im = Image.open("hidden.png").convert("RGB")
w, h = im.size
colors = Counter(im.getdata())
print(colors.most_common(5))

# 取两种主要颜色中最暗/最亮作为 0/1（按实际直方图调整）
vals = [c for c, _ in colors.most_common(2)]
zero, one = min(vals)[0], max(vals)[0]
bits = []
for y in range(h):
    for x in range(w):
        r, g, b = im.getpixel((x, y))
        bits.append("0" if r == zero else "1")

bitstr = "".join(bits)
for order in ("msb", "lsb"):
    out = []
    for i in range(0, len(bitstr) - 7, 8):
        chunk = bitstr[i:i+8]
        if order == "lsb":
            chunk = chunk[::-1]
        out.append(chr(int(chunk, 2)))
    text = "".join(out)
    print(order, text[:200])
```

说明：PoC 为通用双色位流提取，具体映射/位序需按题目调整；未在本机对附件复跑。

## 变体与关联

- **黑白二值**：0/255 或 254/255，肉眼可见但可能被当作普通黑白图；同样按位流处理。
- **2-bit 四色**：四种灰度/颜色映射 00/01/10/11，容量翻倍；参见 [[ctf-forensics-phantom-tank-rgba-2bit-pair-parity]]。
- **通道内位平面**：只用 R/G/B 某一通道的最低位，其他通道正常；用 `stegsolve`/`PIL` 提取位平面。
- **Alpha 通道**：透明像素的 alpha 值承载数据，视觉上完全透明；检查 RGBA。
- **大像素块**：每个逻辑 bit 用 10×10 像素块表示，需按块采样；见 [[ctf-forensics-xor-known-key-large-pixel-block]]。
- **关联**：[[ctf-forensics-png-lsb-column-major-scan-order]]（行优先失败时改列优先）、[[ctf-misc-low-frequency-image-downscale-blur-reveal]]（低频隐写）。

## 检测与防御

- 检测：直方图只有两个相邻灰度峰、颜色数异常少、LSB 平面呈现文字/图案；用 `stegsolve`/`zsteg`/自写脚本检查。
- 防御：对上传图片重新编码/量化（如转 JPEG 或统一调色板）会破坏 128/129 的精确值；但重编码也可能影响业务画质。
- 取证时保留原图；截图/微信传输可能重压缩，导致数据不可恢复。
