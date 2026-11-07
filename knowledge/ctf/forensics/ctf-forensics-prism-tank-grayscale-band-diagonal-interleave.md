---
id: ctf-forensics-prism-tank-grayscale-band-diagonal-interleave
title: 光棱坦克隐写：灰度分段 + 对角线交错像素分离（支持多图与彩色）
type: scenario
domain: ctf
path: ctf/forensics
technique: prism-tank-grayscale-band-diagonal-interleave
aliases:
- 光棱坦克
- Prism Tank
- 灰度分段隐写
- 色阶分段双图
- 对角线交错隐写
- 拉高曝光隐写
- 多图合一
tags:
- ctf
- forensics
- stego
- image
- histogram
- grayscale
- diagonal-interleave
- prism-tank
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:48:31+08:00'
  notes: 已对照原文1.2核对：灰度分段/HSV V通道、对角线(i+j)%2掩码、色阶/曲线与直方图识别、解码脚本思路一致；未验证点：PoC未本机执行，xoff/xmod自动检测不保证命中。
---

## 一句话结论

光棱坦克隐写把两张或多张图分别压缩到灰度（或 HSV 的 V 通道）的不同亮度区间，再按对角线掩码交错采样合成一张图；肉眼看到的是混合结果，调色阶/曲线或按掩码提取某一亮度区间的像素，就能分离出隐藏图，且可保留彩色、扩展到多图。

## 原理

- **亮度分段**：灰度值 0–255 可以切成多个区间。经典双图做法把表图压进暗段 `[0, level_max]`、里图压进亮段 `[level_min, 255]`，中间留出空隙；每个像素只来自其中一张图，合成后直方图会出现两簇/空隙。
- **对角线交错**：用 `(i+j) mod 2 == 0` 之类的对角线掩码决定像素归属：掩码为真取图 1，否则取图 2。人眼在看缩略图时会混合两簇亮度，看起来像一张正常图；放大或调色阶后，交错纹理与隐藏图就显现出来。
- **多图扩展**：把 0–255 分成 n 个区间 `[a1,b1], [a2,b2], …`，每个像素按其灰度归入某一类，再按类输出就是 n 张独立图。区间越多，每张图的动态范围越小，隐藏效果越差。
- **彩色保留**：彩色变体保留表图的 H（色相）和 S（饱和度），只把里图编码进 V（明度）通道，最后 `HSV → RGB`；这样表图颜色正常，里图藏在明度分段里。
- **为什么调色阶能看见**：图像编辑器的色阶/曲线工具本质是按输入灰度重新映射输出；把输入范围限制到暗段或亮段，就能把该段的像素拉伸到全动态范围，隐藏图从混合结果中“浮”出来。直方图上异常的高峰/空段是最快的识别特征。
- **与幻影坦克的区别**：幻影坦克依赖 Alpha 与背景混合，换背景才显示第二张；光棱坦克把两张图都写进 RGB 灰度，单看一张图也能通过色阶/直方图分离，且支持多图与彩色。

## 触发条件

- 附件是 PNG/BMP 等无损或高质量图片；直方图出现异常空段、双峰或某个窄区间的高峰。
- 图片放大后能看到对角线/棋盘状交错像素，或调色阶/曲线时出现第二幅图。
- 题目提示“光棱坦克 / 拉高曝光 / 色阶 / 多图合一”，或图片在 PS 里色阶窗口明显不自然。
- 图片未被有损压缩/缩放破坏；彩色变体还需要保留 HSV 通道关系。

## 利用步骤

1. 生成/查看直方图：统计 0–255 各灰度的像素数，寻找中间空段、左右两侧异常峰；也可在 PS 打开“色阶”或“曲线”直接看分布。
2. 手动分离：在 PS 中打开色阶，把输入指针拉到暗段或亮段，把该段拉伸到 0–255；或用曲线把输入限制到目标区间，观察隐藏图。
3. 脚本分离：检测对角线掩码的周期 `m` 与斜率/偏移 `k`（常见 `(x + y·k) mod m == 0`），取出掩码位置的像素，按该区间最大值归一化到 0–255。
4. 对非掩码位置用最近邻/邻域均值/形态学膨胀插值补全，得到完整隐藏图；若图像仍偏暗/偏亮，做直方图均衡或反相。
5. 彩色变体：在 HSV 空间取 V 通道做上述分段/掩码处理，H、S 保留原图，再合并回 RGB。
6. 多图变体：按直方图峰值把像素分成 n 类，每类单独输出；调整分类阈值直到每张图清晰。

## PoC

最小分离脚本（示意，未在本机执行；周期/斜率需按目标调整）：

```python
from PIL import Image
import numpy as np

img = Image.open("prism.png").convert("RGB")
arr = np.asarray(img).astype(np.float32)
gray = arr.mean(axis=2)                       # 近似灰度
h, w = gray.shape
yy, xx = np.indices((h, w))

# 常见对角线掩码：取其中一簇像素
mask = (xx + yy) % 2 == 0
vals = gray[mask]
scale = 255.0 / max(vals.max(), 1)
out = np.zeros((h, w), dtype=np.float32)
out[mask] = np.clip(vals * scale, 0, 255)

# 非掩码像素用 3x3 邻域均值迭代补全（简化）
for _ in range(2):
    padded = np.pad(out, 1, mode="edge")
    neigh = sum(padded[1+dy:1+dy+h, 1+dx:1+dx+w]
                for dy in (-1, 0, 1) for dx in (-1, 0, 1))
    out[~mask] = (neigh[~mask] / 9.0)

Image.fromarray(out.astype(np.uint8)).save("hidden.png")
```

彩色变体可改为取 `V = max(R,G,B)` 或 `colorsys.rgb_to_hsv` 的 V 通道做同样的掩码/归一化，再与原始 H、S 合并。原文的 `calculate_optimal_levels` 是启发式阈值，实际题目需按直方图调整；原文解码脚本同样依赖自动检测的 `xoff/xmod`，不保证一次命中。

## 变体与关联

- 变体：双图（暗段/亮段）、多图（n 个灰度区间）、彩色（H/S + V 分段）、对角线/棋盘/斜线等不同掩码。
- 变体：先做直方图均衡/反相再分离；或直接把图片缩放到很小，利用缩略图的混合效果读隐藏图。
- 关联：[[ctf-forensics-mirage-tank-alpha-two-image-checkerboard]]（Alpha 双背景，另一类双图）、[[ctf-forensics-png-lsb-column-major-scan-order]]（LSB 扫描）、[[ctf-misc-low-frequency-image-downscale-blur-reveal]]（低频/模糊恢复隐藏图）。
- 边界：有损压缩会抹平窄亮度区间；区间过窄/过多会导致分离后噪声大；彩色变体若 H/S 被二次压缩，颜色会偏移。

## 检测与防御

- CTF 识别：直方图有空段/异常峰、图片有对角线交错纹理、调色阶/曲线出现第二幅图；优先检查灰度分段与掩码周期。
- 取证：保留原图，记录直方图和调色阶参数；用脚本与 PS 手动法交叉验证，避免把正常高对比图误判。
- 防御：敏感数据不要用灰度分段隐写；DLP 可检测直方图异常与周期性掩码；对图片做重编码/缩放会破坏窄区间，但也会损失正常画质。
