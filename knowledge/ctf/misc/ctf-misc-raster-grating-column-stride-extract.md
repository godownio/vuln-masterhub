---
id: ctf-misc-raster-grating-column-stride-extract
title: 光栅图隐写：按步长 N 隔列抽取像素，还原被横向拉伸/交错的隐藏文字
type: scenario
domain: ctf
path: ctf/misc
technique: image-column-stride-grating-extract
aliases:
- 光栅图
- 隔列抽取
- 列步长隐写
- Raster-Terminator
- 列交错隐写
- grating image stego
tags:
- ctf
- misc
- stego
- image
- pil
- numpy
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V651
  verified_at: '2026-11-13T05:04:08+08:00'
  notes: 已对照原文（xz.aliyun.com/news/12489，Misc-3 2.4 节）与全部37张图逐张核对：图27 为被横向条纹化的 Password.png；图35 PIL+NumPy 按 for i in range(5) / z[:, i::5, :] = img[:, i::5, :] 拆分后某相位清晰显示 PPeRLR6SEmHGC，与卡内 PoC 的步长参数 N=5 逐字一致；图34/37 该密码成功解压 baseout.7z（flag.txt 为 DASCTF{d68b6013-d70a-4ada-926d-68fe3265360a}），与一句话结论一致；图36 Raster-Terminator 自动爆破横向步长并输出切割图，与卡内关联工具描述一致。dedup 报告 top 候选（螺旋置乱、低频缩小、16bit 低位等）均为不同隐写手法，无同一利用链；dup-scan.json 30 对不涉及本卡。CTF 无组件版本，不设 affected_versions。未验证点：未在本机重跑脚本（原文截图已给出结果）。
---

## 一句话结论

当图片看起来像被横向拉伸/交错、文字模糊不可读时，可以按固定步长 N 做“隔列抽取”：对每个偏移 `i in 0..N-1` 取第 `i::N` 列生成一张新图，N 取对时应看到清晰文字。本例 N=5，用 PIL+NumPy 五行代码从一张被 5 倍横向拉伸的 PNG 中还原出 7z 解压密码。

## 原理

- **生成方式**：隐藏文字先被画进一张图，再把每一列复制/拉伸成 N 列（或按列交错写入），肉眼看上去像素被横向“抹开”，文字结构被破坏成一团条纹；这就是常说的“光栅图”。
- **可逆性**：如果每个原始列被重复 N 次，或按固定步长交错，那么取回 `原图[:, ::N]` 的任意相位即可重建原图：`z[:, i::N, :] = img[:, i::N, :]` 保留所有 `col % N == i` 的列，其余置零/置黑，得到的正是原图中每隔 N 列的一列。
- **为什么能用**：文字笔画在水平方向是连通的，只保留某一相位列后，笔画在垂直方向仍然连续，人眼/OCR 可读；而其它相位只会得到更稀疏的竖线。多试几个 N 与偏移即可命中。
- **N 未知时**：对 N=2..k 与每个偏移都尝试，输出拼图人工挑选；也可用自动化工具（如公开的 Raster-Terminator）批量爆破步长与偏移。
- **边界**：行方向拉伸则要对行操作（`z[i::N, :] = img[i::N, :]`）；通道/对角线交错是更复杂的变体（见光棱坦克卡）；若图片本身经过 JPEG 压缩，抽取后可能有噪声但仍可辨认。

## 触发条件

- CTF misc/取证题给出一张横向条纹化、文字不可读的图片，或提示“光栅/栅格/列”等字样。
- 图片为无损格式（PNG/BMP）效果最好；JPEG 需容忍压缩噪声。
- 隐藏内容是文本/密码/flag，抽取后有可读字形或可用 OCR 识别。

## 利用步骤

1. 用 PIL/NumPy 读入图片，先打印尺寸与通道数，确认是横向异常（宽远大于高，或字符被水平拉长）。
2. 依次尝试步长 N=2,3,4,5,...，对每个偏移 i 生成 `z[:, i::N, :] = img[:, i::N, :]` 的新图并显示/保存。
3. 挑出文字清晰的相位；若仍模糊，改用灰度阈值、二值化或反色后重试。
4. 若横向无结果，改试行方向（`i::N` 作用在第一维）、单通道（R/G/B/A 分别抽）或对角线交错。
5. 识别出的字符串作为压缩包密码/下一阶段线索；必要时配合 OCR 批量识别。

## PoC

```python
from PIL import Image
import numpy as np

img = np.array(Image.open('baseout.png'))
for i in range(5):                     # 步长 N=5，未知时对 N=2..8 外层再套一层
    z = np.zeros_like(img)
    z[:, i::5, :] = img[:, i::5, :]
    Image.fromarray(z).show()          # 保存/OCR 亦可
# 本例某一相位输出清晰文字：PPeRLR6SEmHGC（7z 密码）
```

```python
# 通用化：未知步长与方向
def strides(img, n_max=8, axis=1):
    for n in range(2, n_max + 1):
        for i in range(n):
            z = np.zeros_like(img)
            if axis == 1:
                z[:, i::n, :] = img[:, i::n, :]
            else:
                z[i::n, :, :] = img[i::n, :, :]
            Image.fromarray(z).save(f'out_n{n}_i{i}.png')
```

## 变体与关联

- 光棱坦克（灰度分段 + 对角线交错）见 `ctf-forensics-prism-tank-grayscale-band-diagonal-interleave`；螺旋置乱见 `ctf-forensics-spiral-pixel-scramble-blank-fill`；幻影坦克见 `ctf-forensics-phantom-tank-rgba-2bit-pair-parity`。
- 列优先 LSB 扫描（行优先无结果时换列序）见 `ctf-forensics-png-lsb-column-major-scan-order`。
- 变体：RGB 通道分离后各自隔列抽取、行列双向交错、按 2D 网格（每 N 行 M 列）重排。
- 关联工具：PIL、NumPy、ImageMagick（`-crop`/`-resize`）、OCR；本文提到的开源工具有 Raster-Terminator。

## 检测与防御

- CTF/取证侧：先做尺寸/通道 anomaly 检查，再按步长扫描；对无损图优先，JPEG 先转灰度降噪。
- 出题/防御侧：光栅图只是视觉混淆，不提供密码学安全性；若需隐藏信息应使用加密或真正的隐写，并注意发布前无损压缩。
