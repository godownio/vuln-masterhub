---
id: ctf-forensics-qr-4x4-tile-reorder
title: 4×4 打乱二维码按顺序重排并解码
type: scenario
domain: ctf
path: ctf/forensics
technique: qr-4x4-tile-reorder
aliases:
- Jigsaw QR
- 二维码拼图
- 4x4 图块重排
- QR 碎片还原
tags:
- ctf
- forensics
- qr-code
- image-reassembly
- pyzbar
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:31:42+08:00'
  notes: 已对照原文核对：4×4 打乱二维码、ORDER=[2,6,15,13,11,14,12,3,5,4,1,7,0,8,10,9]、按目标位置贴回、pyzbar 解码、flag VishwaCTF{t00_sm4rt_t0_us3_brut3_f0rc3} 均一致。未验证点：无二维码附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

二维码被切成 4×4 共 16 块并打乱时，按给定的“目标位置→原图块编号”映射把图块重新拼回 4×4 画布，再用 pyzbar/扫码器解码，即可得到 flag。

## 原理

- 二维码的定位图案与模块排列对位置敏感；图块打乱后无法直接解码，但每块内容仍是原图的一部分。
- 题目通常给出或可推断 16 块的排列顺序（文章给出 `[2,6,15,13, 11,14,12,3, 5,4,1,7, 0,8,10,9]`）。
- 按目标位置顺序取对应原图块粘贴，保持每块不旋转/翻转，即可恢复原二维码。
- 用 `pyzbar.decode` 或手机扫码读取恢复后的图像。

## 触发条件

- 拿到被切成规则网格的二维码图片，块数/网格已知（如 4×4）。
- 能确定或暴力枚举图块排列（16! 太大，通常题目给顺序或有定位图案辅助）。
- 图块无旋转/缩放，或可枚举旋转。

## 利用步骤

1. 读取图片，按等宽高切成 4×4 图块，按从左到右、从上到下编号 0–15。
2. 按题目给的 `ORDER` 列表，把第 pos 个目标位置放 `tiles[ORDER[pos]]`。
3. 粘贴到 4×4 画布，保存。
4. 用 pyzbar 解码；失败则人工扫码或尝试旋转/翻转组合。

## PoC

```python
from PIL import Image
from pyzbar.pyzbar import decode

ORDER = [2,6,15,13, 11,14,12,3, 5,4,1,7, 0,8,10,9]
img = Image.open("shuffled_flag1.png").convert("RGB")
w, h = img.size
xs = [round(i*w/4) for i in range(5)]
ys = [round(i*h/4) for i in range(5)]
tiles = [img.crop((xs[c], ys[r], xs[c+1], ys[r+1]))
         for r in range(4) for c in range(4)]

canvas = Image.new("RGB", (tiles[0].width*4, tiles[0].height*4), "white")
for pos, src in enumerate(ORDER):
    r, c = divmod(pos, 4)
    canvas.paste(tiles[src], (c*tiles[0].width, r*tiles[0].height))
canvas.save("recovered_qr.png")
print(decode(canvas)[0].data.decode())
```

## 变体与关联

- 网格可换成 3×3、5×5；图块可能带旋转/翻转，需要枚举。
- 可先用二维码定位图案（三个角）确定四角图块，再推导顺序。
- 关联：[[ctf-forensics-1bpp-qr-row-shift-frame-recovery]]（QR 行移位恢复）、[[ctf-forensics-arnold-cat-map-inverse-parameter-brute-force]]（图像置乱逆变换）。

## 检测与防御

- 这是 CTF 取证题型；防御上可加入旋转/缩放/噪声，增加自动拼接难度。
- 检测：图片被规则网格切割、块边缘不连续。
