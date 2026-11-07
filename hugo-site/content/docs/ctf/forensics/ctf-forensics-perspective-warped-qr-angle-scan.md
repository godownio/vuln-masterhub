---
id: ctf-forensics-perspective-warped-qr-angle-scan
title: 透视形变二维码：正面无法识别，按近大远小从侧面角度扫描
type: scenario
domain: ctf
path: ctf/forensics
technique: perspective-warped-qr-angle-scan
tags:
- ctf
- forensics
- qr
- perspective
- warp
- image
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:58:13+08:00'
  notes: 已对照原文与截图核对：猫脸还原后透视二维码正面扫不出、侧面角度可扫、flag提示move your body一致；未验证点：未复跑逆透视PoC。
url: /docs/ctf/forensics/ctf-forensics-perspective-warped-qr-angle-scan/
draft: false
kb_aliases:
- 透视二维码
- 形变二维码
- 近大远小二维码
- 侧面扫码
- anamorphic QR
---

## 一句话结论

把二维码做透视/梯形拉伸后，正面看模块不再是正方形，常规扫码器会失败；但从出题人设定的角度和距离观察（或对图片做逆透视变换把四边形拉回正方形），投影恢复后即可扫出 flag。

## 原理

- **QR 解码依赖几何**：二维码由定位图案（finder patterns）、定时图案和正方形模块网格组成；解码器先定位三个角点，再按网格采样模块。若图像被透视变换，模块在近端变大、远端变小，正面视角下的采样网格与真实网格不匹配，解码失败。
- **透视变换是单应性（homography）**：一个 3×3 矩阵 `H` 把正方形二维码映射为任意四边形；从特定视点观察时，眼睛/相机的投影恰好是 `H^{-1}`，于是二维码重新变成正方形。出题人就是利用“近大远小”制造这种投影。
- **恢复方法**：
  - 物理方法：把手机/屏幕移到与出题人相同的侧面角度和距离，边移动边扫；
  - 数字方法：在图片中找出二维码四边形的四个角点，用 `cv2.getPerspectiveTransform` 求 `H` 的逆，`cv2.warpPerspective` 拉回正方形，再交给 `pyzbar`/`zbarimg`。
- **为什么不是加密**：信息完整保留，只是几何形变；知道变换（或找到正确视角）即可无损恢复。
- **本题**：猫脸变换还原后得到一张被透视拉伸的二维码，正面扫不出；把手机挪到侧面即可识别，flag 也提示 `move your body`。

## 触发条件

- 图片中二维码明显呈梯形/倾斜，一侧模块大、另一侧小；定位图案仍可辨认。
- 正面用手机/`zbarimg`/`pyzbar` 解码失败，或只能解出部分。
- 题目提示“角度/移动/身体/透视/近大远小”。
- 前置层可能是拼图、猫脸变换、旋转等，需要先还原再处理透视。

## 利用步骤

1. 先完成前置还原（拼图、猫脸逆变换、旋转/镜像等），得到含二维码的图片。
2. 物理尝试：把手机屏幕/打印件倾斜到与图片相同的透视角度，前后移动并调整距离，直到扫码器识别。
3. 数字尝试：用 OpenCV 找二维码四边形：
   - 灰度化、二值化、`findContours`；
   - 找面积最大的近似四边形（`approxPolyDP`，4 个顶点）；
   - 按左上/右上/右下/左下排序四个角点；
   - `getPerspectiveTransform(src, dst)`，其中 `dst` 是边长为 `N` 的正方形四角；
   - `warpPerspective` 输出 `N×N` 图，再用 `pyzbar.decode`。
4. 若自动找角失败，手工在图片编辑器中读取四个角坐标，填入脚本。
5. 多次尝试不同 `N`（如 300/600/1000）和不同角点顺序；必要时先做去噪/对比度增强。
6. 扫出内容后检查是否需要再做 Base64/hex/反转等解码。

## PoC

```python
import cv2
import numpy as np
from pyzbar.pyzbar import decode

img = cv2.imread("warped_qr.png")
gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
_, bw = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

# 手工给出二维码四角（左上、右上、右下、左下），可用画图工具读取
src = np.float32([[x1, y1], [x2, y2], [x3, y3], [x4, y4]])
N = 600
dst = np.float32([[0, 0], [N, 0], [N, N], [0, N]])
M = cv2.getPerspectiveTransform(src, dst)
fixed = cv2.warpPerspective(img, M, (N, N))
cv2.imwrite("fixed_qr.png", fixed)

for r in decode(fixed):
    print(r.type, r.data.decode("utf-8", "replace"))
```

说明：PoC 中四角坐标需按实际图片填写；也可用 `cv2.findContours` + `approxPolyDP` 自动定位。未在本机对附件复跑。

## 变体与关联

- **柱面/曲面形变**：二维码印在杯子/曲面上，透视之外还有非线性弯曲；可先做网格校正或分段展开。
- **镜像/旋转**：先 `flip`/`rotate` 再解码；QR 解码器通常能处理旋转，但镜像不一定。
- **猫脸/拼图前置**：本题先做拼图和 Arnold 猫脸逆变换，再处理透视；见 [[ctf-forensics-arnold-cat-map-inverse-parameter-brute-force]]、[[ctf-forensics-qr-4x4-tile-reorder]]。
- **3D 变形二维码**：从特定角度才能读的“anamorphic”印刷品，原理相同。
- **关联**：[[ctf-forensics-1bpp-qr-row-shift-frame-recovery]]（另一种几何失真二维码还原）。

## 检测与防御

- 这不是安全漏洞，而是信息隐藏/展示技巧；对业务方而言，不要依赖“正面扫不出”作为安全边界，二维码内容应视为公开信息。
- 若用于票据/门禁，应对二维码内容做签名/时效校验，并限制扫描端点的重放；几何形变不能替代密码学保护。
- 取证/分析时保留原图，先做前置还原再尝试透视校正；不要用会重压缩的截图反复传递。
