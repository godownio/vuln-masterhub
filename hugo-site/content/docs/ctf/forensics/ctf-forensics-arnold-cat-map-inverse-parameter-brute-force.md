---
id: ctf-forensics-arnold-cat-map-inverse-parameter-brute-force
title: Arnold 猫脸变换逆变换：矩阵求逆 + 多轮还原 + a/b 参数爆破
type: scenario
domain: ctf
path: ctf/forensics
technique: arnold-cat-map-inverse-parameter-brute-force
tags:
- ctf
- forensics
- stego
- image
- arnold
- cat-map
- inverse-matrix
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:00:41+08:00'
  notes: 已对照原文Arnold_image与cat cat cat两题及图07/09/10核对：BrainFuck 解出 hint 35 次、脚本经典矩阵(1,1,1,2)/swap(2,1,1,1)及其逆、35轮逆变换、QR(pyzbar)与直方图筛选；cat cat cat 用 foremost 从图片分离两张图、原图EXIF给出a/b在10-15、暴力枚举。卡片的模逆公式 det=ad-bc、M^-1=(d,-b,-c,a)/det、transform 落点 (a*x+b*y)%n/(c*x+d*y)%n 均正确；文中脚本只用了经典与swap两个变体，卡片已注明要按题目公式核对。未在本机复跑；无组件版本。
url: /docs/ctf/forensics/ctf-forensics-arnold-cat-map-inverse-parameter-brute-force/
draft: false
kb_aliases:
- 猫脸变换
- Arnold transform
- 图像置乱
- 逆矩阵还原
- 参数爆破
- Arnold_image
---

## 一句话结论

当图片被 Arnold 猫脸变换（`x'=(a·x+b·y) mod n, y'=(c·x+d·y) mod n`）置乱时，先求变换矩阵在模 `n` 下的逆矩阵，按题目给的轮数反复应用逆变换即可还原；若参数 `a,b,c,d` 未知，则根据提示范围（如 a,b∈10..15）暴力枚举并用 QR/可读性/直方图筛选。

## 原理

- **Arnold 猫脸变换**：对 `n×n` 图像，逐像素做线性变换 `(x,y) → ((a·x+b·y) mod n, (c·x+d·y) mod n)`。经典形式是 `(1,1,1,2)`（`x'=x+y, y'=x+2y`），它是一一映射，可逆。
- **逆变换**：变换矩阵 `M=[[a,b],[c,d]]` 在模 `n` 下求逆（`det(M)` 必须与 `n` 互素）；逆矩阵 `M^{-1}` 作用于置乱图即可还原。多轮变换只需重复应用 `M^{-1}` 相应次数（本题 hint 为 35 次）。
- **参数未知**：若 EXIF/hint 给出 `a,b` 范围，枚举所有候选矩阵，逐一对图做逆变换，用 QR 解码成功、直方图/边缘连续性、可读文字等判据选正确参数。
- **为什么成立**：Arnold 变换是双射，信息没有丢失；只要知道矩阵和轮数，逆变换就能精确还原。未知参数只是有限搜索空间（本题 10..15）。
- **注意**：不同题目可能用变体矩阵（如 `(2,1,1,1)`）；必须按题目公式/代码核对，不能默认经典矩阵。

## 触发条件

- 图片呈现明显置乱/噪声，但尺寸为正方形或接近正方形；题目名称/提示出现“猫脸/Arnold/置乱”。
- 已知或可推测变换矩阵/轮数；EXIF/hint 可能给出参数范围。
- 置乱图为无损 PNG/BMP（JPEG 压缩会破坏双射，还原效果差）。
- 有 PIL/OpenCV 与 QR 解码库（pyzbar）用于验证。

## 利用步骤

1. 读取图片尺寸 `n`，确认是正方形/可按 `n` 取模；读取 EXIF/提示得到轮数与参数范围。
2. 对候选矩阵 `M=[[a,b],[c,d]]` 求 `det` 与模 `n` 逆；构造 `M^{-1}`。
3. 定义 `transform_once(img, M)`：`dst[(a*x+b*y)%n, (c*x+d*y)%n] = src[x,y]`。
4. 对置乱图应用 `M^{-1}` 共 `rounds` 次；保存结果，用 QR 解码/直方图/可读性判断。
5. 参数未知时枚举 `a,b`（必要时 c,d），对每个候选重复 2-4；正确结果通常 QR 可解或图像边缘连续。
6. 本题 `Arnold_image` 用 BF 提示 35 轮，逆变换后 QR 解码得到 flag；`cat cat cat` 从 foremost 分离出图，EXIF 给出 a,b∈10..15，暴力破解后得到二维码/flag。

## PoC

```python
from PIL import Image

def inverse_matrix(a, b, c, d, n):
    det = (a * d - b * c) % n
    inv_det = pow(det, -1, n)
    return ((d * inv_det) % n, (-b * inv_det) % n,
            (-c * inv_det) % n, (a * inv_det) % n)

def transform_once(img, matrix):
    n = img.size[0]
    src, dst_img = img.load(), Image.new("RGB", (n, n))
    dst = dst_img.load()
    a, b, c, d = matrix
    for x in range(n):
        for y in range(n):
            nx, ny = (a * x + b * y) % n, (c * x + d * y) % n
            dst[nx, ny] = src[x, y]
    return dst_img

def undo(img, forward, rounds):
    n = img.size[0]
    inv = inverse_matrix(*forward, n)
    cur = img
    for _ in range(rounds):
        cur = transform_once(cur, inv)
    return cur

# 经典矩阵 (1,1,1,2) 的逆是 (2,-1,-1,1) mod n = (2,n-1,n-1,1)
img = Image.open("enc1.png").convert("RGB")
out = undo(img, (1, 1, 1, 2), 35)
out.save("restored.png")
```

## 变体与关联

- **变体（参数未知）**：枚举 a,b,c,d 的小范围；用 QR/文本/边缘连续性筛选；也可用已知明文（水印/边框）反推矩阵。
- **变体（其他置乱）**：Fibonacci 变换、仿射变换、像素交换、螺旋/蛇形；先识别变换公式再求逆。
- **变体（多图层）**：foremost/binwalk 分离出多张图，分别还原；EXIF 可能藏参数。
- **关联卡片**：[[ctf-forensics-png-lsb-column-major-scan-order]]（PNG LSB 扫描顺序）、[[ctf-misc-selectric-typeball-tilt-rotation]]（图像旋转/倾斜隐写）、[[crypto-classical-hill-cipher-3x3-matrix-inverse-mod26]]（模矩阵求逆）。
- **边界**：JPEG 有损压缩会破坏双射；`det` 与 `n` 不互素时矩阵不可逆；轮数/矩阵错误会得到另一种置乱图。

## 检测与防御

- **CTF 识别**：图像呈规则置乱、题为“猫脸/Arnold”、EXIF 给参数范围，按本卡先求逆再爆破。
- **图像处理**：Arnold 变换不是加密，只是置乱；敏感图像应使用真正的加密/水印。
- **实现**：注意 `n` 为图像边长、矩阵取模、逆矩阵负元素取模；多轮逆变换顺序不能反。
