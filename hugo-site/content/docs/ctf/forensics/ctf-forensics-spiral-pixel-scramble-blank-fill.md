---
id: ctf-forensics-spiral-pixel-scramble-blank-fill
title: 螺旋像素置乱还原 + 空白像素填充隐写
type: scenario
domain: ctf
path: ctf/forensics
technique: spiral-pixel-scramble-blank-fill
tags:
- ctf
- forensics
- stego
- image
- spiral
- pixel-permutation
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:08:48+08:00'
  notes: 已对照原文全文与 7 张内嵌图片核对：题目步骤、密码链、脚本与 flag/密码均与原文一致。未验证点：PoC 按原文重写未本机复跑；原文无组件版本，未设置 versions；卡 frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-spiral-pixel-scramble-blank-fill/
draft: false
kb_aliases:
- 螺旋加密
- 螺旋像素置乱
- 空白像素填充
- SCB 隐写
- 鲨士比亚王国的金融危机
---

## 一句话结论

当图片是奇数正方形（如 889×889）且内容呈螺旋状纹理时，可从中心顺时针生成螺旋坐标序列，把加密图像素按序列读出、按行优先写回，还原原图；若还有一张“空白像素”掩码图（SCB），把原图像素按行填入掩码的白色空白区域，即可提取隐藏图/flag。

## 原理

- **螺旋置乱**：加密时把原图按行优先的像素依次放进从中心顺时针螺旋展开的位置；解密时生成同样的螺旋坐标序列，`out[x,y] = enc[spiral[index]]`，即还原。
- **奇数正方形**：螺旋从中心开始、每两圈增加步长，要求宽高相等且为奇数（如 889），否则中心/边界不唯一。
- **空白像素填充**：掩码图（如 SCB.PNG）大部分为白色/空白；把秘密图像素按行优先填入掩码的空白像素位置，肉眼看仍是掩码图；解密时提取空白位置的像素按行重排即可恢复秘密图。
- **为什么成立**：两者都是确定性像素置换/填充，信息未丢失；只要坐标序列/阈值/顺序一致即可逆。
- **边界**：螺旋方向（顺/逆时针）、起点、步长规则可能不同；掩码阈值/空白判断（RGB≥230）需按题目调整；JPEG 有损会破坏。

## 触发条件

- 图片为奇数正方形，纹理呈螺旋/放射状；题目提示“螺旋/中心/旋转”。
- 另有掩码图/“空白”图，白色区域足够容纳秘密图像素。
- 图片为无损 PNG/BMP；像素未被重压缩。
- 秘密图尺寸/像素数 ≤ 掩码空白像素数。

## 利用步骤

1. 确认图片尺寸为奇数正方形；按题目/观察确定螺旋方向、起点、步长。
2. 生成 `spiral_positions(n)`：从中心 `(n//2,n//2)` 开始，按右/下/左/上方向、步长 1,1,2,2,3,3... 展开，直到 `n*n` 个坐标。
3. 解密：按行优先遍历输出图，依次取 `enc[spiral[index]]` 写入；保存还原图。
4. 读取掩码图，收集所有“空白”像素坐标（RGB≥阈值，本题 230）。
5. 把还原图的像素按行优先依次填入空白坐标，输出隐藏图；或反向从掩码图中提取空白像素按行重排。
6. 本题还原后得到隐藏图/flag。

## PoC

```python
from PIL import Image

W = H = 889

def spiral_positions(width, height):
    assert width == height and width % 2 == 1
    positions = []
    x = y = width // 2
    dx = [1, 0, -1, 0]
    dy = [0, 1, 0, -1]
    direction = 0
    steps_to_take = 1
    steps_count = 0
    turn_count = 0
    positions.append((x, y))
    while len(positions) < width * height:
        x += dx[direction]
        y += dy[direction]
        if 0 <= x < width and 0 <= y < height:
            positions.append((x, y))
        steps_count += 1
        if steps_count == steps_to_take:
            steps_count = 0
            direction = (direction + 1) % 4
            turn_count += 1
            if turn_count % 2 == 0:
                steps_to_take += 1
    return positions

def decrypt_spiral(input_path, output_path):
    img = Image.open(input_path).convert("RGB")
    src = img.load()
    out = Image.new("RGB", (W, H), "white")
    dst = out.load()
    positions = spiral_positions(W, H)
    index = 0
    for y in range(H):
        for x in range(W):
            sx, sy = positions[index]
            dst[x, y] = src[sx, sy]
            index += 1
    out.save(output_path)

def fill_blank(secret_path, mask_path, output_path, threshold=230):
    secret = Image.open(secret_path).convert("RGB")
    mask = Image.open(mask_path).convert("RGB")
    w, h = mask.size
    blank = [(x, y) for y in range(h) for x in range(w)
             if all(c >= threshold for c in mask.getpixel((x, y)))]
    pixels = [secret.getpixel((x, y)) for y in range(secret.size[1]) for x in range(secret.size[0])]
    assert len(pixels) <= len(blank)
    for pos, pix in zip(blank, pixels):
        mask.putpixel(pos, pix)
    mask.save(output_path)
```

## 变体与关联

- **变体（螺旋方向）**：顺时针/逆时针、从外向内、步长变化；按题目/图像纹理尝试。
- **变体（置乱）**：蛇形、Z 字形、块置换、Arnold 猫脸；见 [[ctf-forensics-arnold-cat-map-inverse-parameter-brute-force]]。
- **变体（填充）**：按空白像素/透明通道/掩码颜色填充；秘密图可能需缩放/裁剪。
- **关联卡片**：[[ctf-forensics-png-lsb-column-major-scan-order]]（像素扫描顺序）、[[ctf-forensics-phantom-tank-rgba-2bit-pair-parity]]（双图隐写）、[[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]（逆向置换）。
- **边界**：尺寸非奇数正方形时需补零/裁剪；螺旋规则不匹配会得到错位图；JPEG 有损会破坏像素。

## 检测与防御

- **CTF 识别**：奇数正方形 + 螺旋纹理，按中心螺旋坐标还原；有掩码图时检查空白像素。
- **图像取证**：保留原始 PNG；记录尺寸/螺旋方向/阈值；用多组参数交叉验证。
- **安全**：像素置乱/填充不是加密，不能保护敏感图像；使用真正加密。
