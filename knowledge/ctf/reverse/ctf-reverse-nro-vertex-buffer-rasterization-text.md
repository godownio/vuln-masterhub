---
id: ctf-reverse-nro-vertex-buffer-rasterization-text
title: NRO 顶点缓冲重绘：按 6 float/顶点 + 三角形光栅化还原白字 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: nro-vertex-buffer-rasterization-text
aliases:
- not drawing
- drawing.nro
- glBufferData
- glVertexAttribPointer
- 顶点缓冲
- 三角形光栅化
tags:
- reverse
- nintendo-switch
- nro
- opengl
- vertex-buffer
- rasterization
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:08:59+08:00'
  notes: 已对照原文核对：glBufferData 0x16650、6 float/顶点步长 24、glDrawArrays 0xEEE、数据偏移 0x44BC60 与 +0x10 shift、NDC 转屏幕与光栅化过滤条件均一致。注意点：原文脚本注释渲染文本为 texsaw{2switch1918462350923>，而原文最终 flag 为 texsaw{2switch1918402350923}，卡片采用最终 flag，属原文内部不一致；无 nro 附件，PoC 未复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

`drawing.nro` 用 OpenGL 把一大块顶点数据画成白字：`glBufferData` 上传 `0x16650` 字节，`glVertexAttribPointer` 说明每顶点 6 个 float（`x,y,z,r,g,b`，步长 24），`glDrawArrays(GL_TRIANGLES,0,0xEEE)` 画三角形；把顶点流起点后移 `0x10` 后按 NDC 转屏幕坐标、光栅化三角形，即可读出 flag `texsaw{2switch1918402350923}`。

## 原理

- **顶点布局**：每个顶点 6 个 float：位置 `(x,y,z)` + 颜色 `(r,g,b)`；步长 24 字节；三角形每 3 个顶点。
- **绘制调用**：`glBufferData(..., size=0x16650, data=...)` 上传顶点数组；`glDrawArrays(GL_TRIANGLES, 0, 0xEEE)` 画 `0xEEE` 个顶点（约 1274 个三角形）。
- **数据位置**：原始 NRO 里顶点数据在 `0x44BC60`，但题目叫 “not drawing”，前面多塞了 `0x10` 字节；直接按程序原样画会错位，必须把起点后移 `0x10` 才能还原真正的图。
- **坐标转换**：OpenGL NDC `[-1,1]` → 屏幕 `sx=(x*0.5+0.5)*(W-1)`、`sy=(1-(y*0.5+0.5))*(H-1)`；本题 `W=1600,H=900`。
- **过滤**：跳过非有限值、`|x|/|y|/|z|>2`、颜色越界、颜色均值 < 0.5 的三角形，避免尾部坏数据和背景。
- **结果**：渲染出白字；最后一位可能画坏，按 flag 格式补 `}`；原文最终 flag `texsaw{2switch1918402350923}`。

## 触发条件

- 目标是 NRO/NSO/OpenGL 程序，包含 `glBufferData`/`glVertexAttribPointer`/`glDrawArrays`。
- 顶点数据在二进制/资源中可定位，布局为 6 float/顶点（或可从 `glVertexAttribPointer` 推断）。
- 数据可能有偏移/前置填充，需要尝试 shift。
- 能写简单三角形光栅化/用 OpenGL 离屏渲染。

## 利用步骤

1. 反编译/搜索 `glBufferData`、`glVertexAttribPointer`、`glDrawArrays`，记录数据地址、大小、顶点步长、顶点数。
2. 从二进制中取顶点 blob；按 `6 float` 分组，过滤非有限/越界值。
3. 尝试不同起始偏移（本题 `+0x10`），按 NDC→屏幕坐标转换。
4. 对每个三角形做重心坐标光栅化，白色/按颜色阈值填像素。
5. 输出图片，读文字；若最后一位损坏，按 flag 格式修复。
6. 用 `glDrawArrays` 的顶点数/三角形数校验是否漏画。

## PoC

```python
from pathlib import Path
import numpy as np
from PIL import Image

NRO_PATH = "drawing.nro"
BLOB_OFF, SHIFT, BLOB_SIZE = 0x44BC60, 0x10, 0x16650
W, H = 1600, 900

data = Path(NRO_PATH).read_bytes()
blob = data[BLOB_OFF + SHIFT: BLOB_OFF + BLOB_SIZE]
vals = np.frombuffer(blob, dtype="<f4")
vals = vals[:(len(vals) // 6) * 6]
verts = vals.reshape(-1, 6)
tris = verts[:(len(verts) // 3) * 3].reshape(-1, 3, 6)

img = np.zeros((H, W, 3), dtype=np.uint8)

def ndc_to_screen(x, y):
    return int((x * 0.5 + 0.5) * (W - 1)), int((1 - (y * 0.5 + 0.5)) * (H - 1))

def raster(tri):
    pts = [ndc_to_screen(v[0], v[1]) for v in tri[:, :3]]
    (x1, y1), (x2, y2), (x3, y3) = pts
    minx, maxx = max(0, min(x1, x2, x3)), min(W - 1, max(x1, x2, x3))
    miny, maxy = max(0, min(y1, y2, y3)), min(H - 1, max(y1, y2, y3))
    den = (y2 - y3) * (x1 - x3) + (x3 - x2) * (y1 - y3)
    if den == 0:
        return
    for y in range(miny, maxy + 1):
        for x in range(minx, maxx + 1):
            a = ((y2 - y3) * (x - x3) + (x3 - x2) * (y - y3)) / den
            b = ((y3 - y1) * (x - x3) + (x1 - x3) * (y - y3)) / den
            if a >= 0 and b >= 0 and 1 - a - b >= 0:
                img[y, x] = 255

for tri in tris:
    pos, col = tri[:, :3], tri[:, 3:]
    if not np.isfinite(pos).all() or not np.isfinite(col).all():
        continue
    if np.any(np.abs(pos[:, :2]) > 2.0) or np.any(np.abs(pos[:, 2]) > 2.0):
        continue
    if np.any(col < -0.1) or np.any(col > 1.1) or float(col.mean()) < 0.5:
        continue
    raster(tri)

Image.fromarray(img).save("render.png")
```

## 变体与关联

- **图形载体变体**：OpenGL 顶点缓冲、Vulkan/GLES、3D 点云/3DGS、OBJ/PLY 模型；先找顶点布局和绘制调用。
- **偏移变体**：数据前有填充/头部，尝试 `0x10`、`0x20` 等 shift；用渲染结果可读性判断。
- **过滤变体**：按颜色、alpha、深度、三角形面积过滤；背景/噪声可能干扰。
- **关联卡片**：[[ctf-reverse-nro-appended-jpeg-carving]]（同题 NRO 尾部 JPEG）、[[ctf-misc-3dgs-point-cloud-lattice-rasterization]]（点云栅格化）、[[ctf-forensics-video-single-pixel-channel-extraction]]（像素/通道还原）。
- **边界**：若顶点数据被压缩/加密、或使用复杂着色器/纹理，简单光栅化可能还原不出；需要复现 shader。

## 检测与防御

- **防御**：不要把 flag/敏感信息编码进顶点/纹理/模型数据；发布前剥离调试资源。
- **检测信号**：NRO/可执行文件中大块浮点数组；`glDrawArrays` 绘制数量异常；顶点数据偏移与代码不一致。
- **CTF 技巧**：先看 OpenGL 调用参数确定布局，再尝试 shift；用简单光栅化而不是完整模拟 GPU。
