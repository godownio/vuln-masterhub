---
id: ctf-misc-tiff-multilayer-hidden-image
title: TIFF 多图层隐写：普通查看器只显示顶层，用 PS/GIMP 分层查看隐藏 flag
type: scenario
domain: ctf
path: ctf/misc
technique: tiff-multilayer-hidden-image
aliases:
- TIFF 图层隐写
- TIF 多图层
- 分层 TIFF
- Photoshop 保存图层隐写
- TIFF 多页
tags:
- ctf
- misc
- tiff
- layers
- image
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:57:52+08:00'
  notes: 已对照原文50重力故事与截图核对：无扩展名10MB高熵容器、挂载得到TIFF、PS分层见flag{orknights_heavyfield}一致；未验证点：未复现容器挂载。
---

## 一句话结论

TIFF 可以把多个图层/页保存在同一个文件里，普通图片查看器通常只渲染最上面一层；把扩展名改成 jpg/png 也不影响 TIFF 解析，用 Photoshop/GIMP 分层查看或用 ImageMagick/Pillow 按页导出，就能看到隐藏层里的 flag。

## 原理

- **TIFF 是容器格式**：文件头用 `II*\0`（小端）或 `MM\0*`（大端）标识，随后是一个或多个 IFD（Image File Directory），每个 IFD 描述一幅图像/一页；多页 TIFF 就是多个 IFD 串联。
- **Photoshop 图层 TIFF**：在“存储为 TIFF”时勾选“存储图层”，Photoshop 会把图层信息写入私有标签/额外 IFD；普通查看器按第一幅图渲染，只显示合成后的顶层，图层数据不可见。
- **扩展名无关**：图片查看器/库通常按文件头魔数判断格式，TIFF 文件改成 `.jpg`/`.png` 仍能被识别为 TIFF；反过来，题目也可能把 TIFF 伪装成其他扩展名。
- **为什么隐蔽**：文件外观与普通图片无异；缩略图/在线预览只显示顶层；只有支持图层/多页的工具（PS、GIMP、ImageMagick、tifffile）才能枚举全部 IFD。
- **本题**：文件头不是 PNG 而是 TIFF；改成 `.tif` 放进 Photoshop 后发现还有一个图层，上面直接写着 flag。

## 触发条件

- `file`/`xxd` 显示 `II 2A 00` 或 `4D 4D 00 2A`，但扩展名是 jpg/png。
- `identify` 报多帧，或 `tiffinfo` 显示多个 IFD；文件大小远大于单幅同尺寸图片。
- 题目提示“图层/TIFF/PS/分层”；图片在普通查看器中只有背景/空白。
- 文件未被重编码为单层 PNG/JPEG。

## 利用步骤

1. 用 `file`、`xxd -l 16`、`exiftool` 确认实际格式与页数。
2. 用 ImageMagick 列出并按页导出：
   ```bash
   identify hidden.tif
   convert hidden.tif[0] page0.png
   convert hidden.tif[1] page1.png
   ```
3. 用 Pillow 的 `ImageSequence.Iterator` 或 `tifffile` 遍历所有页/IFD：
   ```python
   from PIL import Image, ImageSequence
   im = Image.open("hidden.tif")
   for i, frame in enumerate(ImageSequence.Iterator(im)):
       frame.convert("RGBA").save(f"page{i}.png")
   ```
4. 用 Photoshop/GIMP 打开，打开“图层”面板，逐个显示/隐藏图层；注意不透明度、混合模式和图层蒙版。
5. 若图层仍不可见，检查 alpha 通道、图层偏移、图层组、智能对象；对每层做反相/对比度拉伸。
6. 若文件是伪装扩展名，先复制并改回 `.tif`，再在支持 TIFF 的工具中打开。

## PoC

```python
from PIL import Image, ImageSequence

im = Image.open("hidden.tif")
print("format:", im.format, "size:", im.size, "n_frames:", getattr(im, "n_frames", 1))
for i, frame in enumerate(ImageSequence.Iterator(im)):
    frame.convert("RGBA").save(f"page{i}.png")
    print("saved page", i, frame.size, frame.mode)

# 需要更完整的 TIFF 标签/IFD 信息时：
# import tifffile
# t = tifffile.TiffFile("hidden.tif")
# for i, page in enumerate(t.pages):
#     print(i, page.shape, page.tags)
```

说明：PoC 按标准多页 TIFF 编写；Photoshop 私有图层不一定能被 Pillow 枚举，遇到这种情况优先用 Photoshop/GIMP 打开。未在本机对附件复跑。

## 变体与关联

- **多页 TIFF**：扫描件/传真常用多页；按 IFD 顺序导出即可。
- **Photoshop 图层 TIFF**：图层信息在私有标签中，Pillow 可能只看到合成图；PS/GIMP 最可靠。
- **BigTIFF**：文件头版本号 43，偏移为 8 字节；解析思路相同。
- **EXIF 缩略图**：JPEG/TIFF 的 EXIF 中可嵌入缩略图，查看缩略图有时能看到主图之外的内容；参见 [[ctf-misc-jpeg-segment-metadata-stego]]。
- **伪装扩展名**：与 [[ctf-misc-ppm-p6-header-height-tamper-hidden-rows]] 的“扩展名不可信”思路一致。

## 检测与防御

- 发布前把多图层/多页 TIFF 拼合（flatten）并重新导出为单层 PNG/JPEG，或显式删除图层/私有标签。
- 检测：`tiffinfo`/`identify` 检查 IFD 数量与标签；对上传文件按魔数而非扩展名识别，并拒绝包含多个 IFD 或 Photoshop 私有标签的图片。
- 取证时保留原始 TIFF，不要用会自动拼合的查看器覆盖保存。
