---
id: ctf-misc-pptx-slide-image-binary-separator
title: PPTX 幻灯片图片序列隐写：6/7 图片映射 0/1，每 9 张一个分隔符
type: scenario
domain: ctf
path: ctf/misc
technique: pptx-slide-image-binary-separator
aliases:
- Six to the Seven
- pptx 隐写
- slide 图片
- image2/image3
- 分隔符
- 6->0 7->1
tags:
- ctf
- misc
- pptx
- slides
- stego
- binary
- ascii
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:08:04+08:00'
  notes: 已对照原文核对：215 张 slide、image2/3/4 三种图、每 9 张一个分隔、6->0/7->1、每 8 bit ASCII 与原文一致；未实际运行 PoC。
---

## 一句话结论

215 张 slide 每张只放 `image2.png`（数字 6）、`image3.png`（数字 7）或 `image4.jpg`（空白分隔）；`image4.jpg` 每 9 张出现一次，前 8 张一组，6→0、7→1，每 8 bit 转 ASCII 得 flag。

## 原理

- **幻灯片顺序即 bit 顺序**：每张 slide 的 XML 只引用一张图片；图片种类少且重复，说明用图片选择编码 bit。
- **分隔符分组**：空白图 `image4.jpg` 每 9 张出现一次，把 215 张分成若干组，每组前 8 张为 8 bit，第 9 张为分隔；这样不需要额外长度/同步信息。
- **映射规则**：图片内容是数字 6/7，分别映射 0/1；每 8 bit 大端转 ASCII，得到可打印 flag。
- **PPTX 是 zip**：`ppt/slides/slide*.xml` 按文件名排序即幻灯片顺序；`r:embed` 指向 `ppt/media/imageN.*`。

## 触发条件

- 拿到 pptx/ppsx；幻灯片数量多且每页只有一张/少量图片。
- 图片种类很少（2 种数据图 + 1 种分隔图），或图片位置/尺寸/旋转有规律。
- 常规文本提取看不到 flag。

## 利用步骤

1. 解压 pptx（`unzip` 或 Python `zipfile`）。
2. 按 `ppt/slides/slideN.xml` 的数字顺序读取每个 slide 的 `r:embed` 关系，映射到 `ppt/media/imageN.*`。
3. 统计图片序列，找出周期出现的分隔图（本例每 9 张一次）。
4. 按分隔符分组，取每组前 8 张；6→0、7→1，每 8 bit 转 ASCII。
5. 若顺序/映射不对，尝试 bit 反转、小端、从 1 开始编号或按 slide 显示顺序而非文件名排序。

## PoC

```python
import re, zipfile

with zipfile.ZipFile("sixtotheseven.pptx") as z:
    names = sorted([n for n in z.namelist() if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)],
                   key=lambda n: int(re.search(r"(\d+)", n).group(1)))
    seq = []
    for n in names:
        xml = z.read(n).decode("utf-8", "ignore")
        rid = re.search(r'r:embed="(rId\d+)"', xml).group(1)
        rel = z.read(n.replace("slides/slide", "slides/_rels/slide") + ".rels").decode()
        target = re.search(rf'Id="{rid}"[^>]*Target="([^"]+)"', rel).group(1)
        seq.append(target.split("/")[-1])

bits = []
for img in seq:
    if img == "image4.jpg":
        continue
    bits.append(0 if img == "image2.png" else 1)

print("".join(chr(int("".join(map(str, bits[i:i+8])), 2)) for i in range(0, len(bits)//8*8, 8)))
```

## 变体与关联

- **编码变体**：图片位置（x/y）、层级、旋转角度、尺寸、透明度编码；分隔符周期不同；bit 映射反转。
- **载体变体**：pptx/docx/xlsx、PDF 页面、视频帧；也可能用 slide 备注/动画顺序。
- **关联卡片**：[[ctf-misc-cs-skin-pattern-seed-ascii]]（皮肤图案转 ASCII）、[[ctf-misc-punctuation-2bit-encoding]]（标点 2-bit）、[[ctf-misc-unicode-variation-selector-hex-stego]]（Unicode 变体选择符）。
- **边界**：若 pptx 被加密/转 PDF 丢失对象顺序，需先解密/保留原始 XML；若图片被重命名/压缩，需按内容哈希分类。

## 检测与防御

- **CTF/验证**：分组后每组应正好 8 个数据图 + 1 个分隔图；解出的 ASCII 应为可打印 flag。
- **防御**：对 pptx 做重保存/转 PDF 可破坏对象级隐写；DLP 检测重复小图/周期分隔；不要用文档对象顺序承载秘密。
- **检测信号**：幻灯片数量异常多、每页仅一张小图、图片种类极少且周期性出现空白图。
