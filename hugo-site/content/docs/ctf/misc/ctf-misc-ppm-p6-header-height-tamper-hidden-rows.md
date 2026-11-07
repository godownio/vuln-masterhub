---
id: ctf-misc-ppm-p6-header-height-tamper-hidden-rows
title: PPM P6 文件头高度被篡改：按实际像素数重算高度还原隐藏行
type: scenario
domain: ctf
path: ctf/misc
technique: ppm-p6-header-height-tamper-hidden-rows
tags:
- misc
- file-format
- ppm
- image
- header
- stego
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:29:51+08:00'
  notes: 已对照原文核对：flag.pdf 实为 PPM P6、头 284 150 255、文件 157635 字节/头 15 字节/像素数据 157620、157620/3/284=185、改高度为 284 185 后显示隐藏行、flag kashiCTF{iLOVEkashi} 均一致。未验证点：无附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-ppm-p6-header-height-tamper-hidden-rows/
draft: false
kb_aliases:
- PPM 文件头高度错误
- P6 像素数据 重算高度
- flag.pdf 实为 PPM
- 图像头尺寸篡改
---

## 一句话结论

文件扩展名是 `.pdf` 但开头是 `P6` 时，它其实是二进制 PPM 图像；若头部宽高与实际像素数据长度不一致（如头写 284×150，数据实为 284×185），按 `数据长度 / 3 / 宽度` 重算高度并改回头部，就能显示原本被“裁掉”的隐藏行与 flag。

## 原理

- PPM P6 头由 `P6\n<width> <height>\n<maxval>\n` 组成，后面是每像素 3 字节的 RGB 原始数据；很多查看器按头部宽高读取，多余数据被忽略。
- 出题人把高度改小，查看器只渲染前 `height` 行，真实数据中多出的行不可见；但文件总大小暴露了真实像素数：`height_real = (file_size - header_len) / 3 / width`。
- 把头部高度改成真实值后，查看器会读取全部像素，隐藏区域（通常是底部若干行）显示出来。
- 为什么可行：PPM 没有强制校验头与数据长度一致；查看器/库通常信任头部，不会拒绝多余数据。

## 触发条件

- 文件头为 `P6`（或 `P3` 文本 PPM），但扩展名/题面伪装成其他格式。
- 头部宽高与文件大小不匹配；`(size - header_len) % (3 * width) == 0` 可算出整数高度。
- 隐藏内容在头部高度之外的多余像素行中，且未被压缩/裁剪破坏。

## 利用步骤

1. `xxd`/`head -c 64` 查看文件头，确认 `P6`、宽、高、maxval。
2. 计算像素数据长度：`file_size - header_len`；除以 3 得到像素数，再除以宽度得到真实高度。
3. 若真实高度大于头部高度，用十六进制编辑器/脚本把头部高度改成真实值（保持分隔符与长度）。
4. 用支持 PPM 的查看器打开，查看底部新增行；若仍不可读，尝试裁剪/放大/对比度增强。
5. 若文件被当作 PDF 打开失败，直接按 PPM 处理，不要被扩展名误导。

## PoC

```python
from pathlib import Path

p = Path("flag.pdf")
data = p.read_bytes()
# 解析 P6 头：P6\n<w> <h>\n<max>\n
parts = data.split(b"\n", 3)
assert parts[0] == b"P6"
w, h = map(int, parts[1].split())
maxv = int(parts[2])
header_len = len(parts[0]) + 1 + len(parts[1]) + 1 + len(parts[2]) + 1
real_h = (len(data) - header_len) // 3 // w
print(w, h, maxv, "real_h=", real_h)

if real_h != h:
    new_header = b"P6\n%d %d\n%d\n" % (w, real_h, maxv)
    Path("fixed.ppm").write_bytes(new_header + data[header_len:])
```

说明：PoC 为原文思路的结构化复现，未在本机执行；原文 284×150 的头对应实际 185 行，修正后底部隐藏区域显示 flag。

## 变体与关联

- 变体（格式）：P3 文本 PPM、PGM/PBM、BMP/PNG 头宽高篡改；PNG 还可用 CRC32 校验反推正确宽高。
- 变体（隐藏方式）：多余行、行尾多余像素、调色板/通道 LSB、头部注释字段。
- 关联：[[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]（PNG IHDR 宽高与 CRC 反推）；[[ctf-misc-zip-local-header-repair-pseudo-encryption]]（文件头损坏修复）；[[ctf-forensics-webp-riff-custom-chunk-ech0-extraction]]（自定义 chunk 隐写）。
- 边界：头部高度正确、数据被裁剪/重编码、或查看器严格校验长度时，需改用其他解析/取证手段。

## 检测与防御

- 检测：文件魔数与扩展名不符；图像头宽高与文件大小不匹配；像素数据长度不是 `3*width*height` 的整数倍。
- 防御：上传/处理前按魔数识别真实格式并校验尺寸；对图像重新编码后再使用；不要信任扩展名。
- 取证：保留原始文件，记录头部字段与重算过程；修正后的图像作为派生证据保存。
