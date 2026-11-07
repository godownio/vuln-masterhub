---
id: ctf-misc-jpeg-segment-metadata-stego
title: JPEG 段与 EXIF/COM/DQT 元数据隐写：遍历 marker 提取隐藏片段
type: scenario
domain: ctf
path: ctf/misc
technique: jpeg-segment-metadata-stego
aliases:
- JPEG 段隐写
- JPG 标识符隐写
- COM 段隐写
- DQT 段隐写
- EXIF 镜头型号隐写
- JPEG marker stego
tags:
- ctf
- misc
- jpeg
- exif
- com
- dqt
- marker
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:57:47+08:00'
  notes: 已对照原文3/6节与截图核对：DQT段part1_b3 YCvo9YcS、part2_JDHac...、EXIF LensModel part4_Usog203Ry+、marker结构与段长度解析一致；未验证点：未对附件复跑。
---

## 一句话结论

JPEG 以 `FF D8` 开始、`FF D9` 结束，中间是“`FF xx` + 2 字节大端长度 + 载荷”的段；把数据写进 COM（FFFE）、DQT（FFDB）或 APP1/EXIF 等段，图片仍能正常打开，遍历 marker 并提取各段中的可打印字符串即可拿到隐藏片段。

## 原理

- **JPEG marker 结构**：每个段以 `FF` 加一个非零 marker 字节开始；除 SOI（FFD8）、EOI（FFD9）和 RSTn 外，段后跟 2 字节大端长度（长度包含这 2 字节本身），再跟载荷。熵编码数据从 SOS（FFDA）之后开始，不再有统一的长度字段，需按扫描数据边界处理。
- **可承载数据的段**：
  - `COM`（FFFE）：注释段，解码器通常直接忽略，最适合藏文本。
  - `DQT`（FFDB）：定义量化表；修改其中的表项通常仍能解码，只是画质/数值变化，隐蔽性较好。
  - `APP1`（FFE1）：EXIF 的容器，内部是 TIFF 头 + IFD，可把数据放进 `ImageDescription`、`UserComment`、`LensModel`（0xA434）、`Make/Model` 等字符串标签。
  - `APP0`（FFE0）：JFIF 头，也有注释/缩略图字段。
- **为什么成立**：JPEG 解码器只依赖 SOF/DQT/DHT/SOS 等必要段，未知或非关键段按长度跳过；因此在段载荷里追加字符串不会破坏图片打开。文件大小/段长度与正常编码器产物不同，是主要破绽。
- **本题**：DQT 段中出现 `part1_b3 YCvo9YcS`，另一段中出现 `part2_JDHac...`，EXIF 的“镜头型号”字段出现 `part4_Usog203Ry+`；把各段片段按题目顺序拼接即可进入下一层。

## 触发条件

- JPG 能正常打开，但文件大小明显大于同尺寸图片，或 `strings`/`binwalk`/`exiftool` 输出异常文本。
- 题目提示“JPG/EXIF/分段/标识符”，或十六进制查看发现 COM/APPn 段长度异常。
- 段载荷中有 Base64 字符集、`partN_` 前缀、`flag{` 片段等可读内容。
- 图片可能经过多次拼接，需按段偏移/题目提示排序。

## 利用步骤

1. 先用现成工具快速扫一遍：
   ```bash
   exiftool -a -G1 -s file.jpg
   strings -a -n 6 file.jpg
   binwalk file.jpg
   ```
2. 用脚本遍历 marker：从 `FF D8` 后开始，读 `FF xx`、2 字节长度，跳过载荷；遇到 `FFDA` 停止按段解析，改为处理扫描数据/其后内容。
3. 对 COM、APP1、APP0、DQT 的载荷分别 `strings`/正则提取可打印片段；EXIF 段可用 `exiftool` 读所有标签，或按 TIFF IFD 解析。
4. 记录每个片段的段偏移与段类型，按题目提示/出现顺序拼接；若片段带 `partN` 编号，按编号排序。
5. 若段内数据是 Base64/hex，先解码再拼接；若 DQT 表项被当成字节数组，按 8 位/16 位尝试。
6. 同时检查 SOF0 的宽高与扫描数据长度是否匹配：把高度改小可以隐藏底部像素行（参见变体）。

## PoC

```python
from pathlib import Path

data = Path("hidden.jpg").read_bytes()
assert data[:2] == b"\xff\xd8"
i = 2
while i < len(data) - 1:
    if data[i] != 0xFF:
        i += 1
        continue
    while i < len(data) and data[i] == 0xFF:  # 填充字节
        i += 1
    if i >= len(data):
        break
    marker = data[i]
    i += 1
    if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
        continue
    if marker == 0xDA:  # SOS 之后是熵编码数据，停止按段解析
        print("SOS at", i - 2)
        break
    seg_len = int.from_bytes(data[i:i+2], "big")
    payload = data[i+2:i+seg_len]
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in payload)
    if any(c.isalnum() for c in printable):
        print(f"marker FF{marker:02X} off={i-2} len={seg_len} :: {printable[:120]}")
    i += seg_len
```

说明：PoC 为最小 marker 遍历器，用于定位 COM/APP1/DQT 中的可读片段；EXIF 标签可用 `exiftool -j` 结构化读取。未在本机对附件复跑。

## 变体与关联

- **多段拼接**：把长文本拆进多个 COM/APPn 段，按 `partN` 或偏移排序。
- **EXIF 标签**：数据可藏在 `LensModel`、`UserComment`、`ImageDescription`、`Make`、`Model`、`Software`、缩略图等字段；优先用 `exiftool` 全量导出。
- **DQT 表项**：把量化表当字节数组，数据藏在表项的低位/表序号中；需要按 JPEG 规范解析 8 位或 16 位表项。
- **SOF0 高度篡改**：把图像高度改小，底部真实像素行不被渲染，形成“裁剪式”隐藏区域；修复高度即可看到（同类思路见 [[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]）。
- **文件尾追加**：`FF D9` 之后追加 Base64/压缩包也很常见，可用 `binwalk`/`foremost` 分离（参见 [[ctf-misc-png-trailing-data-lcg-xor-base62]]）。
- **关联**：[[ctf-reverse-esp32-rf-trigger-frame-reconstruction]]（从 JPEG COM 取业务参数的另一用法）。

## 检测与防御

- 上传/发布前用 `exiftool -all=` 清空元数据并重新编码 JPEG，可去掉 COM/APPn/EXIF 中的隐藏内容；仅改扩展名或复制文件不能清除。
- 检测：解析段表，标记非标准 COM/APPn、异常段长度、DQT 表项与标准表差异、EXIF 字符串中的 Base64/十六进制特征。
- 取证时保留原始文件，不要用会重写 JPEG 的查看器打开后再分析；先计算哈希并复制副本。
