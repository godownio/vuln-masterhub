---
id: ctf-misc-png-idat-chunk-anomaly-stego
title: PNG IDAT 块长度异常与未填满块后续块：识别人工插入的隐藏数据
type: scenario
domain: ctf
path: ctf/misc
technique: png-idat-chunk-anomaly-stego
tags:
- ctf
- misc
- png
- idat
- chunk
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:57:50+08:00'
  notes: 已对照原文4节与截图核对：9个8192 IDAT、2个4508 IDAT、最后CRC False与截图完全一致；未验证点：未对附件复跑。
url: /docs/ctf/misc/ctf-misc-png-idat-chunk-anomaly-stego/
draft: false
kb_aliases:
- IDAT 块隐写
- PNG 块长度异常
- IDAT 未填满新块
- PNG chunk 隐写
- IDAT 分块异常
---

## 一句话结论

PNG 的 IDAT 块按固定大小连续存储，编码器不会在上一个块未填满时另起一个新块；若看到 IDAT 长度不一致、短块后紧跟另一个 IDAT、或某一 IDAT 的 CRC 校验失败，就说明有人手工插入/改写了数据块，应把异常块单独提取分析。

## 原理

- **PNG 块结构**：`长度(4 字节大端) + 类型(4 字节) + 数据 + CRC32(4 字节)`；IDAT 是 zlib 压缩后的像素数据流，按顺序拼接后交给 zlib 解压。
- **正常编码器的行为**：libpng 等通常用固定块大小（常见 8192 或 65536 字节）连续写 IDAT，只有最后一个块可能不足固定大小；一旦某块未填满，说明 zlib 流已结束，后面不应再出现新的 IDAT。
- **异常信号**：
  - 多个 IDAT 的长度本应统一（除最后一块），却出现两个相同的“短块”；
  - 短块之后继续出现 IDAT；
  - 某个 IDAT 的 CRC 与块数据不匹配（人工插入时容易忘记重算 CRC）；
  - 图片能正常显示，但块表与正常编码器产物明显不同。
- **为什么能藏数据**：解码器通常按顺序拼接所有 IDAT 数据并忽略块边界；在正常 zlib 流之后追加的字节可能被忽略，或者额外的 IDAT 块会被某些解码器跳过。出题人也可以把隐藏数据放在异常块中，使常规查看器仍能显示原图。
- **本题**：块表显示 9 个 8192 字节的 IDAT，随后出现两个 4508 字节的 IDAT，且最后一个 CRC 校验为 False，说明最后一块是人工添加/改写的。

## 触发条件

- PNG 能正常打开，但 `pngcheck -v`、随波逐流、binwalk 或自写脚本报告 IDAT 长度异常/CRC 错误。
- 图片内容与文件大小不匹配；文件尾/块尾出现可读字符串或高熵数据。
- 题目提示“PNG/IDAT/块/隐写”。
- 文件不是经过多次重编码的“干净”产物；重编码通常会重建统一 IDAT 块，破坏该痕迹。

## 利用步骤

1. 列出所有块：类型、偏移、长度、CRC 是否正确；重点看 IDAT 序列。
2. 找出“未填满的短 IDAT 后又出现 IDAT”的位置；把该短块及其后续块的数据单独导出。
3. 对异常块数据做 `strings`/`xxd`，检查是否直接是可读片段、Base64、压缩包头（`PK`、`Rar!`、`7z`）或图片头（`FF D8`、`89 50 4E 47`）。
4. 若数据看起来是 zlib 流，尝试 `zlib.decompress`；若失败，尝试从不同偏移开始解压，或按 raw deflate 处理。
5. 若隐藏数据在正常 zlib 流之后，定位 zlib 流的结束位置（解压成功后的 `unused_data` 即为尾部附加数据）。
6. 同时检查 IHDR 宽高与 IDAT 解压后的像素数是否一致，排除“改宽高隐藏行”的变体。

## PoC

```python
import struct, zlib
from pathlib import Path

data = Path("hidden.png").read_bytes()
assert data[:8] == b"\x89PNG\r\n\x1a\n"
i = 8
idat_parts = []
prev_short = False
while i + 8 <= len(data):
    length = struct.unpack(">I", data[i:i+4])[0]
    ctype = data[i+4:i+8]
    payload = data[i+8:i+8+length]
    crc_stored = data[i+8+length:i+12+length]
    crc_ok = (zlib.crc32(ctype + payload) & 0xFFFFFFFF) == struct.unpack(">I", crc_stored)[0]
    print(f"{ctype.decode('latin1')} off={i} len={length} crc_ok={crc_ok}")
    if ctype == b"IDAT":
        if prev_short:
            print("  [!] 短 IDAT 之后又出现 IDAT，疑似人工插入")
        idat_parts.append(payload)
        prev_short = length < 8192
    if ctype == b"IEND":
        break
    i += 12 + length

blob = b"".join(idat_parts)
try:
    raw = zlib.decompress(blob)
    print("zlib ok, raw bytes:", len(raw))
except zlib.error as e:
    print("zlib error:", e)
    # 尝试定位 zlib 流结束后的附加数据
    d = zlib.decompressobj()
    raw = d.decompress(blob)
    print("unused_data:", d.unused_data[:64])
```

说明：PoC 仅做块表与 CRC 检查，不保证还原具体题目数据；异常块的提取需按块偏移单独 dump。未在本机对附件复跑。

## 变体与关联

- **IHDR 宽高篡改**：改小高度隐藏底部像素行；见 [[ctf-forensics-png-ihdr-width-height-crc32-brute-force]] 与 [[ctf-misc-ppm-p6-header-height-tamper-hidden-rows]]。
- **尾部附加数据**：在 `IEND` 之后追加数据，用 `binwalk`/`foremost` 分离；见 [[ctf-misc-png-trailing-data-lcg-xor-base62]]。
- **辅助块隐写**：`tEXt`/`zTXt`/`iTXt`/`eXIf`/`tIME` 等块可承载文本；与 IDAT 异常可同时出现。
- **自定义块**：私有 ancillary chunk（小写首字母）可被解码器忽略，常被用来藏数据；遍历时不要只筛 IDAT。
- **关联**：[[ctf-forensics-multilayer-png-wav-spectrogram-maze-stego]]（多层 PNG 隐写链）。

## 检测与防御

- 用 `pngcheck -v`、`identify -verbose` 或自写块遍历器检查 IDAT 长度/CRC；正常图片的 IDAT 长度应基本一致，仅最后一块可短。
- 发布前用图像库重新编码（Pillow/ImageMagick）可重建标准 IDAT 块并丢弃未知 ancillary chunk；但重编码也可能改变像素，需确认业务可接受。
- 取证时保留原始文件并计算哈希；不要先用会重写 PNG 的编辑器保存。
