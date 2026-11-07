---
id: ctf-misc-png-invalid-chunk-type-zlib-wav-stego
title: PNG 非法 chunk 类型 Fl4G 藏 zlib 压缩流：提取解压得到隐藏 WAV
type: scenario
domain: ctf
path: ctf/misc
technique: png-invalid-chunk-type-zlib-stego
aliases:
- PNG 非法 chunk 隐写
- Fl4G chunk
- PNG 自定义块藏文件
- pngcheck invalid chunk type
- chunk data zlib 解压
tags:
- ctf
- misc
- png
- chunk
- stego
- zlib
- wav
- file-format
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T13:48:24+08:00'
  notes: 已对照原文与图02/03核对：Fl4G 非法 chunk，offset 0x80040、length 17321，data 头 78 9c，zlib.decompress 得到 hidden.wav（1ch/16-bit/48kHz），均与原文一致。PoC 遍历逻辑与原文等价；未对附件复跑。无 sources/source_url；affected_versions 未设置。
---

## 一句话结论

PNG 规范要求 chunk type 为 4 个 ASCII 字母；当块表中出现 `Fl4G`（含数字）这类非法类型时，`pngcheck` 会报 `invalid chunk type (contains non-letters)`，而该块的 data 往往以 `78 9c` 开头、是一段 zlib 压缩流，直接 `zlib.decompress` 就能还原出隐藏文件（本文为 WAV 音频）。

## 原理

- **PNG 块结构固定**：每个 chunk 为 `长度(4 字节大端) + 类型(4 字节) + 数据 + CRC32(4 字节)`。类型字段规范要求 4 个 ASCII 字母，第 1 字节的大小写决定 critical/ancillary，解码器应忽略不认识的 ancillary chunk。
- **非法类型是明显的人为痕迹**：`Fl4G` 含数字 `4`，不满足“4 个字母”的约束；`pngcheck -v` 会直接报 `ERROR: invalid chunk type (contains non-letters): "Fl4G"`，同时仍列出其偏移和长度。正常编码器不会产生这种块。
- **数据是标准压缩流**：本题 `Fl4G` 块 data 的前两字节为 `78 9c`，是 zlib 默认压缩头（CMF/FLG）。zlib 流自带长度与 Adler-32 校验，解压后得到 `RIFF....WAVE`，说明隐藏的是完整 WAV 文件。
- **为什么查看器不受影响**：解码器按块类型分发，遇到未知/非法 ancillary chunk 通常跳过；图片仍能正常显示，隐藏数据不会被重编码或渲染流程破坏。
- **解析要点**：按长度字段前进并跳过 4 字节 CRC，不要依赖 CRC 正确性（手工插入的块 CRC 可能错误或未重算）；类型字段按原始 4 字节比较，不做大小写归一化。
- **可复用性**：这是 CTF Misc 中常见的“自定义/非法 chunk 承载二级文件”手法；同类载体还有 WebP 的 RIFF chunk、ZIP 注释、JPEG APPn 段等。

## 触发条件

- 题目给出 PNG，正常打开无异常，但 `pngcheck -v`、`binwalk`、`file` 或自写块遍历器报告未知/非法 chunk。
- 块表出现非 4 字母类型（含数字、下划线等）、私有 ancillary chunk，或块长度与文件大小明显不符。
- 该 chunk 的 data 开头是已知文件/压缩魔数（`78 9c`、`PK`、`Rar!`、`7z`、`89 50 4E 47`、`FF D8` 等）。
- 题目提示“PNG/块/隐写/音频”等关键词。

## 利用步骤

1. 用 `pngcheck -v` 列出块表，记录异常块类型、偏移、长度；本题输出包含 `chunk Fl4G at offset 0x80040, length 17321` 与 invalid chunk type 警告。
2. 按 PNG 块结构遍历文件，匹配 `ctype == b"Fl4G"`，取出 data。
3. 观察 data 头：`78 9c` 表示 zlib；调用 `zlib.decompress(data)`。
4. 校验解压结果魔数：`RIFF....WAVE` 即 WAV，写出 `hidden.wav`。
5. 继续分析二级文件（本题 WAV 内还有频域隐写，见关联卡）。
6. 若 zlib 解压失败，尝试 raw deflate（`zlib.decompress(data, -15)`）、gzip（`1f 8b`）、或从不同偏移开始；也可能是 XOR/Base64 而非压缩。

## PoC

```python
import struct, zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"

def iter_chunks(path):
    data = open(path, "rb").read()
    assert data[:8] == PNG_SIG
    pos = 8
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos+4])[0]
        ctype = data[pos+4:pos+8]
        payload = data[pos+8:pos+8+length]
        yield ctype, payload
        if ctype == b"IEND":
            break
        pos += 12 + length

for ctype, payload in iter_chunks("warmup.png"):
    print(ctype, len(payload), payload[:4].hex())
    if ctype == b"Fl4G":
        raw = zlib.decompress(payload)   # data 以 78 9c 开头
        open("hidden.wav", "wb").write(raw)
        print("magic:", raw[:12])
```

```text
# 预期输出（节选）
b'Fl4G' 17321 789c...
magic: b'RIFF...WAVEfmt '
```

说明：原文用 `pngcheck -v` 确认 `Fl4G` 非法块，再用上述遍历脚本解压出 `hidden.wav`（1 声道、16-bit、48000 Hz）；本卡未对附件复跑。

## 变体与关联

- **块类型变体**：私有 ancillary chunk（首字母小写，如 `prVt`）、伪标准名（`tEXt`/`zTXt`/`iTXt`/`eXIf`/`pHYs`）以及完全非法名（`Fl4G`、`1D4T`）；遍历时不要只筛 IDAT，也不要只筛“合法字母”。
- **数据编码变体**：zlib/deflate、gzip、ZIP、Base64 文本、XOR 后再压缩；先看魔数再决定解码方式。
- **位置变体**：块可能在 IDAT 之前或之后；也可能在 `IEND` 之后追加（按尾部数据/`binwalk` 处理）。
- **CRC 变体**：手工插入块常忘记重算 CRC，`pngcheck` 会同时报 CRC 错误；解析时按长度跳过 CRC，不要因 CRC 失败而放弃。
- **关联**：[[ctf-misc-png-idat-chunk-anomaly-stego]]（IDAT 长度异常与短块后继续 IDAT）、[[ctf-misc-png-trailing-data-lcg-xor-base62]]（IEND 后尾部数据）、[[ctf-forensics-webp-riff-custom-chunk-ech0-extraction]]（RIFF 自定义 chunk 同类思路）、[[ctf-forensics-wav-multifrequency-8bit-block-fsk-stego]]（本链下一层音频隐写）。

## 检测与防御

- **发现**：`pngcheck -v`、`binwalk`、`identify -verbose`、自写 chunk 遍历器；重点检查非 4 字母类型、未知 ancillary chunk、CRC 失败、长度与文件大小不符。
- **清洗**：用 Pillow/ImageMagick 重新编码 PNG 会重建标准块并丢弃未知/非法 chunk；对外发布的图片应先重编码，避免携带原始元数据与隐藏载荷。
- **取证**：保留原始文件与哈希，不要用会重写 PNG 的编辑器保存；解析时记录每个块的偏移、长度、CRC 状态，保证可复现。
- **CTF 解题**：先 `pngcheck -v` 看块表，再按类型/魔数批量提取；不要只依赖 `strings` 或 `binwalk`，非法 chunk 可能被它们忽略。
