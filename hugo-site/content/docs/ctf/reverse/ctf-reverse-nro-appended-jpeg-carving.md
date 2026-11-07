---
id: ctf-reverse-nro-appended-jpeg-carving
title: Switch NRO 尾部追加 JPEG：按 SOI/EOI 边界 carve 提取隐藏图片
type: scenario
domain: ctf
path: ctf/reverse
technique: nro-appended-jpeg-carving
tags:
- reverse
- nintendo-switch
- nro
- jpeg
- file-carving
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:08:47+08:00'
  notes: 已对照原文核对：NRO 尾部 JPEG SOI/EOI 偏移 5931064/5937349、6285 字节、256x256、flag texsaw{switch96959d49370} 均一致。未验证点：无 nro 附件，PoC 未复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-nro-appended-jpeg-carving/
draft: false
kb_aliases:
- drawing
- drawing.nro
- NRO
- JPEG carve
- FF D8 FF
- FF D9
- Nintendo Switch homebrew
---

## 一句话结论

`drawing.nro` 是 Switch homebrew 可执行文件，文件尾部追加了一张完整 JPEG；在二进制中搜 `FF D8 FF`（SOI）到 `FF D9`（EOI）的边界，按偏移切片即可 carve 出 6285 字节的 256×256 JPEG，图片上就是 flag `texsaw{switch96959d49370}`。

## 原理

- **NRO 格式**：Nintendo Switch homebrew 的 `.nro` 是可执行容器，头部之后是代码/数据；攻击者/出题人可以在文件末尾追加任意数据，加载器通常不会校验尾部。
- **JPEG 边界**：JPEG 以 `FF D8 FF` 开始（SOI + APP0/其他标记），以 `FF D9` 结束（EOI）。在二进制中搜索这两个标记，取第一处 SOI 和其后第一处 EOI，即可切出完整 JPEG。
- **本题数据**：起始偏移 `5931064`、结束偏移 `5937349`，长度 `6285`；`file` 识别为 `JPEG image data, JFIF standard 1.01, 256x256`，说明 carve 正确。
- **为什么不是误切**：`file` 能识别为有效 JPEG，且图片内容可读；若切到随机数据，`file` 不会给出完整 JPEG 头/尺寸。
- **结果**：图片上显示 `texsaw{switch96959d49370}`。

## 触发条件

- 目标是 `.nro`/`.nso`/其他可执行容器，文件尾部有额外数据。
- 二进制中存在完整 JPEG/PNG/GIF 等文件头尾。
- 能读取原始文件字节（不要用文本编辑器/转码）。
- 图片内容可读或需要 OCR/人工查看。

## 利用步骤

1. 用 `file`、`xxd`/`binwalk` 确认文件类型和尾部结构。
2. 搜 `FF D8 FF` 找 JPEG SOI，搜其后第一个 `FF D9` 找 EOI。
3. 按 `[start:end+2]` 切片写出 `.jpg`；用 `file` 验证尺寸/格式。
4. 打开图片查看 flag；若图片损坏，检查是否有多个 SOI/EOI 或需要从 APP 标记开始。
5. 若没有 JPEG，尝试 PNG（`89 50 4E 47` ... `49 45 4E 44 AE 42 60 82`）、GIF、ZIP 等魔数。

## PoC

```python
from pathlib import Path

data = Path("drawing.nro").read_bytes()
start = data.find(b"\xff\xd8\xff")
end = data.find(b"\xff\xd9", start)

if start == -1 or end == -1:
    print("JPEG not found")
else:
    end += 2
    jpg = data[start:end]
    Path("extracted.jpg").write_bytes(jpg)
    print(f"JPEG extracted: start={start}, end={end}, size={end-start}")
```

```bash
file extracted.jpg
# JPEG image data, JFIF standard 1.01, 256x256
```

## 变体与关联

- **格式变体**：PNG、GIF、BMP、ZIP、PDF 追加/拼接；用对应魔数和结束标记 carve。
- **容器变体**：NRO/NSO、ELF、PE、APK、固件；尾部追加数据不影响原程序加载。
- **多文件变体**：一个二进制里可能有多张图/多个压缩包；循环搜索所有 SOI/EOI。
- **关联卡片**：[[ctf-reverse-nro-vertex-buffer-rasterization-text]]（同题 NRO 顶点缓冲重绘）、[[ctf-forensics-png-ihdr-width-height-crc32-brute-force]]（PNG 结构修复）、[[ctf-misc-png-trailing-data-lcg-xor-base62]]（尾部数据）。
- **边界**：若图片被加密/压缩/分片，直接 carve 可能失败；需要先解密/拼接。不要用有损转码后的文件。

## 检测与防御

- **防御**：发布前剥离可执行文件尾部附加数据；对固件/安装包做签名与完整性校验。
- **检测信号**：文件大小远大于代码段；尾部出现图片/压缩包魔数；`binwalk` 识别出嵌入文件。
- **CTF 技巧**：先 `file`/`binwalk`，再按魔数 carve；用 `file` 验证 carve 结果。
