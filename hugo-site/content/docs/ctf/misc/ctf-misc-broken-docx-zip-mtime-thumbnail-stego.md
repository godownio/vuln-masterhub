---
id: ctf-misc-broken-docx-zip-mtime-thumbnail-stego
title: 损坏 Word 文档 ZIP 结构排查：按修改时间与缩略图定位背景图零宽隐写
type: scenario
domain: ctf
path: ctf/misc
technique: broken-docx-zip-mtime-thumbnail-stego
tags:
- ctf
- misc
- docx
- zip
- mtime
- thumbnail
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:53:44+08:00'
  notes: 已对照原文与图 04/06/08 核对：docx 当 ZIP 用 7z 查看、Thumbnails 条目 mtime 异常、提取后得到 grodno{my_lovley_06_12} 一致；图08 显示 flag 与 \xa0 不可见字符，标题“零宽隐写”表述略宽泛但正文已列 NBSP，可保留。未复跑脚本。
url: /docs/ctf/misc/ctf-misc-broken-docx-zip-mtime-thumbnail-stego/
draft: false
kb_aliases:
- Word 打不开
- docx ZIP 结构
- 7z 查看 docx
- 修改时间异常
- Thumbnails 隐写
---

## 一句话结论

Word 文档打不开时，先把它当 ZIP（OOXML）用 `7z l -slt` 查看条目；按修改时间排序，若 `Thumbnails/`、`word/media/` 等条目与 `content.xml`/`styles.xml` 的时间明显不同，就提取这些异常图片，再用 `file`/`binwalk`/`zsteg`/零宽字符检测找隐藏数据/flag。

## 原理

- **OOXML 本质是 ZIP**：`.docx`/`.xlsx`/`.pptx` 是 ZIP 容器，内含 `[Content_Types].xml`、`word/document.xml`、`word/media/`、`docProps/thumbnail.jpeg`、`Thumbnails/` 等；即使 Word 报“文件损坏”，`7z`/`unzip` 仍可列出/提取条目。
- **修改时间是强线索**：正常文档的 XML 与 media 通常在同一时间生成；出题人后续插入/替换的图片、缩略图会留下不同的 mtime（本题 `Thumbnails` 为 16:39，其他内容为 13:05）。
- **背景图/缩略图载体**：`word/media/` 的背景图、页眉图、`docProps/thumbnail.jpeg` 可被替换成含隐写的图片；常见隐写包括 LSB、零宽字符（在图片文本元数据/XML 中）、尾部附加数据、PNG 块异常。
- **零宽字符**：如果隐写落在 XML/文本字段，可能出现 `U+200B`/`U+200C`/`U+200D`/`U+FEFF`/NBSP 等不可见字符；用 Python 按 UTF-8 统计码点可发现。
- **本题**：`7z` 看到 `Thumbnails`/背景图条目时间异常，提取后在图片/文本中发现隐写，得到 `grodno{my_lovley_06_12}`。

## 触发条件

- `.docx`/`.xlsx`/`.pptx` 无法正常打开，或打开后显示异常/空白。
- `file` 显示为 Zip archive；`7z l` 能列出 OOXML 条目。
- 条目 mtime 不一致，尤其是 `Thumbnails/`、`docProps/thumbnail.*`、`word/media/` 比 XML 新/旧很多。
- 提取的图片/XML 中出现异常字符串、零宽字符、尾部数据或 PNG 块异常。

## 利用步骤

1. `file doc.docx` 确认 ZIP/OOXML；`7z l -slt doc.docx` 列出条目、大小、修改时间。
2. 按 mtime 排序，标记异常条目（缩略图、背景图、media、customXml、嵌入对象）。
3. `7z x doc.docx -oout` 或 `unzip` 提取；对图片执行 `file`、`exiftool`、`binwalk`、`strings`、`zsteg`。
4. 对 XML/文本字段用 Python 统计不可见字符（`U+200B`/`200C`/`200D`/`FEFF`/`00A0`），尝试零宽解码。
5. 检查图片 `FF D9`/`IEND`/`PK` 之后是否有附加数据；检查 PNG IDAT/IHDR 异常（参见相关卡）。
6. 还原 flag；若文档只是伪加密/头损坏，可参考 [[ctf-misc-zip-local-header-repair-pseudo-encryption]] 修复 ZIP 头。

## PoC

```bash
file Santa_s_Report.docx
7z l -slt Santa_s_Report.docx | sort -k4   # 查看条目与修改时间
7z x Santa_s_Report.docx -oout
find out -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort
file out/Thumbnails/* out/word/media/* 2>/dev/null
binwalk out/Thumbnails/* out/word/media/* 2>/dev/null
```

```python
# 统计 XML/文本中的不可见/零宽字符
import unicodedata
s = open("out/word/document.xml", encoding="utf-8").read()
for ch in set(s):
    if unicodedata.category(ch) in ("Cf", "Zs") and ch not in " \t\r\n":
        print(hex(ord(ch)), unicodedata.name(ch, "?"), s.count(ch))
```

说明：PoC 为通用 OOXML 排查流程；具体隐藏位置需按题目文件调整。未在本机对附件复跑。

## 变体与关联

- **缩略图隐写**：`docProps/thumbnail.jpeg`/`Thumbnails/thumbnail.png` 可被替换为含 flag 的图片；Word 打开时可能只用主文档，不显示缩略图。
- **背景图/页眉图**：`word/media/` 中的图片可承载 LSB/尾部数据。
- **customXml/注释**：`customXml/item*.xml`、批注、修订记录可藏 Base64/文本；参见 [[ctf-misc-docx-customxml-base64-comment]]。
- **零宽字符**：XML 文本节点中插入零宽字符；参见 [[ctf-misc-zero-width-unicode-binary-quinary-stego]]。
- **关联**：[[ctf-forensics-docm-vba-base64-xor-powershell-download-url]]（DOCM 宏）、[[ctf-misc-zip-local-header-repair-pseudo-encryption]]（ZIP 修复）。

## 检测与防御

- **检测**：比较 OOXML 条目 mtime、提取 `Thumbnails/`/`media/` 做 stego 扫描；检查 XML 中的不可见字符。
- **防御**：对外发文档重新生成/拼合（flatten）并删除缩略图、批注、customXml、嵌入对象；使用文档清洗/DLP 工具。
- **取证**：保留原始 docx 与哈希；不要用 Word 打开后另存（会重写 ZIP 结构，破坏 mtime/隐藏数据）。
