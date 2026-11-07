---
id: ctf-forensics-docx-customxml-base64-comment
title: DOCX 解压取 customXml/item1.xml 注释中的 Base64 隐藏数据
type: scenario
domain: ctf
path: ctf/forensics
technique: docx-customxml-base64-comment
tags:
- ctf
- forensics
- docx
- office
- customxml
- base64
- stego
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:08:05+08:00'
  notes: 已对照原文核对：docx 解压 customXml/item1.xml、XML 注释 Base64（c2lsbHlDVEZ7... 解出 SillyCTF{cartman_homework_solutions}）与原文一致；未实际运行 PoC。
url: /docs/ctf/forensics/ctf-forensics-docx-customxml-base64-comment/
draft: false
kb_aliases:
- docx 隐写
- customXml/item1.xml
- XML 注释 Base64
- Office 文档隐藏数据
- Cartman's Business Venture
---

## 一句话结论

`.docx` 本质是 zip；解压后 `customXml/item1.xml` 的 XML 注释里藏 Base64，解码即得 flag。

## 原理

- **OOXML 是 zip 容器**：docx/pptx/xlsx 由 `[Content_Types].xml`、`word/`、`customXml/` 等部件组成；`customXml/item1.xml` 用于存放自定义 XML 数据，Word 正常界面不显示。
- **XML 注释不渲染**：`<!-- ... -->` 中的内容不会出现在文档正文，但会原样保留在 zip 部件中；用 `strings`/解压即可看到。
- **Base64 载荷**：注释中常放 Base64/hex/压缩数据；解码后得到 flag 或下一层线索。
- **为什么容易漏**：只打开 Word 看正文、只 `strings` 整个 docx（压缩后可能看不到）都会错过；必须解压后逐个 XML 部件检查。

## 触发条件

- 拿到 docx/pptx/xlsx 等 OOXML 文件；正文没有明显异常。
- 文件大小与正文内容不匹配，或题目提示“文档/作业/备注”。
- 常规 `strings` 可能因 deflate 压缩看不到明文。

## 利用步骤

1. `unzip -o file.docx -d docx_out` 或 Python `zipfile` 解压。
2. 遍历 `customXml/*.xml`、`word/document.xml`、`word/header*.xml`、`docProps/*.xml`。
3. 搜索 `<!--`、`<w:comment`、`base64`、长字符串。
4. 提取注释/文本中的 Base64，`base64 -d` 或 Python 解码。
5. 若解码结果还是乱码，尝试 hex、gzip/zlib、XOR 或下一层文件。

## PoC

```python
import re, base64, zipfile

with zipfile.ZipFile("cartman.docx") as z:
    for name in z.namelist():
        if not name.endswith(".xml"):
            continue
        text = z.read(name).decode("utf-8", "ignore")
        for m in re.finditer(r"<!--(.*?)-->", text, re.S):
            for token in re.findall(r"[A-Za-z0-9+/=]{16,}", m.group(1)):
                try:
                    print(name, base64.b64decode(token).decode("utf-8", "ignore"))
                except Exception:
                    pass
```

## 变体与关联

- **载体变体**：`docProps/core.xml`、`word/settings.xml`、批注、页眉页脚、隐藏文字、altChunk、嵌入对象。
- **编码变体**：Base64、hex、Base32、zip/gzip、XOR；也可能藏在图片/媒体文件尾部。
- **关联卡片**：[[ctf-forensics-docm-vba-base64-xor-powershell-download-url]]（DOCM 宏提取）、[[ctf-forensics-office-doc-password-office2john-hashcat]]（Office 加密文档）、[[ctf-misc-zip-local-header-repair-pseudo-encryption]]（zip 结构）。
- **边界**：若文档被转为 PDF/图片，customXml 部件丢失；若注释被清理/重保存，载荷消失。

## 检测与防御

- **CTF/验证**：解压后逐个 XML 部件搜索注释；Base64 解码结果应为可打印 flag/下一层文件头。
- **防御**：对外文档做清洗/重保存（移除 customXml、注释、元数据）；DLP 检查 OOXML 内部部件；不要用文档注释承载秘密。
- **检测信号**：docx 中存在异常大的 `customXml/item1.xml`；XML 注释含长 Base64；文档大小与正文不匹配。
