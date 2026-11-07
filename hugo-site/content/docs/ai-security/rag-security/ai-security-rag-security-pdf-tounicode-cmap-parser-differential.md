---
id: ai-security-rag-security-pdf-tounicode-cmap-parser-differential
title: PDF /ToUnicode CMap 映射劫持：页面渲染正常、RAG Parser 提取到另一段指令
type: scenario
domain: ai-security
path: ai-security/rag-security
technique: pdf-tounicode-cmap-parser-differential
tags:
- ai-security
- rag
- pdf
- tounicode
- cmap
- parser-differential
- prompt-injection
- data-poisoning
- occlusion
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V105
  verified_at: '2026-11-05T23:00:03+08:00'
  notes: 已对照原文与图03-11核对ToUnicode/bfchar重写、40字符分段、pdftotext/pdfplumber/OCR三路验证以及RAGFlow Chunk/检索结果；PoC未在本机执行；卡片'RAGFlow等Parser提取到指令'与图10-11一致，并已注明OCR路径可能阻断。
url: /docs/ai-security/rag-security/ai-security-rag-security-pdf-tounicode-cmap-parser-differential/
draft: false
kb_aliases:
- ToUnicode CMap 劫持
- PDF 渲染与提取语义分离
- Parser Semantic Differential
- RAG 入库视图差异
- bfchar 映射改写
- CANARY-CMAP
- OCR 与文本层不一致
---

## 一句话结论

PDF 的字符码同时走两条解释通道：字体/Encoding 决定人眼看到的 Glyph，`/ToUnicode` CMap 决定复制、搜索与 Parser 提取的 Unicode；只改 `/ToUnicode` 而保持字形不变，就能让页面显示正常排障指南、RAGFlow 等 Parser 却提取出攻击者指令，并继续进入 Chunk、Embedding、Retrieval 与 LLM Context。

## 原理

- PDF 页面中的“文字”至少有三层对象：字符码、字体程序/Encoding 映射到的 Glyph（Human View）、`/ToUnicode` CMap 映射到的 Unicode 字符串（Parser/Copy/Search View）。正常 PDF 两条路径表达同一内容，但它们不是同一个处理过程，可以被人为制造差异。
- `/ToUnicode` 流中的 `beginbfchar ... endbfchar` 是 `<字符码> <Unicode 字符串>` 映射表。只改写这张表，就能影响文本提取器看到的内容，而不必同步修改页面字形；人眼仍然看到原字形。
- 实验用内嵌 TrueType 简单字体，使字符码与 CID 保持一致，避免 Type0 复合字体在不同提取器（poppler `pdftotext` 与 pdfminer/pdfplumber）中的键空间差异导致样本只在某个工具上生效。
- 载体字符选用 Zero Width Space（U+200B）、Zero Width Non-Joiner（U+200C）、Zero Width Joiner（U+200D）、Soft Hyphen（U+00AD）：页面几乎不可见，但字体中确有可用编码映射（具体可用性依赖字体，原文使用 Arial Unicode.ttf）。把 payload 分段写进这些载体字符码的 `bfchar` 目标，其他字符码统一映射为空格 `<0020>`，Parser 就得到 payload 加大量空格。
- 解析 CMap 时不能对整份流做 `<hex> <hex>` 正则：`begincodespacerange` 中也有 `<00> <7F>`，误当作 bfchar 条目会按 UTF-16BE 解码异常。只处理 `beginbfchar` 与 `endbfchar` 之间的内容。
- 单条 `bfchar` 目标字符串过长时 poppler 会报 `Illegal entry in bfchar block`（原文实测 48 字符可提取、64 字符报错并提取为空），因此 payload 按不超过 40 字符分段，分给多个载体字符码。
- 回写时不能只按 `/Type /Font` 判断目标字体，复合字体也属于 Font；需结合 `/Subtype` 等字段定位，再把新的 `/ToUnicode` 流写回字体对象。
- 验证结果：`pdftotext` 与 pdfplumber 都提取到 payload（含 `CANARY-CMAP-20260812`），页面渲染后做 Vision OCR 只读到正常排障指南；上传 RAGFlow 后，左侧预览仍是正常指南，右侧 Chunk 已包含 CMap 映射后的文本；业务查询召回的是 `/ToUnicode` 通道内容。

## 触发条件

- RAG 平台/文档审核使用文本提取器（poppler、pdfminer、pdfplumber、OCR 之外的文本层）作为知识来源，而人工审核只看渲染页面或 OCR。
- PDF 文本层与渲染层没有被交叉比对；`/ToUnicode` 未被检查异常长映射、空格比例、零宽字符映射。
- 攻击者能上传/投递 PDF，且该文档会被解析进入知识库并被检索。
- 使用内嵌简单 TrueType 字体时，字符码与 CID 一致，跨提取器稳定性更高；复合字体可能只在部分工具生效。

## 利用步骤

1. 用 reportlab 等生成一份“人眼正常”的 PDF（如数据库排障指南），在页面末尾追加零宽载体字符。
2. 用 pikepdf 读取目标字体的 `/ToUnicode`，只解析 `beginbfchar/endbfchar` 块中的映射，避免误读 `codespacerange`。
3. 把攻击者 payload 按 ≤40 字符分段，分配给各载体字符码；其余字符码映射为 `<0020>`（空格），保持 Parser 输出可读。
4. 将新 CMap 写回字体对象的 `/ToUnicode` 流；按 `/Subtype` 等字段确认目标字体，避免误改复合字体。
5. 用 `pdftotext`、pdfplumber 与渲染后 OCR 三路验证：文本层应出现 payload，OCR/渲染应保持正常。
6. 上传 RAG 平台，确认 Chunk 中出现 payload；用正常业务问题触发检索，确认 payload 进入 Retrieval 与 LLM Context。

## PoC

```python
import re
import pikepdf

bfchar_block = touni.split("beginbfchar", 1)[1].split("endbfchar", 1)[0]
base_map = {}
for a, b in re.findall(r"<([0-9A-Fa-f]{1,4})>\s*<([0-9A-Fa-f]{2,8})>", bfchar_block):
    base_map[int(a, 16)] = bytes.fromhex(b).decode("utf-16-be")

parts = [PAYLOAD[i:i+40] for i in range(0, len(PAYLOAD), 40)]
entries = []
for code, ch in sorted(base_map.items()):
    if ch in CARRIERS and CARRIERS.index(ch) < len(parts):
        encoded = parts[CARRIERS.index(ch)].encode("utf-16-be").hex().upper()
        entries.append(f"<{code:02X}> <{encoded}>")
    else:
        entries.append(f"<{code:02X}> <0020>")

cmap = (
    "/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n"
    "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
    "/CMapName /Adobe-Identity-UCS def /CMapType 2 def\n"
    "1 begincodespacerange <00> <7F> endcodespacerange\n"
    f"{len(entries)} beginbfchar\n" + "\n".join(entries) + "\nendbfchar\n"
    "endcmap CMapName currentdict /CMap defineresource pop end end\n"
)

for key in pdf.pages[0].Resources.Font.keys():
    font = pdf.pages[0].Resources.Font[key]
    if "/ToUnicode" in font:
        font["/ToUnicode"] = pikepdf.Stream(pdf, cmap.encode("utf-8"))
pdf.save("cmap_attack.pdf")
```

```python
# 验证：文本层应含 payload，渲染 OCR 应仍为正常指南
# pdftotext cmap_attack.pdf - | grep CANARY-CMAP-20260812
# pdfplumber -> extract_text() 应含 CANARY-CMAP-20260812
```

## 变体与关联

- 变体：不改 `/ToUnicode`，而用白色文本、隐藏图层、注释/表单字段、页外对象、渲染与文本层不一致的字体；白色文本只是“页面里有两段文本”，CMap 是“同一组字符码被解释成两种语义”，后者更隐蔽。
- 变体：Type0 复合字体、CID 键空间差异、编码/CMap 组合可让不同提取器产生不同结果；可针对特定 RAG Parser 定制。
- 关联：[[ai-security-prompt-injection-invisible-unicode-tag-variation-selector-smuggling]]（不可见字符走私）、[[ai-security-rag-security-indirect-prompt-injection-context-concat]]（检索内容与问题拼接导致间接注入）、[[ai-security-supply-chain-safetensors-duplicate-key-audit-bypass]]（检查器与加载器解释不一致的通用模式）。
- 边界：OCR/渲染交叉校验、严格 CMap 审计或禁止上传 PDF 可阻断；`bfchar` 目标长度限制因工具/版本而异；简单字体与复合字体的稳定性不同。

## 检测与防御

- 检测：入库前同时生成“渲染 OCR 文本”与“Parser 提取文本”，比较相似度与 Parser-only 比例；检查 `/ToUnicode` 的长映射、空格映射比例、零宽字符映射、异常字体；对 PDF 文本层与可见页面做差异告警；记录文件哈希、字体名与 CMap 条目。
- 修复/防御：对上传 PDF 做规范化/重渲染后再入库；拒绝或隔离 `/ToUnicode` 异常、文本层与渲染层差异大的文件；在 Chunk 中保留 `parser_warning`/来源/页偏移；对 RAG 检索结果加可信度策略。
- 加固：使用 RAG-ViewGuard 一类工具做 PASS/REVIEW/BLOCK；对 OCR 与文本层双通道审核；限制外部 PDF 直接入库；对知识库内容做来源与完整性签名。
