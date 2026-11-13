---
id: web-java-component-allegra-download-attachment-filename-traversal-jwt-key
title: Allegra AttachmentGlobalAction#download 任意文件读取：fileName 未过滤读 GeneralSettings.properties 取 JWT 签名密钥（CVE-2024-22507）
type: scenario
domain: web
path: web/java/component
technique: allegra-attachment-global-download-path-traversal-jwt-key
tags:
- java
- struts
- allegra
- trackplus
- path-traversal
- file-read
- jwt
- cve-2024-22507
cve:
- CVE-2024-22507
affected_versions: Allegra < 7.5.1（原文明确）
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V532
  verified_at: '2026-11-11T17:19:06+08:00'
  notes: 已对照原文13184与3/3截图核对：正文影响版本明确Allegra<7.5.1；img01 ZDI表确认CVE-2024-22507=downloadAttachmentGlobal Directory Traversal Information Disclosure(7.5)；img02请求fileName=../../GeneralSettings.properties并回显配置，第210行确为jwt.SigningKey(Base64密钥)。修正：卡原写jwt.signingKey已按截图改为jwt.SigningKey；原触发条件称原文请求未带Cookie，实际请求含theme/JSESSIONID/ext-admin*登录态Cookie，已改为需要有效会话并加PoC说明。dedup候选为其他产品JWT泄露/下载穿越，非同链。
url: /docs/web/java/component/web-java-component-allegra-download-attachment-filename-traversal-jwt-key/
draft: false
kb_aliases:
- CVE-2024-22507
- Allegra 任意文件读取
- AttachmentGlobalAction download
- attachmentGlobal!download.action
- trackplus GeneralSettings.properties
- jwt.SigningKey 泄露
---

## 一句话结论

Allegra（trackplus）使用 Struts 的 `foo!method` 路由，`attachmentGlobal!download.action` 的 `fileName` 参数被直接传给 `AttachBL.download(diskFileName, this.fileName, ...)` 并 `new File(fileName)` 打开，未做路径规范化/基目录校验；攻击者用 `fileName=../../GeneralSettings.properties` 即可读取任意文件，读到 `jwt.SigningKey` 后还能伪造 JWT 访问受保护 API（CVE-2024-22507，影响 < 7.5.1）。

## 原理

- **Struts 动态方法路由**：Allegra 基于 Struts，支持 `Action!method.action` 形式直接调用 Action 的方法；`attachmentGlobal!download.action` 对应 `AttachmentGlobalAction#download`。
- **sink 未校验路径**：`download` 最终调用 `AttachBL.download(diskFileName, this.fileName, outstream, false)`；内部 `File file = new File(fileName);` 后直接 `new FileInputStream(file)`（或 SVG 转 PNG 分支），没有任何 `getCanonicalPath()` 前缀检查、`..` 过滤或白名单基目录。`fileName` 完全来自请求参数，因此可穿越到 Web 根之外的配置目录。
- **为什么能拿到 JWT 密钥**：Allegra 的配置 `GeneralSettings.properties` 位于应用目录，里面有 `jwt.SigningKey`（截图中第 210 行可见其 Base64 值，已脱敏）以及 `sys.trackplus...` 等配置。JWT 签名密钥泄露后，攻击者可自行签发任意用户/权限的 token，访问 `/rest/...` 等受 JWT 保护的接口，也为后续 zipslip 等需要认证的漏洞提供入口。
- **同一路由的其他类似 CVE**：ZDI 公告表中还有 `downloadExportedChart` 目录穿越认证绕过（CVE-2023-22361）、`uploadSimpleFile`/`saveInlineEdit` 目录穿越 RCE 等，说明该产品多处 Action 都存在同类路径处理问题。

## 触发条件

- 目标为 Allegra < 7.5.1，Web 端可达。
- `attachmentGlobal!download.action` 可从攻击者位置访问；原文请求携带登录态 Cookie（`theme`、`JSESSIONID`、`ext-admin*` 等），原文未说明可未认证利用，实际可能需要登录或低权限账号。
- 目标文件对 Web 进程可读（如应用目录下的 `GeneralSettings.properties`、JWT 密钥文件）。

## 利用步骤

1. 确认目标为 Allegra/trackplus（登录页/静态资源/`/allegra/` 路径）。
2. 发送 `GET /allegra/attachmentGlobal!download.action?fileName=../../GeneralSettings.properties`。
3. 从响应中读取配置，提取 `jwt.SigningKey`（以及 `sys.*`、邮件/集成配置等敏感项）。
4. 用泄露的签名密钥伪造 JWT（HS256 等，按产品配置），访问需要认证的 REST 接口；也可继续读其他路径文件（如数据库配置、密钥库）。
5. 清理/记录请求；如用于后续利用，进入 zipslip/反序列化链。

## PoC

```http
GET /allegra/attachmentGlobal!download.action?fileName=../../GeneralSettings.properties HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

（原文请求还携带登录态 Cookie：`theme`、`JSESSIONID`、`ext-admin*` 等，说明该入口在原文环境是登录后可达；PoC 中省略，复现时需补有效会话。）

响应（节选，原文截图）：

```properties
# ...
jwt.SigningKey = <redacted-jwt-signing-key>
# ...
sys.trackplus...
```

## 变体与关联

- **路径深度变体**：按应用部署路径调整 `../` 数量；也可读 `web.xml`、数据库配置、日志、密钥库等。
- **同产品其他 CVE**：`downloadExportedChart` 目录穿越（CVE-2023-22361）、硬编码凭据认证绕过（CVE-2023-22360）；文件上传（CVE-2024-22510，[[web-java-component-allegra-branding-uploadfile-path-traversal]]）、反序列化（CVE-2024-22505，[[web-java-deserialization-allegra-renderfieldmatch-listmapping]]）、zipslip（CVE-2024-22504，[[web-java-component-allegra-import-allegra-format-zipslip]]）。
- **关联技术**：Java Web 任意文件读取/路径穿越见 [[web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter]]。

## 检测与防御

- **检测（Web 日志）**：`attachmentGlobal!download.action` 的 `fileName` 含 `../`、`..%2f`、绝对路径或指向 `.properties`/`.xml`/密钥文件；同一来源短时间内读取多个非附件路径；响应内容类型与附件不符。
- **检测（应用）**：附件下载接口出现应用目录外文件的读取；JWT 密钥文件被读取后出现异常 token 签发/访问。
- **防御**：升级到 7.5.1+；下载前对 `fileName` 做规范化并校验必须位于附件基目录内（`getCanonicalPath().startsWith(base)`）；拒绝 `..`/绝对路径；附件用 ID 映射而非用户传路径；JWT 签名密钥轮换并限制配置文件权限。
