---
id: cloud-object-storage-response-content-type-xss
title: 对象存储公共写 + response-content-type 覆盖：上传 HTML 后强制按 text/html 解析触发存储型 XSS
type: scenario
domain: cloud
path: cloud
technique: oss-response-content-type-override-xss
aliases:
- OSS response-content-type
- 对象存储存储型 XSS
- Bucket 公共写 XSS
- response-content-type=text/html
- MinIO 存储桶 XSS
- OSS 响应头覆盖
tags:
- cloud
- object-storage
- oss
- s3
- minio
- xss
- public-write
- response-header
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V61
  verified_at: '2026-11-05T12:11:20+08:00'
  notes: 已对照原文与图22-26核对：MinIO edu-yy 桶 GET 返回 NoSuchKey(图22)、匿名 PUT TEST 返回 200(图23)、DELETE 返回 204(图24)、PUT TEST.html 写入 <script>alert("test123")</script>(图25)、GET ...TEST.html?Response-content-type=text/html 弹出 test123(图26)，与卡一致。卡内已说明大小写按厂商、原文图26为 Response-content-type。未验证点：Bucket 公共写/删除的 ACL 配置与 CDN/WAF 行为原文未展开；PoC 未在本机复跑；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

当对象存储 Bucket 允许匿名写入时，可上传一个 HTML/JS 对象；若直接访问因对象元数据 `Content-Type` 不是 HTML 而被下载，在 URL 后追加 `?response-content-type=text/html`（或厂商等价的 `Response-content-type`）即可让存储服务用 HTML 类型返回该对象，在 Bucket 域名上触发存储型 XSS。

## 原理

- S3 兼容对象存储（AWS S3、阿里云 OSS、腾讯云 COS、MinIO 等）支持 GET 请求的响应头覆盖参数，如 `response-content-type`、`response-content-disposition`、`response-content-encoding`、`response-cache-control`。服务端会用查询参数值覆盖对象元数据中的同名响应头。
- Bucket 公共读写时，攻击者可匿名 `PutObject` 任意内容；若上传时没有设置 `Content-Type: text/html`（或元数据被固定为 `application/octet-stream`），直接访问会触发下载而不是渲染。
- 追加 `response-content-type=text/html` 后，存储服务返回 `Content-Type: text/html`，浏览器把对象内容当 HTML 解析，内联 `<script>` 执行；若 Bucket 绑定自定义域名/被业务引用，XSS 发生在受信域名下，可用于钓鱼、窃取 Cookie/Token、发起同源请求。
- 之所以成立：对象内容是攻击者可控的，响应头覆盖参数又是存储服务的合法功能；两者组合把“静态文件托管”变成“可控内容的 HTML 执行”。
- 边界：Bucket 若禁止公共写、或 CDN/WAF 剥离响应头覆盖参数、或响应带 `Content-Disposition: attachment`/`X-Content-Type-Options: nosniff`/严格 CSP，利用会受限。

## 触发条件

- Bucket ACL/策略允许匿名 `PutObject`（公共读写），或存在可上传任意内容的预签名/前端直传通道。
- 允许 GET 对象并支持 `response-content-type` 等响应头覆盖参数（S3/OSS/MinIO 默认支持）。
- 对象内容可为 HTML/SVG/JS；Bucket 域名可被受害者访问（自定义域名或云厂商默认域名）。
- 响应未强制 `Content-Disposition: attachment`，也未通过 CSP 限制脚本。

## 利用步骤

1. 从页面源码/JS/抓包中找到对象存储域名与 Bucket（如 `bucket.oss-cn-*.aliyuncs.com`、`*.minio.*`）。
2. 探测写权限：对随机 Key 发送 `PUT`，返回 200/204 即公共可写。
3. 上传 HTML 测试对象（内容如 `<script>alert(document.domain)</script>`），先用默认 `Content-Type` 访问，确认是否被下载。
4. 在对象 URL 后追加 `?response-content-type=text/html`（大小写按厂商），再次访问，观察脚本是否执行。
5. 若执行，构造钓鱼/凭据窃取页面，或利用同源权限调用业务接口；记录 Bucket、对象 Key 与复现 URL。
6. 测试完成后删除测试对象（若 DELETE 权限允许），避免污染业务数据。

## PoC

上传：

```http
PUT /upload/20250605/TEST.html HTTP/1.1
Host: bucket.example.com
Content-Type: application/octet-stream
Content-Length: 30

<script>alert("test123")</script>
```

默认访问（可能下载），加上覆盖参数：

```http
GET /upload/20250605/TEST.html?response-content-type=text/html HTTP/1.1
Host: bucket.example.com
```

说明：原文在 MinIO 的 `edu-yy` 桶上实测：PUT 返回 200、DELETE 返回 204；直接访问 `TEST.html` 不弹窗，追加 `?Response-content-type=text/html` 后成功弹出 `test123`；PoC 未在本会话执行。

## 变体与关联

- **其他响应头**：`response-content-disposition=inline` 强制内联、`response-content-type=image/svg+xml` 触发 SVG 脚本、`response-content-encoding` 影响解析。
- **覆盖已有对象**：公共写可覆盖业务 JS/CSS/HTML，造成前端供应链劫持或缓存投毒。
- **自定义域名/CDN**：Bucket 绑定受信域名时 XSS 危害更大；CDN 缓存可能扩大影响。
- **AK/SK 泄露**：若前端/配置泄露 AccessKey/SecretKey，可从公共写升级为 Bucket 完全接管（见关联卡）。
- 关联：[[cloud-object-storage-bucket-acl-misconfig]]（公共读/写与 ListObject）、[[cloud-cloud-iam-oss-ak-sk-leak-bucket-pii-proof]]、[[web-generic-xss-html-static-stored-xss]]。

## 检测与防御

- **检测**：Bucket 出现匿名 PUT/DELETE；对象列表出现 `.html`/`.svg`/`.js` 等可执行内容；GET 请求带 `response-content-type`/`response-content-disposition` 等覆盖参数；CDN 回源响应类型与对象元数据不一致。
- **防御**：Bucket 默认私有，禁止公共写；对上传对象强制安全 `Content-Type` 与 `Content-Disposition: attachment`；在 CDN/WAF 层拒绝 `response-content-*` 覆盖参数；返回 `X-Content-Type-Options: nosniff` 与严格 CSP；开启版本控制/访问日志，发现异常对象立即删除并回滚 ACL。
