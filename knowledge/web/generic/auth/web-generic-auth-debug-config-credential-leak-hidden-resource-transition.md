---
id: web-generic-auth-debug-config-credential-leak-hidden-resource-transition
title: 调试配置泄露管理员凭据 + 隐藏条目状态越权发布：/debug/config.json 到 review-flow/transition
type: scenario
domain: web
path: web/generic/auth
technique: debug-config-credential-leak-hidden-resource-transition
aliases:
- N-RustPICA
- /debug/config.json
- passwordParts
- review-flow
- anime transition
- 隐藏条目
tags:
- auth
- information-disclosure
- debug-endpoint
- base64
- broken-access-control
- business-logic
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:11:35+08:00'
  notes: 已对照原文截图核对并修正：/debug/config.json 的 passwordParts 实为 ["cHVyZXN0","cmVhbQ=="]（解出 purest+ream=purestream），原卡 PoC 多写了一段导致拼接成 purestreamream，已按截图改正；review-flow 模板与 transition 发布隐藏条目 anime-0007、响应 description 中 flag 均一致；未实际运行 PoC。
---

## 一句话结论

Rust 应用的静态目录残留 `/debug/config.json`，泄露管理员用户名与 Base64 分段密码；登录后在 `/api/admin/anime` 看到隐藏条目 `anime-0007`（status internal），用 `/api/admin/templates/review-flow` 给出的请求体模板向 `/api/admin/anime/anime-0007/transition` 提交 `publish`，即可把隐藏条目发布并在响应的 description 中拿到 flag。

## 原理

- **调试文件泄露**：`/debug/config.json` 被放在静态资源目录，返回 `adminUser: anime_admin` 和 `passwordParts`（Base64 分段）。Base64 只是编码，不是加密；解码拼接即得后台密码（原文为 `purestream`，以实际拼接为准）。
- **隐藏资源**：`/api/admin/anime` 返回条目列表，其中 `anime-0007` 的 `status` 为 `internal`，`descriptionPreview` 为空；普通列表/前端不显示，但 API 仍返回其 id。
- **请求体模板**：`/api/admin/templates/review-flow` 返回旧审核流程的 `payload` 模板，包含 `action`、`targetStatus`、`reviewerToken`、`featured`、`approvalTicket` 字段；这是给审核工具用的示例，不是服务端强制状态机。
- **越权状态变更**：`POST /api/admin/anime/{id}/transition` 接受客户端提交的 `reviewerToken`（`FEATURE-REVIEW-2025`）和 `approvalTicket`（`PENDING-APPROVAL`），没有在服务端校验 token 是否有效/票据是否批准；因此管理员会话可以直接把 `internal` 条目改成 `published`。
- **flag 位置**：隐藏条目的完整 `description` 中包含 flag；发布接口的响应 `data.description` 直接返回，未发布时列表只给空的 `descriptionPreview`。

## 触发条件

- 应用静态目录/调试路由暴露 `/debug/config.json` 或类似配置文件。
- 管理员密码以 Base64 分段/编码形式存放，可解码。
- 存在返回请求体模板的审核接口（如 `/api/admin/templates/review-flow`）。
- 状态变更接口信任客户端提交的 `reviewerToken`/`approvalTicket`，只校验登录/管理员会话。
- 隐藏资源可通过 id 直接访问/变更。

## 利用步骤

1. 访问 `/debug/config.json`，取 `adminUser` 和 `passwordParts`。
2. Base64 解码各段并拼接，得到管理员密码；用 `adminUser/password` 调 `/api/auth/login` 拿会话。
3. 调 `/api/admin/anime`，找 `status: internal` 的隐藏条目 id（本题 `anime-0007`）。
4. 调 `/api/admin/templates/review-flow`，取 `payload` 模板中的字段名与示例值。
5. 向 `/api/admin/anime/anime-0007/transition` POST 模板（`action: publish`、`targetStatus: published`、`reviewerToken: FEATURE-REVIEW-2025`、`approvalTicket: PENDING-APPROVAL`）。
6. 从响应 `data.description` 读取 flag；若被截断，再调 `/api/admin/anime/anime-0007` 取完整对象。

## PoC

```bash
# 1) 泄露的调试配置
curl -s http://target/debug/config.json
# {"adminUser":"anime_admin","passwordParts":["cHVyZXN0","cmVhbQ=="]}

# 2) 解码并登录
python - <<'PY'
import base64
parts = ["cHVyZXN0", "cmVhbQ=="]
print(b"".join(base64.b64decode(p) for p in parts).decode())  # purestream
PY
curl -s -X POST http://target/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"anime_admin","password":"purestream"}'

# 3) 取隐藏条目与审核模板
curl -s http://target/api/admin/anime -b 'session=...'
curl -s http://target/api/admin/templates/review-flow -b 'session=...'

# 4) 发布隐藏条目
curl -s -X POST http://target/api/admin/anime/anime-0007/transition \
  -H 'Content-Type: application/json' -b 'session=...' \
  -d '{"action":"publish","targetStatus":"published","reviewerToken":"FEATURE-REVIEW-2025","featured":false,"approvalTicket":"PENDING-APPROVAL"}'
```

## 变体与关联

- **配置泄露变体**：`/debug/config.json`、`/config.json`、`/.env`、`/assets/*.map`、前端打包残留的 `VITE_*`/`REACT_APP_*`。
- **密码编码变体**：Base64 分段、hex、URL 编码、简单 XOR；不是加密，拿到即可解。
- **状态机变体**：审核 token/票据由客户端提交、服务端只查登录；隐藏资源 id 可枚举；`internal`/`draft` 可直接 `publish`。
- **关联卡片**：[[pentest-recon-frontend-obfuscated-js-hardcoded-credentials]]（前端硬编码凭据）、[[web-generic-auth-dev-reset-admin-password-default]]（调试接口重置密码）、[[web-generic-auth-multi-session-matrix-leakscore]]（越权检测）、[[web-generic-xss-maxsite-upload-missing-authz-admin-page-exfil]]（同类低权限/管理员链）。
- **边界**：若 `/debug` 在生产被禁用、密码不是可逆编码、transition 接口在服务端校验 token/票据，链不成立；flag 也可能在发布后的详情接口而非 transition 响应。

## 检测与防御

- **移除调试资产**：生产构建不打包 `/debug`、source map、`.env`、配置文件；静态目录做白名单。
- **凭据管理**：不要把密码/密钥放在前端可访问文件；使用服务端哈希/密钥管理，分段 Base64 不是保护。
- **状态机**：transition 接口在服务端校验资源状态、审核 token、票据和权限；`reviewerToken`/`approvalTicket` 不能由客户端自证。
- **检测信号**：`/debug/config.json` 被访问；管理员登录后立即枚举 `internal` 条目并调用 transition；请求体带固定 `reviewerToken`/`PENDING-APPROVAL`。
