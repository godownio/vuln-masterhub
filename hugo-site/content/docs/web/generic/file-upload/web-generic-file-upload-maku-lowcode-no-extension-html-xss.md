---
id: web-generic-file-upload-maku-lowcode-no-extension-html-xss
title: MAKU 低代码平台 /sys/file/upload 无后缀校验任意文件上传导致 HTML 存储型 XSS
type: scenario
domain: web
path: web/generic/file-upload
technique: maku-upload-no-extension-html-xss
tags:
- web
- file-upload
- stored-xss
- html
- spring-boot
- maku
- java
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V56
  verified_at: '2026-11-05T09:17:42+08:00'
  notes: 已对照原文核对：SysFileUploadController /sys/file/upload 与 /sys/file/uploads、getPath→getNewFileName（getPrefix_时间.getSuffix，保留原后缀无白名单）、LocalStorageService 落盘并返回 domain/url/path、上传 test.html 后访问 /upload/20260103/test_80618.html 弹窗，均与 26 张图片一致；SecurityFilterChain anyRequest().authenticated() 与白名单 /upload/** 为静态目录，卡片未宣称未授权，处理正确。原文仅验证 HTML 存储型 XSS，未验证 JSP/PHP 解析或 RCE，卡片未夸大；原文未给版本区间（仅 pom revision 4.10.0），不写 affected_versions 正确。
url: /docs/web/generic/file-upload/web-generic-file-upload-maku-lowcode-no-extension-html-xss/
draft: false
kb_aliases:
- MAKU 任意文件上传
- SysFileUploadController 上传
- /sys/file/upload
- 上传 HTML 存储型 XSS
---

## 一句话结论

MAKU 低代码平台的 `SysFileUploadController` 在 `/sys/file/upload`（及 `/sys/file/uploads`）只检查文件非空，不校验扩展名/类型；上传 `.html` 后文件落到本地存储目录映射的 `/upload/YYYYMMDD/name_time.html`，同源访问即执行脚本，构成存储型 XSS/任意文件写入。

## 原理

- `upload()` 调用 `storageService.getPath(file.getOriginalFilename())` → `StorageService.getPath()` → `getNewFileName()`，文件名由 `FileNameUtil.getPrefix` + `_` + 秒级时间 + `.` + `getSuffix` 组成，保留原始后缀，不做白名单校验。
- `LocalStorageService.upload()` 把 `properties.getLocal().getPath() + File.separator + path` 作为落盘路径，目录不存在则自动创建，并返回 `domain + "/" + local.url + "/" + path`；本地存储根目录被映射为 Web 静态路径 `/upload/`（原文上传后 URL 为 `http://localhost:8080/upload/20260103/test_80618.html`）。
- 由于扩展名未限制、落盘目录可被 Web 直接访问，`.html` 以 `text/html` 返回，浏览器执行其中 `<script>`；这是“随机改名≠安全”的典型：攻击者不能覆盖已有文件（文件名带时间），但可以写入可执行 HTML。
- 上传接口本身受 Spring Security 保护（`anyRequest().authenticated()`），白名单 `/upload/**` 指向静态目录而非上传端点；原文 PoC 的 Authorization 为空但实际环境需结合登录态/ Cookie 判断，卡片不宣称未授权。

## 触发条件

- 目标为 MAKU 低代码平台，可访问 `/sys/file/upload` 或 `/sys/file/uploads`，并具备上传权限/有效登录态；
- 存储方式为本地存储（local），存储根目录映射到 Web 可访问路径 `/upload/`；
- 响应未强制 `Content-Disposition: attachment`，浏览器按 `text/html` 解析 `.html`；
- 上传目录未被鉴权拦截，或攻击者可直接访问上传后的静态 URL。

## 利用步骤

1. 登录后抓取上传请求，确认接口为 `POST /sys/file/upload`、参数名 `file`。
2. 上传含 JS 的 `.html` 文件，记录响应中的 `url`（形如 `/upload/20260103/test_80618.html`）。
3. 浏览器访问该 URL，确认脚本执行（原文弹窗 `1`）。
4. 将 URL 发给受害者或嵌入站内链接，脚本以同源身份读取页面数据、发起带 Cookie 的请求或钓鱼跳转。

## PoC

```http
POST /sys/file/upload HTTP/1.1
Host: localhost:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.html"
Content-Type: text/plain

<script>alert(1)</script>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

原文上传后访问 `http://localhost:8080/upload/20260103/test_80618.html`，页面弹窗显示 `1`。`/sys/file/uploads` 逻辑相同，只是返回结构不同。

## 变体与关联

- 上传 `.svg`、`.htm`、`.xhtml` 等同源可执行类型；
- 若本地存储目录恰好可被容器解析 JSP/PHP，可升级为 RCE（原文未验证）；
- 该上传点也可作为钓鱼页、恶意文件托管与 CSRF 载体；
- 关联通用“任意后缀上传 HTML 到 Web 静态目录形成同源存储型 XSS”卡片。

## 检测与防御

- 服务端按白名单校验扩展名与文件魔数，图片重编码；上传目录独立域名/对象存储，禁止 HTML 解析，响应加 `Content-Disposition: attachment` 与 `X-Content-Type-Options: nosniff`；
- 上传接口强制鉴权与权限校验，限制文件大小与类型；
- 监控上传目录出现 `.html/.svg/.xhtml` 等非预期文件，及上传后立即被访问的异常 URL。
