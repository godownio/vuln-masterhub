---
id: web-generic-file-upload-upload-blacklist-miss-html-family-stored-xss
title: 上传后缀黑名单只列脚本后缀、漏掉 html 家族：同源 uploads 目录落地存储型 XSS
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-blacklist-miss-html-family-stored-xss
aliases:
- 黑名单漏 html
- uploads 目录同源 XSS
- 上传 1.html 弹窗
- 只挡 jsp/php 不挡 html
- 上传扩展名黑名单不完整
tags:
- file-upload
- blacklist
- stored-xss
- html
- spring-boot
- cms
- arbitrary-write
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: UJCMS 9.7.3（原文审计版本）
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:30:54+08:00'
  notes: '已对照原文与图03/07/09/10/14核对：/api/backend/core/web-file-upload/upload 对 1.jsp 返回 message=Web file illegal extension: 1.jsp(图03)、checkName 第227行 props.getFilesExtensionExcludes() + FilenameUtils.getExtension().toLowerCase() 抛 Http400(图07)、uploadsExtensionBlacklist 含 html,htm,xhtml,xml,shtml,sh 而 filesExtensionBlacklist 仅 exe,com,bat,jsp,jspx,asp,aspx,php(图09)、1.jspa 上传返回 status:0(图10)、/uploads/1/1.html 弹窗(图14)均一致。affected_versions 设为 UJCMS 9.7.3（原文审计版本）。未验证点：未复跑上传；原文称 jspa 访问只下载未进一步验证，卡内仅作为对照提及。'
---

## 一句话结论

当上传校验用「后缀黑名单」且黑名单只覆盖脚本类（`exe,com,bat,jsp,jspx,asp,aspx,php`）时，攻击者可以上传 `.html`/`.htm`/`.xhtml`/`.shtml` 等浏览器可解析的类型；文件落在 Web 同源的静态目录（`/uploads/...`），直接访问即按 `text/html` 渲染并执行脚本，形成存储型 XSS —— 黑名单的漏项本身就是绕过入口，而漏洞的最终危害不再是「传不传得上 webshell」，而是「同源脚本执行」。

## 原理

- 黑名单是「穷举禁止」模型：只要枚举不全，未枚举的类型默认放行。脚本后缀（`.jsp`/`.php`）数量有限且危险，通常被列全；而 `html`/`htm`/`xhtml`/`shtml` 属于「静态页面」，在开发者心里常被当成无害内容而不进黑名单。
- 但浏览器判断类型靠后缀与响应头：`GET /uploads/1/1.html` 返回 `Content-Type: text/html`（或无 `nosniff` 时浏览器按后缀渲染），其中的 `<script>` 就在该站点同源下执行，可读取同源非 HttpOnly Cookie、带会话发起请求、读取同源接口数据。
- 落地位置决定危害：文件管理/上传模块通常把文件存到 `/uploads/<siteId>/<文件名>` 这类对外静态目录，且该路径往往被鉴权拦截器排除（否则图片无法显示），所以匿名即可访问。
- 同源 XSS 与「传 webshell」的差别在于：它不需要服务器把 `.html` 当脚本执行（那是容器配置问题），只需要浏览器解析，因此即使 Tomcat/Spring 对 `.jspa`、`.html` 只做下载/静态返回，XSS 仍然成立；这也是原文里 `.jspa` 传上去但访问只触发下载、而 `.html` 仍能造成 XSS 的原因。
- 为何「两份黑名单」会放大问题：同一产品里上传路径与文件管理路径各有一份后缀黑名单（如 `uploadsExtensionBlacklist` 与 `filesExtensionBlacklist`），前者列了 `html,htm,xhtml,shtml`，后者只列脚本后缀；只要走到用后者的那条路径（上传/文件管理），弱的那份就决定了可上传的范围。
- 扩展名比较还依赖规范化：先把后缀转小写再比对（`toLowerCase`）能防住大小写绕过，但黑名单本身漏项时规范化也无济于事。

## 触发条件

- 存在可上传文件的后台/前端功能，服务端用后缀黑名单校验，且黑名单未包含 `html`/`htm`/`xhtml`/`shtml`（或存在只含脚本后缀的另一份名单被实际使用）。
- 上传文件落到 Web 可直接访问的同源目录，且该路径不需要登录即可访问。
- 响应未强制 `Content-Disposition: attachment`，也未设置 `X-Content-Type-Options: nosniff`。
- 上传功能本身可达（低权限账号即可，若上传点对普通用户开放则影响面更大）。

## 利用步骤

1. 上传一个 `.jsp`/`.jspx`，记录报错文案（如 `Web file illegal extension: 1.jsp`），确认是后缀黑名单而非白名单。
2. 由报错/源码确认黑名单内容；若拿不到源码，按「黑名单只列脚本后缀」的常见形态，依次尝试 `.html`、`.htm`、`.xhtml`、`.shtml`、`.svg`。
3. 上传内容为 `<script>alert(document.domain)</script>` 的 `1.html`，确认返回成功（响应 `status:0` 之类）。
4. 在文件列表中拿到落地路径（如 `/uploads/1/1.html`），浏览器直接访问，确认脚本在同源下执行。
5. 换成实际利用载荷：读取同源接口数据、带 Cookie 发起后台操作、或跳转钓鱼页；把链接投递给后台管理员/站内用户。
6. 若目标还有模板编辑功能，检查其保存的模板文件是否同样落在可访问目录并能注入脚本（模板编辑 + 同源静态访问是同类风险）。

## PoC

```http
POST /api/backend/core/web-file-upload/upload HTTP/1.1
Host: target
Cookie: <后台会话>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="1.html"
Content-Type: text/html

<script>alert(document.domain)</script>
------X--
```

```json
// 上传成功的响应形态
{"status":0,"result":null,"message":null,"exception":null}
```

```text
# 落地路径（文件列表中的「浏览」链接）
/uploads/1/1.html
```

```http
GET /uploads/1/1.html HTTP/1.1
Host: target
# 返回 200 + text/html，脚本在同源执行
```

## 变体与关联

- 变体：黑名单漏 `svg`/`xhtml`/`shtml`；或漏 `jspa`、`jspf` 等容器可解析的变体后缀（需容器把它们交给 JSP 引擎）。
- 变体：黑名单存在但过滤点只在「文件管理」路径，而「上传」路径用另一份更弱的名单（两份名单覆盖差异即绕过入口）。
- 变体：上传目录被 `Content-Disposition: attachment` 保护时，改用同源内的其他渲染入口（模板编辑、富文本预览、文件预览页）打 XSS。
- 关联：`[[web-generic-file-upload-html-static-stored-xss]]` 是「完全不做后缀校验」的同源 XSS 场景，本卡的前提是「有黑名单但漏 html 家族」，两者入口不同；`[[web-generic-file-upload-maku-lowcode-no-extension-html-xss]]` 是零校验的同类实例；模板编辑导致的 XSS 见既有模板类卡。
- 边界：改成白名单（只允许图片且校验魔数）、上传目录独立域名/对象存储并强制下载、`nosniff` + CSP 严格时 XSS 不可达。

## 检测与防御

- 检测：上传接口出现 `.html/.htm/.xhtml/.shtml/.svg` 扩展名；上传目录出现文本型页面文件；`GET /uploads/**/*.html` 返回 `text/html` 并被大量访问。
- 修复：把后缀策略从黑名单改为白名单（只允许业务需要的图片/文档类型，并校验魔数/内容）；对 html 家族与 svg 一律拒绝或强制 `Content-Disposition: attachment`。
- 加固：上传目录放到独立域名或对象存储并禁止解析 HTML；统一维护「一份」后缀策略，避免上传/文件管理各自一套名单；响应加 `nosniff`、CSP；Cookie 加 `HttpOnly`/`SameSite`。
