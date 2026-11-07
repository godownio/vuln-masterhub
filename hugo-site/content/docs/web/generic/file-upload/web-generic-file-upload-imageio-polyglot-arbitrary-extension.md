---
id: web-generic-file-upload-imageio-polyglot-arbitrary-extension
title: ImageIO.read 图片校验可被图片马绕过：保留原后缀上传 HTML 形成同源存储型 XSS
type: scenario
domain: web
path: web/generic/file-upload
technique: imageio-polyglot-extension-preserve-xss
tags:
- web
- file-upload
- image
- polyglot
- stored-xss
- java
- spring
- newbee-mall
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T09:20:23+08:00'
  notes: '已对照原文与图14-18核对：UploadController.upload 先 ImageIO.read 判空、再 fileName.substring(lastIndexOf(''.'')) 原样保留后缀、时间戳+随机数命名后 transferTo；图16 请求 filename=test.html、Content-Type: image/jpeg、JPEG 字节尾部追加 <html><body><svg onload="alert(1)"></body></html>，图15/17 响应 /upload/20260121_12263825.html，图18 浏览器访问弹窗，图片马+任意后缀上传形成同源存储型 XSS 成立，与卡内一致。图01 Constants.FILE_UPLOAD_DIC=D:\upload\，卡内说明当前部署不在 web 根、JSP 不可解析，按存储型 XSS 计，准确。原文未给版本，未写 affected_versions 正确。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。'
url: /docs/web/generic/file-upload/web-generic-file-upload-imageio-polyglot-arbitrary-extension/
draft: false
kb_aliases:
- ImageIO 图片马
- 图片校验绕过
- 任意后缀上传
- 图片马 HTML
- Java 上传图片检测绕过
- newbee-mall 文件上传
---

## 一句话结论

上传接口用 `ImageIO.read()` 判断文件能否解码为图片，但解码成功只说明“文件开头是一张合法图片”；攻击者在正常图片数据后追加 HTML/JS，并把文件名后缀写成 `.html`，接口仍会保留原后缀落盘，访问上传目录中的该文件即可执行脚本，形成同源存储型 XSS。

## 原理

- 校验逻辑 `BufferedImage bufferedImage = ImageIO.read(file.getInputStream()); if (bufferedImage == null) return fail;` 只要求输入流中存在可解码的图片。JPEG/PNG 解码器读到结束标记即可返回图像，尾部追加的任意字节不会被判为非法。
- 保存逻辑 `String suffixName = fileName.substring(fileName.lastIndexOf("."))` 直接取客户端文件名的最后一个后缀，未做扩展名白名单；新文件名虽然是“时间戳+随机数”，但后缀原样保留。
- 因此 `test.jpg`（图片内容 + HTML）和 `test.html`（图片内容 + HTML）都能通过校验；返回的 URL 形如 `/upload/20260121_12263825.html`，上传目录被静态映射到 `/upload/**`，浏览器按 `text/html` 渲染，`<svg onload>`/`<script>` 执行。
- 若部署时把 `Constants.FILE_UPLOAD_DIC` 放在 Web 根目录且容器解析 JSP，同样的缺陷可升级为上传 `.jsp` getshell；原文环境上传目录在 Web 根之外，JSP 只能下载不能解析，因此按存储型 XSS 计。
- 根因：把“图片可解码”等同于“文件类型安全”，并且没有把落盘后缀与校验类型绑定；内容校验与文件名/扩展名校验是两条独立链路，必须同时收紧。

## 触发条件

- 上传接口做图片内容校验（如 `ImageIO.read`），但保留客户端原始扩展名，且无后缀白名单。
- 上传目录位于 Web 可访问路径（如 `/upload/**`），且未强制 `Content-Disposition: attachment`。
- 响应未设置 `X-Content-Type-Options: nosniff`，或静态服务器按后缀返回 `text/html`。
- 上传点需要后台管理员会话（本卡对应 `/admin/upload/file`）；若其他上传点复用同一控制器/逻辑，也可作为入口。

## 利用步骤

1. 登录后台，进入商品编辑等带上传功能的页面，抓取 `POST /admin/upload/file` 请求。
2. 准备一张合法图片，在文件末尾追加 HTML/JS 载荷（如 `<html><body><svg onload=alert(1)></body></html>`），文件名设为 `test.html`，`Content-Type` 保持 `image/jpeg`。
3. 上传并记录响应中的 `data` URL（形如 `http://host/upload/20260121_12263825.html`）。
4. 用浏览器访问该 URL，确认脚本执行；若 404，等待静态资源刷新或重启后再试。
5. 将链接发给受害者，脚本以受害者身份读取同源数据、发起请求或钓鱼；验证后删除测试文件。

## PoC

```http
POST /admin/upload/file HTTP/1.1
Host: target
Cookie: JSESSIONID=<管理员会话>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryRII4LixNAimwdMeH

------WebKitFormBoundaryRII4LixNAimwdMeH
Content-Disposition: form-data; name="file"; filename="test.html"
Content-Type: image/jpeg

<合法 JPEG 字节>
<html><body><svg onload="alert(1)"></body></html>
------WebKitFormBoundaryRII4LixNAimwdMeH--
```

```text
响应：{"resultCode":200,"message":"SUCCESS","data":"http://target/upload/20260121_12263825.html"}
访问 data 中的 URL 触发 alert(1)。
```

## 变体与关联

- 变体：后缀改为 `.svg`，利用 SVG 内嵌 `<script>`；或 `.htm`、`.shtml` 等静态解析后缀。
- 变体：上传目录在 Web 根且解析 JSP/PHP 时，图片马尾部写 webshell 即可 getshell；原文当前部署不满足该条件。
- 变体：`/admin/upload/files` 批量上传接口同样只做 `ImageIO.read`，且逐个保留原后缀，绕过方式一致。
- 关联：[[web-generic-file-upload-html-static-stored-xss]]（不做任何内容校验时的同源 HTML 上传；本卡补充图片内容校验可被图片马绕过）。
- 关联：[[web-generic-file-upload-magic-byte-gif-prefix-bypass]]（只查文件头的绕过；本卡是完整图片解码校验的绕过）。
- 关联：[[web-generic-file-upload-image-render-payload-survival]]（二次渲染场景，需载荷在渲染后存活；本卡不渲染，直接保留尾部数据）。

## 检测与防御

- 防御：上传后缀必须白名单（仅 jpg/png/gif/webp 等），并与服务端检测出的真实图片类型比对；不要保留客户端原始后缀。
- 防御：不要只依赖 `ImageIO.read != null`；应校验解码后的宽高/像素上限，并重新编码保存（剥离尾部附加数据），或使用内容安全库识别 polyglot。
- 防御：上传目录与 Web 应用分离，静态文件强制 `Content-Disposition: attachment` 或 `Content-Type: application/octet-stream`，并加 `X-Content-Type-Options: nosniff`。
- 检测：上传文件名后缀不在白名单、文件尾部存在 HTML/脚本特征、图片解码成功但文件大小异常；上传目录出现 `.html/.svg/.jsp` 等非图片后缀；访问上传目录 HTML 文件的行为。
