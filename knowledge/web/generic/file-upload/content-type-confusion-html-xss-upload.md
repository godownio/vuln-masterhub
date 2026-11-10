---
id: content-type-confusion-html-xss-upload
title: 保留图片后缀改 Content-Type 为 text/html 使上传文件被浏览器解析为 HTML
type: scenario
domain: web
path: web/generic/file-upload
technique: Content-Type 混淆存储型 XSS
aliases:
- 后缀与MIME不一致
- jpg 解析 html
tags:
- file-upload
- xss
- content-type
- stored-xss
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

# 保留图片后缀改 Content-Type 为 text/html 使上传文件被浏览器解析为 HTML

## 一句话结论

对象存储/文件服务以请求中的 `Content-Type` 决定响应 MIME 时，攻击者保持 `filename="xx.jpg"` 合法通过后缀校验，但把 multipart 的 `Content-Type` 改为 `text/html`（或 application/pdf、image/svg+xml），文件内容写入 `<img src=x onerror=alert(document.cookie)>` 等脚本，访问该文件 URL 时浏览器按 HTML 渲染执行脚本，形成存储型 XSS（可盗取 Cookie）。

## 原理

云存储与静态文件服务通常不嗅探文件内容，而是把上传时声明的 Content-Type 原样作为响应头返回（无 X-Content-Type-Options: nosniff 或被浏览器默认渲染）；后缀黑/白名单只校验 filename。两者校验维度分离，"合法后缀 + 危险 MIME"的组合同时通过前者、操纵后者。浏览器对 text/html MIME 的响应直接解析 DOM 并执行内联脚本，与后缀无关。前提是目标提供"预览/内联展示"而非强制下载（`Content-Disposition: attachment` 则无危害）。

## 触发条件

- 上传接口校验 filename 后缀但不校验/不重写 Content-Type；
- 文件访问响应 Content-Type 与上传声明一致且非 attachment；
- 同域或同站点的文件 URL（Cookie 可读范围）。

## 利用步骤

1. 上传正常图片抓包，确认响应包 Content-Type 取自请求且文件可预览。
2. 重放：`filename="11(3).jpg"`、`Content-Type: text/html`，正文 `<img src=x onerror=alert(document.cookie)>`。
3. 上传成功后获取文件访问 URL（如 showPic?fileName=xxx.jpg），浏览器打开触发 alert 弹出 Cookie。
4. 变体：SVG 内嵌脚本（`<svg onload=...>`）、PDF 内嵌 JS、上传 .html 直接文本/html。

## PoC

无 PoC（multipart 片段：`Content-Disposition: form-data; name="file"; filename="11(3).jpg"` / `Content-Type: text/html` / `<img src=x onerror=alert(document.cookie)>`；原文验证：.edu.cn 站点 showPic 页面 .jpg 文件弹出 Cookie `SF_Cookie_Cst_1661=...`）。

## 变体与关联

- 变体：Content-Type 改 application/xml 触发 XXE 面；改 text/plain 绕过图片处理；`.html`/`.svg` 直接上传（任意后缀不限时）。
- 关联：上传路径可控（组合成任意路径 HTML 投放）；PDF 导出 SSRF（同属"内容被二次渲染解析"类）；CSP/响应头缺失是共同前提。

## 检测与防御

- 检测：上传请求中 Content-Type 与后缀不匹配、文件内容含 HTML 标签但声明为图片、文件服务响应缺 nosniff。
- 防御：服务端魔数嗅探并强制重写 Content-Type；静态资源域与业务域分离（独立 Cookie-free 域名）；响应加 `X-Content-Type-Options: nosniff` 与 `Content-Security-Policy: sandbox`；强制 `Content-Disposition: attachment`（业务允许时）。
