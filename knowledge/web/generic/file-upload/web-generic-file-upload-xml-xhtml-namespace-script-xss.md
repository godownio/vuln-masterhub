---
id: web-generic-file-upload-xml-xhtml-namespace-script-xss
title: 'XML 上传 XHTML 命名空间 <prefix:script> + javascript: 标签语法：绕过扩展限制的存储型 XSS'
type: scenario
domain: web
path: web/generic/file-upload
technique: xml-xhtml-namespace-script-upload-xss
aliases:
- prefix:script
- xmlns prefix XHTML
- xml 上传 xss
- 'javascript: 标签语法'
- 2.xml
tags:
- web
- xss
- file-upload
- xml
- xhtml
- namespace
- stored-xss
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:22:39+08:00'
  notes: 已对照原文与图46-47核对：上传 2.xml，内容为 <prefix:script xmlns:prefix='http://www.w3.org/1999/xhtml'>javascript:window['al'+'ert'](1)</prefix:script>，响应返回 fileName 2.xml/fileUrl，访问后弹 1，与卡一致。未复跑 PoC；卡内已注明不同 Content-Type/浏览器行为可能不同。
---

## 一句话结论

上传接口拦截 `.html`/`.svg` 等脚本类型但允许 `.xml` 时，可以上传内容为 `<html><head></head><body><prefix:script xmlns:prefix="http://www.w3.org/1999/xhtml">javascript:window['al'+'ert'](1)</prefix:script></body></html>` 的 XML 文件；浏览器按 XHTML 命名空间把 `prefix:script` 当作 script 元素，而 `javascript:` 前缀在 JS 中是一个合法标签，后面的 `window['al'+'ert'](1)` 会执行，形成同源存储型 XSS。

## 原理

- XML 文档里可以用命名空间前缀把元素映射到 XHTML：`xmlns:prefix="http://www.w3.org/1999/xhtml"` 后，`<prefix:script>` 在支持 XHTML 的浏览器中会被识别为 `<script>` 元素。
- script 元素的文本内容按 JavaScript 执行。载荷 `javascript:window['al'+'ert'](1)` 在 JS 语法中可解析为：标签 `javascript:` + 表达式语句 `window['al'+'ert'](1)`；字符串拼接 `'al'+'ert'` 得到 `alert`，因此执行 `alert(1)`。
- 上传接口往往只按扩展名做黑名单/白名单：`.html`、`.svg` 被拦，但 `.xml` 作为“配置文件/数据文件”被放行；文件落到 Web 可访问目录后，浏览器直接解析 XML/XHTML，脚本执行。
- 本题响应返回 `fileName: 2.xml` 与 `fileUrl`，访问该 URL 弹出 `1`，证明同源脚本执行；危害包括盗取 Cookie/Token、以受害者身份操作、配合 CSRF 等。
- 与 HTML/SVG 上传 XSS 的区别：利用 XHTML 命名空间 + `javascript:` 标签，绕过只针对常见脚本后缀的检查。

## 触发条件

- 上传接口允许 `.xml`（或未校验扩展名/只拦 `.html`、`.svg`）。
- 上传文件保存在 Web 可访问的同源目录，且响应返回可预测的 `fileUrl`。
- 浏览器以 XML/XHTML 或可嗅探为 HTML 的方式渲染该文件（Content-Type 可能为 `text/xml`/`application/xml`，部分浏览器仍会执行 XHTML 命名空间 script）。
- 受害者访问上传文件 URL（例如通过工单、头像、附件预览等入口）。

## 利用步骤

1. 找到允许上传 XML 的入口，确认上传后返回 `fileUrl` 且可直接访问。
2. 构造 XHTML 命名空间 script 载荷，保存为 `2.xml`。
3. 通过 multipart 上传；确认响应 `code=1`/`success:true` 并拿到 `fileUrl`。
4. 浏览器访问 `fileUrl`，确认弹窗/脚本执行。
5. 替换为窃取 Cookie/Token、发起同源请求或钓鱼页面的载荷；结合业务入口诱导受害者访问。
6. 若 `application/xml` 不执行，尝试 `.xhtml`、`.svg`、`.xsl`、`.xslt` 或让响应 Content-Type 变成 `text/html` 的入口。

## PoC

```http
POST /api/upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="2.xml"
Content-Type: text/xml

<html><head></head><body><prefix:script xmlns:prefix="http://www.w3.org/1999/xhtml">javascript:window['al'+'ert'](1)</prefix:script></body></html>
------X--
```

```text
响应：{"code":1,"msg":"操作成功！","data":{"fileName":"2.xml","fileUrl":"https://target/upload/2_xxxx.xml"}}
访问 fileUrl -> 弹出 1
```

## 变体与关联

- **SVG/HTML 上传 XSS**：见 [[web-generic-file-upload-html-static-stored-xss]]、[[web-generic-file-upload-ueditor-default-whitelist-xml-xss]]。
- **XML 解析为 HTML**：`.xsl`/`.xslt` 可引用脚本；`.xhtml` 直接按 XHTML 执行。
- **Content-Type 嗅探**：若服务器返回 `text/html` 或浏览器启用嗅探，XML/文本文件也可能按 HTML 执行；配合 `X-Content-Type-Options: nosniff` 可防御。
- **命名空间绕过**：WAF 若只匹配 `<script>` 字面量，`prefix:script` 可绕过；也可用 `<svg:script>` 等前缀。

## 检测与防御

- 上传白名单只允许业务需要的类型（图片/文档），拒绝 XML/SVG/HTML；按魔数与内容检测，不只看扩展名。
- 上传目录放在独立域名/对象存储，响应加 `Content-Disposition: attachment` 与 `X-Content-Type-Options: nosniff`；禁止脚本执行。
- 对 XML 做安全解析/消毒，禁止 XHTML 命名空间与脚本元素；CSP 限制 inline script。
- 检测：上传文件名后缀为 xml/svg/html/xhtml，内容含 `xmlns`、`script`、`javascript:`；访问上传文件的响应中出现脚本执行。
