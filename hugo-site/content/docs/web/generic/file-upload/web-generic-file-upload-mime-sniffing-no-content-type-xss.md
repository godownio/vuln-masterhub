---
id: web-generic-file-upload-mime-sniffing-no-content-type-xss
title: 上传文件缺 Content-Type 触发浏览器 MIME 嗅探：怪异文件名落地同源 HTML/JS 执行
type: scenario
domain: web
path: web/generic/file-upload
technique: mime-sniffing-upload-xss
tags:
- web
- file-upload
- mime-sniffing
- xss
- apache
- content-type
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:50:29+08:00'
  notes: 已对照原文与图02-04核对：<h1>被Chrome嗅探为HTML、<h2>不嗅探、Apache 2.4下..png/.png缺Content-Type导致alert执行均一致；原文未给受影响版本区间，affected_versions留空；confidence=low合理。未复跑。
url: /docs/web/generic/file-upload/web-generic-file-upload-mime-sniffing-no-content-type-xss/
draft: false
kb_aliases:
- MIME sniffing
- MIME 嗅探 XSS
- 无 Content-Type 上传 XSS
- Apache ..png
- 浏览器内容嗅探
- nosniff bypass
---

## 一句话结论

当 Web 服务器对某些上传文件名（如仅由点号构成的 `.png` 或 `..png`）没有按扩展名映射出 `Content-Type`、且未补默认类型时，浏览器会对响应体做 MIME 嗅探；攻击者上传内容为 HTML/JS 的文件后直接访问或用 `<script src>` 引用，脚本就在站点源下执行，形成存储型 XSS。

## 原理

- 响应缺少 `Content-Type` 时，浏览器按内容自行判断类型。Chrome 的 HTML 嗅探逻辑取响应体前 512 字节、去掉前导空白后匹配魔数：`<!DOCTYPE html`、`<html`、`<script`、`<head`、`<iframe`、`<h1`、`<div`、`<table`、`<a`、`<style`、`<title`、`<body` 等，命中即按 `text/html` 渲染。因此 `<h1>hello</h1>` 会被当 HTML 显示，而 `<h2>hello</h2>` 在 Chrome 中不会。
- `<script src="...">` 加载脚本时，只要响应状态成功，响应体就会按 JavaScript 解析；未设置 `X-Content-Type-Options: nosniff` 时，即使服务器返回的 MIME 不是 JavaScript 类型（例如 `text/html`），Chrome 仍会加载并执行，只是控制台报 MIME 警告或语法错误。
- 反向利用：攻击者把 HTML/JS 内容上传到同源可访问目录。如果服务器因文件名怪异没有给出 `Content-Type`，直接访问得到 HTML 渲染，或把该 URL 作为 `<script src>` 引入任意同源页面，都能执行脚本。
- 文章在 Apache 2.4 上的观察：上传名为 `..png`（截图中实际访问路径为 `/.png`）的文件时，Apache 不再附带预期的响应 `Content-Type`；此时访问该文件，浏览器嗅探为 HTML，脚本 `alert` 执行。该行为与 Apache `mod_mime` 对“最后一个点之后的部分”作为扩展名的解析、以及文件名规范化有关，具体版本/配置间的表现并不稳定。
- 一旦脚本在目标站点源下执行，攻击者可读取同源 Cookie/localStorage、以受害者身份调用接口、窃取页面数据；这是“上传点 + 浏览器解析”组合出的完整 XSS，而不是仅信息泄露原语。

## 触发条件

- 应用允许上传任意内容，且文件名（含后缀、点号、尾随点/空格等）可控或可被客户端指定。
- 上传文件落在 Web 可访问目录，或能通过同源 URL 取回内容。
- 服务器对该文件的响应缺失 `Content-Type` 或给出可被嗅探/可被脚本加载的类型；未设置 `X-Content-Type-Options: nosniff`。
- 浏览器 MIME 嗅探默认开启；直接访问场景需要响应体开头符合 HTML 魔数，`<script src>` 场景需要响应体是合法 JavaScript。
- 原文未给出可核对的 Apache 版本区间，且作者提到“最新版本似乎修了”，因此复现依赖具体版本与配置。

## 利用步骤

1. 确认上传点可控文件名，尝试 `.png`、`..png`、`x.png.`、`x.png ` 等怪异形式，确保文件落到可访问目录。
2. 上传内容为 `<script>alert(document.domain)</script>`（直接访问型）或 `alert(document.domain)`（脚本引用型）的文件。
3. 请求上传后的 URL，检查响应头是否缺少 `Content-Type`；同时用 `curl -I` 对比正常 `.png` 文件的响应。
4. 直接访问该 URL 验证 HTML 嗅探执行；或在一个同源页面（含存在 HTML 注入的页面）中加入 `<script src="/uploads/..png"></script>` 验证脚本执行。
5. 把 payload 换成读取同源敏感数据并外带的 JavaScript，完成利用。

## PoC

上传请求（multipart 文件名使用怪异形式）：

```http
POST /upload HTTP/1.1
Host: victim.example
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="..png"
Content-Type: image/png

<script>alert(document.domain)</script>
------x--
```

直接访问型响应检查：

```bash
curl -i https://victim.example/uploads/..png
# 期望：HTTP/1.1 200，响应头中没有 Content-Type（或类型不是 image/png）
```

脚本引用型 payload：

```html
<script src="https://victim.example/uploads/..png"></script>
<!-- 文件内容为：alert(document.domain) -->
```

## 变体与关联

- 变体：`<script src>` 可接受多种 JavaScript MIME 类型（`application/javascript`、`text/javascript`、`application/x-javascript`、`text/jscript` 等）；若服务器返回这些类型之一，脚本照常执行。
- 变体：上传 `.svg`、`.txt`、无后缀文件或利用文件名截断/尾随点，让服务器漏发或发错 `Content-Type`。
- 变体：即使设置了 `X-Content-Type-Options: nosniff`，若上传内容被服务端明确以 `text/html` 返回且同源可访问，直接访问仍会渲染 HTML；此时应改为强制下载或独立域。
- 关联：[[web-generic-file-upload-html-static-stored-xss]]（直接上传 `.html` 后缀的同类存储型 XSS，本卡补充的是“后缀不是 HTML、靠嗅探执行”的绕过）。
- 关联：[[web-generic-file-upload-presigned-url-response-content-type-xss]]（对象存储通过响应头覆盖把对象变成 `text/html`，与本卡的“缺失 Content-Type 靠嗅探”互为对照）。
- 边界：服务器始终显式设置正确 `Content-Type`（如 `image/png`）且开启 `nosniff`，或上传目录强制 `Content-Disposition: attachment`、独立域托管时，该手法不成立。

## 检测与防御

- 检测：上传目录中出现后缀与实际内容不符的文件；响应缺失 `Content-Type`；短时间访问怪异文件名（`.png`、`..png`、尾随点/空格）；页面出现指向上传目录的 `<script src>`。
- 防御：对所有响应显式设置 `Content-Type`，不要依赖文件名推断；统一加 `X-Content-Type-Options: nosniff`；用户上传内容一律 `Content-Disposition: attachment` 下载。
- 加固：上传文件存放在独立域名/独立源下，避免与主站同源；对文件名做规范化并拒绝点号、尾随点/空格、路径分隔符等怪异形式；服务端按文件内容重新生成安全的存储名和后缀。
