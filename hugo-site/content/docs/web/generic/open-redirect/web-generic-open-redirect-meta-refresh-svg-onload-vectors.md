---
id: web-generic-open-redirect-meta-refresh-svg-onload-vectors
title: 客户端重定向载体：meta http-equiv=refresh 与 SVG onload 的 window.location 跳转
type: scenario
domain: web
path: web/generic/open-redirect
technique: client-side-redirect-meta-svg-vectors
tags:
- open-redirect
- meta-refresh
- svg
- client-side
- phishing
- web
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V445
  verified_at: '2026-11-09T23:29:56+08:00'
  notes: 已对照原文 META 标签重定向/SVG 文件重定向段落与图01/02 核对：<meta http-equiv=refresh content=1;URL=...> 与 <svg onload="window.location='...'"> payload 与原文一致；CSP/img 嵌入限制等补充合理。未验证点：未实测具体内容注入点/上传点；无组件版本。与既有 SSRF meta-refresh 链卡场景不同（客户端跳转载体 vs 服务端抓取链），非同链。
url: /docs/web/generic/open-redirect/web-generic-open-redirect-meta-refresh-svg-onload-vectors/
draft: false
kb_aliases:
- meta refresh 跳转
- SVG onload 跳转
- window.location 重定向
- 客户端开放重定向
- 无 Location 头跳转
---

## 一句话结论

开放重定向不只发生在服务端 `Location` 头：只要攻击者能让页面输出受控 HTML（用户简介、签名、上传的 SVG、模板注入点等），就可以用 `<meta http-equiv="refresh" content="1;URL=http://evil.com">` 或 `<svg onload="window.location='http://evil.com'">` 让浏览器自动/加载即跳转到攻击者站点；当服务端跳转被白名单堵住、或只有内容注入点时，这两类客户端载体仍能完成钓鱼跳转。

## 原理

- HTML `<meta http-equiv="refresh" content="<秒>;URL=<目标>">` 告诉浏览器在指定秒数后跳转，不经过服务端 302，解析发生在浏览器端；任何能控制页面 HTML 的写入点都可以注入。
- SVG 是 XML/HTML 混合的富内容：`<svg onload="window.location='...'" xmlns="...">` 在作为 `image/svg+xml` 加载或内联到页面时，`onload` 事件处理器执行脚本，把浏览器导航到攻击者 URL；这属于 DOM 级 `window.location` 重定向。
- 原文把 URL 重定向的实现归为三类：URL 参数（服务端 Location）、`<meta>` 刷新标签、DOM 中的 `window.location` 属性。前两类是服务端跳转/白名单的常见检测对象，后两类容易被遗漏。
- 为什么有效：服务端只校验跳转参数，无法阻止页面内容中的 meta/SVG；SVG 上传/展示功能若未做内容消毒，恶意 SVG 在受害者浏览器中执行；meta refresh 不需要 JavaScript，绕过 CSP 对脚本的限制（但仍有 frame/导航限制的浏览器策略）。
- 限制：meta refresh 只能跳转，不能直接窃取数据；SVG onload 受 CSP `script-src`/`img-src` 与浏览器对 SVG 脚本策略影响；若 SVG 仅作为 `<img>` 加载，脚本通常不执行，需直接打开或内联。

## 触发条件

- 站点存在用户可控的 HTML 输出点（个人签名/简介、评论、邮件模板、上传图片/SVG 的展示页）；
- 输出未做 HTML 实体编码与标签过滤，或允许 SVG 上传且以 `image/svg+xml` 直接展示；
- 受害者浏览器访问该页面（meta refresh 延迟可设为 0–1 秒，体验上像正常跳转）；
- 无严格 CSP 或 CSP 允许内联/相应来源（SVG onload 场景）。

## 利用步骤

1. 找到可写入 HTML/上传 SVG 的功能点，确认展示时不过滤 `meta`/`svg`/事件属性。
2. 构造 payload：
   - meta：`<meta http-equiv="refresh" content="1;URL=https://evil.com">`
   - SVG：`<svg onload="window.location='https://evil.com'" xmlns="http://www.w3.org/2000/svg"></svg>`
3. 保存后访问展示页，确认浏览器自动/加载即跳转到攻击者页。
4. 把展示页链接（可信域开头）投递给受害者，落地页仿冒登录页进行钓鱼。

## PoC

```html
<!-- meta refresh -->
<meta http-equiv="refresh" content="1;URL=https://evil.example/login">

<!-- SVG onload -->
<svg onload="window.location='https://evil.example/login'"
     xmlns="http://www.w3.org/2000/svg"></svg>
```

```http
HTTP/1.1 200 OK
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg onload="window.location='https://evil.example/'" xmlns="http://www.w3.org/2000/svg"></svg>
```

说明：SVG 以附件/直接打开方式访问时脚本才执行；作为 `<img>` 嵌入时多数浏览器不执行脚本。

## 变体与关联

- 变体：`<body onload>`、`<iframe src=...>`、`<script>location=...</script>` 等其它客户端跳转载体；但在有 CSP 时受限更多。
- 变体：把 meta refresh 放在被允许的富文本/邮件模板中，形成“可信域发出的钓鱼跳转”，对邮件网关更隐蔽。
- 关联：服务端 Location 的解析歧义绕过见 [[web-generic-open-redirect-url-parser-confusion-bypass]]；SSRF 场景下 meta refresh 作为重定向链的一环见 [[web-generic-ssrf-redirect-chain-meta-refresh-error-body]]。
- 关联：SVG 上传导致的存储型内容执行还可关联 XSS/文件上传目录的既有卡。

## 检测与防御

- 对用户可控 HTML 做严格实体编码与标签白名单，禁止 `meta`、`svg`、事件属性（onload 等）；富文本用成熟的 sanitizer。
- SVG 上传要校验内容（拒绝脚本/事件属性），展示时使用 `Content-Disposition: attachment` 或独立无脚本沙箱域，避免同源执行。
- 设置 CSP（`script-src` 不含 unsafe-inline，限制 frame/导航）、`X-Content-Type-Options: nosniff`，降低 SVG 脚本执行与 MIME 混淆风险。
- 检测：内容中出现 `http-equiv=refresh`、`onload=` 与 `window.location`、`<svg` 等组合；对用户资料/评论/上传内容的渲染做输出审计。
