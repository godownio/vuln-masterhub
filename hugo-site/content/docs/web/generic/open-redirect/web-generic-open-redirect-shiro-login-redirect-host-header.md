---
id: web-generic-open-redirect-shiro-login-redirect-host-header
title: Shiro 未登录重定向的 Location 取 Host 头：任意 Host 注入导致开放重定向与会话 ID 泄露
type: scenario
domain: web
path: web/generic/open-redirect
technique: shiro-issue-redirect-host-header
tags:
- web
- open-redirect
- host-header
- shiro
- java
- session-fixation
- phishing
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:00:51+08:00'
  notes: 'Host 注入本身已核对：图09 GET /oa/notify/message?sort=1 带 Host: baidu.com:8090 返回302 Location http://baidu.com:8090/login;JSESSIONID=...，与卡内原理一致。但卡片''将构造好的 URL 发给受害者''的利用步骤不成立：受害者浏览器访问目标域名时 Host 为目标域名，URL 不能控制 Host；截图中的 JSESSIONID 也是攻击者自己请求的会话，不能证明受害者会话泄露。要形成钓鱼/会话劫持需缓存投毒、反向代理 Host 透传、密码重置邮件等额外载体，原文未验证。故 --fail 保留，建议修正利用步骤或把影响限定为 Host 头注入/开放重定向原语。frontmatter 无 sources/source_url。'
url: /docs/web/generic/open-redirect/web-generic-open-redirect-shiro-login-redirect-host-header/
draft: false
kb_aliases:
- Shiro Host 头注入
- redirectToLogin Host 注入
- WebUtils.issueRedirect 开放重定向
- 登录跳转 Host 劫持
- BootDo Host 头注入
---

## 一句话结论

Shiro 的 `AccessControlFilter.redirectToLogin()` 调用 `WebUtils.issueRedirect(request, response, loginUrl)` 时，若 `loginUrl` 不是以 `http(s)://` 开头，Shiro 会用 `request.getScheme() + "://" + request.getServerName() + ...` 拼绝对地址；而 `getServerName()` 在 Tomcat 等容器里直接取 `Host` 头。攻击者把 `Host` 改成自己的域名，未登录请求的 302 `Location` 就会指向攻击者站点，形成开放重定向/钓鱼，并把 `JSESSIONID` 拼进 URL。

## 原理

- 未登录访问受保护路径时，Shiro 的 AccessControlFilter 调用 `redirectToLogin`，默认登录地址为相对路径 `/login`。
- `WebUtils.issueRedirect(request, response, url, ...)` 在 url 非绝对地址时，会补全为 `request.getScheme() + "://" + request.getServerName() + [端口] + contextPath + url`。
- `HttpServletRequest.getServerName()` 的语义是“请求到达的服务器名”，Servlet 容器通常从 `Host` 请求头取值；该头完全由客户端控制，且应用/前置代理未做 Host 白名单校验。
- 于是 `Host: attacker.example` 的请求返回 `Location: http://attacker.example:port/login;JSESSIONID=<id>`。浏览器会跳转到攻击者站点，攻击者可仿冒登录页钓鱼。
- 重定向 URL 中由 Shiro 追加的 `;JSESSIONID=` 会把会话 ID 暴露在 URL/Referer 中；若前置缓存按 Host 或 URL 缓存该 302，还可能造成缓存投毒/会话固定。
- 根因是把“客户端可控的 Host 头”当成生成服务端绝对 URL 的可信来源；这不是认证绕过，而是重定向目标可被操纵。

## 触发条件

- 应用使用 Shiro 且启用默认的未登录重定向（`loginUrl` 配置为 `/login` 等相对路径）。
- Servlet 容器 `getServerName()` 取 `Host` 头（Tomcat/Jetty/Undertow 常见默认行为）。
- 应用或前置代理未校验/重写 `Host` 头（无固定 server name 白名单）。
- 攻击者能向目标发送任意 Host 的 HTTP 请求（直接访问或代理允许）。

## 利用步骤

1. 访问任意受保护路径（如 `/oa/notify/message`），确认未登录时返回 302 到 `/login`。
2. 重放请求，把 `Host` 改为攻击者控制的域名（可带端口），保持路径不变。
3. 观察响应 `Location`：若为 `http://攻击者域名/login;JSESSIONID=...`，则 Host 注入成立。
4. 将构造好的 URL 发给受害者；受害者访问后会被跳转到攻击者仿冒页面，可进一步窃取凭据。
5. 检查 `Location` 中的 `JSESSIONID` 是否可被用于会话固定/会话劫持，并测试前置缓存是否缓存了带恶意 Host 的 302。
6. 记录请求/响应证据；验证后停止，不对生产环境做缓存污染。

## PoC

```http
GET /oa/notify/message?sort=1 HTTP/1.1
Host: attacker.example:8090
User-Agent: Mozilla/5.0
Cookie: JSESSIONID=<任意值>

HTTP/1.1 302
Set-Cookie: JSESSIONID=<新会话>; Path=/; HttpOnly
Location: http://attacker.example:8090/login;JSESSIONID=<新会话>
Content-Length: 0
```

若 `Host` 改为正常域名，`Location` 中的主机随之变为正常域名；改为任意域名则跳转目标随之改变，说明 Host 完全可控。

## 变体与关联

- 变体：`X-Forwarded-Host`/`Forwarded` 头被容器或框架用于构造 URL 时，同样可注入重定向目标。
- 变体：若 `Location` 中的 `JSESSIONID` 被攻击者预先控制（会话固定），可诱导受害者使用攻击者已知的会话 ID 登录，随后劫持会话。
- 变体：前置 CDN/缓存未把 Host 纳入缓存键时，可缓存恶意 302，影响其他用户（缓存投毒）。
- 关联：[[web-generic-auth-host-header-localhost-auth-bypass]]（Host 头被用于权限判断的另一类信任问题）。
- 关联：[[web-generic-auth-password-reset-host-header-poisoning]]（Host 头进入密码重置链接的同类注入）。
- 关联：[[web-generic-cache-poisoning-host-header-ambiguous-request]]（Host 头歧义与缓存投毒）。

## 检测与防御

- 防御：Shiro `loginUrl` 使用站内绝对路径并在生成跳转时固定 scheme/host（配置 server name 或使用相对 Location），不要依赖 `request.getServerName()`。
- 防御：入口代理/应用做 Host 白名单校验，非法 Host 直接拒绝；统一重写 `Host`/`X-Forwarded-Host`。
- 防御：登录重定向不要携带 `;JSESSIONID=`；使用 HttpOnly/Secure Cookie 并禁止 URL 重写会话 ID。
- 检测：302 响应的 `Location` 主机与站点域名不一致；请求 Host 与站点域名不一致；同一路径出现大量不同 Host 的未登录请求；`Location` 含 `JSESSIONID`。
- 检测：缓存层出现带外部域名的 302；WAF 对 Host 头与常见代理头做一致性校验。
