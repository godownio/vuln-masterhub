---
id: web-generic-open-redirect-smuggled-host-header-301
title: 请求走私触发 Host 头重定向：走私 GET 携带攻击者 Host，使下一受害请求收到 301 跳转
type: scenario
domain: web
path: web/generic/open-redirect
technique: request-smuggling-host-header-redirect
tags:
- http-smuggling
- open-redirect
- host-header
- 301
- http1
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:52+08:00'
  notes: '已对照原文『重定向类』节核对：原文给出 GET /home + Host: attacker-website.com + Foo: X 的走私示例与 301 Location，另有协议相对 //attacker-website.com/example 变体；该节无靶场无截图。PoC 原标 CL 54，但同报文在原文缓存投毒小节标 59，按字节数核算正文为 59，已修正为 59 并在说明中记录（54 会截断 Foo: X 尾部）。未验证点：无靶场/截图；无 sources；无版本/CVE。dedup：shiro-login-redirect 是登录跳转直接取 Host，机制不同；与 cache-poisoning-smuggling-redirect 同一原语不同目标（本卡为开放重定向，非缓存），并列保留。'
url: /docs/web/generic/open-redirect/web-generic-open-redirect-smuggled-host-header-301/
draft: false
kb_aliases:
- 走私触发开放重定向
- Host header redirect smuggling
- 请求走私重定向
- 协议相对重定向
- 301 走私
---

## 一句话结论

部分 Web 服务器对缺少尾斜杠的目录请求会依据 `Host` 头返回 301 到"同主机 + 斜杠"的 URL；利用请求走私把带攻击者 `Host` 的目录请求送进后端连接，后端生成的 301 响应被前端交给下一受害者，从而把受害者重定向到外部站点。

## 原理

- Apache/IIS 等服务器的默认行为：请求目录但缺少尾斜杠时，返回 `301 Moved Permanently`，`Location` 由请求的 `Host` 与路径拼接而成。
- 正常情况下浏览器/前端会发送真实 Host，用户无法让其他用户的请求带上攻击者 Host；请求走私则能在后端连接上注入一条完整的 `GET /home HTTP/1.1\r\nHost: attacker-website.com`。
- 后端以攻击者 Host 生成 301，`Location: https://attacker-website.com/home/`；前端按请求顺序把该响应返回给同一连接上的下一个受害者。
- 另一类变体：若服务器允许 `Location` 使用协议相对 URL，走私 `GET //attacker-website.com/example` 可得到 `Location: //attacker-website.com/example/`，即使 Host 校验严格也可能跳转。
- 危害是把可预测的内部重定向变成对任意受害者的开放重定向，可用于钓鱼、OAuth token 泄露、配合缓存投毒持久化。

## 触发条件

- 存在请求走私原语与前后端连接复用。
- 后端/服务器对目录请求或特定路径做基于 Host 的 301/302 重定向。
- 前端不校验或重写走私请求中的 Host（走私请求对前端不可见）。
- 受害者会通过同一前端连接发起请求。
- 若目标有缓存，重定向响应还可能被缓存（见缓存投毒卡）。

## 利用步骤

1. 确认服务器重定向行为：直接请求 `/home`（无尾斜杠）观察是否 301 到 `https://<host>/home/`。
2. 确认走私原语（时间延迟/差分响应）。
3. 构造走私请求：`GET /home HTTP/1.1` + `Host: attacker-website.com` + 占位头（如 `Foo: X`），放在 `0` 块之后，外层用 CL.TE 或 TE.CL 封装。
4. 紧随正常请求；若受害者收到 301 且 `Location: https://attacker-website.com/home/`，即成功。
5. 若 Host 被校验，尝试协议相对路径变体：`GET //attacker-website.com/example HTTP/1.1`，观察 `Location` 是否为 `//attacker-website.com/example/`。

## PoC

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 59
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: attacker-website.com
Foo: X
```

协议相对路径变体：

```http
GET //attacker-website.com/example HTTP/1.1
Host: vulnerable-website.com
```

预期响应：

```http
HTTP/1.1 301 Moved Permanently
Location: https://attacker-website.com/home/
```

说明：原文该小节标注 `Content-Length: 54`，但同一报文在原文缓存投毒小节标注 59，按字节数计算正文（`0\r\n\r\nGET /home HTTP/1.1\r\nHost: attacker-website.com\r\nFoo: X`）确为 59，此处按正确长度 59 修正；54 会截断 `Foo: X` 尾部，仍可能触发 301。原文未提供对应靶场，confidence 记为 medium，PoC 未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：把 `/home` 换成任意目录路径；把 301 换成 302/307；把 Host 换成 `X-Forwarded-Host`（若服务器以其拼接 Location）。
- 变体：协议相对 `//attacker` 绕过只校验 Host 头的场景；双重编码/反斜杠变体可绕过简单过滤。
- 关联：[[web-generic-cache-poisoning-smuggling-redirect-static-asset]]（把该 301 写入缓存）、[[web-generic-http-smuggling-front-end-acl-bypass-smuggled-request]]（同用走私注入完整请求）、[[web-generic-open-redirect-url-parser-confusion-bypass]]（URL 解析歧义类开放重定向）。
- 边界：服务器不基于 Host 重定向、前端重写 Host、或走私原语不可用时，本链不成立。

## 检测与防御

- 检测：响应 `Location` 指向外部域且请求路径为目录；同一连接出现多个请求；Host 与站点真实域不一致；缓存中出现 301 到异常域。
- 防御：服务器重定向使用固定配置的规范域名，不直接拼接 Host；校验 Host/X-Forwarded-Host 白名单；拒绝 CL+TE 并存；禁用后端连接复用。
- 加固：对目录尾斜杠重定向改用相对路径 `Location: /home/`；部署 desync 检测；缓存层不缓存含外部 Location 的重定向。
