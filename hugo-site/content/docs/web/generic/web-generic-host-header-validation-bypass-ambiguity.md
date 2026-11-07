---
id: web-generic-host-header-validation-bypass-ambiguity
title: Host 校验绕过：端口注入、后缀匹配、重复头、绝对 URL 与覆盖头
type: scenario
domain: web
path: web/generic
technique: host-header-validation-bypass
tags:
- web
- host-header
- validation-bypass
- ambiguous-request
- duplicate-header
- x-forwarded-host
- http-parsing
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:27:51+08:00'
  notes: 已对照原文核对；端口注入、后缀匹配、已控子域、重复Host、绝对URL、缩进Host、X-Forwarded-Host等覆盖头均来自原文列举，准确；聚合型卡无单一PoC验证；未复跑
url: /docs/web/generic/web-generic-host-header-validation-bypass-ambiguity/
draft: false
kb_aliases:
- Host 头校验绕过
- Host 验证缺陷
- 重复 Host 头
- 绝对 URL Host 歧义
- X-Forwarded-Host 覆盖
- 缩进 Host
---

## 一句话结论

Host 校验通常只检查域名或某些字符，攻击者可用非数字端口注入、同后缀域名、已入侵子域、重复 Host、绝对 URL、缩进 Host 以及 `X-Forwarded-Host` 等覆盖头，让不同组件看到不同 Host 值，从而通过校验并到达利用点。

## 原理

- Host 校验发生在某个组件（CDN、反向代理、应用框架），而实际使用 Host 的是另一个组件；两者的解析规则、取值优先级、校验范围往往不一致。
- 常见校验缺陷：
  - 只校验域名、不校验端口：`Host: site.com:bad-stuff-here` 可通过；
  - 后缀匹配不严格：`Host: notsite.com` 以 `site.com` 结尾，或注册同后缀域名；
  - 允许已入侵的子域：`Host: hacked.site.com`；
  - 只取第一个 Host 或最后一个 Host，而另一组件相反。
- 常见解析歧义：
  - 重复 Host：前端取第一个、后端取最后一个（或反之）；
  - 绝对 URL：请求行 `GET https://site.com/` 与 Host 不一致，某些组件优先请求行，某些优先 Host；
  - 缩进 Host：行首空格使部分服务器把它当作上一个头的续行或忽略，另一部分正常解析；
  - 覆盖头：`X-Forwarded-Host`、`X-Host`、`X-Forwarded-Server`、`X-HTTP-Host-Override`、`Forwarded` 被框架默认信任。
- 只要“校验组件看到的 Host”合法、而“使用组件看到的 Host”恶意，就能完成注入、路由、缓存投毒或权限绕过。

## 触发条件

- 存在 Host 校验，但校验组件与使用组件不一致，或校验逻辑不覆盖端口/后缀/多值。
- 代理/框架支持并信任覆盖头，或允许绝对 URL 请求行。
- 应用对 Host 的后续使用点存在危害（生成链接、路由、权限判断、缓存）。

## 利用步骤

1. 用 Burp Repeater 把目标 IP 与 Host 分离：Target 设为真实 IP，手动修改 Host/请求行，确保请求到达预期目标。
2. 先发一个不可识别域名，观察是否 `Invalid Host header`；若仍有响应，说明存在默认/后备虚拟主机，可继续研究。
3. 依次尝试：非数字端口、同后缀域名、已入侵子域、重复 Host、绝对 URL、缩进 Host。
4. 若 Host 被严格拦截，尝试用覆盖头（`X-Forwarded-Host` 等）注入恶意值。
5. 观察响应/缓存/路由差异，确认哪个组件使用了哪个值，再接入具体利用（密码重置、缓存投毒、SSRF、权限绕过）。

## PoC

```http
# 端口注入
GET /example HTTP/1.1
Host: vulnerable-site.com:bad-stuff-here

# 同后缀域名（校验只做结尾匹配时）
GET /example HTTP/1.1
Host: notvulnerable-site.com

# 已入侵子域
GET /example HTTP/1.1
Host: hacked-subdomain.vulnerable-site.com

# 重复 Host：前端取第一个，后端取最后一个
GET /example HTTP/1.1
Host: vulnerable-site.com
Host: bad-stuff-here

# 绝对 URL：请求行与 Host 不一致
GET https://vulnerable-site.com/ HTTP/1.1
Host: bad-stuff-here

# 缩进 Host：部分组件忽略/视为续行
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-site.com

# 覆盖头
GET /example HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: bad-stuff-here
```

覆盖头候选：`X-Forwarded-Host`、`X-Host`、`X-Forwarded-Server`、`X-HTTP-Host-Override`、`Forwarded`。

## 变体与关联

- 变体：`Forwarded: host=evil`、`X-Forwarded-Host` 多值、大小写/尾点/IDN 变体、IPv6 字面量、用户信息语法（`user@host`）。
- 变体：请求行使用不同协议（HTTP/HTTPS）导致不同后端行为。
- 关联：[[web-generic-auth-host-header-localhost-auth-bypass]]、[[web-generic-ssrf-host-header-routing-ssrf]]、[[web-generic-cache-poisoning-host-header-ambiguous-request]]、[[web-generic-auth-host-header-dangling-markup-password]]、[[web-generic-http-smuggling-host-connection-state-bypass]]。

## 检测与防御

- 在唯一入口统一解析并规范化 Host：拒绝多值、绝对 URL 不一致、缩进头、非法字符与 IP 字面量；只接受 allowlist 中的域名与端口。
- 显式禁用/清除客户端传入的 `X-Forwarded-Host` 等覆盖头，只信任受控代理写入的值。
- 确保前端与后端使用同一套解析结果（例如由代理重写 Host 并注入可信内部头）。
- 监控 Host 含端口、引号、尖括号、空格、多值或与绝对 URL 不一致的请求。
