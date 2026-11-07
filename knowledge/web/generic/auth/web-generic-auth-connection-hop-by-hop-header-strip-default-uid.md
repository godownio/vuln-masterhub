---
id: web-generic-auth-connection-hop-by-hop-header-strip-default-uid
title: Connection 头声明 X-User 为逐跳头：Go 代理剥除鉴权头，后端默认 uid=0 接管
type: scenario
domain: web
path: web/generic/auth
technique: connection-hop-by-hop-header-strip-default-uid
aliases:
- 'Connection: close,X-user'
- 逐跳头
- hop-by-hop header
- X-User 默认 0
- SecretVault
tags:
- web
- auth-bypass
- http
- proxy
- go
- header-stripping
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:55+08:00'
  notes: '已对照原文与图 29-30 核对：X-User 默认 0、Connection: close,X-user 剥头、admin 页面 flag 一致；未复跑目标。'
---

## 一句话结论

前端 Go 反向代理负责注入/校验 `X-User`，但按 RFC 7230 它会删除 `Connection` 头中列出的逐跳字段；请求带 `Connection: close,X-user` 时，代理转发前把 `X-User` 删掉，后端 Flask `request.headers.get('X-User','0')` 取不到值而默认 `uid=0`，直接以管理员身份进入 `/dashboard` 拿到 flag。

## 原理

- RFC 7230 §6.1：`Connection` 头列出的是逐跳（hop-by-hop）头，代理在转发前必须删除这些字段；Go `net/http/httputil.ReverseProxy` 与多数反向代理实现了该行为。
- 后端鉴权装饰器：`uid = request.headers.get('X-User', '0')`，缺省值 `0` 被当作管理员；随后 `int(uid)` 查用户并放行。它假设代理一定会注入 `X-User`，没有区分“缺失”和“合法 uid=0”。
- 攻击者把 `X-user` 写进 `Connection` 列表（头名大小写不敏感），代理按规则删除该头；后端收到的请求没有 `X-User`，走默认值 0 → admin。
- 这类问题本质是“信任边界上的头默认值 + 代理的逐跳头处理”组合，不依赖 JWT 伪造或 SSRF。

## 触发条件

- 架构为“反向代理/网关 + 后端应用”，代理负责鉴权或注入用户头。
- 后端用 `headers.get('X-User', '0')` 之类带特权默认值的方式读取用户标识。
- 代理遵循 RFC 7230 删除 `Connection` 列出的头（Go ReverseProxy、Nginx 某些配置、Envoy 等都可能；需实测）。
- 目标存在以 uid=0 为管理员的逻辑。

## 利用步骤

1. 正常请求 `/dashboard` 观察是否被重定向/拒绝，确认代理会注入 `X-User`。
2. 发送带 `Connection: close,X-user` 的请求（保留 `close` 以关闭连接）。
3. 代理转发时删除 `X-User`；后端默认 uid=0，返回管理员页面。
4. 读取 flag/敏感数据。

## PoC

```http
GET /dashboard HTTP/1.1
Host: target:port
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml
Connection: close,X-user

```

说明：若代理不删头，可尝试 `Connection: X-user` 单独列出、大小写变体、`Proxy-Connection` 或换用其它逐跳头；不同代理实现差异较大。

## 变体与关联

- **信任身份头**：后端直接信任 `X-User`/`User-Id`/`X-Forwarded-User` 的其它案例；见 [[web-generic-auth-token-renewal-trusted-user-headers-admin-jwt]]、[[web-generic-auth-login-header-userid-token-binding-takeover]]。
- **HTTP 参数/头污染**：重复头、大小写、下划线归一化、`Connection` 列表差异都可用于绕过中间层。
- **代理差异**：Go ReverseProxy 删除 `Connection` 列出的头；Nginx `proxy_set_header` 可能覆盖；Envoy 有 `strip_any_host_port` 等配置。
- **默认值陷阱**：`uid=0`/`role=admin` 作为“缺失时默认”是常见设计缺陷，审计所有 `headers.get(..., default)`。

## 检测与防御

- 后端把“缺失身份头”视为未认证，而不是默认管理员；所有身份必须由可信代理签名/加密。
- 代理应强制覆盖身份头（先删除客户端传入值再注入），并拒绝 `Connection` 列表包含身份头的请求。
- 对管理接口做二次鉴权/会话校验，不依赖单一头。
- 检测：请求头 `Connection` 中出现 `X-User`/`Authorization` 等身份字段；后端收到缺失身份头却以 uid=0 放行的日志。
