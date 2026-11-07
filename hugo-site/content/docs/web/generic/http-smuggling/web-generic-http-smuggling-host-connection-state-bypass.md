---
id: web-generic-http-smuggling-host-connection-state-bypass
title: 连接状态攻击绕过 Host 校验：同一 keep-alive 连接先合法请求再打内网
type: scenario
domain: web
path: web/generic/http-smuggling
technique: host-connection-state-bypass
tags:
- web
- http
- host-header
- connection-state
- keep-alive
- request-smuggling
- desync
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:27:53+08:00'
  notes: 已对照原文核对；单发/admin+Host:192.168.0.1被301、同连接先GET /合法Host再GET /admin成功进入管理面板均一致；依赖Burp single connection序列；未复跑
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-host-connection-state-bypass/
draft: false
kb_aliases:
- 连接状态攻击
- connection state attack
- Host 校验连接复用绕过
- 单连接请求序列
- browser-powered desync
---

## 一句话结论

当反向代理只在一条连接的第一个请求上校验 Host、之后复用该连接的后端状态时，攻击者可在同一 keep-alive 连接上先发一个合法 Host 的普通请求，再发 `Host: 192.168.0.1` 的 `/admin` 请求，第二个请求会绕过校验访问内网管理面板。

## 原理

- HTTP/1.1 keep-alive 允许在同一 TCP 连接上发送多个请求。部分前端代理在首个请求时完成 Host 校验并确定后端/虚拟主机，之后对同一连接上的后续请求不再重复校验，直接复用已有后端连接。
- 后端也可能根据连接上下文（而非每个请求的 Host）决定虚拟主机；这形成“连接状态”与“请求头”不一致。
- 攻击者构造两个请求：第一个用合法 Host 访问 `/`，让连接进入可信状态；第二个用内网 Host 访问 `/admin`，前端跳过校验或后端沿用连接状态，请求被转发到内网管理服务。
- 单独发送第二个请求（新连接）时会被 301/403 拦截；必须与第一个请求在同一连接、按顺序发送。该问题属于浏览器驱动的 HTTP desync/连接状态攻击的一类。

## 触发条件

- 前端代理/负载均衡对 Host 的校验或路由决策按连接缓存，而非逐请求执行。
- 后端连接池按连接复用，未按 Host 隔离。
- HTTP/1.1 keep-alive 开启，攻击者能控制同一连接上的请求序列（代理工具/自定义客户端）。
- 内网管理面板与前端网络可达。

## 利用步骤

1. 在新连接上直接请求 `GET /admin` 并设 `Host: 192.168.0.1`，确认被 301/403 拦截（基线）。
2. 在同一连接上先发 `GET /`、`Host: 正常域名`，让代理完成校验并建立后端连接。
3. 紧接着在同一连接发 `GET /admin`、`Host: 192.168.0.1`。
4. 观察第二个响应是否为 200 管理面板；提取 CSRF token 与删除接口。
5. 在同一条连接上继续发送管理操作请求（如删除用户）完成利用。

## PoC

Burp Repeater 中将两个请求加入同一 group，发送模式设为 **Send group in sequence (single connection)**，Connection 设为 keep-alive：

```http
# 请求 1：合法 Host，建立连接状态
GET / HTTP/1.1
Host: target.example

# 请求 2：内网 Host，复用连接状态
GET /admin HTTP/1.1
Host: 192.168.0.1
```

第二个响应返回管理面板（含删除用户表单）：

```html
<form action="/admin/delete" method="POST">
  <input type="hidden" name="csrf" value="...">
  <input type="text" name="username">
  <button type="submit">Delete user</button>
</form>
```

随后在同一连接序列中提交 `csrf=...&username=carlos` 完成删除。原文基线测试显示单独请求 `GET /admin` + `Host: 192.168.0.1` 会被 301 重定向到首页，序列化发送后第二个请求成功。

## 变体与关联

- 变体：首个请求用任意合法路径/Host 建立状态；第二个请求可用绝对 URL、重复 Host 等配合绕过逐请求校验。
- 变体：HTTP/2 连接复用、代理连接池按 SNI/证书复用等也可能产生类似状态混淆。
- 关联：[[web-generic-ssrf-host-header-routing-ssrf]]、[[web-generic-auth-host-header-localhost-auth-bypass]]、[[web-generic-cache-poisoning-host-header-ambiguous-request]]、[[web-generic-host-header-validation-bypass-ambiguity]]。
- 关联：[[web-generic-http-smuggling-gzip-multi-member-decompression-differential]]（同属前后端解析/状态不一致的 desync 思路）。

## 检测与防御

- 对每个请求独立校验 Host，禁止按连接缓存校验结果；不同 Host 使用不同后端连接池，禁止跨 Host 复用。
- 代理在转发时重写 Host 为后端可信值，并丢弃客户端原始 Host；后端不依赖连接上下文决定虚拟主机。
- 关闭不必要的 keep-alive 或限制单连接请求数；对同一连接上 Host 突变的请求直接拒绝并记录。
- 监控同一连接内 Host 变化的请求序列、内部 IP Host、`/admin` 等敏感路径的非正常访问。
