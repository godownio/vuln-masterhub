---
id: web-generic-ssrf-short-form-ip-302-post-to-get
title: SSRF 短写 IP 127.1 绕过黑名单 + 302 重定向把 POST 转成 GET 访问内网
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-short-form-ip-302-post-to-get
aliases:
- SSRF 127.1
- 短写 IP 绕过
- 302 POST 转 GET
- Webhook SSRF
- 内网端口扫描
tags:
- web
- ssrf
- ip-bypass
- redirect
- webhook
- post-to-get
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:50:53+08:00'
  notes: 已对照原文 Webhook 回调链核对：/api/test-webhook 提交 url、127.1 绕过 127.0.0.1/localhost 黑名单、端口 8000/3000/8080、内网仅 GET、httpbin /redirect-to 302 将 POST 转 GET 读 /flag、flag 值均一致。原文把 127.1 称作“八进制表示”，实际是 IPv4 短写；卡内按短写表述更准确。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

当 Webhook 平台只拦截 `127.0.0.1`/`localhost`、却允许用户提交任意 URL 并发送 POST 时，可以用 IPv4 短写 `127.1`（等价 `127.0.0.1`）绕过黑名单扫描内网；若内网服务只接受 GET，则在外部可控的 302 重定向上跳到 `http://127.1:<port>/flag`，Python `requests` 默认跟随重定向并把 POST 转成 GET，从而读取内网 flag。

## 原理

- **短写 IP**：IPv4 地址有多种等价表示，`127.1` = `127.0.0.1`；很多黑名单只做字符串匹配 `127.0.0.1`/`localhost`，不解析/规范化 IP，因此短写、整数、八进制、十六进制、省略段等形式可绕过。
- **Webhook SSRF**：平台接受用户 URL 并主动发起请求，等于一个可控制目标/方法的 SSRF 原语；即使只允许 POST，也可以访问接受 POST 的内网端点。
- **302 POST→GET**：HTTP 客户端（Python `requests`）跟随 302 时，按规范把非 GET/HEAD 请求转换为 GET（303 也会，307/308 保持方法）。因此用一个外部可控的 302 服务（如 httpbin 的 `/redirect-to?url=...`）即可把平台的 POST 变成对内网的 GET。
- **内网端口扫描**：用 `127.1:<port>` 逐个探测，根据响应/错误/超时区分开放端口；本题发现 8000（Werkzeug）、3000（Express）、8080（Flag Service）。
- **为什么成立**：SSRF 防护只做字面黑名单，未做 DNS/IP 规范化、协议/端口白名单、重定向逐跳校验；客户端的重定向语义被攻击者利用来改变方法。
- **边界**：平台可能禁用重定向/只允许 https/限制端口；内网服务可能要求 Host 头/认证；302 端点可能不可达。

## 触发条件

- 存在接受用户 URL 并主动请求的功能（Webhook 测试、图片抓取、URL 预览等）。
- 黑名单只匹配 `127.0.0.1`/`localhost` 等字面量，未解析/规范化 IP。
- 平台使用的 HTTP 客户端默认跟随重定向，且对 302 做 POST→GET 转换（Python `requests` 默认行为）。
- 内网目标只接受 GET，或可通过重定向/方法转换触达。
- 攻击者有一个外部可控的 302 端点（httpbin、自己的服务器）。

## 利用步骤

1. 确认 Webhook 接口与请求格式（本题 `POST /api/test-webhook {"url": ...}`），观察平台是否回显响应/错误。
2. 用 `127.1` 替代 `127.0.0.1` 测试是否绕过黑名单；逐个端口探测（8000/3000/8080 等），记录开放服务。
3. 确认内网服务只接受 GET（POST 返回 405/错误）；构造外部 302：`http://httpbin.org/redirect-to?url=http%3A%2F%2F127.1%3A8080%2Fflag`。
4. 把该 URL 提交给 Webhook；平台 POST 到 httpbin，收到 302 后跟随并转成 GET 访问 `127.1:8080/flag`。
5. 从平台回显/响应中读取内网返回的 flag；本题得到 `flag{fb6efe84-2dba-4f31-a266-ec1b1df9df59}`。
6. 若 302 被拦截，尝试 303、307/308（方法保持）、DNS 重绑定、十进制/八进制 IP、`[::1]` 等变体。

## PoC

```python
import requests
import urllib.parse

target = "http://target:33196/api/test-webhook"
redirect_url = "http://httpbin.org/redirect-to?url=" + urllib.parse.quote(
    "http://127.1:8080/flag", safe=""
)
r = requests.post(target, json={"url": redirect_url}, timeout=10)
print(r.json())
```

## 变体与关联

- **变体（IP 表示）**：`127.1`、`2130706433`（整数）、`0177.0.0.1`（八进制）、`0x7f.0.0.1`、`127.0.0.1.nip.io`（DNS）、`[::1]`、`0`（部分系统解析为 0.0.0.0）。
- **变体（方法转换）**：302/303 转 GET；307/308 保持 POST；也可用 301/302 + 目标同时接受 GET/POST。
- **变体（重定向）**：自建 302 服务、云函数、GitHub Pages、httpbin；逐跳校验缺失时可跳到任意内网。
- **变体（协议）**：`file://`、`gopher://`、`dict://`、`ftp://` 等（视客户端支持）；本题用 http。
- **关联卡片**：[[web-generic-ssrf-host-header-routing-ssrf]]（Host 头 SSRF）、[[web-generic-ssrf-multi-layer-decode-dword-waf-bypass]]（多层解码绕过）、[[cloud/metadata]]（云元数据 SSRF）。
- **边界**：平台禁用重定向/限制 URL 白名单/校验最终 IP 时失效；内网服务要求认证/Host 头时需额外绕过。

## 检测与防御

- **URL 校验**：解析 URL、DNS 解析后校验 IP 是否在允许范围；拒绝私网/回环/链路本地/元数据地址；对短写/整数/八进制/十六进制统一规范化。
- **重定向**：禁用自动重定向或逐跳校验目标 IP；限制重定向次数；不要把用户 URL 直接交给会跟随重定向的客户端。
- **网络隔离**：Webhook 服务放在独立网段，默认拒绝访问内网；出站代理白名单。
- **检测**：监控 Webhook 请求中的 `127.1`、十进制/八进制 IP、`redirect-to`、异常端口扫描；内网服务日志中的异常 Host/来源。
