---
id: web-generic-ssrf-curl-307-308-method-preserve-internal-post
title: curl 重定向状态码方法语义：301/302/303 转 GET、307/308 保留方法与 body，把受限 SSRF 变成内网 POST
type: scenario
domain: web
path: web/generic/ssrf
technique: curl-307-308-method-preserve-internal-post
tags:
- web
- ssrf
- php
- curl
- redirect
- http-method
- post
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V639
  verified_at: '2026-11-13T02:16:31+08:00'
  notes: 已对照原文与截图核对：301/302/303转GET、307/308保留方法与body(图37/38)，nc -lvp 10010对照302→GET、307→POST(图39)，引用P牛MinIO CVE-2021-21287一致；卡内curl -X POST -L演示符合libcurl行为。dedup首候选为自身，302 POST→GET短写IP卡为相反方向related非同链，保留。未验证点：需入口能发POST且首跳可控，原文为本地对照实验
url: /docs/web/generic/ssrf/web-generic-ssrf-curl-307-308-method-preserve-internal-post/
draft: false
kb_aliases:
- 307 保持 POST
- 308 方法保持
- SSRF 升级 POST
- 302 转 GET
- MinIO SSRF 技巧
- 重定向方法语义
---

## 一句话结论

libcurl 跟随重定向时，301/302/303 会把请求方法统一改成 GET，而 307/308 保留原始方法与请求体；如果一个 SSRF 只能控制 URL、但请求本身是 POST（或能发 POST），让首跳服务器返回 307/308 指向内网地址，就能把“只能发 GET 的鸡肋 SSRF”变成对内网接口的 POST 请求，打到只接受 POST/JSON 的内部 API（如 MinIO CVE-2021-21287 式利用）。

## 原理

- **HTTP 语义**：301/302/303 传统上被客户端改为 GET；307 Temporary Redirect 与 308 Permanent Redirect 要求保持原方法和 body。curl 不缓存重定向、对 301/302/303 一视同仁地转 GET，这一点与浏览器相近但更彻底。
- **SSRF 场景**：很多 SSRF 点方法固定（如表单/接口本身是 POST），或只能改 Host 而方法、body 由前端决定。若攻击者控制首跳 URL 的响应，用 307/308 让 curl 把原始 POST（含 body、Content-Type）重放到内网目标，即可访问“只收 POST”的内部接口，绕过“SSRF 只能 GET”的限制。
- **与 302 的对照**：302 会把 POST 降为 GET，适合“内网只接受 GET”的场景（原库里已有此类卡）；307/308 是相反方向，适合“必须 POST 且 body 可控”。
- **实测**：原文用本地 `nc -lvp 10010` 对照，`curl -L` 对 302 发 GET、对 307 发 POST；PHP 的 SSRF 包装只是把 curl 封装，行为一致。
- **限制**：307/308 只能保持客户端原本愿发的方法；如果 SSRF 入口固定 GET 且没有 body，307 依旧发 GET，无法凭空产生 POST。此外若中间代理改方法/丢 body，也会失效。

## 触发条件

- SSRF 由 curl（或等价客户端）实现并开启跟随重定向。
- 入口请求的方法/body 是攻击者需要的方法/body，或至少可控（如前端表单 POST、富文本抓取 POST）。
- 攻击者能控制首跳服务器返回 307/308。
- 内网目标存在只接受 POST/特定 Content-Type 的接口。

## 利用步骤

1. 确认 SSRF 客户端跟随重定向（提交 `http://your-host/redir` 观察是否二次请求）。
2. 在攻击者服务器配置：`Location: http://127.0.0.1:<port>/internal/api`，状态码 307（临时）或 308（永久）。
3. 让 SSRF 以目标方法提交（POST + body），首跳 307 后 curl 会把同样的 POST body 发到内网接口。
4. 根据内网接口响应/时延/回显判断结果；对需要特定 Header/Content-Type 的接口，在首跳响应中无法注入到第二跳请求（方法/body 保留，但头由原始请求决定），需利用入口可控的头或 body。

## PoC

对照实验（原文方式）：

```bash
# 302：POST 被改成 GET
curl -X POST -L "http://localhost:7777/redir.php?code=302&url=http://127.0.0.1:10010/"
# nc 侧看到：GET / HTTP/1.1

# 307：保持 POST
curl -X POST -L "http://localhost:7777/redir.php?code=307&url=http://127.0.0.1:10010/"
# nc 侧看到：POST / HTTP/1.1
```

SSRF 参数示例：

```http
POST /fetch HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

url=http://attacker/redir307
```

`Location: http://127.0.0.1:8080/admin/api`（307）后，目标收到原始 POST 与 body。

## 变体与关联

- 与 `web-generic-ssrf-short-form-ip-302-post-to-get` 方向相反：302 把 POST 降为 GET 用于只收 GET 的内网；307/308 保留 POST 用于只收 POST 的内网。
- 与 `web-generic-ssrf-curl-redirect-protocol-surface-suffix-whitelist-bypass` 同属重定向维度利用（一个换协议、一个保方法）。
- 经典公开案例：MinIO CVE-2021-21287 利用 307 把只能控制 Host 的 SSRF 变为灵活的 POST 请求；本源语可复用于任何 curl 系 SSRF。

## 检测与防御

- 关闭自动跟随或限制 `CURLOPT_MAXREDIRS`；逐跳校验 scheme/host/IP。
- 对重定向目标重新做协议与方法白名单（业务只应 GET 的外部抓取禁止 307/308 改方法）。
- 监控首跳返回 307/308 后被跟随到内网/非常规端口的请求。
