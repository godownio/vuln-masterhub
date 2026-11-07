---
id: web-generic-ssrf-wallos-testwebhook-notifications-private-ip
title: Wallos testwebhooknotifications.php 未校验私有/保留 IP 的 SSRF（CVE-2026-30839）
type: scenario
domain: web
path: web/generic/ssrf
technique: wallos-webhook-test-url-ssrf
tags:
- php
- wallos
- ssrf
- curl
- webhook
- internal-network
- cve-2026-30839
cve:
- CVE-2026-30839
severity: medium
confidence: high
status: verified
affected_versions: Wallos <=4.6.1；修复版本 4.6.2+（原文标记）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V33
  verified_at: '2026-11-05T06:03:37+08:00'
  notes: 已对照原文与2张截图核对：v4.6.1 仅校验 scheme http/https 与 FILTER_VALIDATE_URL 后直接 curl_setopt(CURLOPT_URL,)+curl_exec，截图一致；v4.6.2 修复为 gethostbyname+filter_var NO_PRIV_RANGE|NO_RES_RANGE，卡内描述与原文一致；CVE-2026-30839、影响 <=4.6.1/修复 4.6.2+ 正确，作者已设 affected_versions；原文 PoC 未带认证头、未说明端点认证要求，卡内已注明；关联卡 [[web-generic-ssrf-cloud-metadata-credential-theft]] 与 [[web-generic-ssrf-dns-rebinding-bypass]] 尚不存在（卡内已写“如已存在”），不影响正文；未在本机复现
url: /docs/web/generic/ssrf/web-generic-ssrf-wallos-testwebhook-notifications-private-ip/
draft: false
kb_aliases:
- CVE-2026-30839
- Wallos SSRF
- testwebhooknotifications.php
- Wallos webhook SSRF
- curl_exec 用户 URL
---

## 一句话结论

Wallos v4.6.1 的 `endpoints/notifications/testwebhooknotifications.php` 只用 `parse_url` 和 `FILTER_VALIDATE_URL` 检查 URL 格式与 `http/https` 协议，随后把用户提交的 `url` 直接交给 `curl_setopt(CURLOPT_URL, ...)` 并 `curl_exec`；没有对解析出的主机/IP 做私有或保留地址过滤，攻击者可让服务器访问 `127.0.0.1`、内网地址或云元数据地址并读取响应。

## 原理

- **输入**：端点接收 JSON（原文 PoC）中的 `url`、`requestmethod`、`payload`、`customheaders`、`ignore_ssl`，`url` 完全由请求方控制。
- **不充分的校验**：代码先 `parse_url($url)`，检查 `scheme` 存在且为 `http`/`https`（大小写不敏感），再用 `filter_var($url, FILTER_VALIDATE_URL)` 检查 URL 语法。这三项只保证“看起来是一个合法 HTTP URL”，不限制目标主机。
- **直接出站**：随后 `curl_init()` → `curl_setopt($ch, CURLOPT_URL, $url)` → 可选设置 `CURLOPT_CUSTOMREQUEST`、`CURLOPT_POSTFIELDS`、`CURLOPT_HTTPHEADER` → `curl_exec($ch)`，并把响应返回给调用方。应用服务器成为请求代理，攻击者可借此访问仅服务器可达的内网服务。
- **可利用的目标**：`127.0.0.1`/`localhost` 上的管理端口、内网网段服务、`169.254.169.254` 等云元数据地址（原文在修复说明中明确把 `169.254.169.254` 作为应拦截的保留地址示例）；`customheaders` 可注入 `Host`、`Authorization` 等头，`requestmethod`/`payload` 可构造 POST/PUT 请求，`ignore_ssl=true` 可访问自签名 HTTPS 内网服务。
- **修复逻辑**：v4.6.2 在 `curl_exec` 前 `parse_url(..., PHP_URL_HOST)` 取主机名，`gethostbyname($host)` 解析为 IP，再用 `filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)` 拒绝私有地址（10/8、172.16/12、192.168/16 等）与保留地址（127/8、169.254/16 等）。校验失败直接返回 `Invalid target IP`。
- **残余风险**：该校验是“先解析一次、curl 再解析/连接一次”，若 DNS 记录在两次解析之间变化（DNS rebinding）仍可能绕过；更稳妥的做法是连接时固定已校验的 IP（curl `CURLOPT_RESOLVE`/自定义解析）并在网络层禁止访问内网。

## 触发条件

- 目标为 Wallos <=4.6.1；修复版本 4.6.2+。
- 攻击者能访问 `testwebhooknotifications.php` 端点；原文 PoC 未带认证头，但文章未明确说明该端点是否要求登录，实际利用前需确认目标的认证/CSRF 保护。
- 应用服务器可出站访问目标内网/元数据地址（无出站防火墙或允许 HTTP）。
- 端点未额外限制目标域名/IP。

## 利用步骤

1. 确认 Wallos 版本与端点可达：`POST /endpoints/notifications/testwebhooknotifications.php`。
2. 提交 JSON，把 `url` 设为 `http://127.0.0.1:<port>/` 或内网地址；先用一个已知会返回特征内容的本地端口验证回显。
3. 按需设置 `requestmethod`（GET/POST）、`payload`（请求体）、`customheaders`（如 `["Authorization: Basic ..."]`）、`ignore_ssl`。
4. 根据响应内容枚举内网服务、读取管理接口/云元数据；必要时用不同内网网段与端口做探测。
5. 若目标已升级到 4.6.2，尝试 DNS rebinding/重定向等绕过前先确认修复实现与网络策略；原文未提供绕过 PoC。

## PoC

原文 PoC：

```http
POST /endpoints/notifications/testwebhooknotifications.php HTTP/1.1
Host: target-site.com
Content-Type: application/json

{
    "requestmethod": "GET",
    "url": "http://127.0.0.1:9999/",
    "payload": "test",
    "customheaders": "[]",
    "ignore_ssl": false
}
```

访问云元数据的变体（仅结构示意）：

```json
{
  "requestmethod": "GET",
  "url": "http://169.254.169.254/latest/meta-data/",
  "payload": "",
  "customheaders": "[]",
  "ignore_ssl": false
}
```

## 变体与关联

- **内网服务探测**：把 `url` 指向 `127.0.0.1`、RFC1918 网段、IPv6 回环/内网地址；`customheaders` 可携带内网服务需要的认证头。
- **协议限制**：只允许 `http`/`https`，不能用 `file://`/`gopher://`；但 HTTP 内的任意路径、方法、头、体均可控。
- **修复绕过**：`gethostbyname` 只解析 IPv4 且只取第一个地址；IPv6、DNS rebinding、HTTP 重定向（若 curl 开启 follow）都可能成为绕过方向；原文只给出修复代码，未验证绕过。
- 关联卡片：[[web-generic-ssrf-cloud-metadata-credential-theft]]（如已存在）、[[web-generic-ssrf-dns-rebinding-bypass]]（如已存在）。

## 检测与防御

- **升级**：Wallos 4.6.2+。
- **代码**：对 URL 主机做解析后 IP 校验（私有/保留/回环/链路本地/组播），并在实际连接时固定该 IP；禁止或限制 `customheaders` 注入 `Host`；对 `requestmethod` 做白名单；仅在必要时允许 `ignore_ssl`。
- **网络**：应用服务器出站默认拒绝，只放行必要的外部 webhook 域名；显式阻断 `169.254.169.254`、`127.0.0.0/8`、RFC1918、IPv6 回环/ULA；云环境启用 IMDSv2 并限制跳数。
- **检测**：`testwebhooknotifications.php` 请求的 `url` 含私有/保留地址、`localhost`、元数据 IP；应用进程对内网端口发起异常 HTTP；响应体含内网服务 banner/元数据；同一账号短时间内大量不同内网目标。
- **应急**：审计该端点的访问日志与出站连接，确认是否读取过元数据/内网敏感接口；轮换可能泄露的云凭据；限制端点访问权限并加 CSRF/认证。
