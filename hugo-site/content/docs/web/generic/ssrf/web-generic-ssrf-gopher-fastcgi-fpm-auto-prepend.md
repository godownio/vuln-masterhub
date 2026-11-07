---
id: web-generic-ssrf-gopher-fastcgi-fpm-auto-prepend
title: gopher SSRF 伪造 FastCGI：PHP_VALUE 注入 auto_prepend_file 执行任意代码
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-gopher-fastcgi-fpm-auto-prepend
tags:
- ssrf
- gopher
- php-fpm
- fastcgi
- rce
- php-value
- auto-prepend-file
- internal-service
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:12:58+08:00'
  notes: 已对照原文及FastCGI架构/键值对图核对；SCRIPT_FILENAME、security.limit_extensions、PHP_VALUE/PHP_ADMIN_VALUE与auto_prepend_file=php://input链路准确；原文未给编码后完整payload，卡内已注明；未复跑
url: /docs/web/generic/ssrf/web-generic-ssrf-gopher-fastcgi-fpm-auto-prepend/
draft: false
kb_aliases:
- SSRF 打 PHP-FPM
- FastCGI 伪造
- gopher 打 FPM
- PHP_VALUE auto_prepend_file
- php://input RCE
- FPM 9000 未授权
---

## 一句话结论

当 SSRF 能通过 `gopher://` 发送任意二进制数据且目标内网开放 PHP-FPM（默认 9000）时，可伪造 FastCGI 键值对，把 `SCRIPT_FILENAME` 指向服务器上任意已存在的 `.php` 文件，并通过 `PHP_VALUE`/`PHP_ADMIN_VALUE` 设置 `auto_prepend_file=php://input`、`allow_url_include=On`，使目标在执行该 PHP 文件前先包含并执行请求体中的 PHP 代码，形成 RCE。

## 原理

- Nginx/Apache 通过 FastCGI 把请求转给 PHP-FPM；FPM 从一组 name-value 键值对中读取 `SCRIPT_FILENAME` 决定执行哪个文件，其余如 `REQUEST_METHOD`、`QUERY_STRING` 来自网关。攻击者若能直接与 FPM 的 9000 端口对话并伪造这组键值对，就绕过了 Web 服务器对脚本路径和请求体的约束。
- FPM 高版本默认 `security.limit_extensions = .php`，只允许执行 `.php` 后缀，因此不能直接让 FPM 解析上传的任意后缀文件；需要挑一个服务器上已存在的 PHP 文件作为“壳”（phpinfo、默认页、框架入口、报错泄露的路径）。
- `PHP_VALUE` 与 `PHP_ADMIN_VALUE` 是 FastCGI 中用于覆盖 per-request PHP ini 的字段。`auto_prepend_file` 指定在执行目标脚本前先包含的文件；把它设为 `php://input`，PHP 就会把 POST body 当作脚本包含执行。`php://input` 属于 URL 包装器，需 `allow_url_include=On`，该值可用 `PHP_ADMIN_VALUE` 设置。
- 因此整条链是：SSRF（gopher 可构造完整二进制）→ 伪造 FastCGI 记录 → FPM 解析并应用恶意 ini → 执行任意 PHP 代码。`gopher://` 之所以关键，是因为 FastCGI 是二进制协议，只有能控制完整字节流的 SSRF 点才能构造；普通的 GET-only SSRF 或不能带二进制的 `dict://` 不行。
- 原文提到 curl 7.71.1 增加限制后可能无法用 gopher 构造合适的协议数据，此时需要换用其他能发原始 TCP 的 SSRF 入口（如自带 socket 拼接、CRLF 注入到 FPM 的入口）。

## 触发条件

- SSRF 入口能通过 `gopher://`（或其他原始 TCP 方式）向任意内网 IP/端口发送完整二进制数据。
- 目标内网 PHP-FPM 端口（默认 9000）可达，且未做来源 IP 白名单/认证。
- 知道服务器上一个已存在的 `.php` 文件绝对路径（phpinfo、默认页、框架入口、报错信息等）。
- FPM 版本允许通过 FastCGI 设置 `PHP_VALUE`/`PHP_ADMIN_VALUE`（常见默认配置允许），且 `allow_url_include` 可被打开。
- `security.limit_extensions` 未放宽到任意后缀（若已放宽，可直接指向上传文件，条件更简单）。

## 利用步骤

1. 确认 SSRF 支持 gopher 且能指定内网 IP:9000；用 DNS/端口探测确认 FPM 开放。
2. 找一个已存在的 PHP 文件路径作为 `SCRIPT_FILENAME`（如 `/var/www/html/index.php`）。
3. 构造 FastCGI 键值对：保留 `GATEWAY_INTERFACE`、`REQUEST_METHOD`、`SCRIPT_FILENAME`、`SCRIPT_NAME`、`QUERY_STRING`、`REQUEST_URI`、`DOCUMENT_ROOT` 等基础字段，追加 `PHP_VALUE: auto_prepend_file = php://input` 和 `PHP_ADMIN_VALUE: allow_url_include = On`。
4. 把这些键值对编码为 FastCGI `FCGI_PARAMS` 记录，再追加一个包含 PHP 代码的 `FCGI_STDIN` 记录，整体作为 gopher 的 `_` 后 payload（URL 编码）。
5. 通过 SSRF 发送该 gopher URL，同时在请求体/STDIN 中放入 `<?php system('id'); ?>` 之类的代码。
6. 观察响应或回连确认命令执行；若失败，检查 FPM 版本、`security.limit_extensions`、`allow_url_include` 是否可覆盖、路径是否正确。

## PoC

```text
# FastCGI 键值对（原文给出的核心结构）
{
  'GATEWAY_INTERFACE': 'FastCGI/1.0',
  'REQUEST_METHOD': 'GET',
  'SCRIPT_FILENAME': '/var/www/html/index.php',
  'SCRIPT_NAME': '/index.php',
  'QUERY_STRING': '',
  'REQUEST_URI': '/index.php',
  'DOCUMENT_ROOT': '/var/www/html',
  'SERVER_SOFTWARE': 'php/fcgiclient',
  'REMOTE_ADDR': '127.0.0.1',
  'REMOTE_PORT': '12345',
  'SERVER_ADDR': '127.0.0.1',
  'SERVER_PORT': '80',
  'SERVER_NAME': 'localhost',
  'SERVER_PROTOCOL': 'HTTP/1.1',
  'PHP_VALUE': 'auto_prepend_file = php://input',
  'PHP_ADMIN_VALUE': 'allow_url_include = On'
}
```

```text
# 发送形态（payload 需按 FastCGI 记录格式编码后 URL-encode）
gopher://127.0.0.1:9000/_<urlencoded-fastcgi-records>
# STDIN 中放入：<?php system('id'); ?>
```

```text
# 无完整可复制 PoC：原文只给出 FastCGI 参数结构，未给出编码后的完整 gopher payload。
# 需借助 FastCGI 客户端/自写编码器生成 FCGI_PARAMS + FCGI_STDIN 记录。
```

## 变体与关联

- 变体：若 `security.limit_extensions` 为空或包含其他后缀，可直接让 FPM 执行上传的恶意文件，无需 `auto_prepend_file`。
- 变体：Nginx `pathinfo` 解析漏洞本质也是 FastCGI 对 `SCRIPT_FILENAME` 的解析差异；修复后只能执行 `.php`。
- 变体：用 `.user.ini` 的 `auto_prepend_file` 达到类似效果（需要能把 `.user.ini` 写入 Web 目录），见关联卡。
- 关联：[[web-php-file-inclusion-user-ini-auto-prepend-rce]]（同一 ini 机制的本地文件写入版）、[[web-generic-ssrf-redis-inline-protocol-crlf]]（同为 SSRF 打内网服务的协议伪造思路）、[[web-generic-ssrf-cloud-metadata]]。
- 边界：FPM 仅监听 Unix socket、入口不支持 gopher/二进制、`security.limit_extensions` 严格且无可执行 PHP 文件、`allow_url_include` 无法覆盖、curl 版本限制 gopher 时失效。

## 检测与防御

- 检测：SSRF 请求中出现 `gopher://` 与 9000 端口；FPM 访问日志/慢日志出现异常 `SCRIPT_FILENAME` 与 `PHP_VALUE`；Web 进程执行了来自 `php://input` 的代码；FPM 监听端口出现非 Nginx/Apache 来源的连接。
- 修复：FPM 只监听 Unix socket 或绑定 127.0.0.1，并用防火墙限制 9000 仅允许 Web 服务器；`security.limit_extensions = .php`；禁用 `allow_url_include`；在 pool 配置中固定 `php_admin_value[auto_prepend_file]` 为空并禁止覆盖。
- 加固：SSRF 入口只允许 http/https、拒绝 gopher/dict/file；解析目标 IP 并阻断内网/回环；对出站 9000 做白名单。
