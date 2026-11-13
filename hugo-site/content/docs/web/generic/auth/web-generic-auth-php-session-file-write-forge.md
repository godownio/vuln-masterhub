---
id: web-generic-auth-php-session-file-write-forge
title: PHP Session 文件任意写入伪造会话：备份文件名可控把 admin|b:1; 写进 /tmp/sess_<id>
type: scenario
domain: web
path: web/generic/auth
technique: php-session-file-write-forge
tags:
- php
- session
- auth-bypass
- arbitrary-file-write
- file-write
- privilege-escalation
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V604
  verified_at: '2026-11-12T18:33:53+08:00'
  notes: '已对照原文与20图核对：图01 用户名 sess，Burp 抓到 PHPSESSID=f1719926b3ba42a2；图02 compression=./&backup=1，响应 Content-Disposition: attachment; filename="sess_f1719926b3ba42a2"，正文开头即 admin|b:1;username|s:4:"sess";memos|a:0:{}；图03 替换 PHPSESSID 后页面由 admin 分支 system(cat /flag) 输出 flag。源码逻辑复核：filename=/tmp/<username>_<bin2hex(random_bytes(8))>，default 分支 .= ''.'' . compressionMethod 后 while 删除 ''../''，compression=./ 正好拼出 /tmp/sess_<16hex>；str_rot13 还原 payload，链条成立。affected_versions 留空正确：原文为CTF题无组件版本。dedup 报告判 new，related 的 session poisoning/LFI、upload_progress、user.ini 均为不同信任边界（需包含或改save_path），非同链，保留。未验证点：未实际搭建题目复现。'
url: /docs/web/generic/auth/web-generic-auth-php-session-file-write-forge/
draft: false
kb_aliases:
- PHP Session 伪造
- sess_ 文件写入
- 任意文件写入覆盖 Session
- backup 文件名注入
- PHPSESSID 伪造 admin
- session 内容可控
- 备份功能写 session
---

## 一句话结论

PHP 默认把会话序列化后写入 `session.save_path` 下的 `sess_<PHPSESSID>` 文件；当应用存在“文件名与内容都可控”的任意文件写入（如备份导出）时，攻击者可以把 `admin|b:1;...` 写进自己指定的 `sess_<id>`，再把 Cookie 的 `PHPSESSID` 改成该 id，服务端就会把伪造内容当作可信会话加载，直接获得 `$_SESSION['admin']=true`。

## 原理

- **PHP 会话的存储格式**：默认 `session.serialize_handler=php`，会话数据以 `键|序列化值;键|序列化值;` 的形式写入 `session.save_path`（常见 `/tmp`）下的 `sess_<PHPSESSID>`。例如 `username|s:4:"sess";memos|a:0:{}`。
- **会话文件的信任边界**：PHP 只按 `PHPSESSID` 找同名文件并反序列化，不校验文件来源；任何能写入该路径、且能控制文件内容的程序，都等于能任意设置 `$_SESSION`。
- **本题的任意写**：备忘备份功能把所有 memo 拼接后经 `file_put_contents()` 写到 `/tmp/<username>_<随机16hex>.<compressionMethod>`；memo 内容完全由用户输入控制，username 也由登录时的输入决定。默认分支还会对内容做 `str_rot13`、在文件名后追加 `.<compressionMethod>`，并循环删除文件名中的 `../`。
- **文件名拼成 sess_ 的关键**：`compression=./` 时，追加的 `'.' . './'` 得到 `../`，而代码的 `while (strpos($filename,'../')!==false) $filename=str_replace('../','',$filename)` 会把它删掉，最终文件名恰好变成 `/tmp/sess_<随机16hex>`。用户名取 `sess` 即可让前缀匹配 PHP 会话文件名。
- **内容绕过 rot13**：memo 先经 `str_rot13` 编码再提交，服务端默认分支的 `str_rot13` 会把它还原成 `admin|b:1;username|s:4:"sess";memos|a:0:{}`。
- **会话加载**：把 `PHPSESSID` 设为响应头/下载名中泄露的 16 位随机串，后续请求 PHP 读取该 `sess_` 文件，`admin|b:1;` 被反序列化为布尔 true；页面里 `if ($_SESSION['admin'] === true) system("cat /flag")` 随即执行。

## 触发条件

- PHP 应用使用 `session_start()`，且存在任意文件写入（导出、备份、日志、缓存、上传重命名等），文件名与内容至少部分可控。
- 写入路径可落到 `session.save_path`（常见 `/tmp`），或能通过路径处理/后缀处理拼出 `sess_<合法PHPSESSID>`。
- 会话反序列化使用默认 `php` 格式，且应用信任会话中的权限字段（如 `admin`）。
- 攻击者能设置 `PHPSESSID` Cookie，并知道/能推断写入文件的随机名（本例下载名 `sess_<16hex>` 直接泄露）。

## 利用步骤

1. 登录并确认应用使用 `session_start()`，观察用户名/备忘等功能是否进入会话文件。
2. 找到任意写入口（本例为备份导出），确认文件名由用户名、随机数和可控后缀组成，内容由用户输入控制。
3. 构造目标会话内容 `admin|b:1;username|s:4:"sess";memos|a:0:{}`，按入口的编码要求预处理（本例先 `str_rot13`）。
4. 选择能拼出 `/tmp/sess_<随机>` 的参数：用户名 `sess`、compression 为 `./`（利用 `../` 删除循环），触发导出。
5. 从响应 `Content-Disposition`/下载文件名取得 `sess_<16hex>`，把 Cookie `PHPSESSID` 改为该 16hex。
6. 访问受保护页面，会话中的 `admin=true` 生效；读取 flag/管理员功能。
7. 清理写入的会话文件，避免遗留。

## PoC

```http
POST /memo.php HTTP/1.1
Host: <target>
Cookie: PHPSESSID=<任意合法值>
Content-Type: application/x-www-form-urlencoded

compression=./&backup=1
```

前提：登录用户名设为 `sess`，并在 memo 中加入 rot13 后的会话 payload（十六进制/URL 编码提交）：

```text
admin|b:1;username|s:4:"sess";memos|a:0:{}
```

响应：

```http
Content-Disposition: attachment; filename="sess_f1719926b3ba42a2"
```

随后把 Cookie 改为 `PHPSESSID=f1719926b3ba42a2` 访问 `memo.php`，页面执行 `system("cat /flag")` 输出 flag。

## 变体与关联

- **变体（写入口）**：任意文件写入/路径穿越写、日志注入、上传文件名可控、缓存文件、备份导出；只要文件名能拼成 `sess_<id>` 且内容可控即可。
- **变体（序列化格式）**：`session.serialize_handler=php_serialize` 时内容为 `a:...` 整体序列化，payload 需按对应格式构造；`session.save_path` 在 Web 目录时还可直接访问会话文件。
- **变体（配合 LFI）**：若存在文件包含，可把 payload 写进会话后 `include sess_<id>` 执行 PHP 代码，见关联卡。
- **关联**：[[web-php-file-inclusion-session-poisoning-sess-file]]（LFI 包含会话文件执行代码）、[[web-php-file-inclusion-session-upload-progress-lfi-shell]]（session.upload_progress 写会话）、[[web-php-file-inclusion-user-ini-session-save-path-webshell]]（改 session.save_path）。
- **边界**：会话文件路径不可写/不可达、`session.use_strict_mode` 只影响未初始化的会话 ID、或应用不信任会话中的权限字段时，该链不成立；`session.save_path` 使用不可预测目录时需先泄露路径。

## 检测与防御

- **根因修复**：禁止用户控制写入路径/文件名；备份/导出功能使用服务端生成的固定目录与随机文件名，内容与路径解耦。
- **会话加固**：`session.save_path` 指向 Web 进程不可写之外的目录；`session.use_strict_mode=1`；对会话中的权限字段做服务端校验，不信任客户端可写文件。
- **权限隔离**：Web 进程对 `/tmp`/会话目录的写权限最小化；避免 `file_put_contents` 使用用户拼接路径。
- **检测**：`/tmp` 下出现内容含 `admin|b:1;` 或 `<?php` 的 `sess_` 文件；下载/备份接口返回的文件名以 `sess_` 开头；同一会话 ID 的 Cookie 在文件写入后立即访问受保护页面。
