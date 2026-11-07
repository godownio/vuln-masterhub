---
id: web-php-file-inclusion-htaccess-auto-prepend-base64-filter
title: .htaccess auto_prepend_file + php://filter base64-decode：把 base64 图片当 PHP 预包含执行
type: scenario
domain: web
path: web/php/file-inclusion
technique: htaccess-auto-prepend-base64-filter-rce
tags:
- php
- htaccess
- auto-prepend-file
- php-filter
- base64
- file-upload
- rce
- apache
- ctf
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:16+08:00'
  notes: 已对照原文uploadfile段核对：AddType对.jpg不生效、base64一句话PD9waHAgc3lzdGVtKCJscyAvIik7Pz4=、php_value auto_prepend_file "php://filter/convert.base64-decode/resource=55.jpg"、访问上传文件回显ls /与最终flag均一致。未验证点：PoC未本机复跑；原文未给完整.htaccess/响应头；frontmatter无sources/source_url。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-htaccess-auto-prepend-base64-filter/
draft: false
kb_aliases:
- uploadfile
- auto_prepend_file base64
- php://filter/convert.base64-decode/resource
- .htaccess 预包含
- base64 图片 getshell
- AddType application/x-httpd-php
---

## 一句话结论

文件上传只拦截明显的 PHP 特征、`.htaccess` 中的 `AddType application/x-httpd-php .jpg` 又不生效时，可以把 PHP 代码 Base64 编码后存成图片，再上传一个 `.htaccess` 写入 `php_value auto_prepend_file "php://filter/convert.base64-decode/resource=55.jpg"`；之后访问任意 PHP 文件，`auto_prepend_file` 会先把 55.jpg 经 base64-decode 过滤器解码成 PHP 并执行，从而 RCE。

## 原理

- **上传过滤只查明显特征**：`<?php system(...); ?>` 会被识别，但 `<script language="php">`、`GIF89a` 前缀 + `echo file_get_contents(...)`、Base64 文本都能上传；只是上传后不可访问/不执行。
- **AddType 不总是生效**：`.htaccess` 的 `AddType application/x-httpd-php .jpg` 依赖 mod_php；在 PHP-FPM/某些 Apache 配置下，`.jpg` 仍按静态文件返回，不会执行。
- **auto_prepend_file 是目录级 PHP 配置**：mod_php 下 `.htaccess` 的 `php_value auto_prepend_file <file>` 会让该目录下每个 PHP 请求在执行前自动包含指定文件；包含文件按 PHP 解析，不看扩展名。
- **php://filter 解码**：`php://filter/convert.base64-decode/resource=55.jpg` 会读取 55.jpg，先做 base64-decode，再把结果作为 PHP 代码交给 include；因此图片里只放 Base64 文本（`PD9waHAgc3lzdGVtKCJscyAvIik7Pz4=` 即 `<?php system("ls /");?>`）即可。
- **为什么需要两步**：直接上传 `.php` 会被过滤；直接 Upload `.htaccess` 的 AddType 可能不执行；`auto_prepend_file` + `php://filter` 把“可上传的图片/文本”变成“可执行的 PHP”，绕过了扩展名与内容特征两道限制。
- **影响**：以 Web 进程权限执行任意命令；读取源码/配置/flag，或进一步提权。

## 触发条件

- 上传功能允许上传 `.htaccess`（或能写入目标目录的 `.htaccess`），且 Apache 使用 mod_php（`php_value` 生效）。
- 上传目录可被 Web 访问/执行 PHP；存在任意 PHP 文件可请求（`index.php`、上传的 `.jpg` 配合 AddType 等）。
- 能上传 Base64 文本/图片文件（内容过滤不拦 Base64）。
- 进程对目标文件有读权限。

## 利用步骤

1. 上传一个普通图片/文本，确认上传路径与访问方式；测试 `.htaccess` 是否可上传。
2. 将 PHP payload Base64 编码：`<?php system("ls /");?>` -> `PD9waHAgc3lzdGVtKCJscyAvIik7Pz4=`，保存为 `55.jpg` 并上传。
3. 上传 `.htaccess`：
   ```apache
   AddType application/x-httpd-php .jpg
   php_value auto_prepend_file "php://filter/convert.base64-decode/resource=55.jpg"
   ```
4. 访问上传目录下任意 PHP 文件（或 `55.jpg`，若 AddType 生效）；`auto_prepend_file` 先解码执行 55.jpg，命令输出出现在响应中。
5. 用 `ls /`/`cat` 读取 `thisisfl@g.php` 等源码/flag；若 `auto_prepend_file` 被禁用，尝试 `.user.ini`、`auto_append_file`、日志包含等替代。
6. 清理 `.htaccess`/payload（如需要）。

## PoC

Base64 payload：

```text
PD9waHAgc3lzdGVtKCJscyAvIik7Pz4=
# <?php system("ls /");?>
```

`.htaccess`：

```apache
AddType application/x-httpd-php .jpg
php_value auto_prepend_file "php://filter/convert.base64-decode/resource=55.jpg"
```

访问上传目录的 PHP 文件，响应中出现 `ls /` 结果（含 `thisisfl@g.php`），再从源码中读取 flag。原文实测最终 flag `flag{9ba9ef6ddfbe14916fa2d3337b427774}`；未在本库复跑。

## 变体与关联

- **配置变体**：`.htaccess` 的 `php_value auto_prepend_file`/`auto_append_file`、`.user.ini` 的 `auto_prepend_file`、`php.ini` 的 `auto_prepend_file`；Nginx+PHP-FPM 用 `.user.ini`。
- **编码变体**：Base64、`convert.iconv`、`convert.quoted-printable-decode`、`zlib.inflate` 等 `php://filter` 链；把 payload 藏在图片/文本中。
- **上传变体**：`.htaccess` 内容过滤绕过、双扩展名、`.htaccess` 被重命名/追加垃圾、`AddType`/`SetHandler`/`php_value` 组合。
- **关联卡片**：[[web-php-file-inclusion-htaccess-self-include-dirty-bypass]]（auto_append 自包含）、[[web-php-file-inclusion-user-ini-auto-prepend-rce]]（.user.ini auto_prepend）、[[web-php-file-inclusion-php-filter-insert-bypass]]（php://filter 过滤器绕过）。

## 检测与防御

- **上传限制**：禁止上传 `.htaccess`/`.user.ini`；按内容类型 + 扩展名 + 真实路径校验；上传目录禁止执行 PHP（`php_admin_flag engine off`）。
- **PHP 配置**：禁用 `auto_prepend_file`/`auto_append_file` 的用户级覆盖；`allow_url_include=Off`；限制 `php://filter` 在包含场景的使用。
- **Web 服务器**：上传目录单独配置，禁止 `.htaccess` 覆盖（`AllowOverride None`）；静态文件目录不经过 PHP。
- **检测**：上传目录出现 `.htaccess`/`.user.ini`；请求触发 `auto_prepend_file` 包含；`php://filter/convert.base64-decode` 出现在日志；Web 进程执行 `system`/`ls` 等命令。
