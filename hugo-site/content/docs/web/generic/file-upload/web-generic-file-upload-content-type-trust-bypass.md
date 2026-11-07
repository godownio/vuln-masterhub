---
id: web-generic-file-upload-content-type-trust-bypass
title: 后端仅信任 multipart 的 Content-Type 判断类型，改包即可上传脚本
type: scenario
domain: web
path: web/generic/file-upload
technique: mime-type-spoofing
tags:
- web
- file-upload
- mime
- content-type
- multipart
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
  verified_at: '2026-11-05T00:40:20+08:00'
  notes: 已对照原文与图25/26核对：把 y.php 的 multipart Content-Type 改为 image/jpeg 后上传成功，响应回显 ./upload/y.php，证明后端仅信  type。卡中 curl type=image/png 的等价构造成立。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-content-type-trust-bypass/
draft: false
kb_aliases:
- MIME 验证绕过
- Content-Type 伪造
- $_FILES type 不可信
- 改包上传 php
- image/png 绕过
---

## 一句话结论

服务端用 `$_FILES['file']['type']`（即请求里的 `Content-Type`）做图片白名单时，这个值完全由客户端控制；把上传包的该字段改成 `image/png`，即可让 `.php` 文件通过校验并落盘执行。

## 原理

- PHP 的 `$_FILES['file']['type']` 来自 multipart 每个 part 的 `Content-Type` 头，是浏览器根据扩展名猜测后发送的提示值，不是服务端读取文件内容后得出的结论。
- 后端白名单逻辑只是 `in_array($_FILES['file']['type'], ['image/jpeg','image/png','image/gif'])`，命中就调用 `move_uploaded_file` 保存原始文件名，没有再检查后缀或文件头。
- 因此攻击者只要在代理里把 `Content-Type: application/x-php`（或 `text/plain`）改成 `image/png`，MIME 判断通过，文件名仍保留 `.php`，脚本便落到 Web 目录。
- 这根链条成立的核心是“把客户端声明当成了服务端事实”，与文件真实内容无关。

## 触发条件

- 上传接口只以 `$_FILES[...]['type']` 或请求头 `Content-Type` 作为类型判断依据。
- 文件名后缀未被另行限制，或允许白名单外后缀落盘。
- 上传目录可访问且脚本后缀会被解析。

## 利用步骤

1. 正常上传一张图片，确认成功；上传 `.txt` 时返回“文件类型不正确”，说明存在 MIME 校验。
2. 抓取上传请求，把一个 `.txt` 或 PHP 文件的 part 的 `Content-Type` 改为 `image/png`，重放确认通过。
3. 把文件名改为 `shell.php`，同样把 `Content-Type` 改为 `image/png` 后上传。
4. 访问响应中回显的上传路径，确认 PHP 执行。

## PoC

```bash
curl -s -X POST 'http://target/upload.php' \
  -F 'file=@shell.php;filename=shell.php;type=image/png' \
  -F 'submit=Upload'
```

对应原始 multipart 片段：

```http
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png

<?php phpinfo(); ?>
```

若后端还检查 `$_FILES['file']['name']` 的后缀，可继续结合双写、替代后缀或路径截断等手法。

## 变体与关联

- 变体：把 `type` 改成白名单中的任意图片 MIME；若后端用 `getimagesize()`，则需要同时伪造文件头（见魔数卡）。
- 关联：[[web-generic-file-upload-magic-byte-gif-prefix-bypass]]（MIME + 文件头双重校验时同时伪造）；[[web-generic-file-upload-clientside-js-whitelist-bypass]]（前端也按 MIME 判断时）。
- 边界：若服务端用 `finfo_file`/`getimagesize` 读取真实内容，单纯改 Content-Type 无效。

## 检测与防御

- 检测：上传请求的 `Content-Type` 与文件扩展名、实际内容不一致；同一来源反复提交不同后缀但相同 MIME；上传目录出现脚本文件。
- 防御：不要使用 `$_FILES['type']` 做安全判断；用 `finfo_file()` 或 `getimagesize()` 读取实际内容；同时校验扩展名白名单、重命名文件、将上传目录置于 Web 根之外或禁止脚本执行。
