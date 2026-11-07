---
id: web-generic-file-upload-null-byte-path-truncation
title: PHP 空字节截断上传保存路径：GET 解码 %00 或 POST 注入原始 NUL
type: scenario
domain: web
path: web/generic/file-upload
technique: null-byte-truncation
tags:
- web
- file-upload
- null-byte
- truncation
- php
- path-manipulation
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:40:24+08:00'
  notes: 已对照原文与图35-39核对：road 路径参数可控，=road/随机名，GET %00 解码为 NUL 截断后落盘 shell.php，图37 显示 PHP 5.2.17 执行。原文只给出靶场环境版本、未明确声明受影响版本区间，故按规则 clear affected_versions（正文仍保留 PHP<5.3.4 的技术说明）。PoC 未在本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-null-byte-path-truncation/
draft: false
kb_aliases:
- 00 截断
- '%00 截断上传'
- 空字节截断
- PHP 路径截断
- upload-labs 00 truncation
---

## 一句话结论

上传保存路径由用户可控参数与“随机名+白名单后缀”拼接，且运行在 PHP < 5.3.4 时，在路径后注入 NUL 字节可让底层 C 字符串截断，最终落盘为攻击者指定的 `shell.php`。

## 原理

- 代码形式：先生成 `$filename = rand(10,99).date("YmdHis").".".$ext`，再 `$des = $_GET['road']."/".$filename; move_uploaded_file($tmp, $des);`。
- 后缀检查针对 `$ext`（来自上传文件名），因此攻击者上传 `y.png` 可满足白名单；但最终目标路径 `$des` 由另一个用户可控参数 `road` 决定。
- PHP 内核由 C 实现，文件系统函数使用 C 字符串；C 字符串以 `\x00` 作为结束符。当 `$des` 在 `shell.php` 之后包含 NUL 时，拼接在 NUL 后的随机文件名被忽略，实际路径变成 `.../upload/shell.php`。
- GET 参数会被 URL 解码，`%00` 在服务端还原为 NUL；POST 参数不会自动 URL 解码，`%00` 只是普通字符，需在 Burp 中对选中文本执行 URL-decode 变成真正的不可见 NUL。
- PHP 5.3.4 起对文件系统函数中的 NUL 字节做了处理，该手法失效；`magic_quotes_gpc=On` 也会转义 NUL。

## 触发条件

- PHP 版本 < 5.3.4，`magic_quotes_gpc=Off`。
- 上传保存路径（目录或完整路径）由 GET/POST 参数可控，且代码在路径后拼接自动生成的文件名。
- 上传文件本身通过后缀白名单（如 `y.png`），最终解析仍按 `.php` 后缀进行。

## 利用步骤

1. 抓上传包，确认存在用户可控的保存目录参数（示例为 `road` 或 `save_path`），并确认最终文件名由服务端拼接。
2. 上传 `y.png`（内容为 PHP 代码），保持 `Content-Type: image/png` 通过白名单。
3. GET 型：把路径参数改为 `.../upload/shell.php%00`；POST 型：写入 `%00` 后用代理 URL-decode 成原始 NUL。
4. 发送请求，访问 `http://target/upload/shell.php` 验证执行。

## PoC

GET 参数截断的原始请求行示例：

```http
POST /?road=/var/www/html/upload/shell.php%00 HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="y.png"
Content-Type: image/png

<?php phpinfo(); ?>
------X--
```

POST 参数 `save_path` 中应包含真实 `\x00` 字节（代理里对 `%00` 执行 URL-decode），而非字面量 `%00`。

## 变体与关联

- 变体：截断点可放在目录名、文件名或完整路径中；若代码用 `basename()` 先处理，则需寻找未过滤的路径参数；Windows 下还可尝试其他非法字符截断。
- 关联：[[web-generic-file-upload-blacklist-double-write-bypass]]（同属“检查值与落盘值不一致”）；[[web-generic-file-upload-move-uploaded-file-trailing-dot]]（利用 `move_uploaded_file` 的路径归一化，而非 NUL）。
- 边界：现代 PHP（≥5.3.4）默认拒绝含 NUL 的路径，本卡主要适用于遗留系统/靶场；原文未给出 PHP 版本区间之外的验证。

## 检测与防御

- 检测：请求参数或文件名中出现 `%00`、`\x00`；上传落盘名与随机名规则不符；Web 目录出现非预期后缀文件。
- 防御：升级 PHP；对路径参数使用白名单/固定目录，禁止用户控制完整保存路径；用 `basename()` 并拒绝含 NUL、控制字符的输入；落盘前规范化路径并校验其位于预期目录内。
