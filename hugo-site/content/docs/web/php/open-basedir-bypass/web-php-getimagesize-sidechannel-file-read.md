---
id: web-php-getimagesize-sidechannel-file-read
title: getimagesize() 报错侧信道读取任意文件：借助宽高/类型回显逐字节推断文件内容
type: scenario
domain: web
path: web/php/open-basedir-bypass
technique: getimagesize-error-sidechannel-file-read
tags:
- php
- getimagesize
- side-channel
- file-read
- lfi
- information-disclosure
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:15:15+08:00'
  notes: 已对照原文核对（图片信息查看器功能、fileowner 回显 33=www-data、getimagesize 回显宽/高/类型、读 class.php 与 chal13nge.php 源码、原题另加 hI3t.php 提示，一致）；本次核对未读取图片，仅依据正文；原文仅断言 getimagesize 存在侧信道读文件，未给出 oracle 的具体报错文本，卡中「warning 携带文件内容片段」属机制推断，已保留 medium 置信并声明无 PoC
url: /docs/web/php/open-basedir-bypass/web-php-getimagesize-sidechannel-file-read/
draft: false
kb_aliases:
- getimagesize 侧信道
- getimagesize 读文件
- 图片信息接口文件读取
- getimagesize warning 泄露文件内容
---

## 一句话结论

后端把用户可控路径直接交给 `getimagesize()`（图片信息查看器类功能），且回显宽/高/类型等结果时，可以用「该函数对非图片文件仍会尝试按图片格式解析并抛出带文件内容片段的 warning/报错」这一点当作 oracle，在无法直接读文件（被 `open_basedir`、权限或包含点限制）时逐字节推断目标源码/配置文件内容。

## 原理

- `getimagesize()` 先按文件头判定格式，再按对应解析器读结构；对不是图片的文件，它会在解析过程中读到文件的某些字节并把它并入 `Warning: getimagesize(...): ... in ...` 一类错误信息（例如把疑似格式标识、长度字段回填到报错里）。
- Web 端若把 `getimagesize()` 的返回值（或 PHP 错误输出）直接回显，攻击者就能看到「函数解析到了哪一步、读到了什么」——这就是一个把文件内容映射到回显的侧信道，而不是常规的文件读取漏洞。
- 因为不是 `file_get_contents` 式直读，常规的「禁用危险函数 / 不给读权限」思路拦不住；真正的边界是「路径可控 + 错误回显」。
- 排错向的提示（`display_errors=On`、框架 debug 模式）会显著放大这个信道；关闭错误回显后只能靠返回值的差异（宽度/高度/类型是否变化）做布尔型推断，效率低但仍在。
- 同一处代码里的 `fileowner()`（回显数字 uid，如 33=www-data）是辅助信息：确认了自己在目标上的身份，也提示后端确实对传入路径做了文件系统调用。

## 触发条件

- 存在「输入文件路径 → 输出图片信息」的功能点（`getimagesize($path)`、`fileowner($path)` 等）。
- 路径参数可控且未做目录约束，能指向 Web 目录外的文件（`../../` 或绝对路径）。
- 错误信息或函数返回值被回显（`display_errors=On`、debug 模式，或代码把 `$m[0..3]`、`$m['mime']` 打印出来）。
- 目标文件可被 Web 进程读取（`open_basedir`/权限允许）。

## 利用步骤

1. 找到功能点：表单提交图片路径后返回「宽度/高度/类型/所有者」的接口。
2. 先用已知图片确认基线回显（正常图片宽度/高度/类型稳定），再用不存在路径确认报错形态。
3. 把路径指向目标文件（先读同目录的 `class.php`、`chal13nge.php` 等源码），观察报错/返回值差异；逐步把路径推进到 `/flag`、数据库配置等高价值文件。
4. 若回显只是「无法获取图像信息」，说明错误被吞掉：改用返回值布尔差异（真/假、类型编号变化）做逐字节猜解，或用 `php://filter` 等包装器把内容转成可被解析的形态再喂给 `getimagesize()`。
5. 读到源码后继续找二次入口（如源码里被 include 的类文件、可触发 `phar://` 的文件函数）。

## PoC

```http
POST /chal13nge.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

image_path=../../../../var/www/html/class.php
```

对照基线：

```http
POST /chal13nge.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

image_path=../../../../var/www/html/uploads/normal.jpg
```

无 PoC（不同 PHP 版本的 `getimagesize()` 报错文本与包含内容不同，原文未给出可复制的完整脚本，本卡按 oracle 思路记录，confidence 定为 medium）。

## 变体与关联

- 变体：`fileowner()`/`filesize()`/`stat()` 一类文件函数同样会在报错里带路径与 errno，可组合成「存在性 + 权限 + 文件头」三态 oracle。
- 变体：错误被关闭时，用 `php://filter/convert.base64-encode/resource=...` 让内容变成 base64，再借「解析失败位置/长度」差异做推断。
- 关联：[[web-php-open-basedir-bypass]]（同目录下的 open_basedir 绕过手法，可与本卡组合突破路径限制）。
- 关联：[[web-php-deserialization-xunruicms-qrcode-getimagesize-phar-ci4-system]]（同样以 `getimagesize()` 为入口，但落点是 PHAR 反序列化）。

## 检测与防御

- 防御：不要用 `getimagesize()` 处理用户提供的路径；先把上传文件落到固定目录、用服务端生成的随机文件名，路径由服务端拼接，杜绝 `../`。
- 防御：关闭 `display_errors`，框架关闭 debug；`open_basedir` 限制到 Web 目录与上传目录。
- 检测：请求参数中出现 `../`、绝对路径、`php://` 等，且伴随 `getimagesize`/`fileowner` 相关 warning；同一接口短时间内大量不同路径请求（逐字节猜解特征）。
- 响应：确认泄露范围（哪些文件被读到）、轮换配置文件中的口令、修补路径拼接逻辑。
