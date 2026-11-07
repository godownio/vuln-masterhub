---
id: web-generic-file-upload-blacklist-double-write-bypass
title: 黑名单关键字被替换为空时，双写 php 使过滤后恢复可解析后缀
type: scenario
domain: web
path: web/generic/file-upload
technique: blacklist-double-write
aliases:
- 双写绕过
- pphphp 上传
- str_ireplace 黑名单绕过
- 关键字替换为空
- upload-labs 双写
tags:
- web
- file-upload
- blacklist
- double-write
- bypass
- php
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:40:23+08:00'
  notes: 已对照原文与图33/34核对：str_ireplace 将 php 等替换为空，上传 shell.pphphp 后响应回显 ./upload/shell.php。双写还原逻辑正确。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

后端把黑名单关键字用 `str_ireplace` 替换为空（而不是直接拒绝），上传 `shell.pphphp` 这类双写文件名，过滤后恰好还原成 `shell.php`，从而绕过黑名单落盘。

## 原理

- 代码形式：`$blacklist = ["php","php5","php4","php3","phtml","pht","htaccess"]; $name = str_ireplace($blacklist, "", $name); move_uploaded_file($tmp, UPLOAD_PATH.$name);`
- 过滤是“删除命中子串”而不是“命中即拒绝”。删除操作只做一次扫描，不会递归删除新拼接出的关键字。
- 在 `shell.pphphp` 中，`php` 子串出现的位置被删除后，剩余字符重新拼接可能形成一个新的 `php`：例如 `pphphp` 删除中间的 `php` 后留下 `php`，最终文件名为 `shell.php`。
- 因此“过滤后的字符串”与“被检查的字符串”不是同一个值：白名单/黑名单检查发生在替换前（或替换结果恰好被当成非脚本），而落盘使用替换后的名字。

## 触发条件

- 黑名单采用“替换为空/删除关键字”的实现，且只执行一次。
- 替换后仍保留或能重组出可被中间件解析的脚本后缀。
- 服务端没有对最终文件名再做一次后缀白名单或内容检测。

## 利用步骤

1. 上传 `shel.php`，观察返回中的落盘名变成 `shel`（关键字被删），确认是替换为空型过滤。
2. 根据被删关键字构造双写文件名，使删除一次后正好得到目标后缀。
3. 上传双写文件名，内容为一句话木马。
4. 访问替换后的实际路径，确认脚本执行。

## PoC

```bash
# 文件内容
printf '<?php phpinfo(); ?>' > shell.pphphp
# 上传
curl -s -X POST 'http://target/upload.php' \
  -F 'file=@shell.pphphp;filename=shell.pphphp;type=text/php' \
  -F 'submit=Upload'
```

后端 `str_ireplace("php", "", "shell.pphphp")` 的结果预期为 `shell.php`；访问 `http://target/upload/shell.php` 验证。

## 变体与关联

- 变体：黑名单包含多个后缀时，可组合双写（如 `pphphp`、`phphpp`）或用大小写混写（`PHP`）；若过滤是正则单次替换，也可利用重叠匹配。
- 关联：[[web-generic-file-upload-apache-alternate-php-extension]]（黑名单漏掉其他可解析后缀）；[[web-generic-file-upload-null-byte-path-truncation]]（同为“检查值≠落盘值”的经典形态）。
- 边界：若后端在替换后重新做严格后缀白名单，或直接拒绝命中项而非删除，本手法不成立。

## 检测与防御

- 检测：上传文件名中出现重复脚本关键字（`pphphp`、`phphpp`）；落盘文件名与请求文件名不一致且被删除若干字符；上传目录出现脚本文件。
- 防御：不要用“替换为空”实现黑名单；使用扩展名白名单并直接拒绝；对最终落盘名再做一次规范化与白名单校验；上传目录禁止脚本解析。
