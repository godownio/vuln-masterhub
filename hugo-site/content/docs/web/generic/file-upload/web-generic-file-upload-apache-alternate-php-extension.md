---
id: web-generic-file-upload-apache-alternate-php-extension
title: 黑名单漏掉 Apache 默认 PHP 解析后缀，phtml/pht/php3 可直接执行
type: scenario
domain: web
path: web/generic/file-upload
technique: alternate-extension-blacklist-gap
tags:
- web
- file-upload
- apache
- blacklist
- extension
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
  verified_at: '2026-11-05T00:40:26+08:00'
  notes: 已对照原文与图46/47/54核对：Burp Intruder 显示 phtml/php3/php4/php5/pht 均上传成功，访问确认可解析；Apache 默认将多后缀交给 PHP 的说明与原文截图一致。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-apache-alternate-php-extension/
draft: false
kb_aliases:
- 黑名单绕过
- phtml 上传
- pht 解析
- php3 php4 php5 后缀
- Apache 多后缀解析
---

## 一句话结论

后端黑名单只列了 `php`、`jsp`、`asp` 等常见后缀，但 Apache + PHP 默认把 `phtml`、`pht`、`php3`、`php4`、`php5` 等也交给 PHP 解释器；上传这些未列入黑名单的后缀即可执行。

## 原理

- 黑名单的安全假设是“枚举完所有可执行后缀”。但可执行后缀集合不由应用决定，而由 Web 服务器/PHP 模块的 MIME 与 handler 配置决定。
- Apache 的 `mod_php`/`SetHandler application/x-httpd-php` 以及 `/etc/mime.types` 中常把 `phtml pht php php3 php4 php5` 关联到 PHP handler；这些后缀在默认环境下都会被解析。
- 应用黑名单只拦截了其中一部分，`in_array($ext, $blacklist)` 未命中 `phtml` 等就放行并原样保存。
- 落盘后 Apache 仍按后缀选择 PHP handler，文件内容中的 PHP 代码被执行；黑名单的“漏项”直接变成可执行入口。

## 触发条件

- 目标为 Apache + PHP（mod_php 或等效 handler 配置），且默认/配置中存在多个 PHP 后缀映射。
- 上传接口使用有限黑名单，未包含 `phtml`、`pht`、`php3`、`php4`、`php5` 等。
- 上传目录可访问，且没有额外的内容检测。

## 利用步骤

1. 用 Burp Intruder 对上传文件名后缀做字典 fuzz：`php, php3, php4, php5, phtml, pht, pHp` 等。
2. 观察响应状态/长度，筛出能成功上传的后缀。
3. 逐个访问上传后的文件，确认哪些后缀真正被 PHP 解析（返回 `phpinfo` 等）。
4. 用可解析的后缀上传一句话木马并连接。

## PoC

```bash
printf '<?php phpinfo(); ?>' > shell.phtml
curl -s -X POST 'http://target/upload.php' \
  -F 'file=@shell.phtml;filename=shell.phtml;type=text/php' \
  -F 'submit=Upload'
curl -s 'http://target/upload/shell.phtml'
```

可在服务器侧核对映射：

```bash
grep -r "application/x-httpd-php" /etc/apache2 /etc/mime.types
```

输出中通常能看到 `phtml pht php php3 php4 php5` 等后缀。

## 变体与关联

- 变体：大小写混写（`.PHP`、`.PhP`）；若黑名单用 `pathinfo` 取最后一段，可尝试多点后缀；Apache 配置含 `AddHandler` 时还可能解析 `.php5`、`.phtml`。
- 关联：[[web-generic-file-upload-htaccess-handler-override]]（主动改配置扩大解析范围）；[[web-generic-file-upload-blacklist-double-write-bypass]]（同属黑名单实现缺陷）。
- 边界：若服务器只把 `.php` 映射到 PHP，或上传目录 `RemoveHandler` 了所有脚本，本手法不成立。

## 检测与防御

- 检测：上传目录出现 `phtml`、`pht`、`php3/4/5` 等文件；请求文件名后缀在短时间被批量枚举；这些文件被 Web 访问。
- 防御：改用扩展名白名单（只允许业务图片类型）；不要依赖黑名单；上传目录禁止脚本解析；删除/收敛 Apache 中多余的 PHP 后缀映射。
