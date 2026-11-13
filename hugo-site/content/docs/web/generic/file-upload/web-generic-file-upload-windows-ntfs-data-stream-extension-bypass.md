---
id: web-generic-file-upload-windows-ntfs-data-stream-extension-bypass
title: Windows NTFS ::$data 后缀绕过文件上传黑名单：校验看到 php::$data，访问 shell.php 仍被解析
type: scenario
domain: web
path: web/generic/file-upload
technique: windows-ntfs-ads-filename-extension-bypass
tags:
- file-upload
- windows
- ntfs
- ads
- blacklist
- php
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V513
  verified_at: '2026-11-11T11:22:41+08:00'
  notes: 已对照原文与26张截图逐张核对：图09 tiger.php 被后缀黑名单拦截、图07/08 phpinfo.png 被文件头拦截，图15 filename=phpinfo.php::$data（jpeg 文件头+php 代码）上传成功，图16 带 ::$data 访问 403，图17 去 ::$data 访问在目标 PHP 7.4.19 上执行；原理/触发条件与原文一致。验证中修正两处：PoC 原写虚构端点 PUT /admin/signature%0d（原文 Burp 截图请求行被裁掉、不可见），改为与截图一致的 multipart 字段（_token、_method=PUT、signature）通用接口占位；环境描述澄清为本机 PHP 7.3.4 验证图片马解析、目标 PHP 7.4.19 上 ::$data 落地执行。dedup：库内 web-java-component-mcms-fileaction-upload-blacklist-jspx-ads 也含 ::$DATA 手法，但那是 MCMS 未授权上传的具体组件链，本卡是通用 Windows NTFS ADS 文件名规范化绕过（PHP/Apache+文件头双校验），非同一条利用链，并列保留；其余候选（zip NUL 截断、尾部空格、替代后缀）均不同链。未设 affected_versions（原文未给版本，Server 2016/PHP 7.4 仅为环境）
url: /docs/web/generic/file-upload/web-generic-file-upload-windows-ntfs-data-stream-extension-bypass/
draft: false
kb_aliases:
- ::$data 上传绕过
- NTFS 数据流后缀绕过
- php::$data
- Windows 文件上传黑名单绕过
- filename ADS bypass
---

## 一句话结论

Windows + NTFS 上的文件上传点若只用"点号之后的扩展名"做黑名单比较，可上传 `filename="shell.php::$data"`：校验逻辑把后缀视为 `php::$data`（不等于 `php`）而放行，文件实际保存为 `shell.php` 的默认数据流；随后访问不带 `::$data` 的 `/uploads/shell.php`，容器仍把同一文件当作 PHP 解析执行，从而 getshell。

## 原理

- NTFS 支持备用数据流（ADS）：`file.php::$data` 表示 `file.php` 的默认未命名数据流（`:stream` 则指定命名流）。Windows 的文件 API 打开 `file.php::$data` 时，实际访问的就是 `file.php` 本身的内容。
- 上传校验通常把 `filename` 字符串按最后一个 `.` 切分取后缀再与黑名单比较（如 `php`、`php5`）。`shell.php::$data` 的后缀字符串是 `php::$data`（或整个文件名的一部分），不等于黑名单里的 `php`，因此绕过；部分实现若只检查 `strstr($name, '.php')` 则反而会命中，需要按实际校验逻辑构造。
- 文件落盘后，Web 服务器收到的请求路径 `shell.php` 对应的正是这个文件；请求 `shell.php::$data` 可能被服务器拒绝（实例中返回 403），但直接请求 `shell.php` 可正常读取默认流并交给 PHP 解析。
- 该技巧依赖 Windows/NTFS 与中间件的路径处理；Linux 上 `::$data` 只是普通文件名字符，不成立。实例目标为 Apache + PHP 7.4.19 on Windows Server 2016（上传目录可解析 PHP）；作者本机 PHP 7.3.4 仅用于验证图片马可解析。

## 触发条件

- 目标为 Windows 服务器，上传目录位于 NTFS 卷。
- 上传校验为文件名后缀黑名单（或白名单不含 `::$data` 处理），且未对文件名做 `::$data`、尾部点/空格的规范化。
- Web 容器会解析同名 `shell.php`（上传目录可执行，或存在解析配置）。
- 目标已有上传接口与可访问的上传路径（实例中为后台签名上传点，返回 `.../uploads/signature/<id>.png` 形式的 URL）。

## 利用步骤

1. 先判断校验组合：用 `tiger.phpabcde` 测试是否黑名单（非白名单后缀也放行）；再用「PNG 文件头 + php 代码 + .png 后缀」测试是否校验文件头；用「php 文件 + .png 后缀」测试文件头是否必需。实例结论为"后缀黑名单 + 文件头校验"。
2. 制作图片马：`copy small.jpg /b + phpinfo.php /a shell.jpg`（小图优先，避免图片脏数据破坏 PHP 解析）。
3. 将图片马以 `filename="shell.php::$data"`（multipart 的 filename 字段）上传，Content-Type 可写 `image/jpeg`。
4. 上传成功后请求 `shell.php::$data` 得到 403 时，改为请求 `/uploads/signature/shell.php`（去掉 `::$data`），即可看到 PHP 执行结果。
5. 用该 shell 上传功能更完整的 webshell（注意见关联卡：Windows Defender 可能对 webshell 命令执行做进程链查杀）。

## PoC

```http
POST /<后台签名上传接口> HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX

------WebKitFormBoundaryX
Content-Disposition: form-data; name="_token"

<后台会话 CSRF token>
------WebKitFormBoundaryX
Content-Disposition: form-data; name="_method"

PUT
------WebKitFormBoundaryX
Content-Disposition: form-data; name="signature"; filename="shell.php::$data"
Content-Type: image/jpeg

<JPEG 文件头 + PHP 代码>
------WebKitFormBoundaryX--
```

```
# 访问（部分服务器对 ::$data 直接 403）
GET /uploads/signature/1709020291.php::$data  -> 403 Forbidden
# 去掉 ::$data 后解析
GET /uploads/signature/1709020291.php         -> PHP 代码执行
```

## 变体与关联

- 变体：Windows 文件名规范化类绕过——尾部空格 `shell.php `、尾部点 `shell.php.`、`shell.ph p`、大小写 `shell.Php`；`::$data` 可与这些组合使用（`shell.php::$data` 在某些过滤器下等价于 `shell.php`）。
- 变体：IIS 下的分号路径参数、`%20`/`%2e` 截断；Apache 的 `AddType`/`.htaccess` 解析配置滥用。
- 关联：[[web-generic-file-upload-extension-blacklist-trailing-space]]（尾部空格黑名单绕过）；[[web-generic-file-upload-magic-byte-gif-prefix-bypass]]（文件头校验绕过）；[[web-generic-file-upload-defender-process-chain-webshell-command-block]]（同篇的后续：WebShell 命令执行被 Defender 阻断）。
- 限制：仅 Windows/NTFS；若上传端对文件名做了 `::$data` 移除或使用文件头+重编码（如 GD 重绘）该链失效。

## 检测与防御

- 上传端：对文件名做 Windows 规范化（去除 `::$data`、尾部点与空格、控制字符），并使用白名单扩展名；不要只取最后一个点做比较。
- 文件头校验应配合图片重编码（GD/ImageMagick）破坏嵌入脚本，而不是只读魔数。
- 服务器：上传目录禁止脚本解析（`php_admin_flag engine off`、IIS 处理程序映射限制），以只读/独立域名提供静态文件。
- 检测：Web 日志中出现 `::$data`、`%3A%3A%24data` 文件名；上传目录内出现可执行的图片同名文件。
