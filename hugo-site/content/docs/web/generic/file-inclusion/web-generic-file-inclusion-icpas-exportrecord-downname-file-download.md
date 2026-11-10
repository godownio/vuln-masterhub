---
id: web-generic-file-inclusion-icpas-exportrecord-downname-file-download
title: ICPAS php/exportrecord.php downname 任意文件下载：双重 URL 解码后直接 fopen/fread 流式输出
type: scenario
domain: web
path: web/generic/file-inclusion
technique: icpas-exportrecord-downname-arbitrary-file-download
tags:
- php
- arbitrary-file-read
- file-download
- path-traversal
- icpas
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:22:46+08:00'
  notes: 已对照原文图05/06核对；downname 经 rawurldecode(urlencode(urldecode())) 后 fopen/fread 流式输出，无 basename/realpath，任意文件下载成立；原文未给版本，PoC 路径为构造性示例
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-icpas-exportrecord-downname-file-download/
draft: false
kb_aliases:
- ICPAS exportrecord 任意文件读取
- IP 网络对讲广播系统文件下载
- downname 参数文件读取
- exportrecord.php fopen fread
---

## 一句话结论

ICPAS 的 `php/exportrecord.php` 在收到 `downname` 参数时，先做 `rawurldecode(urlencode(urldecode(...)))` 处理并把反斜杠转成斜杠，然后直接把结果交给 `file_exists`/`fopen`/`fread` 并加上 `Content-Disposition: attachment` 输出；没有任何 basename、realpath 或基准目录校验，攻击者用 `../` 或绝对路径即可下载 PHP 源码、配置文件、日志等任意文件。

## 原理

- 代码入口是 `if (isset($_GET['downname']))`；`$_GET['downname']` 经 `rawurldecode(urlencode(urldecode($x)))` 处理。该表达式先解码一次、再编码、再以 raw 规则解码，净效果接近一次 `urldecode`，但中间的 encode/decode 往返可改变 `%25`、`%2f` 等序列的表现，常被用来绕过只检查原始字符串的 WAF/过滤。
- 非 Windows 分支额外执行 `str_replace("\\", "/", $recFile)`，把 Windows 风格反斜杠归一化；Windows 分支保留原样。两种风格路径都能用。
- 之后 `if (!file_exists($recFile))` 仅检查存在性，不限制目录；存在则 `fopen($recFile, "r")`、`filesize`、按 8192 字节块 `fread`，并以 `Content-type: application/octet-stream`、`Accept-Ranges: bytes`、`Content-Disposition: attachment; filename=<basename>` 输出。
- 由于路径来自 GET 参数且没有 `basename()`/`realpath()` 与允许目录比对，`../` 可跳出 `php/` 目录；PHP 进程可读的任意文件（web 配置、数据库配置、`/etc/passwd`、日志）都能被下载。
- 这是一种“参数直达文件路径”的经典任意文件读取，不需要文件包含的执行条件，也不能直接 RCE，但可泄露源码与凭据，常与上传/命令执行漏洞组合。

## 触发条件

- 目标为 ICPAS（IP 网络对讲广播系统）且 `php/exportrecord.php` 可访问（是否需要登录取决于部署，原文未展开）。
- Web 进程对目标文件有读权限。
- 请求能带上 `downname` 参数；路径可为相对或绝对。

## 利用步骤

1. 探测 `php/exportrecord.php?downname=<路径>`，先用 `../` 相对路径读同目录源码确认可读。
2. 读取 Web 配置/数据库配置（如 `config.ini`、`php/*.php`）获取凭据。
3. Windows 目标用 `..\..\` 反斜杠路径；Linux 目标用 `../../`。
4. 对含特殊字符的路径做 URL 编码；若被 WAF 拦，利用代码的 decode/encode 往返尝试不同的 `%25`/`%2f` 编码层级。
5. 结合其他漏洞（上传、命令注入）扩大影响。

## PoC

```http
GET /php/exportrecord.php?downname=../../config.ini HTTP/1.1
Host: target
```

```http
GET /php/exportrecord.php?downname=..%5c..%5cphp%5cconfig.php HTTP/1.1
Host: target
```

## 变体与关联

- 变体：同系统的 `php/getjson.php` 也有 `jsondata[filename]` 路径穿越读取（见关联卡），但返回方式与参数不同。
- 变体：若 WAF 对 `../` 拦截，使用双重编码、反斜杠、绝对路径、`....//` 等变体；代码内部的 `urldecode` 会帮助还原。
- 关联：[[web-generic-file-inclusion-icpas-getjson-path-traversal-read]]（同产品另一处任意文件读取）。
- 关联：[[web-generic-file-upload-icpas-addmediadata-fullpath-upload-arbitrary-write]]（读源码拿凭据后可配合任意写）。

## 检测与防御

- 检测：`exportrecord.php` 的 `downname` 参数含 `..`、`%2e%2e`、`%5c`、绝对路径或敏感文件名；响应出现 `application/octet-stream` + `Content-Disposition` 下载异常文件。
- 检测：Web 日志中同一 IP 连续请求 `exportrecord.php` 读取不同路径；异常文件读取审计（auditd）。
- 防御：`downname` 只接受白名单文件名，使用 `basename()` + `realpath()` 并校验前缀在允许目录；禁用绝对路径与 `..`；最小权限运行 Web 进程；升级修复版本。
