---
id: web-generic-file-inclusion-download-param-source-disclosure
title: 下载接口按 file 参数原样读取：泄露联调说明、内部路由索引与 admin.php 源码
type: scenario
domain: web
path: web/generic/file-inclusion
technique: download-endpoint-raw-file-source-disclosure
tags:
- web
- php
- file-read
- source-disclosure
- information-disclosure
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:16:12+08:00'
  notes: 已对照原文核对：/download.php?file=files/notes/preview-readme.txt、route-index.txt、admin.php 分别回显联调说明、内部路由索引与 PHP 源码，且读取不执行，与卡片一致。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-download-param-source-disclosure/
draft: false
kb_aliases:
- download.php?file=
- 源码读取
- 联调说明泄露
- route-index.txt
- 内部诊断路由
- 下载接口任意文件读取
---

## 一句话结论

下载/预览接口直接把 `file` 参数拼进文件读取函数并返回原始字节时，攻击者不仅能读普通文档，还能读同目录或 Web 根下的 `.php` 源码（读取不会执行）、联调说明与内部路由索引；这些内容常泄露后台逻辑、内部接口名和后续利用入口。

## 原理

- 目标接口形如 `GET /download.php?file=files/notes/preview-readme.txt`，服务端用 `readfile()`/`file_get_contents()` 读取 `file` 指向的文件并输出。因为输出的是文件字节而不是交给 PHP 解释器执行，请求 `?file=admin.php` 会得到 PHP 源码，而不是执行结果。
- 如果 `file` 没有目录白名单、扩展名白名单或规范化校验，攻击者可以：
  - 读取同目录/相邻目录的说明文档（本题 `preview-readme.txt` 泄露“后台预览面板联调说明”和 `admin.php` 提示）；
  - 读取 `route-index.txt` 这类内部路由索引，拿到 `health`、`mailq`、`final` 等诊断别名；
  - 读取 `admin.php` 源码，直接看到双人复核的 `md5($a) == md5($b)` 逻辑，从而构造绕过。
- 本题的读取路径是相对 Web 根的正常路径（`files/notes/...`），不需要 `../`；说明漏洞不是“路径穿越”，而是“下载接口对可读文件范围没有限制”。一旦参数可拼接，还可以进一步尝试 `../`、绝对路径、`php://filter` 等变体。
- 泄露内容与后续利用强相关：说明文档给出内部诊断路由，源码给出校验逻辑，二者组合后才有 SSRF + 魔术哈希的完整链。根因是“把内部运维材料放在 Web 可读目录，并提供一个无范围限制的文件读取接口”。

## 触发条件

- 存在下载/预览/附件读取接口，`file`/`path`/`filename` 参数直接进入文件读取函数。
- 没有目录白名单、扩展名白名单、`realpath` 前缀校验或认证限制。
- Web 根或可读目录下存在源码、说明文档、路由索引、备份文件等敏感材料。
- 接口把文件内容原样返回（而不是只返回元数据/下载链接）。

## 利用步骤

1. 找到下载/预览接口，提交一个正常文件，确认返回内容与 `Content-Type`/`Content-Disposition`。
2. 尝试读取同目录说明文件，例如 `?file=files/notes/preview-readme.txt`，寻找内部接口、调试材料、清理提示。
3. 读取路由索引/配置文件，例如 `?file=files/notes/route-index.txt`，记录内部别名与路径。
4. 读取同目录 PHP 源码，例如 `?file=admin.php`，分析认证与校验逻辑；若被后缀拦截，尝试 `admin.php.bak`、`admin.php~`、`admin.php.swp`、`php://filter/convert.base64-encode/resource=admin.php`。
5. 用泄露的逻辑构造后续 payload（如 0e 魔术哈希 + `target_url` SSRF）。
6. 若参数可穿越，继续尝试 `../`、绝对路径、编码斜杠，扩大读取范围。

## PoC

```http
GET /download.php?file=files/notes/preview-readme.txt HTTP/1.1
Host: target
```

```http
GET /download.php?file=files/notes/route-index.txt HTTP/1.1
Host: target
```

```http
GET /download.php?file=admin.php HTTP/1.1
Host: target
```

返回内容为 PHP 源码（示意）：

```php
<?php
$tokenA = (string)($_POST['token_a'] ?? '');
$tokenB = (string)($_POST['token_b'] ?? '');
if ($tokenA === $tokenB) { exit('两份输入不能完全相同'); }
$h1 = md5($tokenA); $h2 = md5($tokenB);
if ($h1 == $h2 && $h1 !== $h2) { echo "校验通过"; }
```

## 变体与关联

- **读取范围变体**：同目录相对路径、`../` 穿越、绝对路径、`php://filter`、`file://`、软链接。
- **文件类型变体**：`.php` 源码、`.bak`/`.swp`/`~` 备份、`.env`、`config.php`、日志、路由索引、README/联调说明。
- **接口变体**：下载、预览、附件查看、模板读取、日志查看、导出功能。
- **关联**：[[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]（下载接口 `fileName` 路径穿越）；[[web-generic-file-inclusion-mes-download-filename-path]]（下载接口直接拼路径）；[[web-generic-auth-php-md5-magic-hash-pair-double-verify]]（本题源码泄露后的校验绕过）；[[web-generic-ssrf-preview-panel-target-url-localhost]]（本题路由索引泄露后的 SSRF）。
- **边界**：接口使用固定文件 ID 映射、目录白名单、扩展名白名单、`realpath` 前缀校验，或源码文件不在可读目录时，本路径失效。

## 检测与防御

- **检测**：`file`/`path`/`filename` 参数出现 `admin.php`、`.bak`、`php://`、`../`、绝对路径；下载接口返回 `text/plain` 的 PHP 源码；同一 IP 连续读取说明/索引/源码文件。
- **防御**：下载接口使用文件 ID 到固定路径的映射，不接受任意路径；目录与扩展名双白名单；`realpath` 后校验前缀；源码、备份、说明文件移出 Web 根。
- **加固**：下载接口加认证与权限校验；禁止 Web 服务器把 `.bak`/`.swp`/`.env` 当作可下载文件；定期扫描 Web 根下的敏感文件。
