---
id: web-php-open-basedir-bypass-curl-protocols-all
title: PHP 8.3 curl 扩展 open_basedir 绕过：CURLOPT_PROTOCOLS_STR 设为 all 读取任意文件
type: scenario
domain: web
path: web/php/open-basedir-bypass
technique: php-curl-open-basedir-bypass
aliases:
- curl open_basedir bypass
- CURLOPT_PROTOCOLS_STR all
- GH-16802
- curl file 协议绕过 open_basedir
- PHP 8.3 open_basedir bypass
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- php
- curl
- libcurl
- open_basedir
- bypass
- arbitrary-file-read
- protocol-restriction
cve: []
affected_versions: PHP 8.3（经 curl 扩展；PHP 8.5 已修复）
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:50:10+08:00'
  notes: 已对照原文与截图核对 CURLOPT_PROTOCOLS_STR=all 绕过 file 检查、Windows 读取 D:/flag.txt 与修复 commit；未验证点：未在本机复现，依赖原文请求/响应截图
---

## 一句话结论

PHP 8.3 的 curl 扩展在设置 `open_basedir` 时只检查 `CURLOPT_PROTOCOLS_STR` 字符串中是否含 `file`，而 libcurl 支持特殊值 `all`；把协议限制设为 `all` 就能让 `file://` 通过检查，读取 `open_basedir` 之外的任意本地文件。

## 原理

- PHP 为了在 `open_basedir` 生效时阻止 curl 读取本地文件，在 `ext/curl/interface.c` 处理 `CURLOPT_PROTOCOLS` / `CURLOPT_PROTOCOLS_STR` 时做字符串匹配：只要传入值里出现 `file` 子串就直接拒绝。
- 该检查把“协议限制”当成普通字符串比较，而不是按 libcurl 的语义解析。libcurl 接受 `CURLOPT_PROTOCOLS_STR` 的特殊值 `all`（以及 `+`/`-` 前缀的组合写法），表示允许所有协议；字符串 `all` 本身不含 `file`，因此 PHP 的检查放行。
- 放行后 libcurl 按 `all` 解析协议白名单，`file://` 被允许，curl 通过本地文件协议读取内容并返回给 PHP。整个过程中不经过 PHP 文件函数，`open_basedir` 自然不生效。
- 后续修复把 `all` 也加入拒绝条件（并做大小写不敏感匹配），因此 PHP 8.5 起该手法失效。

## 触发条件

- PHP 8.3（含 curl 扩展），`open_basedir` 已设置；
- libcurl 版本支持 `CURLOPT_PROTOCOLS_STR`（libcurl >= 7.85）；
- 攻击者已能执行任意 PHP 代码（webshell、文件包含、模板注入等）；
- 目标文件对 Web 进程可读。

## 利用步骤

1. 用 `phpinfo()` 或 `extension_loaded('curl')` 确认 curl 扩展可用，并读取 `open_basedir`。
2. 用 `file://` 指向目标文件，初始化 curl。
3. 设置 `CURLOPT_PROTOCOLS_STR` 为 `all`，执行请求。
4. 从返回值读取文件内容；可批量读取 `/etc/passwd`、应用配置、密钥等。

## PoC

```php
<?php
$ch = curl_init("file:///etc/passwd");
curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
$data = curl_exec($ch);
echo $data;
```

Windows 目标同样适用，把路径换成 `file:///D:/flag.txt` 即可。

## 变体与关联

- 同一 curl 扩展还可通过 `CURLOPT_SSLENGINE` 加载恶意共享库实现 RCE，见独立卡片。
- 与 `glob://`、`symlink` 等经典 `open_basedir` 绕过并列，属于“扩展自带文件访问能力绕过 PHP 层校验”的一类。
- 若 `CURLOPT_PROTOCOLS_STR` 不可用，可尝试旧常量 `CURLOPT_PROTOCOLS` 的等价位掩码写法，但需按 libcurl 版本确认。

## 检测与防御

- 升级到已修复版本（PHP 8.5+）；无法升级时禁用 curl 扩展，或在业务层禁止 `curl_setopt` 设置协议为 `all`。
- 代码审计关注 `CURLOPT_PROTOCOLS_STR` 被赋值为 `all`、`+file` 等写法，以及 URL 可控的 `curl_init`。
- 运行时监控 Web 进程对 `file://` 目标（尤其 `/etc/`、密钥目录）的读取。
- 仍应在 OS 层做隔离，不要单独依赖 `open_basedir`。
