---
id: web-generic-file-inclusion-icpas-getjson-path-traversal-read
title: ICPAS php/getjson.php jsondata[filename] 路径穿越：读取 Web 目录任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: icpas-getjson-path-traversal-read
aliases:
- ICPAS getjson 任意文件读取
- IP 网络对讲广播系统文件读取
- jsondata[filename] 路径穿越
- getjson.php LFI
tags:
- php
- arbitrary-file-read
- path-traversal
- file-inclusion
- icpas
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T07:07:27+08:00'
  notes: 已对照原文 AI 审计表（getjson.php 任意读取，PoC jsondata[filename]=..\php\test.php）核对；原文无函数体与回显验证，confidence low 如实标注；与 uploadjson 写原语不同端点不同行为，dup-scan 裁决为并列保留。
---

## 一句话结论

ICPAS 的 `php/getjson.php` 直接使用请求中的 `jsondata[filename]` 读取文件，未做路径规范化或基准目录校验，可用 `..\php\test.php` 之类的相对路径穿越读取 Web 目录及相邻目录中的任意文件，进而获取源码、配置或凭据。

## 原理

- 原文的 AI 审计表将 `php/getjson.php` 列为“任意读取（路径穿越）”：`filename` 可含 `..`，PoC 为 `jsondata[filename]=..\php\test.php`。
- 机理与常见 PHP 文件读取一致：接口把用户传入的 filename 拼接到固定目录（或直接作为路径）后交给 `file_get_contents`/`fopen`/`readfile` 等函数；因为没有 `basename()`、`realpath()` 基准校验或 `..` 过滤，`../` 会跳出预期目录。
- Windows 下使用反斜杠 `..\`，Linux 下使用 `../`；可读取 `php/*.php` 源码、`config.ini`/数据库配置、日志等，为后续登录绕过或 RCE 提供信息。
- 注意：原文只给出审计表与 PoC，没有展示 `getjson.php` 的函数体，具体读取函数与返回方式需在目标版本中确认；因此置信度标 low。

## 触发条件

- `php/getjson.php` 可访问，接受 `jsondata[filename]` 参数。
- Web 进程对目标文件有读权限（Web 目录内文件通常可读）。
- 目标路径已知或可枚举（如 `..\php\test.php`、`..\config.ini`、Web 根下的日志）。

## 利用步骤

1. 访问/抓取 `getjson.php` 的正常请求，确认参数名与响应格式。
2. 将 `jsondata[filename]` 设为 `..\php\test.php`，观察是否返回源码内容。
3. 按需调整 `..\` 层级读取 `config.ini`、数据库配置、日志、其他 PHP 源码。
4. 用泄露的配置/凭据衔接后台登录或数据库访问；若读到源码，可进一步寻找上传/命令执行点。

## PoC

```bash
curl -s -X POST 'http://target/php/getjson.php' \
  --data-urlencode 'jsondata[filename]=..\php\test.php'

# Linux 目标
curl -s -X POST 'http://target/php/getjson.php' \
  --data-urlencode 'jsondata[filename]=../../etc/passwd'
```

## 变体与关联

- **编码绕过**：若后续版本加了 `..` 过滤，可尝试 URL 编码、双重编码、`....//`、反斜杠/正斜杠混用。
- **同系统读取点**：`php/exportrecord.php` 的 `downname` 也被原文列为后缀弱校验的任意下载，可与本卡互补。
- **关联**：读取 `config.ini` 可获得 AppServer 端口/配置；读取源码可定位 `ping.php`、`addscenedata.php`、`uploadjson.php` 等 RCE 点。

## 检测与防御

- **修复**：使用 `basename()` 只取文件名；用 `realpath()` 校验目标位于固定基准目录内；扩展名/文件类型白名单；禁止返回任意路径内容。
- **加固**：敏感配置移出 Web 根；Web 进程最小权限；关闭目录列表。
- **检测**：监控 `getjson.php` 请求中的 `..`、绝对路径、`php://` 等特征；审计异常文件读取与大量源码访问。
