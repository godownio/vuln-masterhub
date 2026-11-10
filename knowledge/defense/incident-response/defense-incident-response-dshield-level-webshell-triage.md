---
id: defense-incident-response-dshield-level-webshell-triage
title: D盾分级扫描 Web 根目录：按级别定位 eval/已知后门与日志残留
type: scenario
domain: defense
path: defense/incident-response
technique: dshield-level-webshell-root-triage
aliases:
- D盾查杀 webshell
- D盾分级扫描
- Web 根目录后门排查
- Eval后门 级别4
- 已知后门 级别5
- runtime 日志后门
tags:
- incident-response
- webshell
- dshield
- php
- web-root
- webshell-scan
- eval-backdoor
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V314
  verified_at: '2026-11-08T13:52:52+08:00'
  notes: 拆分后复核：对照图15 D盾扫描结果（4761文件/6可疑，级别5 .func.php，级别4 上传目录与runtime日志）与原文核对，单一原子、独立触发条件与PoC成立
---

## 一句话结论

用 D盾（D盾_Web查杀）对网站根目录做分级扫描，可以把排查面从数千个文件快速收敛到少数可疑文件：`phpinfo` 探针通常为级别 1，Eval 后门/内藏后门多为级别 4，签名命中的已知后门为级别 5；再按级别复核上传目录与 `runtime/log` 中的 PHP 代码。

## 原理

- **分级来自静态特征匹配**：D盾对 PHP/ASP/JSP 做语法与特征匹配，识别 `eval`、`assert`、回调执行、已知后门片段等，按可疑程度给出级别（数字越大越危险）。
- **后门落点有规律**：`uploads/`、`runtime/`、`public/` 等既可写又可能被 Web 访问的目录是上传/写入型后门的常见位置；日志文件中出现 `<?php`/`eval` 说明日志可能被当作写入载体或被包含利用。
- **级别只是排序，不是定性**：级别 1 的 `phpinfo.php` 仍是信息泄露入口；级别 4/5 的文件必须结合源码、修改时间（mtime）与访问日志确认，否则容易误删业务文件或漏掉同批投放的马。
- **隐藏点文件也参与扫描**：以点开头的文件（如 controller 目录下的 `.func.php`）不会被常规目录列表展示，但 D盾仍可命中并将其标为高级别。
- **本题扫描证据**：扫描 4761 个文件，发现 6 个可疑文件，用时 11.50 秒；`hazel.php` 为级别 1（phpinfo），`application/<随机目录>/controller/.func.php` 为级别 5（已知后门，内容是类封装 + `array_map(assert, $_POST)` 回调马），`public/uploads/20210427/1.php`、`god.php` 为级别 4（Eval 后门），`runtime/log/202104/...` 两个日志为级别 4（含 Eval 后门）。

## 触发条件

- 能取得网站根目录：打包下载、磁盘镜像、离线副本或主机在线排查。
- 有 D盾或等价的静态 webshell 扫描能力（可运行 Windows 工具或使用 YARA/特征规则）。
- Web 目录存在上传、缓存、日志等可写路径，或攻击者已留下 webshell/隐藏点文件。

## 利用步骤

1. **固定证据**：对 Web 根目录打包并计算哈希，记录获取时间、主机名与目录来源；先不要删除任何文件。
2. **D盾扫描**：选择网站根目录，记录扫描文件数、可疑文件数、每个文件的路径/级别/说明。
3. **按级别复核**：先看级别 5，再看级别 4；打开源码确认 sink（`eval`/`assert`/`array_map`/回调/可变变量），并核对 mtime 与业务基线、访问日志。
4. **检查可写目录**：重点看 `uploads/`、`runtime/log/` 下新增的 `.php` 与日志中夹带的 PHP 代码，结合 access log 定位上传/写入请求。
5. **处置**：隔离样本与相关日志，删除后门，修复上传/写入/包含点，重置 Web 应用与数据库凭据，并排查同目录其他被篡改文件。

## PoC

D盾扫描结果（本题截图）：

```text
检测文件数: 4761  发现可疑文件: 6  用时: 11.50秒
hazel.php                                    级别 1  phpinfo
application/<随机目录>/controller/.func.php  级别 5  已知后门（array_map(assert,$_POST) 回调马）
public/uploads/20210427/1.php                级别 4  Eval后门
public/uploads/20210427/god.php              级别 4  (内藏)Eval后门
runtime/log/202104/...-25.log                级别 4  Eval后门
runtime/log/202104/21.log                    级别 4  (内藏)Eval后门
```

无法运行 D盾时可用命令行做交叉粗筛（只做排序，不替代分级扫描）：

```bash
# 可写目录下的 PHP 文件按 mtime 倒序
find /www/html/public/uploads /www/html/runtime -type f -name '*.php' \
  -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort -r

# 在 Web 根目录粗筛 eval/assert/回调 sink 与 PHP 起始标记
grep -RInE 'eval[[:space:]]*\(|assert[[:space:]]*\(|array_map[[:space:]]*\(|create_function[[:space:]]*\(|<\?php' \
  /www/html --include='*.php' --include='*.log' | head -50
```

## 变体与关联

- **扫描器变体**：河马、长亭、牧云或自建 YARA 规则；不同引擎对混淆 webshell 的命中率差异大，建议多引擎交叉。
- **后门形态**：上传目录直接落 `.php`；向日志/缓存文件写马；用点文件（如 `.func.php`）逃避常规枚举；用 `.user.ini`、`.htaccess` 改变 PHP 执行行为。
- 关联：[[web-php-rce-class-array-map-assert-webshell]]（本题级别 5 的类封装回调马形态）、[[defense-incident-response-hidden-dotfile-base64-decode]]（同一 Web 根目录的隐藏 dotfile 排查）、[[defense-incident-response-docker-tomcat-mining-triage]]（WebShell 到挖矿的后续处置）。

## 检测与防御

- **检测**：对 Web 根目录做周期性 webshell 扫描与文件完整性基线比对；监控 `uploads/`、`runtime/` 下新增 `.php` 文件以及点文件的新增/修改。
- **防御**：上传目录禁止 PHP 解析（独立域名/存储或 `php_admin_flag engine off`）；Web 进程最小权限；日志目录不可被 Web 直接访问；关闭 `phpinfo` 等调试页面。
- **响应**：确认后门后先隔离样本与访问日志再删除；排查同目录其他文件、计划任务与账户，轮换 Web 应用与数据库凭据。
