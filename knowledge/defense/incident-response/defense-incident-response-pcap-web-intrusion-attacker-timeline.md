---
id: defense-incident-response-pcap-web-intrusion-attacker-timeline
title: Wireshark 分协议复盘 Web 入侵：协议分级/会话统计定位攻击者，再按 HTTP、1433、3389 还原时间线
type: scenario
domain: defense
path: defense/incident-response
technique: pcap-web-intrusion-attacker-timeline
aliases:
- pcap 入侵分析
- Wireshark 溯源
- 协议分级统计
- 会话统计定位攻击者
- 流量时间线还原
- 端口扫描识别
tags:
- incident-response
- forensics
- traffic-analysis
- wireshark
- pcap
- web-intrusion
- rdp
- mssql
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-07T23:22:40+08:00'
  notes: 已对照原文核对：协议分级HTTP约79.2%字节、Conversations top talker、535-193656端口扫描与开放Web端口27689、http与ip.addr==192.168.78.1&&http定位攻击者、目录fuzz/web.config.bak口令/后台登录/上传ASPNET/蚁剑webshell、1433 TDS与3389 RDP时间线均与img01-54一致；卡为单一pcap复盘流程，各步骤属同一方法的工具操作，不拆分。未复跑原文pcap。
---

## 一句话结论

面对一份来源不明的全量 pcap，先看 `Statistics → Protocol Hierarchy` 的协议占比（HTTP 占绝对多数通常意味着 Web 入侵），再用 `Conversations` 找 top talker 与扫描源，用 SYN 包识别端口扫描并定位开放 Web 端口，随后用 `http` 与 `ip.addr == <可疑IP> && http` 确认攻击者、梳理敏感请求与响应，最后按 `tcp.port == 1433`、`tcp.port == 3389` 复盘数据库与 RDP 阶段，就能把一次入侵还原成带时间线的完整攻击过程。

## 原理

- 协议分级统计按协议统计分组数、字节数、比特率，能快速判断事件类型：应用层以 HTTP 为主时，优先按 Web 攻击处理。
- 会话统计按 A↔B 聚合 IPv4 流量，top talker 里既有正常业务也有攻击者；扫描阶段表现为一个源向目标大量不同端口发 SYN（`tcp.flags.syn == 1 && tcp.flags.ack == 0`），扫描结束后才对唯一开放的 Web 端口发起正常 GET。
- HTTP 过滤器展开请求方法、URI、状态码与响应长度：目录/备份文件爆破表现为大量 404 后少量 200；后台登录、上传、webshell 访问都有稳定的请求形态。
- `ip.addr == <可疑IP> && http` 把攻击者与正常用户分离，按时间排序即可得到攻击者的完整 HTTP 操作序列。
- 后续阶段可能切换协议：数据库走 1433/TDS，远程桌面走 3389/T.125。按端口过滤后可从同一份 pcap 还原“Web 入口 → 数据库命令执行 → RDP 登录”的全链路。
- 方法成立的前提是抓包点覆盖攻击路径（端口镜像、防火墙、核心交换），且流量未被全链路加密；NAT 环境需结合 NAT 前后地址与主机日志。

## 触发条件

- 已取得疑似入侵时段的全量 pcap，或关键链路/关键主机的流量镜像。
- 目标是定位攻击者 IP、入侵入口、攻击阶段与时间线，而不是只解某一种加密协议。
- 流量未被 TLS 全加密，或已有 keylog/私钥等解密手段。

## 利用步骤

1. `Statistics → Protocol Hierarchy`：确认应用层主导协议与异常协议；HTTP 占比高（本例约 79% 字节）先按 Web 入侵处理。
2. `Statistics → Conversations → IPv4`：按字节/包数排序看 top talker，记录可疑源 IP 与目标 IP。
3. 扫描识别：过滤 `tcp.flags.syn == 1 && tcp.flags.ack == 0`，观察某源对目标多端口的 SYN 序列；扫描末尾通常出现对开放端口的正常握手，本例开放的是非标准 Web 端口。
4. 定位攻击者：`http` 过滤查看请求分布；多个候选源时，取“扫描源 ∩ HTTP 请求源”；再用 `ip.addr == <可疑IP> && http` 确认并排除正常业务。
5. 梳理入口与阶段：目录/备份文件 Fuzz（大量 404 后 200）、后台登录 POST、文件上传、webshell 访问（ASPNET/ASPX 的 POST 与明文回显）、配置文件读取；对 webshell 载荷按关联卡解码。
6. 扩展协议：`tcp.port == 1433` 查看 TDS 登录与 SQL batch；`tcp.port == 3389` 查看 RDP 协商与 `T.125 attachUserConfirm result: rt-successful`；把各阶段首包时间对齐。
7. 与主机侧证据互证：账号创建时间、计划任务/服务/启动项、恶意样本哈希与威胁情报、安全日志 4624 登录类型 10；输出攻击时间线与 IOC 清单。

## PoC

```text
# Wireshark 显示过滤器
http
ip.addr == <可疑IP> && http
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.port == 1433
tcp.port == 3389
```

```bash
# tshark 快速导出 HTTP 请求时间线（按实际文件与字段调整）
tshark -r web.pcap -Y "http.request" -T fields \
  -e frame.time -e ip.src -e ip.dst -e http.request.method \
  -e http.request.uri -e http.response.code

# 统计候选源的 HTTP 请求数
tshark -r web.pcap -Y "http.request" -T fields -e ip.src | sort | uniq -c | sort -nr
```

说明：以上为分析流程示例，未在原文环境复跑；非标准端口、NAT 与 TLS 会改变过滤条件。

## 变体与关联

- 变体：HTTPS 为主时先做 TLS 解密（keylog/服务器私钥），再按 HTTP 流程分析。
- 变体：NAT/反向代理环境下 pcap 中的源地址可能不是真实攻击者，需要结合 `X-Forwarded-For`、代理日志或边界设备日志。
- 变体：抓包不含数据库/RDP 阶段时，用主机侧 SQL ERRORLOG、安全日志 4624 类型 10、RDP 事件补齐时间线。
- 关联：[[defense-forensics-web-access-log-attacker-ip-triage]]、[[defense-forensics-chopper-aspx-webshell-base64-traffic-decode]]、[[defense-forensics-mssql-tds-xpcmdshell-traffic-replay]]、[[defense-incident-response-windows-persistence-triage-run-schtask-service]]。

## 检测与防御

- 检测/响应：把“协议分级 → 会话统计 → SYN 扫描 → HTTP 敏感请求 → 1433/3389 异常连接”固化为应急分析 SOP；对扫描、404 密集后 200、上传、webshell 访问、数据库/远程桌面异常连接做关联告警。
- 防御：保留全流量与 NDR 能力；上传目录禁止脚本执行；数据库端口不对外暴露；RDP 仅经 VPN/跳板并强制 NLA；定期做 pcap 溯源演练。
- 取证：原始 pcap 只读保存并计算哈希；导出会话、HTTP 请求表与各协议时间线作为证据，避免在原始文件上直接过滤后覆盖保存。
