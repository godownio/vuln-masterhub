---
id: ctf-forensics-http-beacon-gate-php-dns-c2-extraction
title: HTTP beacon gate.php + DNS A 记录定位 C2：从 pcap 提取目的 IP、Host 域名与端口
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-http-beacon-dns-a-record-c2-extraction
tags:
- ctf
- forensics
- pcap
- wireshark
- http
- beacon
- dns
- c2
- threat-intel
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:54:18+08:00'
  notes: 已对照原文「deploy-3」与图18-23核对：过滤 http.request.method==POST && uri contains gate.php 得 4 个包（30.03/150.03/210.03/270.03s，间隔120/60/60s，Content-Length 155），目的 IP 203.0.113.45、Dst Port 8443、Host c2.greylinx-consulting.xyz:8443；Follow HTTP Stream 见 uid=GL-2026-0314-BLUE 与响应 <ok/>；DNS 过滤得 0xa101 查询/响应 A 203.0.113.45；图18 时间线与卡片描述一致。未复跑；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-http-beacon-gate-php-dns-c2-extraction/
draft: false
kb_aliases:
- deploy-3
- capture.pcap
- gate.php beacon
- C2 IP 端口
- DNS A 记录定位
- GreyLynx C2
- HTTP 外联分析
---

## 一句话结论

在 `capture.pcap` 中用 `http.request.method == POST and http.request.uri contains "gate.php"` 过滤出周期性 beacon，包详情显示目的 IP `203.0.113.45`、目的端口 `8443`、`Host: c2.greylinx-consulting.xyz:8443`，POST body 带 `uid=GL-2026-0314-BLUE`、响应 `<ok/>`；再用 `dns.qry.name contains "c2.greylinx-consulting.xyz"` 找到 A 记录 `203.0.113.45`，即可确定 C2 的 IP、域名与端口。

## 原理

- **HTTP beacon 特征**：恶意样本按固定间隔向 `gate.php` 发 POST，包长/URI/UA 高度一致（本例 4 个包间隔约 60~120 秒，Content-Length 155），这是 C2 心跳/任务拉取的典型模式。
- **目的 IP 与 Host 分离**：TCP/IP 层的 `Destination` 是实际连接的 IP（`203.0.113.45`），HTTP 层的 `Host` 头是域名（`c2.greylinx-consulting.xyz:8443`）。只 Follow HTTP Stream 可能只看到 Host，不知道 IP；只包列表可能只看到 IP，不知道域名，两者要结合。
- **端口在 Host 与 TCP 头里**：`Host: c2.greylinx-consulting.xyz:8443` 与 TCP `Dst Port: 8443` 一致；若 Host 不带端口，则以 TCP 目的端口为准。
- **DNS 反查/正查**：`dns.qry.name contains "c2.greylinx-consulting.xyz"` 找到查询与响应，响应 `A 203.0.113.45` 把域名和 IP 绑定；事务 ID `0xa101` 用于匹配请求/响应。
- **UEBA/时间线**：本例时间线还显示 03-12 09:30 鱼叉钓鱼 docm → 09:31 AutoOpen 宏 → 21:55 口令爆破 → 22:03 RDP 横向 → 22:04 HTTP beacon → 22:10 计划任务持久化 → 22:21 清除日志 → 03-14 勒索；beacon 是“命令与控制”阶段的关键证据。

## 触发条件

- 拿到包含恶意流量的 pcap；有 HTTP 明文 beacon 或可解析的 TLS SNI/DNS。
- 已知或可猜出 beacon 路径（`gate.php`、`/api/check`、`/beacon` 等），或能按周期性 POST/固定 UA/固定长度筛选。
- pcap 中包含 DNS 查询/响应，或能通过其它日志关联域名与 IP。

## 利用步骤

1. 用 Wireshark 过滤 `http.request.method == POST and http.request.uri contains "gate.php"`，查看包列表的 Source/Destination/Info。
2. 选中一条包，展开 IPv4/TCP/HTTP：记录目的 IP、目的端口、Host、User-Agent、Content-Length、请求 URI。
3. Follow HTTP Stream，查看 POST body（如 `data=...&uid=GL-2026-0314-BLUE`）与响应（`<ok/>`），确认是 C2 心跳而非正常业务。
4. 过滤 `dns.qry.name contains "<Host 域名>"`，查看 DNS 查询与响应，记录 A 记录 IP；若为 HTTPS，改用 `tls.handshake.extensions_server_name` 看 SNI。
5. 汇总 C2 的 IP:端口、域名:端口、URI、UA、UID/参数，作为 IOC。

## PoC

```bash
# 1) 找 gate.php beacon
tshark -r capture.pcap -Y 'http.request.method == "POST" && http.request.uri contains "gate.php"' \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e http.host -e http.request.uri -e http.content_length

# 2) 看 Host / UA / body
tshark -r capture.pcap -Y 'http.request.uri contains "gate.php"' \
  -T fields -e http.host -e http.user_agent -e http.file_data

# 3) DNS A 记录
tshark -r capture.pcap -Y 'dns.qry.name contains "c2.greylinx-consulting.xyz"' \
  -T fields -e dns.qry.name -e dns.a
```

原文实测结果：目的 IP `203.0.113.45`、端口 `8443`、域名 `c2.greylinx-consulting.xyz`，DNS 响应 `A 203.0.113.45`；该分析未在本库复跑。

## 变体与关联

- **协议变体**：HTTPS beacon 看 TLS SNI/JA3/证书；DNS tunneling 看异常 TXT/NULL 查询与高熵子域；ICMP/WebSocket beacon 看固定长度与周期。
- **伪装变体**：UA 伪装成浏览器、URI 伪装成正常 API、使用 CDN/域名前置；需要结合时间线、进程树、DNS/代理日志关联。
- **IOC 变体**：域名、IP、端口、URI、UA、UID、证书序列号、JA3；单一 IOC 易过期，组合更稳。
- **关联卡片**：[[ctf-forensics-modbus-private-pcap-write-register-covert]]（pcap 工控隐蔽信道）、[[ctf-forensics-tcp-urgent-pointer-covert-channel]]（TCP 紧急指针隐蔽信道）。

## 检测与防御

- **网络侧**：对周期性 POST、固定 UA/长度、可疑 `gate.php`/`beacon` 路径告警；DNS 日志监控新注册/高熵域名与异常 A/TXT 查询；出站 8443 等非标准端口按策略限制。
- **终端侧**：关联 Office 宏、PowerShell、计划任务、`%TEMP%` 可执行文件等进程链；对 `iwr`/`Invoke-WebRequest` 与隐藏窗口 PowerShell 告警。
- **威胁情报**：把域名/IP/端口/URI/UA/UID 作为 IOC 下发；注意攻击者可能快速更换基础设施，需结合行为特征。
- **取证**：保留 pcap 原始包与时间线，记录 DNS 事务 ID、TCP 流、HTTP 头/体；对 HTTPS 尽量提取 SNI/证书。
