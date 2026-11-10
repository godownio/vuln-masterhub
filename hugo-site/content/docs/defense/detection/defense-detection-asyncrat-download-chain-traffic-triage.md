---
id: defense-detection-asyncrat-download-chain-traffic-triage
title: AsyncRAT 下载链流量研判：从 Suricata 告警五元组定位数据包，用 PowerShell UA、混淆 PS 响应、JA3S 与证书 hex 四类证据确认受控
type: scenario
domain: defense
path: defense/detection
technique: asyncrat-download-chain-traffic-triage
tags:
- traffic-analysis
- suricata
- wireshark
- ja3s
- tls-certificate
- asyncrat
- powershell
- rat
- incident-response
- detection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V462-fix
  verified_at: '2026-11-10T15:11:43+08:00'
  notes: V462 指出 JA3S 字段构成错误（JA3S 仅版本+加密套件+扩展，不含曲线/EC point formats）且『任一命中即可判定』与多证据链矛盾。已修正原理与一句话结论为『单一证据可能混淆，需多条证据在时间线上连续出现』。
url: /docs/defense/detection/defense-detection-asyncrat-download-chain-traffic-triage/
draft: false
kb_aliases:
- AsyncRAT 流量检测
- JA3S 服务端指纹
- AsyncRAT 证书 hex 特征
- PowerShell User-Agent 告警
- 混淆 PowerShell 载荷特征
- Suricata 告警定位数据包
- 恶意下载链研判
---

## 一句话结论

面对 Suricata/ET 大量告警时，可以按“告警规则名 + 五元组”回到 pcap 逐包定位，用四条互相独立的证据串起 AsyncRAT 下载链：HTTP 请求的 PowerShell User-Agent、HTTP 响应中混淆 PowerShell 的 `MemoryStream` 特征、TLS ServerHello 的 AsyncRAT JA3S 指纹（`b74704234e6128f33bff9865696e31b3`）以及证书里的十六进制片段（`0f 39 39 39 39 31 32 33 ...`）；单一证据可能与其他 .NET 程序或运维脚本混淆，需多条证据在时间线上连续出现才能把内网 IP 判定为下载者/受控主机。

## 原理

- **告警只是线索，必须回到数据包**：流量产品通常只能按五元组把告警关联到一个 TCP 会话，而一个会话可能有上千个包，触发规则的是其中某一个。把告警里的 `src/dst ip:port`、规则名、时间戳拿到 Wireshark 里按五元组过滤，再“追踪 TCP 流”，才能看到真正的请求/响应内容；多类告警按时间排序即可还原攻击链。
- **PowerShell User-Agent 是脚本化下载的强信号**：正常浏览器/业务客户端不会把 `PowerShell` 写进 `User-Agent`。HTTP 请求头出现 PowerShell UA，说明有脚本进程在下载资源；结合内网源 IP 与下载目标（新注册/低信誉域名、`.top` 等），基本可判定该主机中了下载者木马。
- **混淆 PowerShell 载荷有稳定字节特征**：恶意 PowerShell 常用 `New-Object System.IO.MemoryStream`、`[System.Convert]::FromBase64String`、`GZipStream` 等 .NET 类型在内存中解码下一阶段。ET 规则用十六进制 + 字符串混合模式匹配这些构造（如 `|20 3d 20|New|2d|Object|20|System|2e|IO|2e|MemoryStream`，即 ` = New-Object System.IO.MemoryStream`），在 HTTP 响应体命中即可确认“服务器返回了混淆脚本”。
- **JA3S 标识 TLS 服务端实现**：JA3S 只对 TLS `ServerHello` 中的版本、加密套件、扩展列表三项做拼接后 MD5（椭圆曲线与 EC point formats 属客户端 JA3，不在 JA3S 中），得到服务端 TLS 栈的稳定指纹。AsyncRAT 是开源 RAT，其 TLS 服务端实现固定，因此同一版本的 ServerHello 会产生固定 JA3S（本例 `b74704234e6128f33bff9865696e31b3`）；ET 规则命中即说明该服务端“像 AsyncRAT”。
- **证书 hex 是第二条独立指纹**：AsyncRAT 的默认/常见服务端证书字段中存在固定字节序列（本例 `0f 39 39 39 39 31 32 33 31 32 33 35 39 35 39 5a`，其中可见 `99991231235959Z` 形式的 ASN.1 时间串），与 JA3S 联合可降低误报；该证书风格与 Quasar RAT 通用，提示二者同源（AsyncRAT 与 Quasar 均为开源 .NET RAT）。
- **多层证据链的意义**：单看 JA3S 可能与其他 .NET TLS 程序冲突，单看 PowerShell UA 也可能误报运维脚本；但“PowerShell 下载 → 响应含混淆脚本 → 主机外连 JA3S/证书匹配 AsyncRAT 的 TLS 服务端”在时间线上连续出现，即可确认下载者 + 受控，而不是孤立告警。

## 触发条件

- 网络侧部署了 Suricata/ET/PRO 等规则库并输出 `fast.log`/`eve.json`，或已有可回查的 pcap。
- 恶意下载与 C2 通信未被全流量加密完全遮蔽：HTTP 下载可见请求头/响应体，TLS 握手可见 ServerHello 与证书（不需要解密）。
- 内网主机直接出网（或代理保留原始 TLS/HTTP 元数据），能够观察到 PowerShell 发出的 HTTP 请求。
- 规则库包含 PowerShell UA、混淆 PowerShell 特征、AsyncRAT JA3S/证书等规则；否则需要手工按特征过滤。

## 利用步骤

1. **读告警**：从 `fast.log`/SIEM 取规则名、时间、五元组；优先关注 PowerShell UA、混淆 PowerShell 载荷、可疑 `.top` 域名、JA3S/证书类告警。
2. **看全链路**：在 Wireshark 用 `tls.handshake.type eq 1 || http.request` 过滤，按时间排列所有 TLS ClientHello 与 HTTP 请求，先勾勒“下载 → 外连”的会话列表。
3. **定位 PowerShell 下载包**：按告警五元组过滤（如 `ip.addr==<内网IP> && http.request`），或用 `http.user_agent contains "PowerShell"`；追踪流确认请求 URI、Host 与响应内容。
4. **定位混淆载荷响应**：按告警五元组过滤对应 TCP 会话（`ip.src==<服务器> && tcp.srcport==80 && ip.dst==<内网IP> && tcp.dstport==<客户端端口>`），追踪流查看响应体；用十六进制搜索 `New-Object System.IO.MemoryStream` 等特征确认混淆 PowerShell。
5. **提取 JA3S**：过滤 `ip.src==<C2 IP> && tls.handshake.type == 2 && tcp.dstport==<客户端端口>` 找到 ServerHello；从 Suricata `eve.json` 的 `tls.ja3s.hash` 或 Wireshark 插件读取 JA3S，与 AsyncRAT 已知值比对。
6. **提取证书特征**：在 ServerHello 后的 Certificate 消息中查看证书字节，搜索固定 hex 片段；确认证书字段风格（如序列号/有效期中的 `99991231235959Z`）。
7. **时间线关联**：把下载时间、脚本执行时间（可由后续 DNS/HTTP 请求推断）、C2 首次 TLS 连接时间对齐，确认同一内网 IP 的“下载者 → 受控”过程。
8. **处置**：隔离该内网主机，提取内存/磁盘取证（计划任务、PowerShell 历史、AsyncRAT 配置），封禁 C2 IP/域名与相关 JA3S/证书指纹。

## PoC

无攻击性 PoC。检测侧过滤与特征示例：

```text
# 全链路概览
tls.handshake.type eq 1 || http.request

# PowerShell 发起的 HTTP 请求
http.user_agent contains "PowerShell"

# 按告警五元组定位响应（示例）
ip.src==49.13.65.235 && tcp.srcport==80 && ip.dst==10.2.21.101 && tcp.dstport==64066

# 定位 TLS ServerHello 并提取 JA3S
ip.src==5.161.113.150 && tls.handshake.type == 2 && tcp.dstport == 64070
```

AsyncRAT 相关指纹（来自原文案例）：

```text
JA3S: b74704234e6128f33bff9865696e31b3
证书 hex 片段: 0f 39 39 39 39 31 32 33 31 32 33 35 39 35 39 5a
混淆 PowerShell 字节特征: |20 3d 20|New|2d|Object|20|System|2e|IO|2e|MemoryStream
```

JA3S/证书指纹可能随 AsyncRAT 版本、证书更换而变化，需结合规则库更新。

## 变体与关联

- 本案例投递链：合法站点被第三方嵌入伪装成 Edge 更新的提示 → 下载 `UpdateInstaller.zip` → 混淆的 `Version.122.7424.25.js` → PowerShell 依次下载 `/f15.svg` 等脚本 → 解密 AsyncRAT；主机侧持久化为伪装成 DSC 资源的计划任务（见 `pentest-persistence-dsc-resource-masquerade-conhost-log-iex-task`）。
- JA3 是客户端指纹、JA3S 是服务端指纹；通用 JA3 检测方法见 `defense-detection-ja3-tls-fingerprint-suricata`，本卡是 AsyncRAT 服务端指纹与告警研判的具体案例。
- AsyncRAT 样本逆向（字符串解密、互斥体、TLS C2）见 `code-analysis-reverse-windows-asyncrat-string-decrypt-mutex-tls-c2`；AsyncRAT 与 Quasar RAT 的证书风格通用，Quasar 配置解密见 `code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt`。
- 初始投递为合法网站被第三方嵌入“软件更新”下载提示，属水坑/供应链投毒；相关处置见 `defense-incident-response-frontend-watering-hole-js-jsp-tamper-triage`、`pentest-initial-access-internal-software-download-replacement-watering-hole`。
- 其他 RAT 的 TLS/JARM 指纹检测思路见 `defense-detection-sliver-default-tls-jarm-31337`；Cobalt Strike 的 JA3 检测见 `defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract`。

## 检测与防御

- 规则侧：启用并维护 ET/PRO 等规则库中的 PowerShell UA、混淆 PowerShell、恶意 TLS 指纹与证书规则；对 `.top` 等高风险 TLD 的 DNS 查询做狩猎。
- 流量侧：在代理/防火墙记录 `User-Agent`、SNI、JA3/JA3S、证书字段；对“脚本进程发起 HTTP 下载”“TLS 服务端 JA3S/证书命中已知 RAT”建立关联告警。
- 主机侧：限制 PowerShell 直接出网（至少记录并告警）；监控计划任务创建、PowerShell 脚本块日志、`MemoryStream`/`FromBase64String`/`GZipStream` 组合。
- 响应：一旦确认受控，隔离主机、封禁 C2 与下载域名、提取 AsyncRAT 配置与持久化项；对同网段其他主机排查相同 JA3S/证书与下载域名。
