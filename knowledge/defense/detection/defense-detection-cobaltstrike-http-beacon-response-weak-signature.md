---
id: defense-detection-cobaltstrike-http-beacon-response-weak-signature
title: 'Cobalt Strike HTTP beacon 弱特征：200 无 Server 头 + application/octet-stream + Content-Length: 0，配合 5 秒 /pixel.gif 心跳与 PowerShell UA 定位'
type: scenario
domain: defense
path: defense/detection
technique: cs-http-beacon-response-weak-signature
aliases:
- CobaltStrike HTTP beacon response
- pixel.gif 心跳
- 5 秒 beacon
- Content-Length: 0
- ET HUNTING GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser
- PowerShell User-Agent
- Beacon 弱特征规则
tags:
- detection
- cobalt-strike
- beacon
- http
- suricata
- traffic-analysis
- user-agent
- heartbeat
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V493
  verified_at: '2026-11-11T00:10:40+08:00'
  notes: '已对照原文 3.4 节与图15-17/25/26 核对：Suricata 规则（http_stat_code 200、无 Server 头、application/octet-stream、Content-Length: 0、threshold both 5/60s）与原文一致；http64.exe 由 WindowsPowerShell/5.1.19041.3570 UA 下载（图15/25）、20 秒后 /pixel.gif 每 5 秒心跳（图16）、C2IntelFeedsBot 标记 85.209.11.48:443 为 Cobalt Strike（图17/26）均一致。未验证点：弱特征规则未在真实 Suricata 环境编译/回归，原文亦提示生产环境有误报率；原文无版本，未设 affected_versions；frontmatter 无 sources/source_url'
---

## 一句话结论

Cobalt Strike 的 HTTP Beacon 可以用一条“响应弱特征”规则抓：HTTP 200、响应头没有 `Server:`、`Content-Type: application/octet-stream`、`Content-Length: 0`，同一来源在 60 秒内出现 5 次即告警；再结合受害机每 5 秒规律请求 `/pixel.gif`、请求 UA 为 `PowerShell`（下载器拉起）或伪装的浏览器 UA，即可把流量判定为 CS beacon 并定位 C2。该规则误报率不低，需与周期、URI、UA 和威胁情报联合研判。

## 原理

- **Beacon 的 HTTP 响应形态**：CS 的 HTTP listener 按 Malleable C2 profile 返回数据；没有待下发命令时，常见响应是空 body（`Content-Length: 0`）、`Content-Type: application/octet-stream`，且由 CS 服务端直接生成，缺少常见 Web 服务器的 `Server:` 头。多个这样的响应在短时间内重复，是“机器周期轮询”而非人访问的特征。
- **阈值规则降低误报**：单看 200 + octet-stream + 空 body 可能与某些 API/健康检查混淆；规则用 `threshold: type both, track by_src, count 5, seconds 60`（同一源 60 秒 5 次）把“持续心跳”筛出来，原文的规则即为此结构。
- **5 秒心跳**：Beacon 的 sleep 配置为 5 秒时，流量中会出现严格 5 秒间隔的请求；示例 URI 伪装成 `/pixel.gif`（图片/统计像素），响应仍是上述空包。固定周期 + 固定长度是 C2 心跳的强特征。
- **User-Agent 两条线索**：
  - 下载阶段 URL 由 `PowerShell` 进程发起，`http.user-agent` 直接是 PowerShell，说明不是用户浏览器访问；
  - Beacon 阶段使用伪装的浏览器 UA（与真实浏览器版本/顺序不符），ET 规则 `SUSPICIOUS POST to Dotted Quad with Fake Browser` 专门匹配“直接向 IP 提交 + 假浏览器 UA”的组合。
- **为什么需要情报兜底**：该响应弱特征在生产环境有误报概率（某些 CDN/API 也会返回空 body + octet-stream）；原文建议结合开源威胁情报确认 IP 性质，再下“受控”结论。

## 触发条件

- 目标网络部署 Suricata/ET 规则并能看到明文 HTTP，或已对 HTTPS 做 TLS 卸载/端点抓包；纯加密流量只能看周期与 SNI。
- Cobalt Strike 使用 HTTP listener，beacon sleep 较短（示例 5 秒）；Malleable profile 未刻意改写响应头/Content-Type。
- 规则库包含该弱特征规则或可自定义阈值；分析者能按五元组回查 pcap。
- 受害机已执行 CS 载荷（示例经 IcedID/VNC 下载 `http64.exe` 后运行）。

## 利用步骤

> 以下为防御方检测/研判步骤。

1. **读告警**：从 `fast.log`/SIEM 取 `CobaltStrike HTTP beacon response` 告警的五元组与时间，确认 60 秒内是否达到 5 次阈值。
2. **回查 pcap**：按 `ip.addr==<C2-IP> && http` 过滤，查看响应头是否同时满足 200、无 `Server:`、`application/octet-stream`、`Content-Length: 0`。
3. **看周期**：统计同一内网 IP 对同一 URI（示例 `/pixel.gif`）的请求间隔，确认是否稳定 5 秒；观察 URI 是否伪装成图片/统计资源但响应为空。
4. **看 UA**：检查请求 `User-Agent`——下载阶段是否为 `PowerShell`，beacon 阶段是否为与系统/浏览器不符的假 UA；结合 `SUSPICIOUS POST to Dotted Quad with Fake Browser` 告警。
5. **情报确认**：把 C2 IP/域名送威胁情报/沙箱，确认已知 CS 基础设施；避免仅凭弱特征定性。
6. **主机侧**：定位发起进程（PowerShell/IcedID 派生进程），检查 `http64.exe` 一类载荷、内存中的 beacon 与持久化；封禁 C2 并隔离主机。

## PoC

Suricata 规则（原文给出的弱特征规则结构）：

```text
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"CobaltStrike HTTP beacon response"; flow:established; content:"200"; http_stat_code; content:!"Server:"; http_header; content:"application/octet-stream"; http_header; distance:0; content:"Content-Length: 0"; http_header; distance:0; threshold: type both, track by_src, count 5, seconds 60;)
```

Wireshark 定位：

```text
# 响应弱特征
ip.addr==<C2-IP> && http.response.code==200 && http.content_type contains "octet-stream"
# 5 秒心跳与伪装 URI
ip.addr==<C2-IP> && http.request.uri contains "pixel.gif"
# PowerShell 发起的下载
http.user_agent contains "PowerShell"
```

无攻击性 PoC；规则用于检测侧验证。

## 变体与关联

- **HTTPS/malleable profile**：C2 走 HTTPS 或改写响应头/Content-Type 后该规则失效；需要 TLS 卸载后用明文规则检测（见关联卡），或改用 JA3/JA3S、证书、周期与 URI 特征。
- **其他 Beacon 形态**：DNS beacon、SMB/TCP beacon、staged stager 下载；stager 流量可用 checksum8/JA3 定位，beacon 阶段用本卡规则。
- **其他 C2 框架**：Sliver、AdaptixC2、Mythic 等也有空响应/心跳特征，但具体头字段不同，规则需按框架调整。
- **关联卡**：TLS MITM 卸载 + Suricata 检测 CS、CS checksum8/JA3 配置提取、CS beacon 密钥解密、IcedID 下载链（本案例前置）。
- **边界**：空 body + octet-stream 的正常 API 会造成误报；5 秒周期也可能被其他轮询软件模仿；必须结合情报与主机侧证据。

## 检测与防御

- **规则**：部署并调优该弱特征规则，按环境调整阈值；对 `POST` 到裸 IP + 假浏览器 UA 的组合单独告警。
- **流量基线**：建立“固定周期 + 固定长度 + 空响应”的心跳基线，对新增周期流量做威胁狩猎；记录 URI 伪装（图片/统计资源却返回空包）的模式。
- **TLS 可见性**：对出站 HTTPS 做 TLS 卸载或端点侧 ETW/EDR 关联，避免加密后完全失去 HTTP 字段。
- **主机**：监控 PowerShell 下载可执行文件、`http64.exe` 一类随机名 PE、进程内存中的 beacon；限制 PowerShell 出站与脚本执行。
- **响应**：确认 C2 后封禁 IP/域名、隔离主机、提取内存与样本，排查横向与持久化。
