---
id: defense-detection-ja4t-greynoise-syn-block-scanner
title: JA4T + GreyNoise 在 SYN 阶段阻断扫描流量：前 5 指纹覆盖 60% 互联网扫描，JA4/JA4H 组合降误报
type: scenario
domain: defense
path: defense/detection
technique: ja4t-syn-block-scanning
tags:
- defense
- detection
- blocking
- ja4t
- greynoise
- f5
- scanner
- fingerprint
- waf
- threat-intel
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V442
  verified_at: '2026-11-09T23:25:33+08:00'
  notes: 已对照原文与图18-21核对：前5个JA4T指纹（masscan 21%、改版ZMap 19%、改版Nmap 8%、ZMap 6%、Nmap 6%）合计60%，第6位 Tencent 29200_2-4-8-1-3_1424_7 约5%、SSH/22 为主、部分31401 Pi节点、JA4H zhcn、t11d6911h9=TLS1.1+ALPN 等均与原文/截图一致；ge10nn04zhcn 由原文文字确认。未验证点：图20为874x279低分辨率且红框遮挡，卡中另两个 JA4H 示例 he11nn04zhcn/ge11nn11zhcn 无法逐字确认（放大后疑似 he11nn08zhcn/ge11nn10zhcn），建议作者按原始英文博客或高清截图复核，不影响阻断主体结论。
url: /docs/defense/detection/defense-detection-ja4t-greynoise-syn-block-scanner/
draft: false
kb_aliases:
- JA4T 阻断扫描器
- JA4T 指纹黑名单
- GreyNoise JA4T
- F5 iRule 阻断 JA4T
- SYN 阶段拦截扫描
- 29200_2-4-8-1-3_1424_7
- masscan ZMap Nmap 指纹
---

## 一句话结论

GreyNoise 统计显示 masscan、改版 ZMap、改版 Nmap、ZMap、Nmap 五个 JA4T 指纹合计占互联网扫描流量的 60%；把 JA4T 指纹表下发到 WAF/防火墙/负载均衡器，在 SYN 包到达时就 DROP，可在扫描器判断端口是否开放之前阻断流量，且不依赖不断变化的 IP 黑名单；再用 JA4/JA4H 组合可把误报压到可接受范围。

## 原理

- **为什么在 SYN 阶段拦**：TCP 服务端收到 SYN 才回 SYN-ACK，扫描器据此判断端口开放。如果在收到 SYN 时直接丢弃，扫描器只能看到超时，既拿不到开放信息，也看不到服务指纹；相比应用层 WAF 规则，阻断发生在握手最前端，成本低且不消耗后端连接。
- **为什么用指纹而不是 IP**：扫描基础设施的源 IP 会频繁更换（云主机、代理池、被劫持设备），IP 黑名单维护成本高且易漏；JA4T 由扫描工具的 TCP 栈实现决定，同一工具的大量出口 IP 共享同一指纹，稳定性远高于 IP。
- **GreyNoise 前 5 指纹（2024 年 4 月）**：`1024_00_00_00`（masscan，21%）、`65535_2_1460_00`（改版 ZMap，19%）、`1025_2_1460_00`（改版 Nmap，8%）、`65535_00_00_00`（ZMap，6%）、`1024_2_1460_00`（Nmap，6%），合计约 60%。这些指纹的窗口/选项组合极简（如无窗口比例、选项仅 MSS），与正常客户端明显不同，适合直接阻断。
- **Tencent 指纹案例**：第 6 位的 `29200_2-4-8-1-3_1424_7`（约 5%）选项序 2-4-8-1-3 是典型 Unix 栈，MSS 1424 表示链路有 36 字节额外开销——小于 VPN 加密开销，更像未加密隧道或代理；GreyNoise 观察到数百个源 IP 全部位于腾讯 IP 段、监听 22 端口（部分 31401，Pi 节点矿机），推测是流量被反弹/中转而非真实来源。
- **行为画像辅助**：该扫描者主要扫 SSH 及替代端口（22 占大多数，其后是 80/6379/443/8080 等 Web/数据库端口），第二目标是 Web 服务器识别。其 JA4H 多带中文语言标记（`zhcn`），如 `he11nn04zhcn`、`ge11nn11zhcn`，其中 `ge10nn04zhcn` 用 HTTP/1.0 尝试兼容老旧设备；JA4 既有支持 TLS 1.3 与 69 个密码套件的全能扫描器，也有 TLS 1.2/1.1 变体，`t11d6911h9` 甚至是"TLS 1.1 + ALPN 扩展"的异常组合（ALPN 在 TLS 1.1 时代不存在）。
- **组合降误报**：单一 JA4T 可能误伤同栈的正常客户端（尤其 masscan/Nmap 类工具也可能是自家 ASM 资产）；把 JA4T 与同源的异常 JA4H（如 `zhcn` 语言 + HTTP/1.0）或 JA4（异常 TLS 版本/扩展组合）联合匹配，可形成低误报的检测/阻断规则。
- **风险**：阻断规则会连带拦截自家攻击面管理（ASM）扫描器、渗透测试与部分云服务健康检查；上线前必须清点并白名单。

## 触发条件

- 边界设备（WAF、防火墙、负载均衡器、代理）具备 JA4T 提取与匹配能力，或可自行解析 SYN 字段生成指纹。
- 已有 GreyNoise 等威胁情报提供的 JA4T 指纹表，或本地统计出待阻断指纹。
- 阻断动作可作用于 TCP SYN（丢弃而非重置），并能维护 ASM/业务白名单。

## 利用步骤

1. 从 GreyNoise 或自有流量统计中取高风险 JA4T 指纹列表（优先前 5 个覆盖 60% 扫描流量的指纹）。
2. 在边界设备上配置规则：SYN 包的 JA4T 命中列表即 DROP（如 F5 BIG-IP 可用 iRule 实现，F5 提供 JA4 示例规则集）。
3. 先用告警模式运行，观察命中来源与业务影响，把自家 ASM、监控、云健康检查加入白名单。
4. 对剩余可疑指纹做组合规则：JA4T + 异常 JA4H/JA4，进一步降低误报。
5. 持续更新指纹表并复盘误杀；对使用隧道/代理的合法业务单独建基线。

## PoC

无现成利用代码（文章未给出 iRule 源码）。最小规则语义示意：

```text
if (tcp.flags.syn == 1 && tcp.flags.ack == 0) and ja4t in {
    "1024_00_00_00",        # masscan 21%
    "65535_2_1460_00",      # modified ZMap 19%
    "1025_2_1460_00",       # modified Nmap 8%
    "65535_00_00_00",       # ZMap 6%
    "1024_2_1460_00"        # Nmap 6%
} then DROP
```

## 变体与关联

- 变体：对 JA4T 高熵异常但非扫描器的流量（如隧道/代理指纹）先告警后阻断，避免误伤远程办公。
- 变体：服务端侧用 JA4TS 识别本机服务的响应一致性，客户端侧用 JA4TScan 主动测绘资产真实指纹。
- 关联：[[defense-detection-ja4t-ja4ts-ja4tscan-tcp-fingerprint]]（指纹格式与含义）；[[defense-detection-ja3-tls-fingerprint-suricata]]（TLS 层指纹检测与 Suricata 阻断）；[[defense-detection-sliver-default-tls-jarm-31337]]（JARM 服务端指纹）。

## 检测与防御

- 检测：统计 JA4T 分布，出现 top 扫描器指纹、单指纹对应大量源 IP/目标端口、MSS 与链路不符等均告警；结合 JA4H/JA4 特征做关联。
- 防御：SYN 阶段按指纹丢弃；维护 ASM 与业务白名单；定期更新指纹库；不要仅凭 IP 或单一指纹做永久封禁。
- 局限：攻击者可修改 TCP 栈参数伪造 JA4T（如定制 ZMap 选项序）绕过；加密隧道会改变 MSS；规则需持续运营。
