---
id: defense-detection-remcos-v493-tls13-cipher-heartbeat-fingerprint
title: Remcos v4.9.3 TLS1.3 加密流量识别：证书不可见、仅提供 TLS_AES_128_GCM_SHA256(0x1301)、约 30 秒固定长度小包心跳（原文注长度未严格确认），大响应子会话分流为 socket 观测
type: scenario
domain: defense
path: defense/detection
technique: remcos-tls13-single-cipher-heartbeat-fingerprint
tags:
- detection
- traffic-analysis
- tls
- tls1.3
- remcos
- rat
- c2
- fingerprint
- heartbeat
cve: []
severity: medium
confidence: medium
affected_versions: Remcos v4.9.3 Light（原文分析版本；定制版可能改变套件/心跳）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V618
  verified_at: '2026-11-12T21:01:29+08:00'
  notes: 已对照原文与全部 41 张图核对：图 36 ClientHello 仅 TLS_AES_128_GCM_SHA256(0x1301)（Cipher Suites (1 suite)）、图 26 ServerHello 同套件；图 37 TLS 主会话 96 字节小包约 30 秒一次；TLS1.3 握手加密/证书不可见与原文一致；已修正卡片：将'大响应另起子会话'明确限定为 socket 模式观测，原文 TLS1.3 小节未直接给出子会话抓包，标题/结论/原理/步骤/检测点均已加注；'固定长度'保留原文未严格确认的注记。dedup 20 候选中 related=2（Quasar TLS1.2 证书指纹、SChannel 私钥解密）非同链，dup-scan 无 pair。未验证点：tshark 检测命令为作者补充，未用真实 Remcos TLS1.3 pcap 验证阈值。
url: /docs/defense/detection/defense-detection-remcos-v493-tls13-cipher-heartbeat-fingerprint/
draft: false
kb_aliases:
- Remcos 加密流量识别
- Remcos TLS1.3 指纹
- Remcos 心跳 30 秒
- TLS_AES_128_GCM_SHA256 0x1301
- Remcos 检测
- Remcos C2 识别
---

## 一句话结论

Remcos v4.9.3 的 TLS1.3 模式虽然加密了应用数据且握手后证书不可见（TLS1.3 的 Certificate 也在加密握手内），仍可被动识别：ClientHello/ServerHello 只提供 `TLS_AES_128_GCM_SHA256 (0x1301)` 一种套件、主会话上约每 30 秒一次固定长度的小心跳包（原文注：长度是否严格固定未确认）；socket 模式下另观测到大响应会另起短命子会话，同一 Agent 的 TLS1.3 模式可作参考推断（原文 TLS1.3 小节未直接给出子会话抓包）。把这些握手元数据与 TCP 行为组合，再配合 JA3/JA4 与端点进程信息，可用于 C2 预警而不是单凭 payload 匹配。

## 原理

- **TLS1.3 隐藏证书**：TLS1.2 的 ServerHello 之后 Certificate 是明文，可直接看 CN/指纹；TLS1.3 从 ServerHello 之后全部握手消息加密，证书不可见，基于默认证书 CN/hex 的规则（如 Quasar 那类）对 Remcos TLS1.3 失效。
- **单一套件**：Remcos Agent 在这个版本只提供 `TLS_AES_128_GCM_SHA256 (0x1301)` 一种密钥套件，ClientHello 与 ServerHello 都能看到；普通浏览器/业务客户端通常会提供多种套件，单一套件是弱指纹但可用于筛可疑会话。
- **应用层心跳**：主会话建立后用于接收远控指令与心跳，默认心跳间隔 30 秒；心跳数据包长度处于固定范围（原文注：不确定是否严格固定），加密后仍表现为周期性、长度相近的小包。它区别于 TCP Keep-Alive（后者无应用数据或仅 1 字节），需要按时间间隔与包长统计。
- **子会话分流（socket 观测）**：socket 模式下当响应数据较大（如截屏、文件、进程列表）时，Agent 会另起一个子会话传输，主会话继续心跳；因此同一 C2 会出现“一条长命主连接 + 多条短命子连接”的拓扑，主会话数据量小、子会话突发大量数据。原文 TLS1.3 小节只展示主会话心跳、未直接给出 TLS 子会话抓包，TLS1.3 下按同一 Agent 行为推断可作辅助特征，需在自有样本上确认。
- **检测定位**：TLS1.3 下内容不可见，强特征只剩握手元数据（版本/套件/JA3/JA4）与 TCP 行为（心跳周期、子会话模式、上下行比例），必须组合研判并和资产基线对比，不能单条定案。

## 触发条件

- 目标为 Remcos v4.9.3（或相近版本）且启用 TLS1.3 通信（Secure Connection TLS 1.3）。
- 网络侧能看到完整 TLS 握手与 TCP 行为，未被 TLS 终止代理完全改写。
- 默认心跳 30 秒、默认单一套件未被定制修改。
- 具备端点侧遥测（进程外联、EDR 日志）或威胁情报，用于确认候选。

## 利用步骤

> 以下为防御方检测/研判步骤。

1. **筛 TLS1.3 会话**：按外联目标、非浏览器进程或情报线索筛选；记录五元组、SNI（若有）、JA3/JA4 指纹。
2. **看套件**：过滤 ClientHello/ServerHello，检查是否只出现 `0x1301` 一种套件（`TLS_AES_128_GCM_SHA256`）；同时确认握手版本为 TLS1.3。
3. **确认证书不可见**：TLS1.3 下 Certificate 在加密握手中，抓包看不到证书属正常，不要因此排除；改为依赖套件与行为。
4. **统计心跳**：对长命主会话统计每 30 秒左右的小包间隔与包长分布，区分 TCP Keep-Alive 与应用心跳。
5. **看子会话**：观察是否在主会话之外出现短命 TCP 子连接，且子会话突发大量数据（截屏/文件传输特征），与主会话小流量形成对比（该行为原文在 socket 模式有抓包证据；TLS1.3 下属推断特征，需自行验证）。
6. **组合研判**：单一套件 + 30 秒心跳 + 主/子会话模式 + 非浏览器进程外联 + 威胁情报，再结合样本配置（若可取得）核对 C2 地址。
7. **处置**：封禁 C2、隔离主机、提取样本与内存，排查持久化与横向；如能取得 keylog/traffic secret，可按 TLS1.3 密钥日志方式解密复核（见关联卡）。

## PoC

```bash
# 1) 列出 ClientHello 提供的套件（观察是否只有 0x1301）
tshark -r remcos.pcap -Y 'tls.handshake.type==1' \
  -T fields -e ip.dst -e tcp.dstport -e tls.handshake.ciphersuite

# 2) 看 ServerHello 实际选中的套件与版本
tshark -r remcos.pcap -Y 'tls.handshake.type==2' \
  -T fields -e ip.src -e tcp.srcport -e tls.handshake.version -e tls.handshake.ciphersuite

# 3) 以 30 秒窗口统计某会话包数与字节数，观察周期性小包
tshark -r remcos.pcap -q -z io,stat,30,"tcp.port==8080"

# 4) 统计主/子会话：同一目标 IP 的 TCP 连接数与时长
tshark -r remcos.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' \
  -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e frame.time
```

说明：以上为被动检测命令，需在授权环境或用自有样本流量验证阈值；`0x1301` 只是筛选条件，不能单独作为结论。

## 变体与关联

- **同类 RAT 指纹对比**：Quasar RAT 的 TLS1.2 固定套件 + 默认证书 + 25 秒心跳见 [[defense-detection-quasar-rat-tls-traffic-fingerprint]]；Remcos TLS1.3 无证书可见，需用套件与心跳区分。
- **明文 socket 模式**：关闭 TLS 时可直接按 magic/分隔符识别，见 [[code-analysis-reverse-windows-remcos-socket-protocol-controller-emulation]]。
- **解密复核**：若能取得 TLS1.3 的 CLIENT/SERVER_HANDSHAKE_TRAFFIC_SECRET 与 CLIENT/SERVER_TRAFFIC_SECRET_0，可导入 Wireshark/tshark 解密（见 [[ctf-forensics-tls-keylog-pcap-decrypt]]）。
- **边界**：定制版可修改套件列表、心跳间隔与包长；TLS 终止代理、会话恢复、0-RTT 会改变可见特征；单一套件在部分业务客户端中也可能出现，必须组合研判。

## 检测与防御

- **检测**：TLS1.3 会话仅提供 `0x1301` 单一套件；主会话 30 秒级小包心跳；主/子会话拓扑与上下行比例异常（子会话特征为 socket 观测）；外联进程非浏览器且无对应业务；JA3/JA4 与已知 Remcos 版本匹配。
- **防御**：对可疑外联做域名/IP 封禁与出站白名单；EDR 监控 Agent 行为（SETTINGS 资源、持久化、键盘记录/截屏 API）；邮件与 LNK/压缩包投递链路拦截；在网关侧记录 TLS 握手元数据以支持事后狩猎。
- **加固**：对默认套件/心跳等弱指纹不要依赖单一规则；结合资产基线、威胁情报与端点遥测，降低误报。
