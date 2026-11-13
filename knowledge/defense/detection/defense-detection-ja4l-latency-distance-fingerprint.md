---
id: defense-detection-ja4l-latency-distance-fingerprint
title: JA4L 延迟与距离指纹：RTT/2 微秒数 + TTL，按光速与传播系数估算物理距离上限
type: scenario
domain: defense
path: defense/detection
technique: ja4l-latency-distance-fingerprint
aliases:
- JA4L 指纹
- JA4-Light Distance
- 网络延迟距离指纹
- TTL 距离估算
- 会话劫持地理检测
tags:
- defense
- detection
- ja4
- latency
- ttl
- geolocation
- traffic-analysis
- tcp
- quic
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:38:59+08:00'
  notes: 已对照原文与图29-32核对：TCP A/B/C 与 QUIC A/B/C/D 的 RTT/2 公式、JA4L_a 微秒/JA4L_b TTL、D=j*c/p、跃点系数表（≤21→1.5…≥26→2.0）均一致；修正两处：初始 TTL 表 >128 由原文的 155 更正为幻灯片正确的 255，边界改为 b<=64→64、65-128→128；示例 2449_104→24 跳→1.8→257.385km 按原文保留。未实测网络。
---

## 一句话结论

JA4L 用会话建立阶段的单向延迟（微秒）和观察到的 TTL 两段值刻画“客户端/服务器到观测点的物理距离”：TCP 用三次握手时间差、QUIC 用 Initial/Handshake 包时间差计算 RTT/2，再按 `D = j*c/p`（光速 c 与传播系数 p）估算距离上限；它可辅助地理定位、识别代理/VPN，并与 JA4H 配合发现会话劫持或中间人。

## 原理

- 会话建立阶段的包交换时间差近似 RTT；除以 2 得到单向延迟。JA4L 用微秒（1 ms = 1000 μs）为单位，因为转发设备本身延迟通常很小。
- **TCP**：以三次握手的三个时间点 A（客户端 SYN）、B（服务端 SYN-ACK）、C（客户端 ACK）计算：
  - `JA4L-C = {(C-B)/2}_客户端TTL`（在服务端/中间观测点测量客户端）；
  - `JA4L-S = {(B-A)/2}_服务端TTL`（在客户端观测点测量服务端）。
- **UDP/QUIC**：以 A（客户端 Initial）、B（服务端 Initial）、C（服务端 Handshake）、D（客户端 Handshake）计算：
  - `JA4L-C = {(D-C)/2}_客户端TTL`；
  - `JA4L-S = {(B-A)/2}_服务端TTL`。
- **JA4L_a** 是单向延迟微秒数，**JA4L_b** 是观察到的 TTL。TTL 随转发跳数递减，可用于反推跃点数和初始 TTL（Windows 常见 128，Linux/macOS/手机/IoT 常见 64，Cisco/F5 等网络设备常见 255）。
- **距离公式**：`D = j * c / p`，j=JA4L_a；c=光速在光纤中的速度（0.128 英里/μs 或 0.206 公里/μs）；p=传播延迟系数。p 可按地形取 1.5（良好：高速公路、海底电缆）或 2（恶劣：山、水），也可按跃点数查表（≤21→1.5，22→1.6，23→1.7，24→1.8，25→1.9，≥26→2.0）。
- 例：`JA4L-S = 2449_104`，初始 TTL 128，跃点数 24，p=1.8，则距离上限 `2449*0.206/1.8 ≈ 257.385 km`。示例中 `2449_42` 按 22 跳、p=1.6、英里单位算得 195 英里（实际 194 英里）。
- 结果只是**上限**：光速恒定，真实路径不可能比直线距离更短；多条 JA4L 值应取最小值计算。
- 用途：地理定位、代理/VPN/中继识别（延迟与声称位置不符）、会话劫持检测（同一 Cookie/JA4H 出现在不可能的低延迟远端）、C2/基础设施地理画像。

## 触发条件

- 能捕获会话建立阶段的包（TCP 三次握手或 QUIC Initial/Handshake），且时间戳精度足够（微秒级）。
- 观测点位置已知（客户端侧、服务端侧或中间接口），否则只能做相对比较。
- 有初始 TTL 基线（按 OS/设备类型）与路由跳数估计。
- 网络抖动、负载均衡、代理和 CDN 会影响测量；需要多次采样。

## 利用步骤

1. 抓取会话建立包，标记 A/B/C（TCP）或 A/B/C/D（QUIC）时间点。
2. 计算 `JA4L_a = RTT/2`（微秒）与 `JA4L_b = 观察到的 TTL`，得到 `JA4L-C`/`JA4L-S`。
3. 根据 JA4L_b 与初始 TTL 表推算跃点数（如 104 → 初始 128 → 24 跳）。
4. 选择传播系数 p（按地形或跃点表），用 `D=j*c/p` 估算距离上限；多条样本取最小值。
5. 与 IP 地理库、JA4H/JA4 会话、登录地点比对；延迟明显低于/高于地理距离时，考虑代理、VPN、CDN 或会话劫持。
6. 对可疑会话多次采样，排除抖动与中间盒影响。

## PoC

```text
# TCP 三次握手
A: 客户端 SYN
B: 服务端 SYN-ACK
C: 客户端 ACK

JA4L-C = {(C-B)/2}_Client TTL
JA4L-S = {(B-A)/2}_Server TTL

# QUIC
A: Client Initial
B: Server Initial
C: Server Handshake
D: Client Handshake
JA4L-C = {(D-C)/2}_Client TTL
JA4L-S = {(B-A)/2}_Server TTL
```

```text
# 距离估算示例
JA4L-S = 2449_104
初始 TTL = 128 -> 跃点 24 -> p = 1.8
D = 2449 * 0.206 / 1.8 = 257.385 km（上限）
```

```text
# 初始 TTL 推断（按观察值反推最可能的初始 TTL）
JA4L_b <= 64     -> 初始 64
65 <= b <= 128   -> 初始 128
b > 128          -> 初始 255（原文表格写作 155，应为笔误；官方幻灯片为 255）
```

说明：公式与示例按文章整理；实际测量需考虑时间戳精度、排队延迟、NAT/代理与路由不对称，未在目标网络复测。

## 变体与关联

- 变体：按英里计算用 c=0.128 mi/μs；按公里用 c=0.206 km/μs。
- 变体：p 可按地形固定（1.5/2）或按跃点表动态选择；不同取值会显著改变距离估计。
- 关联：[[defense-detection-ja4h-http-client-fingerprint]]（结合 JA4H 检测会话劫持）；[[defense-detection-ja4-tls-client-fingerprint-modular]]（TLS 客户端指纹）；[[defense-detection-ja4t-ja4ts-ja4tscan-tcp-fingerprint]]（TCP 层指纹与 TTL）。
- 边界：时间戳精度不足、代理/CDN/负载均衡、非对称路由、网络拥塞、初始 TTL 误判都会导致偏差；结果只能作为上限和辅助证据。

## 检测与防御

- 检测：对同一账号/会话的 JA4L 距离与登录地点、JA4H/JA4 变化做一致性校验；距离突变或不可能的低延迟远端告警。
- 基线：按业务区域/接入方式建立延迟与 TTL 基线；移动网络、卫星、VPN 需单独建模。
- 对抗：攻击者可通过代理/VPN 改变观测延迟；JA4L 只能作为组合特征。
- 合规：延迟测量属于流量元数据，采集与留存需符合隐私与数据治理要求。
