---
id: defense-detection-ja4t-ja4ts-ja4tscan-tcp-fingerprint
title: JA4T/JA4TS/JA4TScan TCP 指纹：窗口_选项序_MSS_窗口比例_重传时序 五段式识别 OS/VPN/代理/运营商
type: scenario
domain: defense
path: defense/detection
technique: ja4t-tcp-fingerprint
aliases:
- JA4T 指纹
- JA4TS 服务端指纹
- JA4TScan 主动指纹
- TCP SYN 指纹
- TCP 客户端指纹
- 窗口大小 MSS 窗口比例 指纹
- p0f Nmap Hershel+ 后继
tags:
- defense
- detection
- tcp
- fingerprint
- ja4
- ja4t
- ja4ts
- ja4tscan
- scanner
- vpn
- proxy
- network
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V442
  verified_at: '2026-11-09T22:51:19+08:00'
  notes: 已对照原文与全部21张图片核对：JA4T/JA4TS/JA4TScan 五段格式、OS/VPN/代理/运营商 MSS 示例（图10/11/12/13/14/17）、JA4TS 依赖客户端、JA4TScan 重传时序均与截图一致；PoC 仅为格式示意脚本。原文为翻译文章、无组件版本。
---

## 一句话结论

JA4T 把 TCP SYN 中的窗口大小、选项序列（按出现顺序的 kind 编号）、MSS、窗口比例按 `a_b_c_d` 拼成稳定、可共享的客户端指纹（JA4TScan 再追加第 5 段重传时序 `e`）；JA4TS 对 SYN-ACK 做同样记录；三者合起来可在不解密、不依赖 IP 的情况下识别操作系统/设备、VPN/隧道/代理、移动运营商与服务器实现。

## 原理

- **指纹构成**：格式为 `JA4T=窗口大小_选项序_MSS_窗口比例[_重传时序]`。例如 `65535_2-1-3-1-1-4_1460_8`：窗口 65535；选项按出现顺序是 MSS(2)、NOP(1)、Window Scale(3)、NOP(1)、NOP(1)、SACK permitted(4)；MSS 1460；窗口比例 8。选项 kind：0=EOL、1=NOP、2=MSS、3=Window Scale、4=SACK permitted、8=Timestamp。
- **为什么能区分操作系统**：SYN 的窗口初值、选项种类与顺序由各 OS 网络栈代码写死。典型示例：Windows 10 `64240_2-1-3-1-1-4_1460_8`；Ubuntu 22.04（Win10 WSL）`64240_2-4-8-1-3_1460_7`；macOS/iOS `65535_2-1-3-1-1-8-4-0-0_1460_6`——iOS 以两个 EOL(0) 凑 4 字节对齐而不是删 NOP，形成独特尾串；AWS Windows Server 2022 `62727_2-1-3-1-1-4_1460_8`、AWS Unix `62727_2-4-8-1-3_1460_7`。
- **MSS 反映路径开销**：以太网 MTU 1500 → IPv4 头 20 + TCP 头 20 后 MSS 1460；WireGuard 额外 80 字节开销对应 MSS 1380，OpenVPN 对应 1326。移动运营商各有固定 MSS：Verizon 1388、T-Mobile 1360、Google Fi 1348、Videotron 1400、Bell 1420，因此可由 MSS 推断运营商；iPhone 经 iCloud Relay 时指纹从 `65535_2-1-3-1-1-8-4-0-0_1460_6` 变为 `64240_2-4-8-1-3_1380_13`，可识别中继。
- **代理改变观察点**：客户端经代理连接时，服务端看到的是代理的 TCP 栈，JA4T 变成代理的指纹而不是真实客户端的，这也是识别"流量并非来自其声称位置"的手段。
- **JA4TS 是响应指纹且依赖客户端**：服务器对 SYN 的 SYN-ACK 只会包含客户端提议过的选项（客户端没提 SACK，服务器不会回 SACK），所以同一台服务器对不同客户端会产生多个 JA4TS。示例中同一 F5 BIG-IP 对 Windows 10 返回 `14600_2-1-3-4-0-0_1460_0`，对 Linux 返回 `14600_2-1-3-4-8_1460_0`。要拿服务器自身指纹需用 JA4TScan。
- **JA4TScan 主动指纹**：发送一个包含所有常见 TCP 选项的 SYN，不完成三次握手；不回应 SYN-ACK，而是记录服务器重传的间隔与次数，把间隔序列追加为指纹第 5 段（如 `..._1460_8_1-2-4-8-16`），观察到 RST 时前缀 `R`。重传节奏由 OS 网络栈决定（部分 IoT 设备不到 1 秒连发多次，桌面系统常见 1/2/4/8/16 秒退避），因此单包即可得到强指纹。
- **与 p0f / Nmap / Hershel+ 的区别**：后三者以"模糊匹配到已知 OS 列表"为目标，原始指纹常含跳数等随观察点变化的值，难以跨观测点共享；JA4T 去掉易变字段、保留握手元数据本身，可作为威胁狩猎的 pivoting 键，也能反向识别中间设备。

## 触发条件

- 在流量路径上能捕获完整 TCP SYN（被动 JA4T/JA4TS），或能向目标发送原始 SYN 并监听重传（JA4TScan，可用 zmap 类工具）。
- 有按 JA4T 格式提取字段的传感器/解析器（Wireshark、Arkime、防火墙、WAF、负载均衡器、NetFlow 传感器等均可部署）。
- 已有或可建立正常资产/设备/运营商的 JA4T 基线，用于对比异常。

## 利用步骤

1. 被动采集：抓取 SYN/SYN-ACK，提取窗口大小、选项 kind 序列、MSS、窗口比例，按 `窗口_选项_MSS_比例` 生成 JA4T/JA4TS。
2. 主动扫描：用 JA4TScan 向目标网段/单 IP 发单 SYN，记录 SYN-ACK 重传时序，生成 `..._e` 五段指纹；出现 RST 记录 `R` 前缀。
3. 归因：按选项序与窗口初值判 OS；按 MSS 与常规 1460 的差值判隧道/VPN/代理开销；按运营商 MSS 表判蜂窝网络；对比客户端与服务端指纹判断中间代理。
4. 建库与比对：把资产、业务客户端、已知扫描器/设备的指纹入库，对异常指纹做告警或阻断（指纹级阻断见关联卡）。
5. 组合分析：JA4T 与 JA4（TLS ClientHello）、JA4H（HTTP 头）联动，避免单一指纹误判。

## PoC

无现成利用代码（方法学场景）。指纹拼接最小示例：

```python
def ja4t(window, option_kinds, mss, wscale):
    return f"{window}_{'-'.join(map(str, option_kinds))}_{mss}_{wscale}"

# Windows 10 典型 SYN
assert ja4t(64240, [2,1,3,1,1,4], 1460, 8) == "64240_2-1-3-1-1-4_1460_8"
# Windows 10 经 WireGuard：MSS 变为 1380
assert ja4t(64860, [2,1,3,1,1,4], 1380, 8) == "64860_2-1-3-1-1-4_1380_8"
# iPhone 经 OpenVPN：MSS 变为 1326
assert ja4t(65535, [2,1,3,1,1,8,4,0,0], 1326, 6) == "65535_2-1-3-1-1-8-4-0-0_1326_6"
```

## 变体与关联

- 变体：JA4TS 用于服务端响应聚类；JA4TScan 追加重传时序得到更强的主动指纹，并可用于资产测绘。
- 变体：JA4T 与 JA4（TLS）、JA4H（HTTP）组合，可同时刻画同一来源的传输层、TLS 层与应用层实现。
- 关联：[[defense-detection-ja3-tls-fingerprint-suricata]]（TLS 层 JA3 检测与阻断）；[[defense-detection-ja4t-greynoise-syn-block-scanner]]（用 JA4T 在 SYN 阶段阻断扫描流量）。

## 检测与防御

- 检测：对边界流量统计 JA4T/JA4TS 分布，出现新指纹、指纹与资产声明 OS 不符、MSS 与链路类型不符、客户端经代理导致指纹"换栈"等均可作为线索。
- 防御：把已知扫描器/恶意工具指纹做成阻断规则（在 SYN 阶段丢弃），并对合法 ASM/扫描资产建立白名单；不要只凭单一指纹阻断业务流量。
- 局限：攻击者可定制 TCP 栈参数伪装指纹；NAT/代理/中间设备会改变观察值，需按观测点分别建库。
