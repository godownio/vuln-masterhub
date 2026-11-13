---
id: defense-detection-ja4ssh-ssh-traffic-fingerprint
title: JA4SSH SSH 会话指纹：200 包窗口内 Payload 长度众数、方向包数与 ACK 数
type: scenario
domain: defense
path: defense/detection
technique: ja4ssh-ssh-traffic-fingerprint
aliases:
- JA4SSH 指纹
- SSH 流量指纹
- SSH Payload 长度众数
- SSH 隧道检测
- ja4.ja4ssh
tags:
- defense
- detection
- ssh
- ja4
- fingerprint
- traffic-analysis
- tunneling
- lateral-movement
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:39:03+08:00'
  notes: 已对照原文与图35-37核对：每 200 包窗口、a=客户端/服务端 TCP Payload 长度众数、b=双方 SSH 包数（和 200）、c=纯 ACK 数；交互式 c36s36_c51s80_c69s0、反向 c76s76_c71s59_c0s70、WinSCP c112s1460_c0s179_c21s0 与幻灯片一致；修正 c 段方向表述：纯 ACK 由发起方（如敲键盘的一侧）发送，与幻灯片一致。未实测抓包。
---

## 一句话结论

JA4SSH 在每 200 个 SSH 包的窗口内提取三类统计：客户端/服务端 TCP Payload 长度的众数（`a` 段）、双方发送的 SSH 包数（`b` 段）、双方的纯 ACK 数（`c` 段）；即使 SSH 内容加密，也能用流量形状识别交互式会话、SCP/SFTP 传输、SSH 隧道、爆破与横向移动。

## 原理

- SSH 的载荷长度由加密算法、MAC/填充和上层行为共同决定：交互式输入一个字符时，chacha20-poly1305 会把载荷填充到固定最小长度（示例 36 字节）；文件传输时服务端可达到 MSS 最大值（如 1460）；隧道/端口转发则呈现不同的双向长度组合。
- **JA4SSH_a**：`c<客户端Payload长度众数>s<服务端Payload长度众数>`，单位是 SSH（TCP Payload）长度，不是整帧长度；可用 Wireshark `tcp.len` 观察。
- **JA4SSH_b**：`c<客户端SSH包数>s<服务端SSH包数>`，默认统计窗口为 200 个 SSH 包，两者相加为 200。
- **JA4SSH_c**：`c<客户端纯ACK数>s<服务端纯ACK数>`；纯 ACK 指不带载荷的确认包，通常由**发起方**（如正在敲键盘/接收数据的一侧）发送。结合 ACK 方向与 Payload 长度可判断谁在发送数据、是否存在单向大流量。
- 示例：
  - 交互式 `c36s36_c51s80_c69s0`（chacha20-poly1305 最小 36 字节）；
  - 反向 SSH `c76s76_c71s59_c0s70`（双向 double padding 到 76）；
  - WinSCP 文件传输到客户端 `c112s1460_c0s179_c21s0`（服务端载荷达最大窗口 1460）。
- 为什么有效：SSH 内容加密但报文长度、方向、ACK 节奏是明文可见的；不同客户端/行为模式在 200 包窗口内形成稳定统计。
- 与 HASSH 的区别：HASSH 基于 SSH 握手算法协商（KEX/加密/MAC 列表），JA4SSH 基于会话流量形状；两者可互补。

## 触发条件

- 能捕获 SSH 会话流量（TCP 22 或自定义端口），无需解密。
- 采集工具支持 JA4SSH：Wireshark 4.2+ 原生或 ja4.dll 插件（自定义列 `ja4.ja4ssh`），或自写统计脚本。
- 有正常业务/客户端/运维行为的基线，用于对比异常。

## 利用步骤

1. 抓取 SSH 会话；按 200 个 SSH 包为窗口切分（默认）。
2. 统计每个方向 TCP Payload 长度的众数，生成 `JA4SSH_a`。
3. 统计双方 SSH 包数，生成 `JA4SSH_b`（和应为 200）。
4. 统计双方纯 ACK 数，生成 `JA4SSH_c`。
5. 与基线比对：交互式、SCP/SFTP、端口转发、隧道、爆破的成功/失败模式在长度众数与 ACK 分布上不同。
6. 对可疑会话（如内网主机大量出站 SSH、服务端 1460 单向大流量、双向 76 字节的隧道特征）结合 JA4/JA4H、登录日志与进程行为研判。

## PoC

```text
# Wireshark 观察
tcp.len            # SSH Payload 长度
ja4.ja4ssh         # JA4SSH 列/字段（版本/插件而定）

# 示例
JA4SSH = c36s36_c55s75_c70s0
         └ a: 客户端/服务端 Payload 长度众数
                 └ b: 客户端/服务端 SSH 包数（和 200）
                          └ c: 客户端/服务端纯 ACK 数

# 文章样例
交互式 SSH        = c36s36_c51s80_c69s0
反向 SSH          = c76s76_c71s59_c0s70
WinSCP 文件传输   = c112s1460_c0s179_c21s0
```

说明：示例值取自文章截图，未在本地复算；窗口大小、纯 ACK 判定与客户端/服务端方向需按实现核对。

## 变体与关联

- 变体：SCP/SFTP、端口转发、X11 转发、SSH 隧道、爆破失败/成功会形成不同的长度/包数/ACK 组合。
- 变体：chacha20-poly1305、AES-GCM 等不同算法的填充规则不同，最小长度会变化；比较时需按算法分组。
- 关联：[[defense-detection-ja4-tls-client-fingerprint-modular]]（TLS 层 JA4）；[[defense-detection-ja4h-http-client-fingerprint]]（HTTP 层 JA4H）；[[defense-detection-ja4t-ja4ts-ja4tscan-tcp-fingerprint]]（TCP 层 JA4T）。
- 边界：SSH 内容加密但长度可见；代理/隧道/填充会改变统计；200 包窗口可能跨多个逻辑会话；JA4SSH 不能单独证明恶意。

## 检测与防御

- 检测：对出站 SSH 做 JA4SSH 基线，识别交互式/传输/隧道模式；对非运维时段、非运维主机、异常方向的大流量告警。
- 隧道识别：双向固定长度（如 76 字节）或上下行比例异常的 SSH 会话，结合进程/命令行与登录日志判断是否为隧道。
- 横向移动：内网主机之间出现 SSH 连接、同一账号短时间多目标登录、SCP 大文件传输等组合告警。
- 对抗：攻击者可通过 SSH 填充、代理链改变流量形状；JA4SSH 只能作为组合特征。
- 合规：仅使用流量元数据与长度统计，不涉及解密内容。
