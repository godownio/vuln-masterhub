---
id: defense-forensics-qemu-socket-tunnel-pcap-extract
title: QEMU socket 隧道流量取证：4 字节长度前缀 + 以太网帧，editcap 去 58 字节还原内层 PCAP
type: scenario
domain: defense
path: defense/forensics
technique: qemu-socket-tunnel-traffic-extraction
aliases:
- QEMU 隧道流量分析
- netdev socket 封装格式
- 4 字节长度 以太网帧
- editcap -C 58
- QEMU 内层流量还原
- 52:54:00 MAC 特征
tags:
- forensics
- traffic-analysis
- qemu
- tunnel
- pcap
- wireshark
- editcap
- rdp
- pivoting
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502
  verified_at: '2026-11-11T03:08:22+08:00'
  notes: 已对照原文与图05/06核对：图05 内层 Frame 48 89 字节、Src MAC 52:54:00:12:34:56（RealtekU_12:34:56）、10.0.2.15→192.168.56.109:3389、TPKT/X.224 CR、Cookie mstshash=Admin，与卡片内层特征一致；图06 外层 Frame 2128 147 字节、TCP Len 93（=4 字节长度+89 字节内层帧），印证 4 字节长度前缀+以太网帧的封装（该截图 Wireshark 将其标为 TLS，应为同 pcap 其他 443 流或载荷中间段，原文正文明确'不使用任何额外加密'，不影响结论）。已核对 QEMU v8.1 net/socket.c net_socket_send 用 htonl(size) 写 4 字节网络字节序长度，卡片字节序描述正确；editcap 手册确认 -C 正数从包首 chop、-L 调整包长，-C 58=14+20+20+4 正确。TCP 选项/VLAN/IPv6 偏移边界说明合理。dedup 候选为 Kimsuky/PyInstaller/AhMyth/CAN/TLS keylog 等不同封装，非同链；dup-scan.json 早于建卡不涉及本卡；frontmatter 无 sources/source_url；非组件无版本。
---

## 一句话结论

QEMU 的 `-netdev socket` 隧道不加密：外层 TCP 载荷由"4 字节大小 + 原始以太网帧"组成，抓到 pivot 主机上的流量后，过滤出该 TCP 会话，用 `editcap -L -C 58 original.pcap extracted.pcap` 去掉每包 14 字节以太网 + 20 字节 IP + 20 字节 TCP 头 + 4 字节长度前缀，即可得到内层封装流量（示例为 Kali 经隧道对 192.168.56.109:3389 的 RDP 连接），再用 Wireshark 正常解析内层 IP/TCP/RDP。

## 原理

- **封装格式**：QEMU socket 后端把虚拟网卡发出的每个以太网帧按 `uint32 长度(网络字节序) || Ethernet frame` 发到 TCP 流；接收端按长度读取完整帧。外层没有 TLS/SSH 等额外加密，只有 TCP/IP 头与这 4 字节长度。原文示例封装帧长 89（0x59）字节，紧跟在 4 字节长度之后。
- **为什么可以按固定偏移剥离**：在一个不含 TCP 选项的 IPv4/TCP 外层包中，链路层 14 字节 + IP 头 20 字节 + TCP 头 20 字节 + 长度字段 4 字节 = 58 字节，之后就是内层以太网帧。`editcap -L -C 58` 会从每个包截掉前 58 字节（`-C` 为 chop 指定字节数，`-L` 调整长度字段），得到只含内层流量的 pcap。
- **偏移的边界**：若外层 TCP 头带选项（如时间戳，常见 12 字节）、VLAN 标签、IPv6 或 IP 选项，则 58 不是正确偏移，需要按实际报文头长度计算；`editcap -C` 对整个文件是统一的，必要时先过滤/重算或用脚本按 TCP data offset 动态剥离。
- **内层可读特征**：示例内层以太网帧源 MAC 为 QEMU 默认 `52:54:00:12:34:56`，源 IP `10.0.2.15`（QEMU user 模式 NAT 的 guest 地址），目的为内网主机，TCP 目标端口 3389，载荷是 RDP 的 TPKT/X.224（`03 00 ...`，含 `Cookie: mstshash=<user>`）。这些是判断"QEMU 隧道 + RDP 横向"的强特征。
- **为什么取证可行**：封装是明文且带显式长度，任何能看到 pivot 出站流量的位置（主机抓包、边界镜像、流量传感器）都能还原内层会话；QEMU 进程命令行（`-netdev socket,connect=... -netdev hubport...`）可与流量互相印证。
- **边界**：若攻击者在 QEMU 外层再套 TLS/SSH/代理，或使用加密的替代后端，则不能直接剥离；仅抓到部分包（丢包）会导致长度字段与帧边界错位，需要按 TCP 流重组后再切分；`editcap -C 58` 只适用于无 TCP 选项的 IPv4 外层。

## 触发条件

- 能在 pivot 主机或网络边界抓到 QEMU socket 隧道的完整 TCP 流（或足够重组的数据包）。
- 确认外层连接为 443/其他端口的裸 TCP，载荷不是 TLS（无 ClientHello），前 4 字节为后续帧长度。
- 外层 IPv4/TCP 头无选项/无 VLAN，或分析者能按实际头长调整偏移。

## 利用步骤

> 以下为防御方取证步骤。

1. 定位可疑流：在 pcap 中筛选到外部 IP、常见 443 端口但没有 TLS 握手的长连接；查看 TCP 载荷前几字节是否呈现"4 字节长度 + 以太网头（目的/源 MAC 前 6 字节）"结构。
2. 只保留该 TCP 会话的数据包：在 Wireshark 用 `tcp.stream eq <n>` 过滤后导出，或在 `editcap`/`tshark` 中按五元组筛选。
3. 剥离外层头：对无 TCP 选项的 IPv4 抓包执行 `editcap -L -C 58 original.pcap extracted_traffic.pcap`；若 TCP 头有选项，按 `14 + IP头长 + TCP头长 + 4` 计算并调整 `-C`。
4. 用 Wireshark 打开提取后的 pcap：应看到完整的以太网/IP/TCP 内层会话；检查 QEMU 默认 MAC `52:54:00`、user-net `10.0.2.0/24`、内网目标 IP 与端口。
5. 还原应用层：如 3389 上的 TPKT/X.224/RDP（`mstshash` cookie 可暴露用户名）、445/SMB、HTTP 等；提取被访问的内网资产清单。
6. 与主机侧证据关联：QEMU 进程命令行（无镜像、`-m 1M`、socket/hubport 参数）、二进制哈希、启动时间与网络连接时间线。
7. 输出报告：隧道两端 IP/端口、内层会话、访问过的内网主机与账户、可能被横向的目标。

## PoC

```bash
# 只保留隧道 TCP 流后，剥离 14(Ethernet)+20(IPv4)+20(TCP)+4(QEMU 长度) = 58 字节
editcap -L -C 58 original.pcap extracted_traffic.pcap
```

```text
# 内层帧特征（示例）
Ethernet II: Src 52:54:00:12:34:56 (QEMU 默认 MAC) -> Dst <内网主机 MAC>
IPv4: 10.0.2.15 -> 192.168.56.109
TCP: <随机源端口> -> 3389
TPKT/X.224: CR Connect Request, Cookie: mstshash=<user>
```

说明：`editcap -C 58` 仅适用于外层为无选项 IPv4/TCP 的抓包；实际偏移需按报头长度核对。

## 变体与关联

- 关联：QEMU 无盘 socket 隧道的搭建与检测见 [[pentest-lateral-movement-qemu-socket-netdev-diskless-tunnel]]；本卡只处理流量取证与内层还原。
- 变体：外层 TCP 带时间戳/VLAN/IPv6 时，用脚本按 `14 + ip_header_len + tcp_data_offset + 4` 动态剥离，或先用 Wireshark 导出 TCP 载荷再按长度字段切分。
- 变体：QEMU `-netdev stream`/`dgram` 后端的封装可能不同；若外层再叠加 TLS/SSH，需要先解密外层。
- 边界：丢包/乱序导致帧边界错位时，先按 TCP 流重组；加密隧道无法直接还原，只能依赖端点内存/进程取证。

## 检测与防御

- 检测：443 等端口上的长连接没有 TLS 握手，载荷呈现"4 字节长度 + 以太网帧"；内层出现 QEMU 默认 MAC `52:54:00:xx:xx:xx`、`10.0.2.0/24` 源地址；同一外部 IP 与内网主机之间出现异常的 RDP/SMB/HTTP 会话。
- 检测：主机侧 `qemu-system-*` 进程无磁盘镜像、`-m` 极小、含 `-netdev socket`/`hubport`/`-nographic`；进程启动后出现到外部 IP 的 443 连接。
- 防御：出站按协议而非端口管控（443 必须真的是 TLS）；应用白名单限制 QEMU；对虚拟化软件网络参数做命令行审计；保留足够长的流量用于回溯。
- 响应：按上述流程还原内层会话，列出被访问资产与账户，封禁外联地址，终止 QEMU 并排查同源 pivot。
