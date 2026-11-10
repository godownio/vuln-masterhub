---
id: defense-detection-merlin-pivot-protocol-split-identify-c2
title: 从协议分工识别 Merlin 多层跳板后的真实 C&C：P2P 跳板走 SMB/TCP/UDP、上线/代理走 HTTP 系协议，外联地址即 C&C
type: scenario
domain: defense
path: defense/detection
technique: merlin-protocol-split-c2-attribution
aliases:
- 识别 C&C 地址
- 跳板网络 C2 溯源
- 协议分工判据
- 外联地址即控制端
- Merlin 上线协议
- P2P 跳板协议
- 多层跳板 C2 归因
tags:
- defense
- detection
- c2
- merlin
- traffic-analysis
- pivot
- c2-attribution
- protocol-fingerprint
- threat-hunting
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-1
  verified_at: '2026-11-07T22:59:39+08:00'
  notes: 已对照原文与 50 张图片逐张核对：协议分工（P2P 跳板走 SMB/TCP/UDP、上线/代理走 HTTP 系）、main.go switch protocol case http/https/h2/h2c/http3 → http.Config{Host,Proxy}（img50）、各组合抓包证据、文章『外联地址即 C&C』判据均与 content.md 一致；为检测/威胁猎捕判据卡（非漏洞利用链），路径合法，dedup 非同链、dup-scan 无 pair；未验证点：结论为作者标注的推测性经验判据（confidence low），需与配置/内存/端点日志交叉验证，TLS/域前置/合法 CDN 场景可能不成立；未在本机复跑，该批次卡按 KB 现状不含 sources/source_url 溯源字段。
---

## 一句话结论

Merlin Agent 在多层跳板网络里不同通信环节使用不同协议：Agent 与 Agent 之间的 P2P 跳板只用 SMB/TCP/UDP（bind/reverse），而 Agent 到 Server 的上线通信与 `-proxy` 代理通信只用 HTTP/HTTPS/H2C/HTTP2/HTTP3；因此在流量中一旦出现 HTTP 系协议（或 proxy 代理通信），其目的外联地址（样本配置/命令行中的 `-url`、`-proxy`、`Host`）基本可判定为真实 C&C，即使中间经过多级跳板也能把 C2 从代理链中剥离出来。

## 原理

- **源码印证**：`main.go` 的 `switch protocol { case "http", "https", "h2", "h2c", "http3": clientConfig := http.Config{ Host: host, Proxy: proxy, ... } }` —— 这 5 种协议走统一的 `http.Config`，外联地址来自 `host`（`-url`）与 `proxy`（`-proxy`）；而 `tcp/udp/smb` 的 bind/reverse 走 `clients/` 下各自 `Connect()`，地址来自 `-addr`（对端 Agent），不接触 Server。
- **协议分层**：Server ↔ Gateway Agent 是 HTTP 系（或经 socks5 代理仍承载 HTTP 系请求）；Gateway ↔ 二级 Agent、二级 ↔ 三级是 TCP/UDP/SMB 原始载荷（抓包为自定义端口 7777/6666、SMB2 445）。只有最外层那一段会呈现 HTTP/HTTPS/H2C/HTTP2/HTTP3 特征。
- **为什么成立**：P2P 跳板是「转发 Agent 消息」的纯传输层，不需要 HTTP 语义；上线/代理才需要构造 Merlin 的 HTTP 请求（OPAQUE/JWT/transformers 加密载荷）。这一分工由 CLI 参数与源码 switch 决定，与是否多层、是否叠加端口转发无关。
- **判据（文章结论）**：若在 Merlin 通信流量中发现使用 HTTP/HTTPS/H2C/HTTP2/HTTP3 通信或 proxy 代理通信，则可基本确定 Merlin Agent 配置信息或运行命令行中的外链地址即为控制端 C&C 地址。作者注明这是「推测由于此项目还在持续更新，因此导致不同通信环节使用不同通信协议」，故本判据是经验性/带推测性的，需与其它证据交叉验证。
- **对多层网络的价值**：跳板网络的目的就是隐藏真实来源；但只要守住「哪一段是 HTTP 系」这一特征，就能从最内层 SMB/TCP/UDP 链路一路向外剥离到唯一的外联 HTTP 地址，避免把 socks5 代理、端口转发主机或中间 Agent 误当成 C2。

## 触发条件

- 已捕获疑似 Merlin Agent 的多段通信流量（含内网跳板段与出口段），或拿到样本配置/命令行。
- 能区分 HTTP 系协议（HTTP/1.1 明文或 TLS 上的 HTTP/2、H2C clear-text、QUIC 上的 HTTP/3）与 SMB/TCP/UDP 原始 P2P 载荷。
- 目标是穿透多层跳板还原真实 C&C（而非解密载荷内容）；需授权应急响应/威胁猎捕环境。

## 利用步骤

1. 在出口/边界抓包并按协议分类：出现 HTTP POST（`application/octet-stream`、JWE 头加密载荷）、TLS 443、HTTP2 `SETTINGS/HEADERS`、QUIC `Initial` 的一段是「上线/代理段」。
2. 内网段抓包若只见 TCP/UDP 自定义端口（如 7777/6666）长连接，或 SMB2 `Negotiate`/`Tree Connect`/`Ioctl FSCTL_PIPE_WAIT`（管道名如 merlinpipe），则这些是 Agent 间 P2P 跳板，不是 C2。
3. 从上线/代理段提取目的 IP/端口，结合样本命令行 `-url https://...`、`-proxy socks5://...`、`Host` 得到外联地址 → 判定为真实 C&C；若外联是 socks5 代理，则继续向代理另一侧追（代理只是中转）。
4. 对多层网络逐段剥离：先定位唯一的 HTTP 系出口，再沿 TCP/UDP/SMB 链路向内回溯每一跳，还原完整跳板拓扑（含 `netsh portproxy` 转发主机）。
5. 与内存/配置取证交叉验证（如 Merlin 系列 OPAQUE 会话密钥解密卡），确认 C2 归属与攻击者指令。

## PoC

```text
抓包特征（Wireshark，按文章各组合实验）：
- 上线/代理段：192.168.64.154 -> 192.168.64.128:80   HTTP/1.1 POST /（JWE 加密载荷）
              :443 TLSv1.3 / HTTP2 SETTINGS、HEADERS / QUIC Initial（HTTP3）
- P2P 跳板段：TCP 7777 / UDP 7777 / TCP 6666（portproxy）
              SMB2 Negotiate Protocol / Tree Connect \\...\IPC$ /
              Ioctl Request FSCTL_PIPE_WAIT Pipe: merlinpipe
判定：HTTP 系那一段的目的 192.168.64.128（或 -proxy 代理另一侧的 -url）为真实 C&C；
      TCP/UDP/SMB 段只是 Agent 间转发，逐跳向内回溯即可还原拓扑。
```

（按文章抓包与 `main.go` 的 `switch protocol` 最小化整理，未在本机复跑；结论为经验性判据。）

## 变体与关联

- 变体：HTTPS/HTTP2/HTTP3 因 TLS/QUIC 加密看不到明文，用 SNI/证书/JA3/JA4/ALPN、QUIC 版本与端口 443 特征辅助识别 HTTP 系段。
- 变体：`-proxy` 仅配合 `http`/`https`；官方文档明确 HTTP/2（h2）不支持 proxy 且 Agent 不自动检测系统代理，可作排除条件——若出口是 socks5 代理，则代理另一侧才是 C&C。
- 变体：协议清单可能随 Merlin 版本变化（上线 HTTP/HTTPS/H2C/HTTP2/HTTP3、跳板 SMB/TCP/UDP），用样本自身 `switch protocol` 与 `-proto` 取值校准，不要硬编码。
- 关联：[[defense-forensics-merlin-agent-opaque-memory-secret-traffic-decrypt]]（同系列：内存取 OPAQUE 会话密钥解密 HTTP/H2C/SMB/TCP/UDP 各协议流量；本卡只做地址归因、不解密）、[[pentest-c2-merlin-agent-multi-proto-p2p-pivot-proxy-chain]]（攻击侧对应跳板搭建方法）、[[pentest-c2-beacon-tcp-smb-tree-cascade-forward-routeid]]（其它 C2 的 TCP/SMB 级联）。
- 局限：判据基于当前 Merlin 实现的协议分工，作者自己标注为「推测」；非 Merlin C2 不适用；TLS/域前置/合法 CDN 会让外联地址不等于真实 C&C；单独使用易把代理或合法服务误判。

## 检测与防御

- 网络侧：对 HTTP 系 C2 上线流量做 JA3/JA4、TLS 证书、HTTP/2 SETTINGS 指纹、QUIC Initial、心跳周期与固定载荷大小检测；对内网 SMB 命名管道（随机名或固定 merlinpipe）、非业务端口长连接、`netsh portproxy` 注册表项做 EDR 告警。
- 处置：定位 C&C 后封禁外联，沿 TCP/UDP/SMB 链路隔离各跳板主机，抓取进程内存与命令行配置，轮换凭据并修复初始入口。
- 边界：本方法是授权应急响应/威胁猎捕思路，本身不产生攻击危害；结论须与配置、内存、端点日志交叉验证；HTTPS 场景需 TLS 密钥或在端点侧取证才能进一步解密内容。
