---
id: code-analysis-dynamic-tracing-ebpf-protocol-stack-packet-callchain
title: eBPF 协议栈透视：起点函数+线程ID把数据包绑定到内核函数调用链
type: scenario
domain: code-analysis
path: code-analysis/dynamic/tracing
technique: ebpf-protocol-stack-packet-callchain-tracing
aliases:
- PacketScope Tracer
- 协议交互透视镜
- 协议栈可见性
- sk_buff 调用链追踪
- 数据包函数调用链关联
- 跨层交互追踪
tags:
- linux
- kernel
- ebpf
- kprobe
- tcpip
- network
- tracing
- sk-buff
- packet-analysis
- observability
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V241
  verified_at: '2026-11-07T13:11:13+08:00'
  notes: 已对照原文与11张图核对；起点函数、线程 ID/时间戳关联、调用链与聚合图指标均一致；原文无命令行 PoC。
---

## 一句话结论

在协议栈收发路径的“起点函数”（`ip_rcv`/`ip_rcv_core`/`tcp_sendmsg`/`udp_sendmsg` 等）上挂 eBPF 探针，进入和返回时记录网络四元组、线程 ID 与时间戳，再按线程内调用连续性把这段时间窗内的内核函数调用串起来，就能把每个数据包绑定到它在协议栈中经过的完整函数调用链，形成可下钻的跨层交互图。

## 原理

- eBPF 允许在不修改内核源码或协议栈代码的前提下，在内核函数上挂 kprobe/kretprobe，记录每次调用的线程 ID 与时间戳。
- **起点函数界定一个包的处理边界**：一次 `sendmsg`/`recvmsg` 路径从起点函数进入，到其返回，期间同一线程执行的内核函数都属于该包的处理链。原文列出的起点函数包括 `icmp_push_reply`、`rawv6_sendmsg`、`raw_sendmsg`、`udp_sendmsg`、`udpv6_sendmsg`、`tcp_sendmsg`、`ip_rcv_core`、`ip6_rcv_core`、`ipv6_rcv`、`ip_rcv`、`ip_list_rcv`、`ipv6_list_rcv`。
- 只按函数名收集事件会产生海量噪声；用**线程 ID 过滤 + 时间戳排序 + 调用连续性（CALL/RETURN 配对）**把离散事件聚成链，再用起点函数的调用/返回把链切分成“一个包一份”。
- 网络四元组（源/目的 IP、源/目的端口；界面五元组另含协议类型）从 socket/sk_buff 取得，用于把函数链绑定到具体流；这样同一线程处理多个包时不会串链。
- 关键内核函数按两类条件筛选：函数名包含 `tcp`、`udp`、`icmp`、`recv`、`send`、`xmit`、`ip`、`sk`、`sock` 等字段，或与核心结构 `sk_buff` 的调用关联频繁。
- **为什么成立**：内核网络栈的收包在软中断/线程上下文内顺序经过链路层→网络层→传输层，发包同理；eBPF 记录的是运行时实际执行路径（含条件分支与协议分发），而不是静态调用图，因此能把“包”和“实际经过的函数”对应起来。
- 在链路层、网络层、传输层各选代表函数插桩，可量化三个指标：层流量（包经过该层插桩点的次数）、跨层交互频率（各层关键函数之间的流转频率）、跨层延迟（层间流转耗时）。可视化中函数平均耗时越长颜色越深，调用次数越多连线越粗。

## 触发条件

- Linux 内核支持 eBPF 与 kprobe；原文在 Linux 6.8 内核完成测试部署。
- 具备 root/CAP_BPF 权限，且内核未通过 lockdown/LSM 禁止探针挂载。
- 能解析内核符号（或 BTF）以按函数名插桩并读取参数。
- 目标 socket 活跃，处于 ESTABLISHED、LISTEN 等可观测状态。
- 追踪有运行开销；高 PPS 或探针数量大时需控制过滤与采样。

## 利用步骤

1. 部署并启动 PacketScope（原文为 1.0 版，当前 1.1.0）。启动监控后读取内核套接字列表，按五元组和 TCP 状态（ESTABLISHED/LISTEN 等）展示所有活跃连接；界面上方可看到 TCP/UDP/RAW/ICMP 连接计数与网卡统计。
2. 选中目标 socket 进入监控，使用**包分析器**查看该流的数据包：时间戳、网口号、方向（入包/出包）、包长度、IPv4 源/目的地址、协议号、TTL、分片信息、可选字段，以及十六进制原始内容。
3. 使用**函数调用链监控器**按 CALL/RETURN 逐级展开。原文示例的 TCP 接收链为：`ip_rcv_core → ip_local_deliver → ip_local_deliver_finish → ip_protocol_deliver_rcu → tcp_v4_rcv → tcp_filter → sk_filter_trim_cap → tcp_v4_fill_cb → tcp_v4_do_rcv → ipv4_dst_check → tcp_rcv_established`；右侧函数详情显示函数名、调用类型、时间戳、函数 ID、线程 ID、调用深度与元数据。
4. 查看聚合的**函数调用关系图**：节点为函数（标注调用次数/平均耗时），有向边为调用关系；颜色深浅表示平均耗时（越长越深），线宽表示调用次数（越多越粗）。可按耗时阈值过滤，只保留高延迟节点，用于定位瓶颈或异常高频函数。
5. 使用**协议栈监控器**查看传输层/网络层/链路层的发送/接收包数、PPS、跨层延迟、跨层交互频率与丢包率，辅助定位耗时层与故障点。

原文只提供 GUI 操作与截图，没有命令行 PoC。若要自建最小验证，可按同一思路用 bpftrace 在相同起点函数挂 `kprobe`/`kretprobe`，按 `tid` 过滤并记录四元组与时间戳后聚合（这是派生实现思路，原文未给出、本库未验证）。

## PoC

无 PoC（原文为工具功能演示，未提供脚本、命令或可执行复现）。

## 变体与关联

- 不用 eBPF 时可用 ftrace `function_graph` 获得内核函数调用图，但没有按包四元组/线程关联的语义；参见 ftrace 定位 syscall 内核错误返回点的场景卡。
- 在 `SSL_read`/`SSL_write` 等用户态库边界加 uprobe，可把内核处理链延伸到应用层明文语义；参见 Agent 运行时 FUSE+eBPF+uprobe 因果链场景卡。
- 安全分析用途：对可疑流定位其实际经过的协议栈函数、发现异常的跨层调用或高频探测；性能用途：按函数耗时与跨层延迟定位瓶颈。
- 局限：只覆盖本机协议栈处理路径，不覆盖硬件卸载/旁路路径；加密流量只能看到密文包与内核处理链，看不到应用层明文。

## 检测与防御

- 该能力本身是观测/防御向：可用于发现协议函数被异常高频调用、跨层交互异常、可疑流的内核处理路径。
- 若环境不允许此类内核观测：启用 kernel lockdown、收紧 CAP_BPF/CAP_SYS_ADMIN、用 LSM 限制 kprobe，并审计 `bpf()` 与 kprobe 注册行为。
- 性能与稳定性：探针数量和事件量会放大开销，生产环境应限制过滤条件、缩小插桩函数集或采样，避免环形缓冲区被噪声覆盖。
