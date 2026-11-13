---
id: code-analysis-dynamic-debugging-nonblocking-socket-second-recv-pacing
title: 重建后门控制端时非阻塞 socket 第二次 recv 立即失败：两次 send 间加延时或配合调试器步过
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: nonblocking-socket-second-recv-pacing
tags:
- debugging
- socket
- non-blocking
- recv
- c2
- malware-analysis
- protocol-rebuild
- windows
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V628
  verified_at: '2026-11-12T23:33:55+08:00'
  notes: 已对照原文全文与30张截图核对：正文明确记载NukeSped样本两次recv（先头后载荷）、样本使用非阻塞socket、第二次recv总在载荷到达前失败；解决方案为控制端第二次send处下断点并在样本第二次recv前步过，最终代码在两次Write间加time.Sleep(2*time.Second)，图27/28显示断点位于第二次conn.Write处。卡中WSAEWOULDBLOCK/EAGAIN为示例性错误类型，原文未点名但属非阻塞socket通用表现。该卡为通用调试技巧，与NukeSped样本卡原子拆分且互相引用；dedup候选Remcos仿真/ICMP隧道/CrimsonRAT及minihttpd二次recv pwn卡均非同一场景，保留。无版本信息。
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-nonblocking-socket-second-recv-pacing/
draft: false
kb_aliases:
- 非阻塞 socket 调试
- 第二次 recv 失败
- WSAEWOULDBLOCK
- 控制端重建时序
- 分段发送调试
- NukeSped 控制端调试
---

## 一句话结论

后门样本用非阻塞 socket 时，接收一次上线响应要分两次 `recv`（先头、再载荷）；如果自研控制端把“响应头 + 载荷”两条 `send` 连续发出，样本的第二次 `recv` 往往在载荷到达前就执行，非阻塞模式下立即返回失败（WSAEWOULDBLOCK），载荷永远收不到。解决办法是在两次发送之间加延时（如 500ms~2s），或调试时在控制端第二次发送处下断点、先步过该断点再让样本继续执行。

## 原理

- **阻塞 vs 非阻塞**：阻塞 socket 的 `recv` 在无数据时会一直等待；非阻塞 socket 的 `recv` 无数据立即返回错误/空值，由程序自行轮询。恶意样本为了不阻塞主循环，常用非阻塞 socket。
- **两次 recv 的协议**：样本先 `recv` 一小段缓冲区解析 HTTP 响应头（`Sec-Fetch-Mode`/`Content-Length`），再按长度 `recv` 负载。头与载荷是两次独立的读。
- **TCP 粘包/分段与调度**：控制端连续两次 `send` 时，第二段数据可能还在内核发送缓冲/网络中，Python/Go 控制端与样本又分别在不同机器/进程调度；样本第二次 `recv` 抢跑时内核接收缓冲里只有第一段，非阻塞模式下立刻返回，样本按“接收失败”处理，出现“头能收到、载荷收不到”的现象。
- **为什么加延时有效**：两次 `send` 之间 `sleep` 给内核和样本留出处理时间，样本第二次 `recv` 时载荷已在内核缓冲中，可正常读出。
- **调试器方案**：在控制端第二次 `send` 处下断点、在样本第二次 `recv` 处下断点；先运行样本停在第二次 `recv` 前，再步过控制端第二次发送断点，使载荷先进入缓冲，随后放行样本，即可稳定接收。

## 触发条件

- 被模拟的样本/客户端使用非阻塞 socket，且一次响应分多次 `recv`。
- 自研控制端把响应头和载荷连续 `send`，中间无延时。
- 控制端与样本不在同一进程/机器，或调试时单步执行放大了时序差异。

## 利用步骤

1. 现象定位：控制端发出头和载荷后，样本只处理了头，第二次 `recv` 日志/返回值显示立即失败（如 WSAEWOULDBLOCK / EAGAIN）。
2. 确认样本 socket 模式：逆向中查看 `ioctlsocket(FIONBIO)` 或 non-blocking 标志，以及 `recv` 的调用次数与错误分支。
3. 修复方案一（代码）：两次 `send` 之间加 `time.Sleep(500 * time.Millisecond)`（原文使用 `Sleep(2s)`/`time.Sleep(2 * time.Second)`），必要时先发头、等样本发起第二次 `recv` 附近再发载荷。
4. 修复方案二（调试）：控制端第二次发送处下断点，样本第二次 `recv` 处下断点；样本先停住，步过控制端断点后再继续样本；反复调试验证。
5. 回归验证：改用阻塞/带延时的控制端重复上线、命令 33 回显测试，确认稳定。

## PoC

控制端响应模板（Go，两次写之间加延时）：

```go
response := string(res1) + string(res2) + "33" + string(res_newline) +
    string(res3) + strconv.Itoa(len(command)+1) + string(res_newline) + string(res_newline)
conn.Write([]byte(response))
time.Sleep(2 * time.Second)              // 关键：给样本第二次 recv 留出时间
conn.Write(encode(append([]byte(command), byte(0))))
```

调试顺序（原文做法）：控制端第二个 `send` 处断点 → 样本第二次 `recv` 处断点 → 样本停住时步过控制端断点 → 继续样本，即可正常接收载荷。

## 变体与关联

- 关联样本分析：[[code-analysis-reverse-windows-nukesped-type1-secfetch-google-c2-rebuild]]（NukeSped 变体 Type 1 控制端重建时遇到并解决了该问题）。
- 同类重建方法学：[[code-analysis-reverse-windows-remcos-socket-protocol-controller-emulation]]（协议仿真时同样要处理分帧与心跳时序）。
- 变体：把两次 `send` 合并成一次写（若协议允许）可规避；或用 `TCP_NODELAY` 关闭 Nagle 后仍不能保证时序，延时/断点最可靠。

## 检测与防御

本卡为分析调试技巧，无直接攻防影响。防御侧可反向利用该特征：监控非阻塞 socket 客户端在收到响应头后频繁重连/放弃的行为，作为模拟控制端或可疑植入体的线索。
