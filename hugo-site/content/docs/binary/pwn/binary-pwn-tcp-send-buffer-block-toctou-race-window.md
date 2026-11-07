---
id: binary-pwn-tcp-send-buffer-block-toctou-race-window
title: TCP 发送缓冲区阻塞放大服务端 TOCTOU 竞态窗口：从概率竞争到接近 100% 命中
type: scenario
domain: binary
path: binary/pwn
technique: tcp-send-buffer-block-toctou-race-window
tags:
- pwn
- race-condition
- toctou
- tcp
- send-buffer
- concurrency
- server
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:12:41+08:00'
  notes: 已对照 The Wolf of Wall Street 阶段2 核对：debug_log_net 解锁窗口、TCP send buffer 阻塞放大竞态、ETF 重写刷钱均与原文一致；PoC 未执行
url: /docs/binary/pwn/binary-pwn-tcp-send-buffer-block-toctou-race-window/
draft: false
kb_aliases:
- TCP send buffer 放大竞态
- debug_log_net 阻塞窗口
- TOCTOU 竞态窗口
- 服务端 unlocked log
- wmem 阻塞写
- 100% 竞争
---

## 一句话结论

服务端在“余额检查”和“实际扣款/更新持仓”之间释放全局锁并调用 `debug_log_net()` 写 socket；如果客户端先把服务端 TCP send buffer 填满，这个写操作会阻塞，竞态窗口从微秒级被拉长到客户端读取前无限长。另一线程在窗口内改写共享持仓数据，服务端随后按被改后的数据扣款/入账，TOCTOU 稳定命中。

## 原理

- **TOCTOU 缺口**：买入逻辑先计算 `total_cost`、检查 `u.cash >= total_cost`，然后为了打 debug 日志执行 `lock.unlock()` 并 `debug_log_net(sock, ...)`，之后再 `lock.try_lock()` 并修改 `u.cash`/`u.holdings`。检查与使用之间释放了锁，另一个线程可以修改被检查对象（ETF 成分/持仓）。
- **把窗口拉长**：`debug_log_net` 是一个阻塞的网络写。TCP socket 的发送缓冲区（`SO_SNDBUF` 与内核 `tcp_wmem`）有限；当应用写入量超过缓冲区且接收端不读时，`send/write` 会阻塞。攻击者先让服务端向自己发送大量数据（例如超长的未知命令，服务端回显 "Unknown command <长串>"），把 send buffer 填满；再触发买入，服务端线程在 debug 日志处阻塞，竞态窗口保持打开。
- **客户端控制窗口结束**：服务端阻塞后，攻击者用另一个连接/线程修改 ETF 持仓；修改完成后再读取第一个连接的数据，send buffer 腾出空间，服务端写完成、重新加锁并执行状态修改。
- **收益**：原逻辑要求线程 A 按“买 1 份仅含 1 个标的的 ETF”检查资金，线程 B 在窗口内把 ETF 改成“所有标的各 10 份”；A 用少量资金买入大量标的，再卖出完成刷钱。重复几轮即可达到高价值功能（如执行任意 Lua）的资金门槛。
- **为什么 TCP 合适**：阻塞写发生在内核 socket 层，不受服务端业务逻辑控制；只要接收端不读，窗口就不会关闭。相比 `usleep`/重试，这种“对端控制”的窗口几乎 100% 可靠，且不需要猜测调度。

## 触发条件

- 服务端存在“检查后释放锁 → 阻塞调用（网络/磁盘/日志）→ 重新加锁使用”的 TOCTOU 模式。
- 攻击者可控制该阻塞调用的对端（TCP 连接）和接收节奏；send buffer 大小可探测/估算。
- 有第二个可控线程/连接能在窗口内修改被检查的共享状态。
- 服务端使用多线程且全局锁在日志调用前释放；日志内容足够大或可重复填充缓冲区。

## 利用步骤

1. **确认代码路径**：定位买入/转账等操作的“检查-解锁日志-更新”序列，确认 `debug_log_net` 在锁外执行且会写攻击者可控的 socket。
2. **建立连接并填充 send buffer**：向服务端发送一个超长未知命令，使服务端回显长响应；客户端暂不读取，直到服务端 `write` 阻塞。
3. **准备竞争线程**：在另一个连接上准备好修改 ETF 持仓/共享状态的请求（例如把 ETF 成分改为所有标的、数量 10）。
4. **触发受害操作**：在第一个连接发起买入；服务端通过资金检查、解锁并写 debug 日志，因缓冲区满而阻塞。
5. **窗口内修改状态**：第二个连接立即提交修改并等待成功；此时服务端尚未扣款/更新持仓。
6. **释放窗口**：读取第一个连接的响应，send buffer 腾空，服务端完成日志写、重新加锁并执行扣款/入账（按修改后的状态）。
7. **兑现收益**：卖出被错误买入的持仓，重复 3~5 轮达到资金门槛；随后调用需要高额资金的功能（如提交 Lua 代码）进入下一阶段。

## PoC

```python
# 1) 建立 ETF：买 1 个标的、数量 1（低资金检查）
# 2) 用超长未知命令填满服务端 send buffer
p1.sendline(b"X" * 0x200000)          # 服务端回显 "Unknown command X..."
# 不读取 p1，让其 send buffer 阻塞

# 3) 竞争线程：把 ETF 持仓改为所有标的各 10 份
p2.sendline(b"ETF_REWRITE ...")

# 4) 受害线程：买入 10 份 ETF
p1.sendline(b"BUY ETF 10")
# 服务端：检查资金 -> unlock -> debug_log_net 阻塞

# 5) 等待 p2 修改完成，再读取 p1 解除阻塞
time.sleep(0.1)
p1.recvuntil(b"done")
# 服务端按修改后的 ETF 入账；卖出持仓完成刷钱
```

原文用 QEMU 环境调试 TCP `wmem` 阈值；不同内核/内存需要调整预填充字节数，使服务端在 debug 日志前不阻塞、日志时恰好阻塞。本卡不执行 PoC。

## 变体与关联

- **其它阻塞点**：`fsync`、DNS 解析、RPC 调用、数据库慢查询、文件锁、`sleep` 等都可替代网络写；关键是攻击者能让它阻塞足够久。
- **缩短/无需阻塞**：若窗口本身较大，可用多线程高频重试；但成功率远低于 send buffer 方案。
- **接收窗口控制**：`SO_RCVBUF`、`TCP_WINDOW_CLAMP`、`TCP_NOTSENT_LOWAT` 可调节阻塞阈值；也可用零窗口通告。
- **关联**：[[web/generic/race-condition]] 类竞态卡、[[binary-pwn-kernel-sock-refcount-race-lock-sock-double-free]]（内核 socket 生命周期竞态）、[[web-generic-payment-amount-tamper-no-order-binding]]（业务状态检查与使用分离）。
- **边界**：需要服务端在锁外执行可阻塞调用；若日志异步、非阻塞或写入前复制状态，窗口不存在；send buffer 阈值受内核版本/内存影响，需现场校准。

## 检测与防御

- **代码修复**：不要在锁外使用已检查的共享状态；检查与更新保持同一临界区，或使用版本号/乐观锁（比较并交换）验证状态未被修改。
- **日志异步化**：debug 日志改为无锁队列/异步落盘，避免在业务临界区做网络写；生产环境关闭 debug 输出。
- **限流/隔离**：限制单连接发送大量未知命令；对回显长度设上限；对同一账户的并发操作串行化。
- **检测**：同一账户在极短时间内的并发买入/修改 ETF；服务端线程长时间阻塞在 socket 写；大量超长未知命令与随后的大额交易相关。
- **响应**：回滚异常交易、冻结账户、审计 debug 日志开关与 ETF 修改权限。
