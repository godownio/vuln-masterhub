---
id: code-analysis-reverse-windows-game-send-architecture-heartbeat
title: 游戏发包架构判定：send 调用栈区分单线程/双线程队列并过滤心跳包
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: game-send-architecture-identification
aliases:
- 单线程发包模型
- 双线程队列发包
- 发包模型判定
- 心跳包识别
- send1 send2
- 游戏发包 call 定位前置
tags:
- reverse-engineering
- game
- windows
- send
- heartbeat
- x32dbg
- network-protocol
- architecture
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:33:27+08:00'
  notes: 已对照原文与61张图核对：单线程/双线程队列两种模型、send 断点调用栈差异、心跳固定小包（send1 len=1）与业务变长包（send2）的区分、stdcall send 栈参数 [esp+4/8/C/10] 均一致（图05/06、图21-23）。未验证点：未在游戏进程实测；原文无版本区间，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

不操作游戏时对 `ws2_32!send` 下断，根据命中频率、包长和调用栈形态，可以判定客户端是“单线程同步发包”还是“双线程队列发包”；同时先用固定周期/固定小包特征识别并过滤心跳包，才能把断点对准真正的业务发包 call。

## 原理

- **单线程同步模型**：控件 call → 功能 call1 → 功能 call2 → 组包 →（加密 call）→ send 全部在同一线程、同一调用栈内完成。断在 send 时沿栈向上能连续看到游戏模块内的业务逻辑与组包代码，且没有“写入全局队列”的步骤。
- **双线程队列模型**：主线程（生产者）只负责业务、组包、加密，然后把包指针/包数据写入全局结构（环形队列）后立即返回；独立网络线程（消费者）循环扫描队列、拷贝缓冲区、调用底层 send。断在 send 时栈上只有网络线程的队列读取/拷贝函数和 send 包装，业务 call 不在同一栈帧链里。共享队列通常有互斥锁，直接在主线程之外模拟调用容易因竞争崩溃。
- **心跳包**：客户端定时发给服务器的极小包，作用是保活和让服务器判断掉线（常见 5 秒无包即判离线）。特征是包体极小（常只有包头+消息 ID）、固定周期（2/3/5 秒）、独立消息 ID、由定时器而不是玩家操作触发。心跳与业务包共用同一条发包链路，所以断 send 会周期性命中，必须先区分。
- **同一 send 包装的多个入口**：文中同一地址被两个地方调用，send1 每次断下长度都是 1，属于心跳/保活类固定小包；send2 的长度随消息内容变化，是真正的业务发包。用“包长是否随操作变化”可以快速区分。

## 触发条件

- 目标为 Win32 游戏客户端（x86/x64），网络层最终调用 `ws2_32!send`、`sendto`、`WSASend` 或它们的游戏内包装函数；
- 已附加调试器（x32dbg/x64dbg 或 CE），能在目标进程下软件/硬件断点；
- 能反复触发移动、技能、聊天等业务操作；
- 客户端未对 send 调用做完整性校验；若存在反调试需先绕过。

## 利用步骤

1. `Ctrl+G` 搜索 `send`，在 `ws2_32!send` 的函数头下断（不要断到内部的拷贝循环）。stdcall 下参数位于栈上：`[esp+4]`=socket、`[esp+8]`=buf、`[esp+C]`=len、`[esp+10]`=flags。
2. 不操作游戏静置观察：若每隔固定时间自动断下，且 len 恒定且很小，该包为心跳；记录其调用栈，之后用条件断点按长度或返回地址过滤。
3. 触发聊天、移动、技能，比较断下时的 len 与 buf 内容是否随操作变化；结合第 2 步把 send 入口分为心跳入口（固定小包）与业务入口（变长包）。
4. 在业务 send 断下时打开调用栈：
   - 若从 send 向上连续出现游戏模块内的业务/组包/加密函数，且都在同一线程，判定为单线程同步模型，可直接沿栈回到功能 call；
   - 若栈上只有网络线程的队列读取、缓冲区拷贝（memmove 等）和 send 包装，判定为双线程队列模型；此时不能直接沿栈找业务，应转去对共享队列/封包缓冲区下硬件写入断点，从写入方（主线程）回溯。
5. 对每个候选业务 call 下断，只触发目标功能，验证“只有该功能断下”，排除其它业务与心跳。
6. 若 send 前存在加密 call，按明文/密文分界继续定位加密与组包（见关联卡）。

## PoC

无 PoC；本卡是后续发包 call 定位的前置判定步骤。调试命令示例：

```text
; x32dbg（地址/长度按目标替换）
bp ws2_32.send
; 只关心长度不是心跳长度（示例心跳 len=1）的断下
bp ws2_32.send, "[esp+C] != 0x1"
; 断下后查看参数
; [esp+4]=socket  [esp+8]=buf  [esp+C]=len  [esp+10]=flags
```

## 变体与关联

- `WSASend` 版：参数通过 `WSABUF` 数组传递，不能只看栈上的 buf/len，需要解析结构体；`sendto` 还带目标地址。
- 加密版：单线程链路在组包与 send 之间多一个加密 call；双线程版在写入队列前加密。
- 队列形态可能是环形队列、链表或双缓冲，但判定特征相同：send 的调用栈与业务/组包调用栈分离。
- 关联卡片：[[code-analysis-reverse-windows-game-call-send-backtrace]]、[[code-analysis-reverse-windows-game-packet-buffer-encryption-locate]]、[[code-analysis-reverse-windows-game-packet-pipeline-code-injection]]。

## 检测与防御

- 检测：调试器附加、send/WSASend 的软件或硬件断点、异常调用栈、非游戏模块发起的 send。
- 防御：关键逻辑以服务端为准；心跳与业务包分离校验；包序号、时间戳、频率限制；客户端反调试与代码完整性校验。
- 注意：客户端发包工具只能复现客户端允许的动作，不能绕过服务端校验。
