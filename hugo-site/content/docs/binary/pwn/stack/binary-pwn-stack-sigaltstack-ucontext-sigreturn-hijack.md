---
id: binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack
title: SIGSEGV + sigaltstack 的 ucontext 劫持：伪造 rt_sigreturn 帧调用 system
type: scenario
domain: binary
path: binary/pwn/stack
technique: sigaltstack-ucontext-sigreturn-hijack
tags:
- pwn
- srop
- sigreturn
- ucontext
- sigaltstack
- sigsegv
- stack
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:43:15+08:00'
  notes: 已对照原文核对：sigaltstack(0x20000 mmap/ss_size 0x4000)、sa_flags=0x8000004(SA_SIGINFO|SA_ONSTACK)、SIGSEGV handler 打印si_addr并memset后递归main、ucontext槽位+0x34e8(RDI)/+0x3520(RSP)/+0x3528(RIP)均与原文exp一致；图02显示最终执行system后输出flag。ucontext偏移依赖该题内核/libc/栈布局，未在本环境复跑；无组件影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/stack/binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack/
draft: false
kb_aliases:
- ucontext 劫持
- sigreturn 帧伪造
- SROP 变体
- SIGSEGV handler 利用
- sigaltstack 攻击
- rt_sigreturn ROP
- broken_manager 控制流劫持
---

## 一句话结论

程序用 `sigaltstack` 在可写的 mmap 区设置备用信号栈，并安装带 `SA_SIGINFO|SA_ONSTACK` 的 SIGSEGV 处理器；处理器打印 `si_addr`、重置分配器后递归调用 `main` 重启。攻击者先通过堆漏洞获得任意地址写，改写备用栈上保存的 `ucontext_t` 中的 RDI/RSP/RIP，再让 `main` 返回、处理器返回，内核 `rt_sigreturn` 就会按伪造的上下文恢复寄存器并执行 `system("cat flag")`。

## 原理

- **信号栈与 ucontext**：安装信号处理器时使用 `sigaltstack()` 指定 `ss_sp`/`ss_size`；`sigaction` 的 `sa_flags` 含 `SA_ONSTACK` 时，内核在投递信号时把 `rt_sigframe`（含 `ucontext_t`）压到备用栈上。处理器返回时，内核执行 `rt_sigreturn`，从该 `ucontext_t` 的 `uc_mcontext.gregs[]` 恢复所有通用寄存器（包括 RDI、RSP、RIP），然后继续执行。
- **可写的备用栈**：本案例 `runtime_init_and_install_sigsegv_handler` 用 `mmap(0, 0x20000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` 分配 0x20000，`ss_sp = base`、`ss_size = 0x4000`，同时把同一块内存当作 arena 区域（`g_arena_region_cursor = base+0x4000`、`limit = base+0x20000`）。备用栈与堆区重叠且可写，为任意写劫持提供条件。
- **处理器逻辑**：`sa_flags = 134217732 = SA_SIGINFO(4) | SA_ONSTACK(0x08000000)`，`sigaction(11, &act, 0)` 注册 SIGSEGV。处理器 `handle_invalid_ptr_and_restart` 从 `siginfo` 取 `si_errno` 与 `si_addr` 打印（`Invalid ptr access: %p`），然后 `memset` 全局 arena/chunks/sizes，并递归调用 `main()` 重启程序。注意：它没有销毁备用栈上的原始 `ucontext_t`，也没有清理那块内存。
- **利用窗口**：处理器调用 `main()` 后，程序在备用栈上继续跑菜单；攻击者通过堆漏洞的任意写修改“当前信号帧”里的 `ucontext_t`（案例中 RDI 在 `altstack_base+0x34e8`、RSP 在 `+0x3520`、RIP 在 `+0x3528`，对应 `uc_mcontext.gregs` 中 RDI→RSP→RIP 的固定间距）。
- **触发返回**：选择 Exit 让递归的 `main()` 返回处理器；处理器返回后内核执行 `rt_sigreturn`，按被改写的 `ucontext_t` 恢复 RDI/RSP/RIP。把 RDI 指向 `"cat flag"` 字符串、RIP 指向 `system`、RSP 指向一个合法可写地址（案例 `altstack_base+0xbf88`），即可执行命令。
- **为什么需要先泄 libc**：RIP 要填 `system` 的真实地址，因此先通过自定义 arena 的任意分配/读泄露 libc base（见关联卡），再用同一任意写原语写信号帧。
- **偏移依赖**：`ucontext_t` 在备用栈上的位置由内核信号帧布局、`ss_size`、架构和 libc 决定；案例偏移只适用于该题目环境，实际利用需在 gdb 中定位 `uc_mcontext.gregs` 或根据 `sigaltstack`/`rt_sigframe` 结构计算。

## 触发条件

- 程序安装 SIGSEGV/SIGBUS 等同步信号处理器，且 `sa_flags` 含 `SA_ONSTACK`，使用可写的 `sigaltstack`；
- 处理器在返回前没有清理/重新初始化信号帧，或会递归调用主逻辑让攻击者继续操作；
- 攻击者拥有任意地址写（或可写备用栈）能力，能修改保存的 `ucontext_t`；
- 能拿到 libc 基址（ASLR 下需先泄露），并能控制程序走到“处理器返回”的路径；
- 目标架构/内核的 `ucontext_t` 偏移已知或可探测。

## 利用步骤

1. 确认程序注册了 SIGSEGV handler，且 `sigaction` 带 `SA_ONSTACK`；用 `strace`/gdb 观察 `sigaltstack` 的 `ss_sp`/`ss_size`。
2. 触发一次可控崩溃，让处理器打印 `Invalid ptr access`（`si_addr`），同时程序重启；记录备用栈基址与 arena 区域的重叠关系。
3. 通过堆漏洞（如自定义 arena double free）获得任意地址读写，泄露 libc base（案例偏移 0x203961）。
4. 在备用栈上写命令字符串（案例 `altstack_base+0xb800` 写 `"cat flag"`），并准备一个合法的 RSP 值（案例 `altstack_base+0xbf88`，必要时写 0 作为返回地址）。
5. 计算 `ucontext_t` 中 RDI/RSP/RIP 槽位：案例 `RDI=+0x34e8`、`RSP=+0x3520`、`RIP=+0x3528`；写入 `RDI=cmd_addr`、`RSP=stack_addr`、`RIP=system`。
6. 选择 Exit 让递归 `main` 返回；处理器返回触发 `rt_sigreturn`，恢复伪造上下文并执行 `system(cmd)`。
7. 若偏移不对，用 gdb 在 `rt_sigreturn` 处断下，观察 `ucontext_t` 布局并调整。

## PoC

以下为按题解压缩的伪造片段（偏移仅适用于该题目环境）：

```python
from pwn import *
context.arch = 'amd64'

# 已有任意写原语 arb_write(addr, data) 与 libc_base
cmd_addr   = altstack_base + 0xb800
rsp_addr   = altstack_base + 0xbf88
system_addr = libc_base + libc.sym['system']

arb_write(cmd_addr, b'cat flag\x00'.ljust(0x10, b'\x00'))
arb_write(rsp_addr, p64(0))

# ucontext_t 中 gregs 的 RDI/RSP/RIP 槽位（案例偏移）
arb_write(altstack_base + 0x34e8, p64(cmd_addr))     # RDI
arb_write(altstack_base + 0x3520, p64(rsp_addr))     # RSP
arb_write(altstack_base + 0x3528, p64(system_addr))  # RIP

io.sendline(b'5')   # 选择 Exit，让 main 返回 handler，handler 返回触发 rt_sigreturn
io.interactive()
```

## 变体与关联

- 变体：不依赖堆任意写，直接利用信号栈溢出/格式化字符串写 `ucontext_t`；或利用 `setcontext`/`swapcontext` 等用户态上下文切换函数。
- 变体：SROP 直接在栈上构造 `sigreturn` 帧并触发 `syscall`；本卡是“信号处理器返回”路径，本质同样是伪造 `ucontext_t`/`sigcontext`。
- 变体：不同 libc/内核的 `ucontext_t` 偏移不同；32 位与 64 位、x86 与 ARM 的 `gregs` 布局也不同，需按目标计算。
- 关联：[[binary-pwn-heap-custom-arena-double-free-cookie-arbitrary-alloc]]（本案例的任意写原语）、[[binary-pwn-stack-ret2syscall-32bit]]（sigreturn 系统调用）、[[binary-pwn-rop-static-link-ret2system-sh]]（ROP 调用 system）。

## 检测与防御

- **安全编码**：信号处理器只做最小、异步信号安全的操作；不要在处理器里递归调用 `main` 或继续使用可被攻击者写的内存；处理器返回前不要信任保存的 `ucontext_t`。
- **备用栈设计**：`sigaltstack` 使用独立、只读/受保护的区域，设置 guard page；不要把备用栈与堆/arena 区域重叠；`ss_size` 满足 `MINSIGSTKSZ` 且不暴露给业务逻辑。
- **缓解**：ASLR/PIE 与 stack canary 不能阻止伪造 `ucontext_t`；可考虑 CET/Shadow Stack（`rt_sigreturn` 恢复 RIP 时影子栈校验可能阻断）、`seccomp` 限制 `rt_sigreturn` 之外的系统调用、`-fstack-protector-strong`、CFI。
- **检测**：监控进程在 `rt_sigreturn` 后立即执行 `system`/`execve` 的异常调用链；对信号处理器内出现大量堆操作、递归 main、异常 `si_addr` 打印做告警；CTF 环境可用 gdb 在 `rt_sigreturn` 下断验证。
- **信息泄露**：不要在崩溃信息中向用户打印完整 `si_addr` 或内部指针；错误处理应终止进程而非带着损坏状态重启。
