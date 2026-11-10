---
id: code-analysis-reverse-linux-syscall-user-kernel-entry-chain
title: Linux 系统调用用户态到内核态全链路：glibc write 包装 → syscall(0F 05) → IA32_LSTAR → sys_write 实现
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: linux-syscall-user-kernel-entry-chain
aliases:
- Linux 系统调用原理
- syscall 指令 0F 05
- IA32_LSTAR
- WRMSR 配置 syscall 入口
- glibc write 包装
- strace printf 变 write
- sys_write 源码
- ring 0 ring 3
tags:
- reverse
- linux
- syscall
- kernel
- glibc
- radare2
- strace
- x86-64
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T09:32:40+08:00'
  notes: '已对照原文全文与 44/44 截图核对：img06-07 strace 显示 write(1, Usage: <key>, 13) 而非 printf、img09-11 baimao.c 与 r2 pdf(mov edi,1; lea rsi,str; mov edx,0xa; call sym.imp.write)、img12-14 PLT jmp qword [reloc.write] 与 libc mov eax,1; syscall、img16 SYSCALL SDM 0F 05/IA32_LSTAR/RCX/R11 语义、img18 WRMSR 0F 30、img20-21 syscall 表 write=1 与 SYSCALL_DEFINE3(write)/ksys_write 源码、img24 LDD3 copy_from/to_user 均与卡片一致。技术点复核：syscall 保存 RIP 到 RCX、RFLAGS 到 R11、IA32_FMASK 屏蔽、IA32_STAR 加载 CS/SS；ring3 执行 WRMSR 触发 #GP(0)；i386 入口寄存器约定与 x86-64 ABI(rdi/rsi/rdx/r10/r8/r9) 均正确。原文为内核机制教学，未给具体内核版本(引用 latest/v4.3 等不同页面)，affected_versions 已 clear。与既有 Windows LSTAR hook、ret2syscall、seccomp 绕过等攻击卡为机制 vs 利用视角，非重复。'
---

## 一句话结论

以 `write(1,"baimao\n",10)` 为例，用户可以沿着 `main → PLT → glibc write 包装（edi=fd, rsi=buf, edx=count, eax=1）→ syscall 指令（0F 05）→ CPU 从 IA32_LSTAR MSR 取内核入口 RIP、切换到 ring 0 → sys_call_table[1] = sys_write → ksys_write → vfs_write` 完整跟踪一次系统调用；`strace` 里 `printf` 变成 `write`、`radare2` 里 PLT 跳到 libc 后的 `mov eax,1; syscall` 是这条链的两个可观察点。

## 原理

- **系统调用是应用与内核的基本接口**：应用不能直接操作硬件/内核数据结构，只能通过 `syscall`/`int 0x80` 等指令从 ring 3 进入 ring 0，由内核在固定入口执行对应服务例程。
- **glibc 包装很薄**：多数 libc 函数只是把参数放进 ABI 规定的寄存器（x86-64：`rdi/rsi/rdx/r10/r8/r9`，系统调用号放 `rax`），执行 `syscall`，返回后检查 `rax` 的负错误码并设置 `errno`；`write` 的包装最终就是 `eax=1; syscall`。`printf` 是带缓冲的库函数，缓冲区刷新到 fd 1 时仍调用 `write`，所以 `strace` 只看到 `write`。
- **`syscall` 指令的硬件语义**：操作码 `0F 05`（64 位模式有效）；它把下一条指令地址保存到 `RCX`、RFLAGS 保存到 `R11`、用 `IA32_FMASK` 屏蔽 RFLAGS 指定位，然后从 `IA32_LSTAR` MSR 加载 RIP，按 `IA32_STAR` 的位段加载 CS/SS，进入 ring 0。`IA32_LSTAR` 必须在 ring 0 用 `WRMSR`（`0F 30`，把 EDX:EAX 写入 ECX 指定的 MSR）在系统启动时配置好；ring 3 用户态无法执行 `WRMSR`，所以用户不能改系统调用入口地址。
- **系统调用号与内核实现**：x86-64 的 `write` 编号为 1（`sys_call_table[1]`）。内核 `fs/read_write.c` 中 `SYSCALL_DEFINE3(write, unsigned int fd, const char __user *buf, size_t count)` 调用 `ksys_write`：`fdget_pos(fd)` 取文件、`vfs_write` 执行实际写、成功后更新 `f_pos`，再 `fdput_pos`。
- **地址空间与 `__user`**：`buf` 参数带 `__user` 注解，表示它来自用户地址空间；内核不能直接解引用，必须通过 `copy_from_user` 等函数处理（见 [[code-analysis-reverse-linux-copy-from-user-stac-clac-access-ok]]）。这也解释了为什么系统调用参数只是“用户虚拟地址”，真正翻译由 MMU/页表在访问时完成。
- **为什么需要理解这条链**：二进制安全中的 syscall 滥用（直接 syscall 绕过 libc hook）、seccomp 过滤、沙箱逃逸、内核 pwn 的入口定位、strace/r2 调试都建立在这条链上；知道寄存器约定和入口机制，才能读懂 `0F 05` 处的行为。

## 触发条件

- 目标为 x86-64 Linux 用户态程序，使用 libc 包装或直接 `syscall` 调用内核服务。
- 有 `strace`、`radare2`/`gdb` 等跟踪工具；允许运行/调试目标程序。
- 需要确认某个 libc 函数实际对应哪个系统调用、参数如何传递、内核执行了哪个函数。
- 分析内核源码时可对照 `fs/read_write.c`、`arch/x86/entry/entry_64.S`、`arch/x86/include/asm/special_insns.h` 等文件。

## 利用步骤

1. 写最小 C 程序直接调用 `write(1, "baimao\n", 10)`，用 `gcc -z execstack -fno-stack-protector -no-pie -z norelro` 编译（关闭防护便于调试；实际分析不必关闭）。
2. `strace ./baimao`：确认没有 `printf`，而是 `write(1, "baimao\n", 10) = 10`；说明 libc 缓冲层最终落到 write 系统调用。
3. `radare2 -d ./baimao`，`aaa` 分析，`s main`、`pdf`：看到 `mov edi,1; lea rax,[str]; mov rsi,rax; mov edx,0xa; call sym.imp.write`。
4. `db 0x0040113e`（call write 处）、`dc` 运行到断点；`s` 单步进入 PLT：`jmp qword [reloc.write]`，再进入 libc 的 `write`。
5. 在 libc 中继续单步，找到 `mov eax,1; syscall`：`eax=1` 是 write 的系统调用号，`syscall` 即 0F 05；用 `dso`/`pdf` 查看 libc 的包装逻辑（含 cancellation 处理）。
6. 对照 Intel SDM 的 SYSCALL 条目与内核 `sys_call_table`/`sys_write` 源码，确认入口从 IA32_LSTAR 加载、内核执行 `ksys_write → vfs_write`。
7. 若要验证“用户不能改入口”，可在 ring 3 尝试 `wrmsr`，会触发 #GP(0)；只有内核在启动时能配置 IA32_LSTAR。

## PoC

```c
#include <unistd.h>
void main(void) {
    write(1, "baimao\n", 10);   // fd=1(stdout), buf, count
}
```

```bash
gcc -z execstack -fno-stack-protector -no-pie -z norelro baimao.c -o baimao
strace ./baimao
# write(1, "baimao\n", 10) = 10
```

```text
radare2 -d ./baimao
[0x...]> aaa
[0x...]> s main
[0x...]> pdf
...
0x00401136  mov rsi, rax        ; buf
0x00401139  mov edi, 1          ; fd = stdout
0x0040113e  call sym.imp.write
...
[0x...]> db 0x0040113e
[0x...]> dc
hit breakpoint at: 0x40113e
[0x...]> s                    ; 单步进 PLT / libc
; libc 内最终：
; mov eax, 1
; syscall                     ; 0F 05，进入内核 sys_write
```

内核侧（源码结构）：

```c
SYSCALL_DEFINE3(write, unsigned int fd, const char __user *buf, size_t count)
{
    return ksys_write(fd, buf, count);
}
/* ksys_write: fdget_pos -> vfs_write -> 更新 f_pos -> fdput_pos */
```

## 变体与关联

- **i386 入口**：32 位 Linux 用 `int 0x80`（或 `sysenter`），系统调用号放 `eax`、参数放 `ebx/ecx/edx/esi/edi/ebp`；x86-64 用 `syscall` + `rdi/rsi/rdx/r10/r8/r9`，两者入口与寄存器约定不同。
- **直接 syscall**：Go/Rust/加壳/恶意样本常内联 `syscall` 指令或自带 syscall stub 绕过 libc hook；见 [[code-analysis-reverse-obfuscation-linux-dynamic-api-hash-syscall-stub]]。
- **动态跟踪**：`strace`/`perf trace`/`ftrace` 可在不同层观察系统调用；`ftrace` 函数图可定位内核内 `ksys_write`/`vfs_write` 的调用链，见 [[code-analysis-dynamic-tracing-ftrace-function-graph-syscall-error-locate]]。
- **用户态拷贝**：`__user` 指针的安全访问见 [[code-analysis-reverse-linux-copy-from-user-stac-clac-access-ok]]。
- **边界**：内核版本/架构不同，入口汇编（`entry_64.S`）、`sys_call_table` 生成方式、`__x64_sys_*` 命名会变化；容器/seccomp 可能拦截或改写系统调用，`strace` 结果需结合环境判断。

## 检测与防御

- 这是 Linux 系统调用机制的分析方法，不直接产生攻击面。防守方关注的是：seccomp 对 syscall 号的过滤、对 `syscall` 指令的直接调用（绕过 libc hook 的样本）、以及内核入口/`IA32_LSTAR` 的完整性（rootkit 可能 hook 系统调用入口）；见 [[code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook]] 的 Windows 对照。
- 分析侧：`strace` 只看到最终 syscall，需结合源码/调试理解 libc 包装；`r2` 单步进入 PLT 时注意懒绑定（首次调用走 `_dl_runtime_resolve`）。
- 防御：保持内核/CPU 微码更新；启用 SMEP/SMAP/KPTI 等缓解；用 seccomp 限制不必要的系统调用；监控异常的直接 syscall stub 与内核入口篡改。
