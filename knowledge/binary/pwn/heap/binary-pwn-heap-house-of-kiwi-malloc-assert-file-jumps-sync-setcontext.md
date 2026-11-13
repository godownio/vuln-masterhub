---
id: binary-pwn-heap-house-of-kiwi-malloc-assert-file-jumps-sync-setcontext
title: House of kiwi：__malloc_assert → fflush(stderr) 劫持 _IO_file_jumps.sync 为 setcontext+61，借 IO_helper_jumps 迁到堆上 ROP（glibc 2.29+ 无 exit/无 hook 场景）
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-kiwi-malloc-assert-io-file-jumps-sync
aliases:
- House of kiwi
- __malloc_assert 触发 IO
- _IO_file_jumps sync
- IO_helper_jumps
- setcontext+61 栈迁移
- glibc 2.34 无 hook 利用
- malloc_assert FSOP
tags:
- binary
- pwn
- heap
- glibc
- io-file
- fsop
- house-of-kiwi
- malloc-assert
- setcontext
- stack-pivot
- orw
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V673
  verified_at: '2026-11-13T10:40:09+08:00'
  notes: 已对照原文与图01-03核对：malloc_assert→__fxprintf→fflush(stderr)→_IO_file_jumps+0x60 sync、RDX=IO_helper_jumps、setcontext+61 取 [rdx+0xA0]/[rdx+0xA8] 的机理与原文及 demo 地址（0x53030+61 / 0x1E48C0 / 0x1E5520）一致。修正：原文 kiwi demo 无 largebin attack，图01 ROP 位于 PIE 全局数组而非堆；largebin 调试图实为后文 emma 部分，卡内已按实际归属注明。原文未附最终读 flag 截图，confidence medium 保持；未复跑。dedup 仅自匹配，邻近 House of Cat/Apple2/Pig 非同链。
---

## 一句话结论

在 glibc 2.29+ 的沙箱堆题里，如果程序不调用 `exit`（或经 syscall 直接退出）导致 `_IO_cleanup` 的 FSOP 路径不可用、且 glibc 2.34 又移除了 `__free_hook/__malloc_hook`，可以用 House of kiwi：用任意地址写（典型为 largebin attack）把 `_IO_file_jumps + 0x60` 的 `_IO_file_sync` 指针改成 `setcontext+61` 处的 gadget，并把 `_IO_helper_jumps + 0xA0/0xA8` 预置为堆上 ROP 地址与 `ret` gadget；随后制造 `__malloc_assert`，其 `__fxprintf → fflush(stderr)` 会经 sync 指针进入 `setcontext+61`，以 `rdx = IO_helper_jumps` 为上下文完成栈迁移并执行 ROP（seccomp 下用 ORW 读 flag）。

## 原理

- **为什么需要 kiwi**：glibc 2.29 之后常见的两条 sandbox 堆题路线是（1）劫持 `__free_hook` 再用 gadget 栈迁移；（2）劫持 `__malloc_hook` 为 `setcontext+61`，同时劫持 `_IO_list_all` 并在 `exit` 时由 `_IO_cleanup` 刷新缓冲区。若程序不调用 `exit`（或通过 syscall 直接退出），`_IO_cleanup` 不会执行；glibc 2.34 又删除了关键 hook，两条路线都失效。剩下的稳定 IO 触发点之一是 **`malloc_assert`**。
- **`__malloc_assert` 的 IO 调用**：`__malloc_assert()` 先 `__fxprintf(NULL, "...Assertion ... failed.\n", ...)`，再 `fflush(stderr)`，最后 `abort()`。`fflush`/`fxprintf` 都是 IO 操作；调试可见 `fflush` 中会调用 `_IO_file_jumps` 里的 `_IO_file_sync` 函数指针，且此时 **RDX 寄存器恒为 `_IO_helper_jumps` 指针地址**。
- **触发 assert 的两种方式**：
  - `_int_malloc` 中的 `assert (chunk_main_arena (bck->bk))`：用 largebin attack 破坏 largebin 的 `bk`，使其指向的 chunk 的 size 不属于 main_arena；
  - top chunk 不足进入 `sysmalloc` 时的断言：`old_size >= MINSIZE`、`prev_inuse(old_top)`、`old_end` 页对齐。用堆溢出/任意写把 top chunk 的 size 改小并清掉 PREV_INUSE，再申请超过 top 的大小即可触发。
- **利用布局**：`setcontext+61` 从 `rdx` 指向的结构取栈：`[rdx+0xA0]` 作为新 `rsp`，`[rdx+0xA8]` 作为 `rcx`（`setcontext` 末尾把它 push 成返回地址）。由于 `rdx = IO_helper_jumps`，只要把 `IO_helper_jumps + 0xA0` 写成堆上 ROP 链地址、`+0xA8` 写成 `ret` gadget 地址，就能在 `setcontext` 结束后落到堆上 ROP 的第一条指令。
- **为什么能绕 ASLR/沙箱**：`_IO_file_jumps` 与 `IO_helper_jumps` 都是 libc 内固定偏移的全局对象，已知 libc 基址即可定位；`sync` 指针劫持发生在合法的 vtable 表内（不触发 vtable 检查），`setcontext+61` 只是普通代码地址；ROP 用 syscall 完成 ORW，不依赖 `execve` 且不受 seccomp 拦截。
- **原文 demo**（glibc 2.32_Ubuntu2.2）：`magic_gadget = libc_base + 0x53030 + 61`（`setcontext+61`）、`IO_helper = libc_base + 0x1E48C0`、`SYNC = libc_base + 0x1E5520`；把 `IO_helper + 0xA0/8` 设为 ROP 地址、`+0xA8/8` 设为 `ret`，`*(size_t*)SYNC = magic_gadget`；再通过 top chunk size 修改触发 `malloc(0x1000)` 的 assert。

## 触发条件

- glibc 2.29 及以上（原文针对 2.29+ 的 sandbox 堆题；demo 使用 2.32），且目标缺少可用 `exit` 路径或 hook 已被移除。
- 具备任意地址写原语（largebin attack、UAF 任意写等），能改写 libc 中的 `_IO_file_jumps` 表项与 `IO_helper_jumps` 字段。
- 已知 libc 基址与（用于布置 ROP 的）堆地址。
- 能触发 `__malloc_assert`（破坏 largebin `bk` 的 arena 归属，或破坏 top chunk 的 size/prev_inuse/页对齐后触发 sysmalloc）。
- 有可用的 `setcontext+61` 与 ORW/ROP gadget；仅限 CTF/授权环境。

## 利用步骤

1. 泄露 libc 与堆地址，计算 `setcontext+61`、`_IO_file_jumps` 的 `sync` 表项（`_IO_file_jumps + 0x60`）、`IO_helper_jumps` 及 ROP gadget。
2. 在堆上布置 ROP 链（seccomp 场景用 `open/read/write` 的 ORW）。
3. 任意地址写：把 `_IO_file_jumps + 0x60` 覆盖为 `setcontext+61`；把 `IO_helper_jumps + 0xA0` 写成 ROP 链地址，`IO_helper_jumps + 0xA8` 写成 `ret`。
4. 制造 `__malloc_assert`：改 top chunk 的 size（清 PREV_INUSE、调小/破坏对齐）后 `malloc(0x1000)`；或破坏 largebin `bk` 后触发 `_int_malloc` 的 arena 断言。
5. `__malloc_assert → __fxprintf → fflush(stderr) → _IO_file_sync(=setcontext+61)`，`rdx = IO_helper_jumps`，栈迁移到堆上 ROP，执行 ORW/命令。
6. 注意 demo 在触发后调用 `_exit(-1)`，避免进入正常退出路径覆盖效果。

## PoC

原文 demo 核心（地址基于 glibc 2.32_Ubuntu2.2）：

```c
size_t magic_gadget = libc_base + 0x53030 + 61; // setcontext + 61
size_t IO_helper   = libc_base + 0x1E48C0;      // IO_helper_jumps
size_t SYNC        = libc_base + 0x1E5520;      // sync in _IO_file_jumps
// ROP: open("./flag") -> read -> write
setROP();
*((size_t*)IO_helper + 0xA0/8) = (size_t)ROP;   // setcontext 取 [rdx+0xa0] 作为 rsp
*((size_t*)IO_helper + 0xA8/8) = ret;           // setcontext 取 [rdx+0xa8] 作为 rcx(ret)
*((size_t*)SYNC) = magic_gadget;                // fflush(stderr) 的 sync 指针

// 改 top chunk size：调小并清 inuse，malloc 大块时进入 sysmalloc 断言
size_t *top_size = (size_t*)((char*)malloc(0x10) + 0x18);
*top_size = (*top_size) & 0xFFE;
malloc(0x1000);   // 触发 __malloc_assert
_exit(-1);
```

原文调试截图展示了 ROP 链布局（`./flag` 字符串紧邻 pop rdx/rsi/rdi 序列；该 demo 的 ROP 为 PIE 全局数组而非堆）以及 largebins/chunk 调试状态（0x430/0x440-0x470 的 FD/BK，实际对应后文 largebin attack 的调试，不属本 kiwi demo 代码路径）。原文未附最终读出 flag 的截图，故置信度 medium。

## 变体与关联

- 变体：assert 触发点可换 `_int_malloc` 的 `chunk_main_arena(bck->bk)`；任意写可换 tcache poisoning/unsorted bin attack（需能写 libc 只读段以外的表项）；`setcontext+61` 可换 `setcontext+53` 等迁移点；ROP 可换 `system("/bin/sh")`（无 seccomp 时）。
- 关联：[[binary-pwn-heap-house-of-emma-cookie-jumps-pointer-guard]]（同源的 vtable 偏移劫持）、[[binary-pwn-heap-house-of-cat-wfile-seekoff-wide-vtable-bypass-vtable-check]]（同样借 `__malloc_assert` 触发 IO，但走 `_IO_wfile_jumps`/`_wide_vtable`）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（exit 路径的 FSOP 对比）。
- 边界：程序若存在可用的 `exit`/`_IO_cleanup` 路径，传统 FSOP 更直接；glibc 若对 `_IO_file_jumps` 所在段做只读保护（RELRO 不覆盖 libc 数据段）/引入额外完整性检查，本手法受影响。

## 检测与防御

- 这是 CTF/漏洞利用技术，防御侧关注点：glibc 堆完整性（top chunk size、largebin bk 归属）被破坏会触发 assert 而非静默成功；生产程序应避免把可控数据与堆元数据混淆，启用 malloc 检查（`MALLOC_CHECK_`/`glibc` 断言）并监控异常 abort。
- 可利用性缓解：保持 ASLR + 不泄露 libc/堆地址（本链第一步依赖基址）；沙箱只限制 syscall 不阻止 ORW；升级 glibc 不会自动消除，因为 `_IO_file_jumps`/`IO_helper_jumps` 仍是固定偏移对象。
- 检测信号：进程异常 `Assertion ... failed` 后 abort、`_IO_helper_jumps`/`_IO_file_jumps` 表项被改写、堆上出现 ROP 形态数据。
