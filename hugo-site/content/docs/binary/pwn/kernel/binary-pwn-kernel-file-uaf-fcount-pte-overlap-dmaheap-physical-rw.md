---
id: binary-pwn-kernel-file-uaf-fcount-pte-overlap-dmaheap-physical-rw
title: struct file UAF：用 f_count 的 dup 自增当「PTE 值 +0x1000」原语，dma-heap 邻接映射收拢控制权后任意物理读写并补丁内核 text（nsjail 逃逸）
type: scenario
domain: binary
path: binary/pwn/kernel
technique: file-uaf-fcount-increment-pte-self-overlap-dma-heap-physical-rw
tags:
- pwn
- kernel
- uaf
- struct-file
- f-count
- cross-cache
- page-table
- pte
- dma-heap
- physical-memory
- kaslr
- nsjail
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:28:16+08:00'
  notes: 已对照原文核对；本次核对未读取图片；f_count 偏移 0x38 落在 PTE 数组第 7 项、dup 0x1000 次使 PTE 值加 0x1000、dma-heap 取 MIGRATE_UNMOVABLE 同 order 页、物理地址 0x9c000 泄漏内核 text 并按 0x1c04000 差值算物理基址、patch do_symlinkat 的 shellcode 与硬编码符号，均与正文一致。已修正两处笔误：删去正文里无意义的「oh」，并把「每个缺页分配一个 PTE 页」改为「每 512 个 PTE 一张末级页表页、每块 0x8000 写入以摊到新页表页」。未验证点：PoC 未执行；PTE 自映射与 dma-buf 邻接证据在截图里，未读图二次核对。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-file-uaf-fcount-pte-overlap-dmaheap-physical-rw/
draft: false
kb_aliases:
- keasy
- m0leCon keasy
- file object UAF 页表利用
- f_count 自增当 PTE 偏移
- dup 递增页表项
- dma-heap 邻接页表
- /dev/dma_heap/system 页表重叠
- 任意物理地址读写
- 物理地址 leak 内核 text
- patch do_symlinkat 逃逸 nsjail
---

## 一句话结论

当漏洞把 `struct file` 释放掉却仍保留可用 fd 时，`dup()` 会持续自增该已释放对象的 `f_count` 字段；一旦用 cross-cache 让末级页表（PTE）页占住这块 victim slab，`f_count` 就变成了 PTE 数组里的一个 qword，若干次 `dup` 等于「把某个 PTE 的值加 N」，加到 0x1000 时该 PTE 恰好指向页表页自身，用一个用户态虚拟页就能改写全部 PTE；再用 `/dev/dma_heap/system` 拿到与被改页表相邻的 UNMOVABLE 页、把控制页挪到页表处，即可获得任意物理地址读写，读固定物理地址 `0x9c000` 泄露内核 text、补丁 `do_symlinkat` 后在 nsjail 内调用 `symlink()` 完成沙箱逃逸。

## 原理

- **UAF 的成因**：驱动在 `copy_to_user` 拿到无效用户地址时拷贝失败，走错误分支调用 `fput(filp)`；当引用计数归零且是匿名文件时，`struct file` 被 `kmem_cache_free` 归还 filp 缓存，但进程的 fd 表项没有清空，fd 仍然指向已释放对象，后续对该 fd 的任意操作都是 UAF。
- **为什么必须 cross-cache**：`struct file` 来自专用的 `filp` kmem_cache，不与 PTE 页同缓存；只有把「该缓存中所有对象都释放 → 空 slab 页被 SLUB 归还 buddy → 再用页表分配取回同一物理页」这条路走通，悬空指针才会别名到页表页上。页表页走 `alloc_pages(GFP_PGTABLE_USER, 0)`，是 order-0、`MIGRATE_UNMOVABLE`。
- **f_count 为什么是原语**：`struct file` 的 `f_count` 位于对象内固定偏移（示例布局为 +0x38）的 `atomic_long_t`；`dup(fd)` 每次让内核按 fd 找到同一个对象并 `get_file()` 自增该字段。对象变成页表页后，这个 qword 正好是页表的第 `0x38/8 = 7` 项，`dup` 0x1000 次等于给该 PTE 的值加 0x1000。x86-64 PTE 的物理页帧号从 bit 12 开始，因此 +0x1000 恰好是物理页帧 +1，PTE 从「映射第 N 个物理页」变成「映射第 N+1 个物理页」。
- **为什么刚好自映射**：喷射时按固定步长 `mmap` 大块区域并逐页写入触发缺页，每次缺页分配一个用户数据页，进入新的 2MB 区间时才会新分配一张末级页表页（每张页表页覆盖 512 个 PTE，原文按每块 0x8000 个地址写入来保证能摊到新的页表页）；页表页和它映射的数据页在伙伴系统里由同一次批量分配取出、物理位置相邻。第 7 项 PTE 指向的物理页 +1 之后即页表页本身，于是「用户虚拟地址 A 指向它自己的页表页」，读 A 等于读 PTE 数组、写 A 等于改 PTE 数组——两个「页」重叠完成。
- **为什么不能只靠 dup**：要让某个 PTE 指向内核 text 的物理页，需要把 PTE 值改成 `phys | flags`，而 `dup` 只能做「+N 页帧」的等比平移，无法跨越大范围物理地址；而 `munmap` 掉该页再让页表重新占位也不行，因为匿名的 `mmap` 数据页来自 `MIGRATE_MOVABLE`，与页表页的 `MIGRATE_UNMOVABLE` 不在同一个 freelist。
- **dma-heap 的作用**：`/dev/dma_heap/system` 的 `DMA_HEAP_IOCTL_ALLOC` 申请的是 `MIGRATE_UNMOVABLE`、同为 order-0 的页，和页表页从同一个区域出页。`munmap` 掉已被篡改的那一页、立刻 `mmap(MAP_POPULATE|MAP_SHARED, dmabuf.fd)` 回同一虚拟地址，dma-buf 的物理页大概率紧邻页表页；再 `dup` 0x1000 次，控制页就被平移到页表中，从此写控制页 = 改 PTE。
- **任意物理读写**：把控制页里的 PTE 写成 `target_phys | 0x8000000000000067`（bit63 NX + present/rw/user/accessed/dirty），对应虚拟地址就映射该物理页；不需要改内核页表、不需要 ROP，SMEP/SMAP/KASLR 都不构成阻碍，因为改的是用户页表。
- **物理 KASLR 绕过**：物理地址 `0x9c000` 处是内核早期页表相关数据，其中一条表项的值等于内核 `.text` 的虚拟地址（direct map 让同一数据有两个视图）。读出它即得内核虚拟基址；由于物理基址与虚拟基址的固定差值（示例 `0x1c04000`）可直接算物理基址。
- **为什么补丁 `do_symlinkat`**：目标在 nsjail 里，可用系统调用受限但 `symlink` 可用；把该 syscall 入口的物理页映射出来、覆盖成用户态准备好的 shellcode，再调用 `symlink("/jail/x","/jail")` 就在内核态执行任意代码。shellcode 做 `commit_creds(init_cred)`、`switch_task_namespaces(task, init_nsproxy)`、`copy_fs_struct(init_fs)` 写回 `task->fs`，最后经 KPTI trampoline 回用户态读块设备拿 flag。

## 触发条件

- 存在「释放 `struct file` 但 fd 仍可用」的 UAF（示例：`copy_to_user` 失败分支里的 `fput()`），或其它能稳定拿到 filp 缓存悬空指针的漏洞。
- 能大量 `open()` 制造 filp 对象并全部 `close()`，把该缓存的 slab 页整页归还 buddy；能 `mmap` + 触碰分配末级页表页。
- 对象内能被反复自增的字段恰好落在 PTE 数组内（示例 `f_count` 在 +0x38；不同内核布局需重算，`struct file` 大小/字段偏移随版本变化）。
- 目标暴露 `/dev/dma_heap/system`（Android/部分发行版默认开启）；没有 dma-heap 时需换其它 `MIGRATE_UNMOVABLE` order-0 页来源。
- 已知目标内核的符号偏移（`commit_creds`、`init_cred`、`init_nsproxy`、`copy_fs_struct`、KPTI trampoline 地址）或能通过物理读写自行扫描。
- 能以 `MAP_FIXED` 回填同一虚拟地址并 `MAP_POPULATE` 立即分配物理页。

## 利用步骤

1. `sched_setaffinity` 绑核，`open("/dev/<vuln>")`、`open("/dev/dma_heap/system")`；先 `mmap` 一大片固定虚拟地址区域（示例从 `0xdead0000` 起、步长 0x10000、每块 0x8000）只建 VMA、不触碰。
2. 堆喷 filp：循环 `open("/", O_RDONLY)`；在序列中点用 `ioctl(dev_fd, 0, 0xdeadbeef)` 触发漏洞，让某一 fd 变成悬空指针（记为 `uaf_fd`）。
3. 关闭所有 fd，让 filp 缓存中的对象全部释放、空 slab 页归还 buddy。
4. 逐块触碰虚拟区域：每块写 8 个页，每次写触发缺页、分配一个 PTE 页，其中一个 PTE 页落在 victim slab 上。
5. 检测重叠：`dup(uaf_fd)` 0x1000 次后遍历所有页，寻找内容不是原填充字符的页——命中即为被自增过的 PTE 所在页（控制页）。
6. `munmap(控制页, 0x1000)` 释放该页，用 `DMA_HEAP_IOCTL_ALLOC` 分配的 dma-buf 以 `MAP_POPULATE|MAP_SHARED` 映射回同一地址；再 `dup(uaf_fd)` 0x1000 次，控制页的物理位置平移到页表处（可用「控制页首 qword 是否变大/是否为合法 PTE 值」判断成功）。
7. 向控制页写入 `0x9c000 | 0x8000000000000067`，读对应虚拟地址得到内核 text 虚拟地址；按固定差值算物理基址。
8. 把控制页的 PTE 改成「目标函数所在物理页 | 标志」，通过对应虚拟地址 `memcpy` shellcode 到页内偏移处；调用 `symlink()` 触发，shellcode 提权/换 namespace/换 fs 后回用户态读 flag。

## PoC

```c
/* 关键原语：把已释放 file 的 f_count 当 PTE 值自增 */
for (int i = 0; i < 0x1000; i++) dup(uaf_fd);          /* PTE 值 += 0x1000（页帧 +1）*/

/* 控制页被挪进页表后：写控制页即写 PTE */
struct dma_heap_allocation_data d = {.len = 0x1000, .fd_flags = 2};
ioctl(dma_fd, DMA_HEAP_IOCTL_ALLOC, &d);
munmap(ctl, 0x1000);
char *dmabuf = mmap(ctl, 0x1000, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_SHARED, d.fd, 0);
for (int i = 0; i < 0x1000; i++) dup(uaf_fd);          /* 平移到页表页 */

*(unsigned long *)dmabuf = 0x8000000000000067UL;       /* 映射物理页 0 */
/* 之后 dmabuf[0..0xfff] 即物理页 0 的内容，可任意改写 PTE → 任意物理读写 */
```

半成点：`struct file` 的 `f_count` 偏移、PTE 自映射所需的 `dup` 次数、dma-buf 与页表页的相邻概率都依赖目标内核版本与内存布局，必须按目标重算；原题最终靠 patch `do_symlinkat` 逃逸，符号偏移为硬编码。

## 变体与关联

- **替代自增原语**：任何「用户可反复 +1 / +4 / +8 的已 UAF 字段」都可替换 `f_count`，只要它在页表页内落成 PTE 项；也可用 `refcount_inc`、`i_count`、socket 引用计数等。
- **替代相邻页来源**：`dma-heap` 之外，AF_PACKET TX/RX ring、`io_uring` 的 ring 页、`userfaultfd` 也可作为 `MIGRATE_UNMOVABLE` 的同 order 页来源，见 [[binary-pwn-kernel-buddy-page-spray-packet-tx-ring]]。
- **与页表页 double free 路线的区别**：[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]] 需要先对 order-0 页做 double free 让两级页表重叠；本卡不 double free 页，而是让 slab 对象与页表页跨缓存重叠，再用对象自身字段做 PTE 自增，把「页表布局」换成「堆对象布局」。
- **跨缓存前置**：如何精确地把空 slab 页归还 buddy，见 [[binary-pwn-kernel-cross-cache-uaf-cred-jar-clone-lpe]] 与同批「SLUB cpu_partial 计数释放页」卡。
- **落地目标**：`modprobe_path`/`core_pattern` 覆盖、`cred` 改写、syscall 补丁都可用本原语完成；本例因为身处 nsjail 且只能调 `symlink`，选择补丁 `do_symlinkat`。

## 检测与防御

- **代码修复**：错误分支释放对象后必须同时失效 fd 表项（`fd_install` 前失败就不该把 fd 暴露给用户），`fput()` 与 fd 生命周期严格配对；对 `copy_to_user` 失败路径单独审计。
- **内核加固**：`CONFIG_PAGE_TABLE_CHECK` 能发现页表页被非法改写；`CONFIG_SLAB_FREELIST_HARDENED`、`CONFIG_DEBUG_VM`、KFENCE 有助于暴露 filp 缓存的 UAF；`CONFIG_INIT_ON_FREE_DEFAULT_ON` 提高 `f_count` 之类字段被复用的门槛但挡不住自增。
- **攻击面收敛**：容器/沙箱下用 seccomp 阻断 `dup` 大规模调用与 `/dev/dma_heap/*` 访问；`dma-heap` 设备节点默认只给特定 group 权限；限制 unprivileged userns 与 `mmap` 固定地址。
- **检测**：单进程对同一 fd 数千次 `dup` 后伴随大段 `munmap`/`mmap(MAP_POPULATE)` 的异常模式；`/dev/dma_heap/system` 的高频 `DMA_HEAP_IOCTL_ALLOC`；进程在极短时间内读遍大量物理页（物理 KASLR 扫描特征）；内核 text 被改写可由 IMA/HVCI、`CONFIG_STRICT_KERNEL_RWX` 与安全启动链提供完整性告警。
