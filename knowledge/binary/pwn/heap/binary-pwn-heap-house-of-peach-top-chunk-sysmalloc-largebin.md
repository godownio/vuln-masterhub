---
id: binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin
title: House of Peach：无 free 函数时借 sysmalloc 释放旧 top chunk 伪造 unsorted/largebin
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-peach-top-chunk-sysmalloc-largebin
aliases:
- House of Peach
- 无 free 堆利用
- sysmalloc 释放 old top
- top chunk size 低 12 位
- 伪造 unsorted chunk
- largebin attack 无 free
- myfruitshop
tags:
- pwn
- heap
- glibc
- top-chunk
- sysmalloc
- unsorted-bin
- largebin-attack
- house-of-orange
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: glibc（原文称任意版本；示例 glibc 2.39）
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:03+08:00'
  notes: 已对照原文源码、demo 输出与 pwndbg 图核对；原文 demo 到任意写为止，未展示完整 RCE；PoC 未复跑。
---

## 一句话结论

当目标没有任何 `free` 功能、只能通过堆溢出改到 top chunk 的 `size` 时，可以只改 size 的低 12 位以保持页对齐，申请一个大于旧 top 的 chunk 触发 `sysmalloc` 把旧 top `_int_free` 到 unsorted bin；再利用 sbrk 扩展后新堆与旧堆连续、旧 top 被缩小留下的空间，伪造一个跨越既有 chunk 的超大 unsorted chunk，完成 libc/heap 泄露并接 largebin attack 任意写。

## 原理

- `sysmalloc` 在主分配区（main_arena）处理“当前 top 不够分配”时，会通过 `MORECORE`/`sbrk` 扩展堆；若返回的新 brk 与旧 top 的 `old_end` 不一致，会先把旧 top 缩小为 `(old_size - 2*CHUNK_HDR_SZ) & ~MALLOC_ALIGN_MASK`，设置两个 fencepost，然后调用 `_int_free(av, old_top, 1)` 把旧 top 放进 unsorted bin。
- 高版本 glibc 在 `sysmalloc` 里有断言：
  - `old_size >= MINSIZE`
  - `prev_inuse(old_top)`
  - `old_end = old_top + old_size` 需要页对齐（`old_end & (pagesize-1) == 0`）
  - `old_size < nb + MINSIZE`
  直接像 House of Orange 那样把 top size 改成 1 会失败；House of Peach 只把 size 改成 `原 size & 0xfff`（保留低 12 位），这样 `old_end` 仍页对齐、`old_size` 仍大于 MINSIZE、`prev_inuse` 保持，同时 `old_size` 小于申请的 `nb+MINSIZE`，四个断言都能过。
- `sbrk` 分配的新堆地址与旧堆连续；旧 top 被 `_int_free` 后进入 unsorted bin，但它的可用空间只到 `old_end`。攻击者随后可以修改“新的 top chunk”的 size，使其覆盖从旧 top 一直延伸到后面的 `chunk_2`/`chunk_3`，并在 `chunk_3` 的数据区伪造 `prev_size`/`size` 形成一个跨块的 unsorted chunk；这样后续从 unsorted bin 分配时就会返回与 `chunk_2`/`chunk_3` 重叠的 chunk。
- 泄露与利用：
  - 先把伪造的 unsorted chunk 申请到 `chunk_2` 的位置，读取其 `fd`/`bk`，得到 libc 地址（unsorted bin 的 fd/bk 指向 `main_arena` 附近）。
  - 再申请让 unsorted chunk 的 `fd_nextsize` 与 `chunk_3` 的数据重合，并申请大块把它移入 largebin，读取 `fd_nextsize`/`bk_nextsize` 得到 heap 地址。
  - 再次修改新的 top chunk size，让新 top 也被 `sysmalloc` 释放进 unsorted bin；随后用 `chunk_3` 覆写 largebin 的 `fd_nextsize`/`bk_nextsize`，在后续 largebin 插入时完成 largebin attack，把堆地址写到任意目标地址（示例写到 `0x4440000` 的 mmap 区）。
- 该手法成立的关键是：`sbrk` 堆连续、旧 top 会被 `sysmalloc` 释放、攻击者能改 top size、能申请大于旧 top 的块、且能在重叠的 `chunk_2`/`chunk_3` 上读写。它把“没有 free”变成“sysmalloc 替我 free”。

## 触发条件

- 目标使用 glibc main_arena（主线程/主分配区），堆通过 `sbrk` 扩展，申请大小低于 `mmap` 阈值（不会走 mmap 分配）。
- 存在至少能改写 top chunk `size` 的堆溢出（只需覆盖 size 字段，不必控制 fd/bk）。
- 程序允许申请比当前 top 更大的 chunk（触发 `sysmalloc`），并能进行多次 malloc/读写。
- 有可重叠的后续 chunk（如两个 0x1000 chunk）用于泄露 libc/heap 和承载 largebin 攻击字段。
- 目标 glibc 的 `sysmalloc` 断言/检查可被“保留低 12 位”的技巧满足（高版本 2.39 示例成立）。

## 利用步骤

1. 先分配一个小 chunk（如 `malloc(0x28)`），通过堆溢出把紧随其后的 top chunk size 改为 `原 size & 0xfff`，保持页对齐。
2. `malloc(0x1000)` 触发 `sysmalloc`：旧 top 被 `_int_free` 到 unsorted bin，新的 top 位于 sbrk 扩展区；再 `malloc(0x1000)` 得到 `chunk_3`。
3. 再 `malloc(0x28)` 从旧 top 的 unsorted 空间切出一块，使旧 top 剩余部分仍留在 unsorted bin。
4. 计算 `chunk_1` 到 `chunk_3` 的偏移，在 `chunk_3` 的数据区写入伪造的 `prev_size`/`size`，并把当前 top chunk 的 size 改为 `offset+1`，使 top 覆盖到 `chunk_3`。
5. 申请一个大块，让伪造的 unsorted chunk 与 `chunk_2` 重叠；读取 `chunk_2` 的 `fd`/`bk` 泄露 libc。
6. 继续申请，使 unsorted chunk 的 `fd_nextsize` 与 `chunk_3` 数据重合，再申请大块触发 largebin；读取 `fd_nextsize`/`bk_nextsize` 泄露 heap。
7. 再次把新 top size 改小并 `malloc` 大块，让新 top 也进 unsorted bin；用 `chunk_3` 覆写 largebin 的 `fd_nextsize`/`bk_nextsize`，触发 largebin attack 写入目标地址。
8. 用任意写改 `__free_hook`/`_IO_list_all`/函数指针等，转入 ROP 或 FSOP 完成 RCE（原文 demo 到任意写为止）。

## PoC

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int main(void) {
    size_t *chunk_1, *chunk_2, *chunk_3, *tmp;
    long offset;

    chunk_1 = malloc(0x28);
    // top chunk size 位于 chunk_1 之后；只保留低 12 位以保持页对齐
    chunk_1[5] = chunk_1[5] & 0xfff;

    chunk_2 = malloc(0x1000);   // 触发 sysmalloc，旧 top 被 free 到 unsorted
    chunk_3 = malloc(0x1000);
    chunk_1 = malloc(0x28);     // 旧 top 剩余部分进入 unsorted

    // 伪造跨 chunk 的 unsorted chunk，并扩大当前 top
    offset = ((chunk_3 - chunk_1) * 8) + 0x400 - 0x30;
    chunk_3[0x7f] = 0x1010 - 0x400;  // fake size
    chunk_3[0x7e] = offset;          // fake prev_size
    chunk_1[5] = offset + 1;         // 新 top size 覆盖到 chunk_3

    // 申请到 chunk_2 位置，读取 fd/bk 泄露 libc
    tmp = malloc(((chunk_2 - chunk_1) * 8) - 0x10 - 0x30);
    printf("libc leak: %p\n", (void *)chunk_2[0]);

    // 继续申请，让 fd_nextsize 与 chunk_3 重合，再申请大块进 largebin 泄露 heap
    tmp = malloc(0x1000 - 0x10);
    tmp = malloc(0x1000 - 0x10);
    printf("heap leak: %p\n", (void *)chunk_3[0]);

    // 再次缩小新 top 并 malloc 大块，让新 top 进 unsorted
    tmp = malloc(0x1000);
    tmp[0x201] = tmp[0x201] & 0xfff;
    tmp = malloc(0x1000);

    // largebin attack：把堆地址写到 0x4440000
    void *addr = mmap((void *)0x4440000, 0x1000,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    chunk_3[1] = 0x4440000 - 0x20;
    tmp = malloc(0x1000);
    printf("target: %p\n", addr);
    return 0;
}
```

## 变体与关联

- 变体：不接 largebin attack，可只利用伪造的 unsorted chunk 做堆重叠，改 `tcache`/`fd` 指针或覆盖相邻对象；也可用重叠 chunk 直接改函数指针/返回地址。
- 变体：有一定 free 能力时，House of Peach 可与 tcache poisoning、unsorted bin attack、House of Storm 组合；有可控 fd/bk 时回到经典 House of Orange。
- 变体：不同 glibc 版本的 `sysmalloc` 断言/`top_pad`/`MINSIZE` 不同，保留低位的具体掩码（0xfff）需按页大小和目标版本确认；非 main_arena 的 `sysmalloc` 路径不同。
- 关联：[[binary-pwn-heap-house-of-storm-unsorted-largebin-fake-chunk]]（unsorted+largebin 组合）、[[binary-pwn-heap-largebin-attack-mp-tcache-bins-stack-rop]]（largebin attack 目标）、[[binary-pwn-heap-house-of-botcake-tcache-poison]]（另一种 top/tcache 利用）。
- 边界：目标走 mmap 分配、使用独立 arena/线程缓存、禁止大块申请、top size 被完整校验（不能只改低位）、或 glibc 修复了该 `sysmalloc` 路径时，本手法失效；原文 demo 是本地验证到任意写，未展示完整 RCE。

## 检测与防御

- 不要只检查“程序没有 free 函数”就认为没有堆利用面；审计 `malloc` 后的堆溢出、top chunk 可写性、以及 `sysmalloc` 触发的大块申请。
- 开启 glibc 的堆保护：`MALLOC_CHECK_`、`glibc.malloc.tcache_count`/`check`、指针 mangling、`malloc_consolidate` 校验；及时更新 glibc 以收紧 `sysmalloc` 断言。
- 使用安全的分配器/隔离堆（Scudo、hardened_malloc），减少 top chunk 元数据被溢出的影响；对 top size 做完整性校验，不只依赖页对齐断言。
- 检测：堆内存中 top chunk size 被改为异常小/异常大的值；`sysmalloc` 频繁触发 `_int_free(old_top)`；unsorted/largebin 的 `fd_nextsize`/`bk_nextsize` 指向非堆/非 arena 地址；进程在 malloc 后立即崩溃于 `malloc_printerr`。
- 响应：保留崩溃现场与堆转储，检查相邻 chunk 的 prev_size/size、unsorted/largebin 链表完整性，定位溢出点并修复。
