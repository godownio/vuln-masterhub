---
id: binary-pwn-heap-malloc-consolidate-unlink-overlapping-via-malloc
title: 借 malloc_consolidate 在 malloc 路径触发 unlink：伪造 fastbin chunk 制造堆块重叠（glibc 2.29）
type: scenario
domain: binary
path: binary/pwn/heap
technique: malloc-consolidate-unlink-overlapping-via-malloc
tags:
- glibc
- heap
- pwn
- malloc-consolidate
- unlink
- overlapping
- fastbin
- prev-size
- prev-inuse
- 2.29
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-9
  verified_at: '2026-11-08T01:15:45+08:00'
  notes: 已对照原文核对；原文图30-40 有 gdb 完整验证：malloc 大请求触发 malloc_consolidate、fastbin 取 chunk、size 与 prev_inuse 检查、unlink_chunk 两检查通过、set_head 0x50 合并后入 unsortedbin 再进 smallbins 0x50，构成 overlapping 执行证据，非纯理论示意；卡结论为 overlapping 中间能力未包装成 RCE，confidence high、severity medium 合理；dedup 复核候选均为 free 触发加全局数组 GOT 或栈 ROP 的完整 RCE 链，与 malloc 触发且仅中间能力不同，dedup_review 成立；原文只有以 glibc-2.29 为例这类示例调试环境版本、未写受影响区间，省略 affected_versions；未验证点：PoC 为结构示意未独立复跑、卡未含 sources 字段。
url: /docs/binary/pwn/heap/binary-pwn-heap-malloc-consolidate-unlink-overlapping-via-malloc/
draft: false
kb_aliases:
- malloc 触发 unlink
- malloc_consolidate 利用
- fastbin 合并 overlapping
- 不依赖 free 的 unlink
- consolidate unlink 堆重叠
---

## 一句话结论

在 glibc 2.29 上，申请一个大于 small bin 范围的 chunk 会触发 `malloc_consolidate`，把 fastbin 中的 chunk 整理进 unsorted bin 并执行与 `free()` 相同的相邻合并逻辑（含 `unlink_chunk`）；只要把某个 fastbin chunk 的 `PREV_INUSE` 清零、`prev_size` 指向一个伪造好的低地址 chunk（其 `size == prev_size`、`fd/bk` 指向自身以过双向链表检查），就能在**不调用 free** 的情况下由 malloc 触发 unlink，把两个 chunk 合并成一个大 chunk 落入 unsorted/small bin，从而制造 chunk 重叠（overlapping）。

## 原理

- **为什么 malloc 会走到 unlink**：`_int_malloc` 处理大请求时先 `idx = largebin_index(nb)`，若 `av->have_fastchunks` 为真就调用 `malloc_consolidate(av)`。该函数是 `free()` 的精简变体：遍历每条 fastbin 链，用 `atomic_exchange_acq(fb, NULL)` 取出全部 chunk，对每个 chunk 做 `fastbin_index(chunksize(p))` 校验后，按 `prev_inuse(p)` / `inuse_bit_at_offset(nextchunk, nextsize)` 决定是否向后/向前合并，合并时对相邻 chunk 调用 `unlink_chunk(av, p)`，最后把结果链入 unsorted bin。
- **unlink 的检查与伪造点**：`unlink_chunk` 校验 `chunksize(p) == prev_size(next_chunk(p))` 以及 `fd->bk == p && bk->fd == p`。因此把低地址伪造 chunk 的 `size` 填成与上层 chunk 的 `prev_size` 相同，并把 `fd`、`bk` 都填成指向该伪造 chunk 自身（或满足 `fd->bk`/`bk->fd` 回指的可写堆地址），即可通过两处检查。`malloc_consolidate` 里还有一条 `chunksize(p) != prevsize` 的 `corrupted size vs. prev_size in fastbins` 检查，同样靠一致伪造绕过。
- **为什么能形成重叠**：unlink 把低地址 chunk 从双向链表摘出后，`size += prevsize`、`p = chunk_at_offset(p, -prevsize)`、`set_head(p, size|PREV_INUSE)`、`set_foot(p, size)`，于是原本两个独立 chunk 被当作一个更大的 chunk 放入 unsorted bin（随后按大小进入 small bin）。攻击者同时持有指向原两个 chunk 的指针，就得到 overlapping，可进一步做 UAF 读/写或 tcache poisoning。
- **与常规 unlink 的区别**：经典 unsafe unlink 靠 `free()` 一个大 chunk 触发；本手法完全由 `malloc()` 大请求触发 `malloc_consolidate` 内的合并路径，适合只有分配操作、无法主动 free 目标 chunk 的题设。
- **版本边界**：示例为 glibc 2.29 源码；`malloc_consolidate` 的合并/unlink 逻辑在高版本大体保留，但各版本对 `prev_size`、`chunksize`、`have_fastchunks` 的检查强度不同，需按目标 libc 复核。

## 触发条件

- 目标 glibc 的 `malloc_consolidate` 仍走「fastbin → unlink 合并 → unsorted bin」路径（示例 2.29）。
- 攻击者能在堆上布置至少两个相邻 chunk，并能写低地址 chunk 的 `size`/`fd`/`bk` 以及高地址 fastbin chunk 的 `prev_size`、`PREV_INUSE` 位（通常需要堆溢出或 UAF 写）。
- 有一个 chunk 已被放进 fastbin（作为触发合并的那个 chunk），且 `av->have_fastchunks` 为真。
- 攻击者能发起一次「大于 small bin 范围」的分配来进入 `malloc_consolidate` 分支。

## 利用步骤

1. 申请 chunk1（低地址，待伪造）与 chunk2（高地址，稍后释放进 fastbin），二者相邻。
2. 在 chunk1 中伪造 `size`、并把 `fd`、`bk` 写成指向 chunk1 自身的堆地址（满足 `fd->bk==p && bk->fd==p`）。
3. 把 chunk2 释放进 fastbin；把 chunk2 的 `prev_size` 改成「chunk1 到 chunk2 的距离」并清掉 chunk2 的 `PREV_INUSE` 位，使合并检查认为低地址 chunk 空闲。
4. 发起一次大于 small bin 范围的 `malloc`，进入 `malloc_consolidate`，从 fastbin 取出 chunk2。
5. `fastbin_index(chunksize(chunk2))` 校验通过后，检查 `!prev_inuse(chunk2)` 成立 → `prevsize = prev_size(chunk2)`、`p = chunk_at_offset(chunk2, -prevsize)` 定位到伪造的 chunk1。
6. `chunksize(chunk1) == prevsize` 与 unlink 双向链表检查均被伪造数据满足 → 对 chunk1 执行 `unlink_chunk`。
7. 两 chunk 合并为一个大 chunk，先入 unsorted bin，随后进入对应 small bin；攻击者保留的两个指针现在指向同一块内存，形成 overlapping。

## PoC

结构示意（glibc 2.29，未在本文档环境编译执行；`chunk` 为 chunk 头地址，`mem` 为用户指针）：

```c
// 布局：A(低地址, 0x20) B(高地址, 0x20)，A 将被伪造成 fake chunk
size_t *a = malloc(0x18);
size_t *b = malloc(0x18);

// 1) 在 A 内伪造 chunk：size 与 B 的 prev_size 一致，fd/bk 自指以过 unlink
a[1] = 0x20 | 1;              // fake size
a[2] = (size_t)(a - 0);       // fd -> 指向自身 chunk 头附近
a[3] = (size_t)(a - 0);       // bk -> 同样回指

// 2) 把 B 的 prev_size 设为 A 的大小，并清 PREV_INUSE
((size_t*)b)[-2] = 0x20;      // prev_size（示意，实际需按溢出/UAF 写）
((size_t*)b)[-1] &= ~1;       // 清 PREV_INUSE 位

// 3) 释放 B 进 fastbin
free(b);

// 4) 大请求触发 malloc_consolidate -> unlink -> 合并
void *big = malloc(0x400);    // > small bin 范围
// 合并后的大 chunk 进入 unsorted/small bin，a 与重叠区域形成 overlapping
```

说明：真实利用中 `a[2]/a[3]` 应填满足 `fd->bk == p && bk->fd == p` 的堆地址（常为「指向全局 chunk 数组 / 指向 a-0x18 处」的已知可写地址），`prev_size`/`PREV_INUSE` 的写入依赖具体漏洞能力（off-by-null、堆溢出或 UAF）。PoC 仅表达字段关系，未独立复跑。

## 变体与关联

- **不依赖 free 的触发**：本手法用 malloc 大请求触发 `malloc_consolidate`；常规 unlink 由 `free()` 大 chunk 触发（本库 `binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system`）。
- **不修改 prev_inuse 位的变体**：改用 small bin chunk 提供天然 `prev_size=0`、避免溢出改下一个 chunk 的 `PREV_INUSE` 位，见关联卡「fastbin + small bin 不改 prev_inuse 位 overlapping」；该变体到 glibc 2.40 仍可用。
- **后续利用**：overlapping 后可做 unsorted bin 泄漏 libc、tcache poisoning 任意地址分配、House of Einherjar / House of Orange / FSOP 等，本库 `binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison`、`binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system`、`binary-pwn-heap-tcache-poison-io-list-all-house-of-apple2`。
- **malloc_consolidate 其它用途**：把 fastbin 中的 chunk 批量转入 unsorted bin 以制造 unsorted bin attack，见 `binary-pwn-heap-glibc235-botcake-malloc-consolidate-io-list-all-apple2`。
- **同源码系列**：本文还讲解 tcache/fastbin 取出不清指针的无 UAF 堆泄漏、tcache stashing unlink attack 等，属同一 malloc.c 分析的不同分支。

## 检测与防御

- 检测：调试/运行时观察 `malloc_consolidate` 中 `unlink_chunk` 被调用、但调用栈来自 `malloc` 而非 `free`；合并前后 chunk 的 `prev_size` 与相邻 chunk `size` 被人为置成一致、`fd/bk` 自指；同一大 chunk 同时被多个指针引用。
- 检测：对 fastbin chunk 的 `PREV_INUSE`/`prev_size` 与相邻 chunk 的 `size` 做一致性校验；监控小请求后紧跟大请求并产生异常大 unsorted/small bin chunk 的模式。
- 防御（题目/审计视角）：保证相邻 chunk 元数据不可被越界写；对 `prev_size`、`size`、`fd/bk` 做边界与一致性检查；升级到引入更严格 `chunksize` 校验与 safe-linking 的 glibc 版本只能缓解部分环节，不能消除伪造 prev_size 类合并攻击。
- 注意：本手法产出的是 overlapping 这一中间能力，本身不直接造成代码执行；最终危害取决于后续 UAF/任意地址写与 FSOP/ORW 链，结论不把它包装成 RCE。
