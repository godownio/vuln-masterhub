---
id: binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks
title: glibc 2.31+ 高版本 large bin attack：中间插入分支的双链表检查与 bk/bk_nextsize 双写点
type: scenario
domain: binary
path: binary/pwn/heap
technique: high-version-largebin-attack-middle-insert-dual-write
tags:
- pwn
- heap
- glibc
- largebin
- large-bin-attack
- arbitrary-write
- bk-nextsize
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: glibc >= 2.31（中间插入分支新增 largebin double linked list corrupted 检查；旧版本无此检查）
verification:
  verified_by: verifier-V177
  verified_at: '2026-11-06T17:22:07+08:00'
  notes: 已对照原文及 4 张图核对；仅双写原语，无 end-to-end 最终链；affected_versions 已按原文设置为 glibc >= 2.31
url: /docs/binary/pwn/heap/binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks/
draft: false
kb_aliases:
- 高版本 largebin attack
- glibc 2.31 largebin
- largebin double linked list corrupted
- bk_nextsize 伪造
- largebin 双写
- large bin 中间插入
---

## 一句话结论

glibc 2.31+ 在把一个 unsorted 大 chunk 插入**非空 largebin 的中间位置**时，新增了 `fwd->bk_nextsize->fd_nextsize == fwd` 与 `bck->fd == fwd` 两项双向链表检查；如果攻击者能通过 UAF/重叠改写已在 largebin 中 chunk 的 `bk` 和 `bk_nextsize`，并让两个目标地址处的对应字段预先等于 `fwd`，插入过程就会把 victim chunk 地址同时写到两个任意可写地址（`*(target1)=victim`、`*(target2)=victim`），得到一次双目标任意写（写入值受限于堆指针）。

## 原理

- **largebin 组织方式**：同一 largebin 中不同大小的 chunk 用 `fd_nextsize` 按从大到小、`bk_nextsize` 按从小到大链接；相同大小的 chunk 用 `fd`/`bk` 链接。`bin->fd` 指向最大 chunk，`bin->bk` 指向最小 chunk。未排序的 chunk 先挂在 unsorted bin，下一次 `malloc` 遍历 unsorted 时才按大小归入对应 largebin。
- **分支选择**：设 `bck = bin_at(av, idx)`、`fwd = bck->fd`，待插入 chunk 为 `victim`。
  - 若 `size(victim) < size(bck->bk)`（比 bin 中最小的还小）：走“小者插入”分支，`fwd = bck; bck = bck->bk;`，主要写 `fwd->fd->bk_nextsize` 与尾部的 `bck->fd`。
  - 否则从最大 chunk 沿 `fd_nextsize` 向前找插入点；若大小相等插到第二个位置；若找到一个比 victim 大的 `fwd`（即 victim 在中间），走**中间插入**分支，这正是高版本检查所在路径。
- **中间插入分支（glibc 2.31+）关键代码**：
  ```c
  victim->fd_nextsize = fwd;
  victim->bk_nextsize = fwd->bk_nextsize;
  if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
      malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
  fwd->bk_nextsize = victim;
  victim->bk_nextsize->fd_nextsize = victim;   /* 写点 A */
  bck = fwd->bk;
  if (bck->fd != fwd)
      malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
  ...
  victim->bk = bck;
  victim->fd = fwd;
  fwd->bk = victim;
  bck->fd = victim;                            /* 写点 B */
  ```
- **两项检查的含义**：
  - 检查 A：`fwd->bk_nextsize->fd_nextsize` 必须等于 `fwd`。若把 `fwd->bk_nextsize` 改成 `target2 - 0x20`，则要求 `*(target2) == fwd`（`fd_nextsize` 位于 chunk+0x20）。
  - 检查 B：`bck = fwd->bk`，要求 `bck->fd == fwd`。若把 `fwd->bk` 改成 `target1 - 0x10`，则要求 `*(target1) == fwd`（`fd` 位于 chunk+0x10）。
- **双写点**：两项检查通过后，`fwd->bk_nextsize = victim` 与 `victim->bk_nextsize->fd_nextsize = victim` 把 `*(target2)` 写成 victim；随后 `bck->fd = victim` 把 `*(target1)` 写成 victim。因此一次 largebin attack 可以同时改写两个地址，写入值是 victim chunk 的地址（堆指针），不是任意 8 字节值。
- **如何满足检查**：两个目标地址必须在攻击前就是可写内存，且 `*(target2)` 与 `*(target1)` 已经等于 `fwd`。常见做法是把目标选在可控的 fake chunk/栈/`.bss` 区域，先用其他写原语把对应槽位写成 `fwd`；或让目标落在已有指针恰好指向 `fwd` 的位置（例如 `fwd` 在 bin 中的链接字段、可控的堆块字段）。若无法预填，触发时 glibc 会直接 `malloc_printerr` 终止。
- **信息泄露**：largebin 中的 chunk 的 `fd/bk` 指向 `main_arena` 附近（泄露 libc），`fd_nextsize/bk_nextsize` 指向其他堆 chunk（泄露 heap）；一个 chunk 可同时提供 libc 与 heap 线索。
- **与旧版本的区别**：glibc <2.31 的 largebin 插入没有上述两项检查，直接改 `bk`/`bk_nextsize` 即可写；2.31+ 必须同时满足回指检查，攻击门槛提高，但通过 fake chunk/预填仍可利用。

## 触发条件

- 目标 glibc 为 2.31 或更高，且存在 UAF、重叠 chunk、或可编辑已释放 chunk 的 `bk`/`bk_nextsize` 字段。
- 能制造至少一个 largebin chunk 和一个待插入的 unsorted large chunk，并使 victim 落在中间插入分支（victim 大小不是 bin 中最大/最小，且不等于已有 chunk 大小）。
- 两个目标地址可写，且攻击前 `*(target1)`、`*(target2)` 能被布置为 `fwd`（否则检查失败）。
- 已知或可预测 `fwd` 的堆地址、目标地址（需要 libc/heap 泄露）。
- 目标写入值为 victim 的堆指针，后续需配合 tcache poisoning、`mp_`、`_IO_list_all` 等把指针转化为代码执行。

## 利用步骤

1. 泄露 libc 与 heap：释放大 chunk 进 unsorted bin，读 `fd/bk` 得 `main_arena` 偏移；释放/整理 largebin chunk 后读 `fd_nextsize/bk_nextsize` 得堆地址。
2. 构造 largebin：让一个 large chunk 归入目标 largebin，保留对其 `bk`/`bk_nextsize` 的写能力（UAF 或重叠 chunk）。
3. 布置检查：选两个可写目标 `target1`、`target2`，把 `*(target1)` 与 `*(target2)` 预填为 `fwd`（可用栈上可控值、`.bss` 或 fake chunk 字段）。
4. 改写 `fwd`：`fwd->bk = target1 - 0x10`、`fwd->bk_nextsize = target2 - 0x20`。
5. 释放一个中间大小的 large chunk 到 unsorted bin，再触发一次 `malloc` 让它进入 largebin 的中间插入分支；检查通过后 `*(target1)=victim`、`*(target2)=victim`。
6. 按目标选择后续链：把 `mp_.tcache_bins` 放大后走 tcache poisoning、改 `_IO_list_all` 走 FSOP、改 `global_max_fast` 等；也可先用双写把一个可控指针写到栈/全局变量，再配合其他原语。
7. 调试：在 `_int_malloc` 的 largebin 插入处下断，检查 `fwd->bk_nextsize->fd_nextsize`、`bck->fd` 是否等于 `fwd`；失败时优先核对目标地址是否可写、预填值是否正确、victim 是否真的走中间分支。

## PoC

文章给出的是 glibc 源码与 pwndbg 堆布局演示，没有完整 end-to-end exp。最小布局/写点示意（未在本机执行）：

```text
# 目标地址预填（检查要求）：
*(target1) == fwd
*(target2) == fwd

# 改写已在 largebin 的 fwd：
fwd->bk        = target1 - 0x10
fwd->bk_nextsize = target2 - 0x20

# 触发：把中间大小的 victim（来自 unsorted bin）插入该 largebin
# 检查通过后：
*(target1) = victim      # bck->fd = victim
*(target2) = victim      # fwd->bk_nextsize->fd_nextsize = victim
```

```c
/* glibc 2.31+ _int_malloc 中间插入分支（关键片段） */
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
if (fwd->bk_nextsize->fd_nextsize != fwd)
    malloc_printerr("malloc(): largebin double linked list corrupted (nextsize)");
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;      /* target2 = victim */
bck = fwd->bk;
if (bck->fd != fwd)
    malloc_printerr("malloc(): largebin double linked list corrupted (bk)");
/* ... */
bck->fd = victim;                               /* target1 = victim */
```

## 变体与关联

- **目标变体**：`mp_.tcache_bins`（放大 tcache 后毒化，见 [[binary-pwn-heap-largebin-attack-mp-tcache-bins-stack-rop]]）、`_IO_list_all`（FSOP，见 [[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]）、`global_max_fast`、`__free_hook`（旧 glibc）。
- **分支变体**：victim 比 bin 中最小 chunk 还小时走“小者插入”分支，该分支在 2.31+ 没有同样的 `fwd->bk_nextsize`/`bck->fd` 回指检查，但可写点位置不同；实际利用需按 victim 大小与 bin 内已有 chunk 选择分支。
- **组合变体**：House of Storm 把 unsorted bin attack 与 largebin 写点组合，见 [[binary-pwn-heap-house-of-storm-unsorted-largebin-fake-chunk]]；tcache stashing unlink 用 largebin 写点预置 fake chunk 的 `bk`，见 [[binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write]]。
- **版本差异**：2.31 前后的检查差异决定了是否需要预填 `fwd`；2.39 等新版本还有 safe-linking/tcache key，但 largebin 的 `fd/bk` 本身不在 safe-linking 保护范围内。
- **边界**：若两个目标地址不可写、无法预填 `fwd`、victim 走错分支或大小落在相同 chunk 的等值分支，攻击会中止或只得到单写点；写入值固定为 victim 堆指针，不能直接写任意常量。

## 检测与防御

- **分配器完整性**：保持 glibc 补丁更新，启用 `MALLOC_CHECK_`/ASAN；监控 `malloc_printerr` 的 “largebin double linked list corrupted (nextsize/bk)” 报错，它通常意味着有人在伪造 `fd_nextsize/bk_nextsize`。
- **代码修复**：修复 UAF/重叠写、越界写和可编辑已释放 chunk 的接口；对 size 与索引做严格校验；不要给攻击者保留对 freed large chunk 的写能力。
- **利用面收敛**：使用 Full RELRO、PIE、Canary、safe-linking、tcache key；避免把 `mp_`/`_IO_list_all` 等敏感结构暴露在可预测地址（PIE/ASLR）。
- **检测特征**：largebin chunk 的 `bk`/`bk_nextsize` 指向栈/`.bss`/非法地址；堆内存中出现指向 `mp_`、`_IO_list_all`、`global_max_fast` 的伪造指针；`malloc` 在遍历 unsorted bin 时崩溃。
