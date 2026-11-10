---
id: binary-pwn-heap-largebin-attack-version-diff-smaller-insert-bypass
title: Largebin Attack 高低版本差异：2.31 前双写 vs 2.31+ 小者插入分支单写绕过检查
type: scenario
domain: binary
path: binary/pwn/heap
technique: largebin-attack-version-diff-smaller-insert-bypass
tags:
- pwn
- heap
- glibc
- largebin
- large-bin-attack
- arbitrary-write
- bk-nextsize
- version-diff
- ctf
cve: []
severity: high
confidence: high
affected_versions: glibc < 2.31（旧版双写）；glibc >= 2.31（2.31 起新增 largebin 双链表检查，但“小者插入”分支仍可绕过）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V283
  verified_at: '2026-11-08T05:04:51+08:00'
  notes: 已对照原文与全部 10 张图核对：2.31 前 how2heap 2.27 布局（0x420/0x500/0x500）与改写 p2 size=0x3f1、bk=target1-0x10、bk_nextsize=target2-0x20 后 p3 插入使两个栈变量均写为 p3 地址 0x555555605bf0（img/02-05）；2.31+ 用 0x428/0x418 布局，free p1→add 0x438 使 p1 入 largebin、free p2、edit p1->bk_nextsize=target-0x20、add 0x438 触发 smaller-insert 分支写 target（img/06-10）。已修正原卡两处错误：①原一句话结论把 2.31 前 how2heap 双写归入‘新块比最小块更小’分支（实际是排序插入/头部 else 分支），②原利用步骤与 PoC 注释称写入 p2 地址（实际写入 victim=p3 地址，与原文输出一致）。与既有 binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks 的差异成立：既有卡是 2.31+ 中间插入分支需预填 fwd 的双写，本卡是 2.31 前排序插入双写 + 2.31+ smaller-insert 免预填单写，分支/PoC/条件不同，保留。dup-scan 与 tcache stashing unlink 卡为 related，均保留。affected_versions 已按原文 2.31 分界设置；未在本机复跑 PoC。
url: /docs/binary/pwn/heap/binary-pwn-heap-largebin-attack-version-diff-smaller-insert-bypass/
draft: false
kb_aliases:
- largebin attack 高低版本
- largebin attack 2.31
- large bin attack
- 小者插入分支
- bk_nextsize 任意写
- largebin double linked list corrupted 绕过
- how2heap largebin attack
---

## 一句话结论

largebin attack 的本质是把一个堆块地址写到攻击者指定的位置：glibc 2.31 之前可在“排序插入”分支利用被篡改块的 `bk`/`bk_nextsize` 完成两个目标地址的双写（how2heap 2.27 demo 即如此）；2.31 起该中间插入分支新增了 `fwd->bk_nextsize->fd_nextsize` 与 `bck->fd` 两项检查，但“新块比最小块更小”的分支不校验被篡改的 `bk_nextsize`，仍可通过改写 largebin 中最大块的 `bk_nextsize = target-0x20`，在插入比它小的 unsorted 块时把该堆块（victim）地址写到 target。

## 原理

- **largebin 的结构**：同一 largebin 中不同大小的 chunk 用 `fd_nextsize`/`bk_nextsize` 按大小排序，相同大小的 chunk 用 `fd`/`bk` 串联；`bin->fd` 是最大块，`bin->bk` 是最小块。unsorted bin 中的块在下一次 `malloc` 遍历时按大小归入 largebin。
- **插入分支**：当 largebin 非空、待插入 `victim` 的 size 小于 `bck->bk`（当前最小块）时，走“小者插入”分支：
  ```c
  fwd = bck;              // fwd 指向 bin 头
  bck = bck->bk;          // bck 指向最小块
  victim->fd_nextsize = fwd->fd;
  victim->bk_nextsize = fwd->fd->bk_nextsize;
  fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
  ```
  最后一行是写点：它把 `victim` 同时写到 `fwd->fd->bk_nextsize`（最大块的 bk_nextsize）和 `victim->bk_nextsize->fd_nextsize`（由 `fwd->fd->bk_nextsize` 解引用得到的地址 +0x20）。如果攻击者能改写 largebin 中最大块的 `bk_nextsize`，就能控制第二个写点。
- **2.31 之前**：排序插入分支的 `victim->bk_nextsize = fwd->bk_nextsize` 与 `bck = fwd->bk` 都取自被篡改的 largebin 块；攻击者把该块（如 p2）的 `size` 改小、`bk` 改为 `target1-0x10`、`bk_nextsize` 改为 `target2-0x20`，再让一个比它大的 unsorted 块（victim，如 p3）插入 largebin，插入时 `victim->bk_nextsize->fd_nextsize = victim` 写 `target2`、`bck->fd = victim` 写 `target1`，写入值为 victim（p3）的堆地址（典型 how2heap `largebin_attack`：一次攻击写两个栈变量）。
- **2.31 起新增检查**：中间插入分支增加了：
  ```c
  if (fwd->bk_nextsize->fd_nextsize != fwd) malloc_printerr("... corrupted (nextsize)");
  ...
  if (bck->fd != fwd) malloc_printerr("... corrupted (bk)");
  ```
  这使“中间插入 + 随意伪造 bk/bk_nextsize”的双写变难；但“小者插入”分支（新块小于最小块）没有对 `bk_nextsize` 做同样的校验，只按上述代码执行。
- **2.31+ 的绕过**：构造 largebin 中一个块 p1（较大）与 unsorted 中一个块 p2（较小，size 小于 p1 所在 bin 的最小块），把 p1->bk_nextsize 改为 `target-0x20`；当 p2 被插入 largebin 时走“小者插入”分支，`fwd->fd->bk_nextsize` 已是 `target-0x20`，最终 `victim->bk_nextsize->fd_nextsize = victim` 即 `*(target-0x20+0x20)=*(target)=p2`，把 p2 的堆地址写到 target。由于 p2 比最小块还小，不会进入带检查的中间插入分支。
- **为什么写入值受限**：写入的是堆块地址（victim/p2），不是 `main_arena` 地址；通常用于改写 `global_max_fast`、`mp_.tcache_bins`、`_IO_list_all`、函数指针/长度字段等需要堆指针的目标，再配合后续 fastbin/tcache/IO 链利用。
- **版本边界**：2.31 之前两条写点都可利用；2.31+ 的中间插入分支受检查限制，但“小者插入”分支仍可单写；更高版本（2.36+）还需按实际 `_int_malloc` 复核。

## 触发条件

- glibc 堆环境，存在可改写已释放 largebin chunk 的 `size`/`bk`/`bk_nextsize` 的原语（UAF、堆溢出、double free 等）。
- 能构造 largebin 非空（至少一个块）且 unsorted bin 中有待插入块；块大小需落在 largebin 范围（通常 > 0x400，且不同 bin 的分段要匹配）。
- 有可写的目标地址（如 `global_max_fast`、`mp_.tcache_bins`、栈变量、函数指针等），且目标处可被写入堆地址。
- 能控制堆布局，防止 free 时相邻块合并（用 guard chunk 隔开）与 top chunk 合并。

## 利用步骤

**2.31 之前（双写）**

1. 分配：`p1=malloc(0x420)`、guard(0x20)、`p2=malloc(0x500)`、guard、`p3=malloc(0x500)`、guard。
2. `free(p1); free(p2);` 两个大块进入 unsorted。
3. `malloc(0x90)` 切分 p1，把 p2 归入 largebin（0x500），p1 剩余部分回到 unsorted。
4. `free(p3)` 进入 unsorted。
5. 改写 p2：`size = 0x3f1`（小于 p3 的 0x500 即可）、`fd = 0`、`bk = target1-0x10`、`bk_nextsize = target2-0x20`。
6. `malloc(0x90)` 触发 p3 插入 largebin；p3 比 p2 大，走“大者插入/头部”路径，把 p3（victim）的地址写到 `target1` 与 `target2`。

**2.31 及以后（小者插入分支单写）**

1. 分配：`p1=malloc(0x428)`、guard(0x20)、`p2=malloc(0x418)`、guard(0x20)。
2. `free(p1);` 然后 `malloc(0x438)`（比 p1 大）把 p1 归入 largebin。
3. `free(p2)` 进入 unsorted。
4. 改写 `p1->bk_nextsize = target-0x20`（注意 p1 的 size 仍保持合法）。
5. `malloc(0x438)`（大于 p2）触发 p2 插入 largebin；p2 比 largebin 最小块还小，走“小者插入”分支，不触发 2.31 的 `bk_nextsize`/`bk` 检查，最终把 p2 的地址写到 `target`。

## PoC

2.31 之前（how2heap 结构，未在本机执行）：

```c
unsigned long stack_var1 = 0, stack_var2 = 0;
unsigned long *p1 = malloc(0x420); malloc(0x20);
unsigned long *p2 = malloc(0x500); malloc(0x20);
unsigned long *p3 = malloc(0x500); malloc(0x20);

free(p1); free(p2);
malloc(0x90);          // p2 进入 largebin
free(p3);

p2[-1] = 0x3f1;        // 改小 size
p2[0] = 0;             // fd
p2[1] = (unsigned long)(&stack_var1 - 2);  // bk = target1 - 0x10
p2[3] = (unsigned long)(&stack_var2 - 4);  // bk_nextsize = target2 - 0x20

malloc(0x90);          // 触发，stack_var1/stack_var2 被写为 p3（victim）地址
```

2.31+（小者插入分支）：

```c
unsigned long *p1 = malloc(0x428); malloc(0x20);
unsigned long *p2 = malloc(0x418); malloc(0x20);

free(p1);
malloc(0x438);                     // p1 进入 largebin
free(p2);                          // p2 进入 unsorted

p1[3] = (unsigned long)(target - 0x20);  // p1->bk_nextsize

malloc(0x438);                     // 触发，*target = p2
```

CTF 模板（按目标偏移调整）：

```text
# 2.31+
add(0x428)   # 1
add(0x20)
add(0x418)   # 2
add(0x20)
free(1)
add(0x438)   # 把 1 放进 largebin
free(2)
edit(1, p64(target-0x20))   # 改写 1 的 bk_nextsize
add(0x438)                   # 触发，target 写入 2 的堆地址
```

## 变体与关联

- **中间插入双写变体（2.31+）**：若能让插入块落在 largebin 中间，需同时满足 `fwd->bk_nextsize->fd_nextsize == fwd` 与 `bck->fd == fwd`，可做双目标写；见 [[binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks]]。
- **目标变体**：`global_max_fast`（扩大 fastbin 范围）、`mp_.tcache_bins`（扩大 tcache 索引）、`_IO_list_all`（IO 链）、`__malloc_hook`/`__free_hook`（旧版）、栈变量/返回地址等。
- **组合链**：largebin attack 通常作为“写堆地址”的前置原语，随后配合 fastbin dup、tcache poisoning、House of Apple/Orange/Storm、IO FILE 链等；见 [[binary-pwn-heap-house-of-storm-unsorted-largebin-fake-chunk]]、[[binary-pwn-heap-house-of-apple2-source-analysis-largebin-system]]、[[binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin]]。
- **关联**：[[binary-pwn-heap-largebin-attack-mp-tcache-bins-stack-rop]]（写 `mp_.tcache_bins` 后接栈 ROP）、[[binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write]]（largebin attack 预置 bk 后接 TSU）。
- **边界**：块大小不落入同一 largebin、目标地址不可写、free 时发生合并、glibc 版本更高导致分支/检查变化时可能失败；2.31+ 的中间插入分支不能沿用旧版双写模板。

## 检测与防御

- **利用条件检测（CTF/防御）**：检查 largebin 中块的 `size` 与 `fd`/`bk`/`fd_nextsize`/`bk_nextsize` 是否自洽；在 `_int_malloc` 插入路径校验 `bk_nextsize` 与 `bk` 的双向一致性；对 `global_max_fast`、`mp_.tcache_bins`、`_IO_list_all` 等敏感全局做写保护/监控。
- **缓解**：升级 glibc 到包含完整 largebin 检查的版本；启用 safe-linking（2.32+）；减少堆溢出/UAF 原语；对堆元数据做完整性校验（如 glibc 的 `malloc_check`）。
- **程序侧**：不要信任已释放 chunk 的 `size`/`bk`/`bk_nextsize`；对 unsorted/largebin 插入前做一致性检查；CTF 中重点观察 largebin 的 `bk_nextsize` 是否指向非堆地址。
