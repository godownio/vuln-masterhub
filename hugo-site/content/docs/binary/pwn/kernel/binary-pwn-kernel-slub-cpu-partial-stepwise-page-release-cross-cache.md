---
id: binary-pwn-kernel-slub-cpu-partial-stepwise-page-release-cross-cache
title: 按 SLUB cpu_partial 与 objs_per_slab 精确布点：七步申请/释放把指定 slab 页整页归还 buddy，完成可控的 cross-cache 页回收
type: scenario
domain: binary
path: binary/pwn/kernel
technique: slub-cpu-partial-step-counted-slab-page-release-cross-cache
tags:
- pwn
- kernel
- slub
- buddy
- cross-cache
- page-allocator
- cpu-partial
- heap-grooming
- uaf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:23:46+08:00'
  notes: 已对照原文核对；本次核对未读取图片；七步申请/释放计数（(cpu_partial+1)*objs_per_slab、objs_per_slab-1、1、objs_per_slab+1；先放 victim、清空同页、再每页放一个）与 put_cpu_partial/unfreeze_partials/discard_slab 源码摘录一致；cpu_partial=13、objs_per_slab 由 oo.x & OO_MASK 取得、示例内核 5.15.0-122 均与正文一致。未验证点：未执行内核 demo；截图中的 slab 布局未读图核对；卡内“第 16 张是唯一满足销毁条件”依赖 min_partial 已满足（原文称该条件基本都满足），已在触发条件注明。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-slub-cpu-partial-stepwise-page-release-cross-cache/
draft: false
kb_aliases:
- Cross Cache Attack 步骤
- cross-cache 页回收七步法
- SLUB cpu_partial 阈值利用
- put_cpu_partial 与 unfreeze_partials
- discard_slab 释放页
- objs_per_slab 布点
- 整页归还 buddy system
---

## 一句话结论

cross-cache 的关键不是「把对象都 free 掉」，而是要让**装着 victim 对象的那一张 slab 页**被 SLUB 判定为空并走 `discard_slab() → __free_pages()` 还回 buddy；由于 `put_cpu_partial()` 只在把「满页第一次变不满」时挂链、且 `unfreeze_partials()` 只在 per-CPU partial 链超过 `cpu_partial` 阈值时才处理，按 `(cpu_partial+1)×objs_per_slab`、`objs_per_slab-1`、1、`objs_per_slab+1` 这几步精确申请，再按「先释放 victim、再清空同页、最后每页放一个」的顺序释放，就能让第 16 张 slab 页成为唯一被 `discard_slab()` 回收的页，从而被任意其它缓存（页表、`msg_msgseg`、`pipe_buffer` 页…）接管。

## 原理

- **SLUB 的三级结构**：`kmem_cache` 的每 CPU `cpu_slab` 有 `freelist` 与当前 `page`；已满的 slab 一旦有对象被释放，会经 `put_cpu_partial()` 挂到 per-CPU partial 链（`page->frozen = 1`，此时不在 node partial 上）；链长度超过 `cpu_partial`（示例 13）时触发 `unfreeze_partials()`，把链上所有页搬到 node partial，其中 `inuse == 0` 且 `n->nr_partial >= s->min_partial` 的页被挂进 `discard_page` 链并 `discard_slab()` 释放。
- **关键的触发条件**：`__slab_free()` 里只有 `(!new.inuse || !prior) && !was_frozen` 才可能设 `new.frozen = 1` 并调用 `put_cpu_partial()`。也就是「这个页之前是满的（`prior == NULL`，没有 freelist）、且不在 partial 链上」时，**释放第一个对象**才会挂链；之后该页 `was_frozen == 1`，继续释放只会走 `FREE_FROZEN` 快路径，不再产生任何链操作。
- **为什么要精确布点**：如果 victim 页在释放时已经是「不满且已挂链」状态，那么即使把它清空，`unfreeze_partials()` 也不一定会走到它（它可能早被搬到 node partial，`min_partial` 满足时留在 node 链上而不被销毁）。只有让「第 N 张页」在释放第一个对象时挂链、随后被清空，并且恰好在同一次 `unfreeze_partials()` 里被处理，才能稳定地把它销毁。
- **七步走的具体含义**（`O` = objs_per_slab，`P` = cpu_partial＝链上 pobjects 阈值）：
  1. 申请 `(P+1)×O` 个对象：铺满 14 张 slab，并因为缓存里可能已有残留对象，使第 15 张不满；
  2. 再申请 `O-1` 个：把第 15 张补满，让第 16 张只占 1 个；
  3. 申请 1 个作为 `uaf_object`，落在第 16 张，并把该张补满；
  4. 再申请 `O+1` 个：把第 16 张剩余的槽位与第 17 张开头都填满，保证「第 16 张没有任何空槽」；
  5. `free(uaf_object)`：第 16 张第一次从「满」变「不满」，`prior == NULL` → `new.frozen = 1` → `put_cpu_partial()` 挂链，但 `pobjects` 未超阈值，不会 `unfreeze_partials()`；
  6. 释放第 16 张其余所有对象：此时 `was_frozen == 1`，全部走 `FREE_FROZEN`，页变成 `inuse == 0` 但仍在 per-CPU partial 链上（**尚未销毁**）；
  7. 释放第 1～14 张各一个对象：每张都从满变不满、各触发一次 `put_cpu_partial()`，链长度逐次 +1 直到超过 `P`；超阈值的那次 `unfreeze_partials()` 会遍历整条链，发现第 16 张 `inuse == 0`，把它挂上 `discard_page` 并 `discard_slab()` → `free_slab()` → `rcu_free_slab()` → `__free_pages()`，页回到 buddy。
- **为什么第 16 张一定是被销毁的那张**：第 1～14 张都还留有对象（`inuse > 0`），只可能被搬进 node partial；第 15/17 张同理。只有第 16 张是「在本次 unfreeze 时 inuse 为 0」的页，因此它是唯一满足销毁条件的候选，攻击者对「哪一页被归还」有确定性。
- **与 Dirty Pagetable 的关系**：页还回 buddy 后，任何用 `alloc_pages` 取 order-0 页的路径（PTE 页、dma-buf、AF_PACKET ring、`msg_msgseg` 数据页、`pipe_buffer` 数组页）都能接管它；cross-cache 决定「能不能换缓存」，后面接什么由目标决定。
- **数值来源**：`objs_per_slab` 与 `cpu_partial` 都不是常量，需要按目标内核与缓存实测（示例内核 5.15.0-122 下 0x200 大小对象 `cpu_partial = 13`）；`cpu_partial` 本质是「链上累计空槽数（pobjects）」而非页数，代码里用 `page->objects - page->inuse` 累加。

## 触发条件

- 目标内核启用 `CONFIG_SLUB`（`CONFIG_SLUB_CPU_PARTIAL` 打开时才有 per-CPU partial 链；关闭时逻辑退化为直接进 node partial，七步需重算）。
- 已知目标缓存的对象大小、`objs_per_slab`、`cpu_partial`、`min_partial`；可通过 `/sys/kernel/slab/<cache>/` 下的 `objs_per_slab`、`cpu_partial`、`objects` 等文件读取（需相应权限），或用同尺寸对象实测。
- 能大量且可控地分配/释放同一缓存的对象（漏洞给的 alloc/free ioctl，或通用对象如 `msg_msg`、`setxattr`）。
- 能绑定 CPU（`sched_setaffinity`）以减少 per-CPU 链被其它核干扰；`unfreeze_partials()` 里的 `min_partial` 条件通常天然满足。
- 能对目标页做「接管」的后续分配原语（页表、dma-buf、packet ring、`msg_msgseg` 等），否则只得到一次页回收。

## 利用步骤

1. 确定目标缓存的 `O`、`P`、`min_partial`（读 `/sys/kernel/slab/*` 或写一个临时内核模块打印 `s->cpu_partial`、`s->oo & OO_MASK`，与原文 demo 一致）。
2. 绑核，先做一次「分配再释放一个对象」把缓存状态归一（原文的 `random_ms` 步骤），让后续计数从确定状态开始。
3. 按 `(P+1)×O` 申请并记录所有指针；再申请 `O-1`；再申请 1 个作为 victim（UAF 对象），记下它的页地址 `page = ptr & ~(page_size-1)`。
4. 再申请 `O+1`，确保 victim 所在页满载。
5. `free(victim)`：这一次 free 使该页首次由满变不满并挂上 per-CPU partial 链。
6. 释放 victim 页内其余所有对象（按索引 `victim_idx ± i` 遍历，跳过已释放的），使该页 `inuse == 0`。
7. 从第 1～14 张页各释放一个对象：链长度增长到超过 `P`，触发 `unfreeze_partials()`，victim 页被 `discard_slab()` 归还。
8. 立刻用目标页来源分配 order-0 页（`alloc_pages(GFP_KERNEL, page_order)` 或用户态等价物），比对返回地址是否等于 `page` 验证命中；命中后即可在该页上构造伪对象/伪造页表。
9. 若未命中：检查是否有其它同缓存分配插入（噪声）、`cpu_partial` 估计是否偏差、是否需要先 flush 掉链上残留页（多分配再释放几轮）。

## PoC

原文的验证方式是内核模块内直接打印：申请/释放七步后调用 `alloc_pages(GFP_KERNEL, page_order)`，把 `page_address()` 与记录的 victim 页地址比较，相等即 `realloc SUCCESS`；随后把整页写成 `hack_func` 指针并再次调用 `uaf_object->func()`，证明页已被完全接管。

```c
cpu_partial  = cache->cpu_partial;
objs_per_slab = cache->oo.x & OO_MASK;      /* OO_SHIFT = 16 */
page_size    = objs_per_slab * cache->object_size;
page_order   = get_order(page_size);

/* 1) (P+1)*O */  for (i = 0; i < (cpu_partial+1)*objs_per_slab; i++) list[sp++] = alloc();
/* 2) O-1    */  for (i = 0; i < objs_per_slab-1; i++)                  list[sp++] = alloc();
/* 3) victim */  uaf = alloc(); idx = sp; list[sp++] = uaf;
/* 4) O+1    */  for (i = 0; i < objs_per_slab+1; i++)                  list[sp++] = alloc();
/* 5) free victim */            free(uaf);
/* 6) empty its slab */         for (i = 1; i < objs_per_slab; i++) { free(list[idx+i]); free(list[idx-i]); }
/* 7) one per page 1..14 */     for (i = 0; i < (cpu_partial+1)*objs_per_slab; i += objs_per_slab) free(list[i]);

/* 8) 验证：直接从 buddy 取页 */
page = alloc_pages(GFP_KERNEL, page_order);
assert(page_address(page) == (void*)((unsigned long)uaf & ~(page_size-1)));
```

用户态复现的难点在于「按索引精确释放第 1～14 张页中的一个对象」需要能区分对象所属页：可先把每个对象写入唯一标记、再按标记/地址低位判断同页，或直接用漏洞的 index 语义对应分配顺序。

## 变体与关联

- **不精确布点的近似法**：直接「大量分配 → 全部释放 → 触发链超阈值 → 再全释放」，命中率低于七步法，但不需要知道 `cpu_partial`；原文的 [[binary-pwn-kernel-cross-cache-uaf-cred-jar-clone-lpe]] 用的就是这种近似（0x500 个对象全释放后 fork 喷 cred）。
- **只关心「有页被归还」**：若后续 spray 足够多（页表一整片、`msg_msgseg` 0x180 个），不追求指定哪一页也能命中，见 [[binary-pwn-kernel-cve-2026-23271-perf-event-race-uaf-core-pattern-lpe]] 的「释放 + 32 个 flush 事件刷 cpu_partial + 关 12 个尾对象」写法。
- **跨 order**：若目标是 order>0 的 slab（大对象缓存），`page_size` 与 `get_order()` 要重算，`discard_slab()` 仍走 `__free_pages(order)`。
- **接管目标**：页表（[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]）、`pipe_buffer`（[[binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null]]）、`msg_msgseg`、packet ring（[[binary-pwn-kernel-buddy-page-spray-packet-tx-ring]]）。
- **反向利用（防守视角）**：`cpu_partial` 越大，链越难被填满、页越不容易归还，因此调大 `cpu_partial`（或 `slub_cpu_partial`）会抬高 cross-cache 的成功门槛，但会增加内存滞留。

## 检测与防御

- **加固**：`CONFIG_SLAB_FREELIST_RANDOM/HARDENED` 只影响对象级 freelist，对页级归还无效；真正相关的是 `CONFIG_SLAB_MERGE_DEFAULT` 的合并策略、`slub_min_objects`/`cpu_partial` 调参，以及 `CONFIG_INIT_ON_FREE_DEFAULT_ON`（提高重用页的内容可控门槛）。
- **监控**：同一缓存短时间内出现「大批分配 → 大批释放 → 目标页被别的缓存取走」的模式；`/sys/kernel/slab/<cache>/` 的 `slabs`/`objects` 剧烈波动；`unfreeze_partials` 高频触发（可用 tracepoint `kmem:mm_page_alloc` 与 `kmem_cache_free` 关联分析）。
- **根因修复**：cross-cache 只是放大器，真正的入口仍是 UAF/double free；修复漏洞、使用 `refcount_t`、free 后失效指针才是根本。
- **环境**：容器内限制可用的 ``msg_msg``/packet ring/`dma-heap` 数量与页表喷射规模，可显著降低命中率。
