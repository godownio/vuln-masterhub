---
id: binary-pwn-heap-fastbin-smallbin-prev-inuse-free-overlapping
title: fastbin + small bin 不改 prev_inuse 位完成 overlapping：借 small bin chunk 天然 prev_size=0 绕过合并检查
type: scenario
domain: binary
path: binary/pwn/heap
technique: fastbin-smallbin-prev-inuse-free-overlapping
aliases:
- 不溢出 prev_inuse 的 overlapping
- small bin 天然 prev_size
- malloc_consolidate overlapping 2.40
- 免改 prev_inuse 位堆重叠
tags:
- glibc
- heap
- pwn
- overlapping
- unlink
- malloc-consolidate
- smallbin
- fastbin
- prev-size
- 2.38
- 2.4
cve: []
severity: medium
confidence: high
status: verified
affected_versions: glibc 一直到 2.40 都可使用
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-9
  verified_at: '2026-11-08T01:15:47+08:00'
  notes: 已对照原文核对；重点核对 affected_versions：原文第530行利用2 标题明确写一直到2.40都可使用，为手法适用版本区间声明，非调试环境版本（调试环境为图43-49 的 glibc-2.38 源码路径、正文另有以 glibc-2.29 为例），故按规范保留 set-versions 并去掉作者自加的括号注释、未用 clear；原文图41-50 有 gdb 完整验证：small bin chunk 天然 prev_size=0、免改 PREV_INUSE、unlink 两检查通过、合并 0x141 入 unsortedbin 再进 smallbins 0x140 形成 overlapping；卡结论为中间能力未包装成 RCE；dedup 复核候选需改 PREV_INUSE 或由 free 触发，理由成立；未验证点：PoC 结构示意未独立复跑、2.40 为原文声明未在 2.40 实测、卡未含 sources 字段。
---

## 一句话结论

用 fastbin chunk 触发 `malloc_consolidate` 合并时，常规做法要溢出改掉下一个 chunk 的 `PREV_INUSE` 位；改用 small bin 中的 chunk 作为「低地址被合并对象」后，它天然带有 `prev_size = 0` 且 malloc 路径不会检查它的 `prev_size`，于是只需伪造一个更早的 fake chunk（`size`、`fd`、`bk`）并写好 fastbin chunk 的 `prev_size`，即可在不修改任何 `PREV_INUSE` 位的情况下通过 unlink 两处检查完成合并，造成 overlapping；原文标注该手法到 glibc 2.40 仍可使用。

## 原理

- **常规 unlink/合并的前提**：`malloc_consolidate` 判断 `!prev_inuse(p)` 才向后（低地址）合并，随后校验 `chunksize(p_low) == prev_size(p)`，再对低地址 chunk 做 `unlink_chunk` 的 `fd->bk==p && bk->fd==p` 检查。多数题设要靠 off-by-null 把相邻高地址 chunk 的 `PREV_INUSE` 位清 0 才能进入这条分支。
- **small bin chunk 的关键性质**：已经在 small bin 中的 chunk，其下一个 chunk 的 `prev_size` 字段为 0（因为该 chunk 在使用/空闲状态切换时由 malloc 维护），且 malloc 在从 small bin 取出/整理路径上**不会检查它的 `prev_size` 字段**。因此把它当作「被合并的低地址 chunk」时，即使我们改写了它的 `prev_size`，也不会在后续 unsorted bin 处理中触发 `mismatching next->prev_size (unsorted)` 报错——这正是原文强调「前面才使用 small bin 中的 chunk」的原因：若换成 unsorted bin 中的 chunk，改写 `prev_size` 会在 `malloc(): mismatching next->prev_size (unsorted)` 处崩溃。
- **为什么不需要改 PREV_INUSE**：作为触发合并的 chunk 是 fastbin chunk（如 0x20），其自身 `PREV_INUSE` 位保持真实值；`malloc_consolidate` 检查的是这个真实位（`!prev_inuse(p)` 成立时进入合并），我们并不伪造它。伪造的是「更早处 fake chunk 的 size/fd/bk」与「fastbin chunk 的 prev_size」，使 `prevsize` 把 p 定位到 fake chunk，并用 `chunksize(fake) == prevsize` 通过检查、用自指 `fd/bk` 通过 unlink 双向链表检查。
- **合并结果**：`set_head(p, size|PREV_INUSE)`、`set_foot(p, size)` 后合并出的大 chunk 先入 unsorted bin，随后进入对应 small bin；攻击者保留的指针指向重叠区域，得到 overlapping，可续接 UAF/任意地址写。
- **版本依据**：示例调试用 glibc 2.38 源码（`malloc.c:4029` 触发 consolidate、`4828` 起合并检查、`1604` 起 unlink 检查），原文明确写「一直到 2.40 都可使用」；高版本是否加入新的 `prev_size`/对齐检查需按目标 libc 复核。

## 触发条件

- 目标 glibc 的 `malloc_consolidate` 仍走 unlink 合并路径，且 small bin 整理/unsorted bin 处理不会对被改写 `prev_size` 的 small bin chunk 报错（示例 2.38，原文称至 2.40 可用）。
- 堆上能布置：一个已进入 small bin 的 chunk（提供天然 `prev_size=0`）、一个更早处可控的 fake chunk（能写 `size`/`fd`/`bk`）、一个能释放进 fastbin 的 chunk（触发合并）。
- 攻击者能写 fastbin chunk 的 `prev_size` 字段（通常经溢出或 UAF 写），并能发起一次「不属于 small bin 范围」的大分配触发 `malloc_consolidate`。

## 利用步骤

1. 申请并释放出一个 small bin chunk（如 0xd0）；再申请一个 fastbin 大小的 chunk（如 0x20）作为触发合并的块。
2. 在更早的低地址处伪造 fake chunk：把它的 `size` 填成与目标 `prev_size` 一致，`fd`、`bk` 填成满足 `fd->bk==p && bk->fd==p` 的堆地址（自指）。
3. 把 fastbin chunk 的 `prev_size` 改成「fake chunk 到该 fastbin chunk 的距离」；**不改动**该 fastbin chunk 自身的 `PREV_INUSE` 位。
4. 把该 fastbin chunk 释放进 fastbin；发起一次不属于 small bin 范围的大分配，进入 `malloc_consolidate`。
5. 从 fastbin 取出该 chunk，`fastbin_index(chunksize(p))` 校验通过；`!prev_inuse(p)` 用真实位判断成立 → 用我们伪造的 `prev_size` 把 p 定位到 fake chunk。
6. `chunksize(fake) == prevsize` 与 unlink 双向链表两检查均被伪造数据满足 → `unlink_chunk` 解链，合并出大 chunk。
7. 合并后的 chunk 进入 unsorted bin，再进 small bin；由于它来自 small bin 且 `prev_size` 被改，后续 unsorted bin 的 `mismatching next->prev_size` 检查不会命中（这是相对「用 unsorted bin chunk」的关键差异），最终形成 overlapping。

## PoC

结构示意（glibc 2.38，未在本文档环境编译执行）：

```c
// 1) 造一个 small bin chunk 与一个 fastbin chunk
void *s = malloc(0xc0);  free(s); malloc(0x400);      // 把 s 推入 small bin（示意）
void *f = malloc(0x18);                               // 触发合并的 fastbin chunk

// 2) 在更早低地址处伪造 fake chunk：size 与目标 prev_size 一致，fd/bk 自指
size_t *fake = (size_t*)(f - 0x120);                   // 距离按布局定
fake[1] = 0x120 | 1;                                  // fake size
fake[2] = (size_t)fake;                               // fd
fake[3] = (size_t)fake;                               // bk

// 3) 只写 fastbin chunk 的 prev_size，不动它的 PREV_INUSE 位
((size_t*)f)[-2] = 0x120;                             // 指向 fake

// 4) 释放 f 进 fastbin，再大请求触发 consolidate
free(f);
void *big = malloc(0x500);   // 不属于 small bin 范围 -> malloc_consolidate
// unlink 合并 fake 与 f，得到 overlapping chunk，进入 unsorted/small bin
```

说明：真实利用需精确计算 fake chunk 到触发 chunk 的距离并使 `chunksize(fake)` 与之相等；`fd/bk` 要落在可写且满足回指条件的地址。PoC 仅表达字段关系，未独立复跑。

## 变体与关联

- **与常规做法对比**：常规 off-by-null / House of Einherjar 需清掉相邻 chunk 的 `PREV_INUSE` 位，见 `binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison`、`binary-pwn-heap-glibc228-offby-null-prev-size-unlink-overlap`；本卡免改该位。
- **同系列 malloc 触发 unlink**：用 malloc 大请求（而非 free）触发 `malloc_consolidate` 里的 unlink，见关联卡「借 malloc_consolidate 在 malloc 路径触发 unlink」；两者都属同一 malloc.c 源码分析的不同伪造方式。
- **为什么不用 unsorted bin chunk**：本库 `binary-pwn-heap-fake-unsorted-chunk-prev-inuse-merge-bypass` 涉及伪造 unsorted chunk 绕过合并检查；本卡改用 small bin chunk 正是为避开 unsorted bin 的 `mismatching next->prev_size` 校验。
- **后续利用**：overlapping 后可续接 unsorted bin libc 泄漏、tcache poisoning、FSOP/ORW 等完整链。

## 检测与防御

- 检测：运行期出现「small bin chunk 的 `prev_size` 被改写、且其更早处存在自指 `fd/bk` 的 fake chunk」；`malloc_consolidate` 中 unlink 合并出的 chunk 尺寸远大于原触发 chunk；同一内存被多个用户指针引用。
- 检测：对从 small bin/unsorted bin 取出的 chunk 增加 `prev_size` 与相邻 chunk `size` 的一致性校验；监控小请求后紧跟大请求且产生异常大 bin chunk 的模式。
- 防御（审计视角）：保证 chunk 元数据不可被越界/UAF 写；升级 glibc 不能保证消除该类伪造 prev_size 合并攻击，需按目标版本复核 `malloc_consolidate`/unlink 检查。
- 注意：本手法产出的是 overlapping 中间能力，本身不直接造成代码执行，结论不把它包装成 RCE。
