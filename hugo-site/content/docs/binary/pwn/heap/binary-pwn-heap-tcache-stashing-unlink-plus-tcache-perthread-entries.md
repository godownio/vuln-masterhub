---
id: binary-pwn-heap-tcache-stashing-unlink-plus-tcache-perthread-entries
title: TSU+ 打 tcache_perthread_struct：smallbin bk 塞入堆内假 chunk，直接改写 tcache entries 绕过 safe-linking
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-tcache-stashing-unlink-plus-tcache-entries
tags:
- pwn
- heap
- glibc
- tcache
- smallbin
- tcache-stashing-unlink
- safe-linking
- arbitrary-alloc
- ctf
cve: []
severity: high
confidence: high
affected_versions: glibc 2.32
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:00:37+08:00'
  notes: 已对照 90762 原文核对：smallbin bk 改堆内假 chunk(heapbase+0x200)、tcache stashing 循环、entries 重叠与绕过 safe-linking 均与原文一致。已修正 PoC：edit 从 buf_(用户指针+8) 写，bk 偏移应为 payload 0（原写 0x18）；触发分配改为 calloc(type=2)，因 malloc 在 tcache 非空时不会进入 _int_malloc。未复跑 exp。
url: /docs/binary/pwn/heap/binary-pwn-heap-tcache-stashing-unlink-plus-tcache-perthread-entries/
draft: false
kb_aliases:
- TSU+
- Tcache Stashing Unlink Attack plus
- tcache stashing unlink 打 tcache_perthread_struct
- smallbin bk 假 chunk
- 绕过 safe-linking 任意分配
- tcache entries 改写
---

## 一句话结论

当堆题只能对最后一个被释放的 chunk 做一次 UAF 写、且申请地址范围检查挡住了 libc 时，可以用 TSU+：把 smallbin 最后一个 chunk 的 `bk` 改成堆内一个假 chunk 地址（如 `heapbase+0x200`），让 tcache stashing unlink 循环把这个假 chunk 当作 smallbin 节点塞进 tcache；假 chunk 的用户区与 `tcache_perthread_struct.entries[]` 重叠，随后一次分配/写入就能把 entries 改成 `__free_hook-0x10` 等原始指针，完全不用伪造 safe-linking 编码。

## 原理

- **tcache stashing unlink 循环**：`_int_malloc` 从 smallbin 分配且对应 tcache 未满时，会把 smallbin 尾部的 chunk 搬到 tcache：
  ```c
  while (tcache->counts[tc_idx] < mp_.tcache_count
         && (tc_victim = last(bin)) != bin) {   // last(bin) = bin->bk
      bck = tc_victim->bk;
      bin->bk = bck;
      bck->fd = bin;                            // 要求 bck 可写
      tcache_put(tc_victim, tc_idx);            // 把 chunk 挂进 tcache
  }
  ```
- **伪造 smallbin 节点**：如果攻击者能改写最后一个 smallbin chunk 的 `bk`，循环下一轮就会把 `bk` 指向的地址当成 `tc_victim`。要让这一轮不崩溃，必须满足：
  1. `fake + 0x18`（即 fake chunk 的 `bk` 字段）必须指向一个可读写的合法 chunk，因为代码会执行 `bck = tc_victim->bk` 和 `bck->fd = bin`；
  2. tcache 计数要控制好，使 fake chunk 被 `tcache_put` 后恰好达到 `mp_.tcache_count`（默认 7），循环随即退出；否则会继续把 fake->bk 当下一节点，极易崩溃。
- **为什么选堆内假 chunk**：直接把 `bk` 指向 `__free_hook` 等 libc 地址通常不满足 `fake+0x18` 可写/可解引用；题目又用 `no_hax_pls` 限制了申请地址不能落在 libc 数据段。改打堆内的 `heapbase+0x200` 则天然满足 `+0x18` 可访问，而且该区域位于第一个 0x290 chunk 内，与 `tcache_perthread_struct` 的 entries 数组同处一块内存。
- **绕过 safe-linking 的原因**：safe-linking 编码的是 tcache/fastbin 空闲 chunk 里的 `next` 指针；smallbin 的 `bk` 不在保护范围，可以直接写成任意地址。另一方面，`tcache_perthread_struct.entries[]` 中保存的是原始 chunk 指针，不是编码值。只要让一次分配返回的区域覆盖 entries 数组，就能直接写入目标地址，无需计算 `target ^ (chunk >> 12)`。
- **原题利用**：0x330 chunk（tc_idx 49）先填满 tcache，再把若干 chunk 排进 smallbin；UAF 改写最后一个 smallbin chunk 的 `bk = heapbase+0x200`。TSU+ 循环把该假 chunk 塞进 tcache 后，下一次分配返回 `heapbase+0x210` 附近；攻击者在该处写入 `__free_hook-0x10`，使后续 malloc 直接返回 `__free_hook-0x10`，再写入 COP gadget/setcontext 布局，最后触发 `free` 完成栈迁移。
- **边界**：该手法依赖 smallbin 的 `bk` 可写、tcache 计数可控、以及假 chunk 与 tcache 管理结构的内存重叠；不同 glibc 版本的 `tcache_perthread_struct` 布局（counts 宽度、bin 数量、entries 偏移）不同，必须按目标版本重新计算。

## 触发条件

- 目标为 glibc 2.29+（含 tcache stashing unlink），原文靶场 libc-2.32；2.42+ 的 tcache 结构与 bin 数量变化需重新核对偏移。
- 存在 UAF/edit-after-free，能改写已释放 smallbin chunk 的 `bk`；通常只能改最后一个释放的 chunk，堆风水要把目标 smallbin chunk 安排在最后释放。
- 能构造同 size 的 smallbin 链与已满/将满的 tcache；能控制 tcache 计数，使 fake chunk 是最后一个被塞入的节点。
- 目标地址附近有可控的堆内存，使 `fake+0x18` 是合法可写指针；常见做法是选第一个堆 chunk（tcache_perthread_struct 所在区域）内的地址。
- 程序有后续 malloc/edit/free 接口；申请地址范围检查只挡 libc 时，堆内目标不受影响。

## 利用步骤

1. 选一个 size class（原文 0x330，tc_idx 49），申请足够多的 chunk；先释放 7 个填满 tcache，再释放若干进入 unsortedbin，触发排序进入 smallbin（可用一次大分配或 [[binary-pwn-heap-scanf-scratch-buffer-malloc-sorting]] 的 scanf 内部 malloc）。
2. 调整 smallbin 链与 tcache 计数：让 tcache 差 2 个满，smallbin 尾部依次为“一个真实 chunk + 一个假 chunk”时，循环搬完两者正好填满并退出。
3. 通过 UAF 改写最后一个 smallbin chunk 的 `bk` 为假 chunk 地址（原文 `heapbase+0x200`）；确保假 chunk 的 `+0x18` 字段指向合法可写 chunk（例如已有的 tcache 节点或可控堆指针）。
4. 触发一次同 size 的 `calloc`（calloc 不查 tcache，直接进入 `_int_malloc`；若用 `malloc`，必须保证对应 tcache 为空才会走到 stashing 循环）；用调试器查看 `tcachebins`，确认假 chunk 的用户地址（如 `heapbase+0x210`）已出现在对应链表。
5. 再次 `malloc` 取回假 chunk（必要时先弹掉压在它上面的 tcache 节点）；写入的数据会覆盖 `tcache_perthread_struct.entries[idx]` 或其 `next` 字段。把 entries 目标写成 `__free_hook-0x10`（原始指针，不需要 safe-linking 编码）。
6. 下一次同 size `malloc` 返回 `__free_hook-0x10`；在返回指针的 `+0x10` 处写入 hook 值（如 bridge gadget / setcontext 布局），再触发 `free`。
7. 若程序没有 `__free_hook`（glibc 2.34+），把目标换成 `_IO_list_all`、`exit_funcs` 或其它可写函数指针，并按对应 FSOP 链布局。

## PoC

```python
from pwn import *

# 伪代码：索引/偏移按题目与 libc 版本调整；原文 libc-2.32
fake = heapbase + 0x200          # 假 chunk 头，位于第一个堆 chunk 内
free_hook = libc.sym['__free_hook']

# 1) 构造 smallbin(0x330) 与 tcache 状态；last_smallbin 是最后一个 smallbin chunk
# 2) UAF 改写它的 bk（chunk 头 +0x18 = 用户指针 +0x8；本题 edit 从 buf_ 即用户指针 +0x8 写，
#    故 payload 偏移 0 即命中 bk）
edit(last_smallbin, p64(fake))

# 3) 触发 tcache stashing unlink：用 calloc 绕过 tcache，进入 _int_malloc 的 stashing 循环
add(2, 0, b'A')                  # 伪代码：type=2 -> calloc(1, 0x320)，不查 tcache

# 4) 取回 fake chunk（必要时先弹掉压在它上面的节点），写入 free_hook-0x10；该写入覆盖 tcache entries
add(1, 0, p64(free_hook - 0x10))

# 5) 下一次 malloc 返回 free_hook-0x10，在 +0x10 处写 hook 值
add(1, 0, p64(0) * 2 + p64(bridge_gadget))   # 实际偏移按 hook 位置调整

# 6) 触发 free -> __free_hook
free(0)
```

调试检查点：

```text
pwndbg> tcachebins
0x330: 0x...f210  ← 假 chunk 用户地址出现在链表
pwndbg> x/4gx 0x...f200
0x...f200: ...  0x...   (fake chunk 的 bk/fd)
```

## 变体与关联

- **经典 TSU + largebin attack**：当 `fake+0x18` 没有合法指针时，先用 largebin attack 在 `target+0x8` 预置一个堆指针，再让 TSU 把目标地址塞进 tcache；见 [[binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write]]。
- **直接 tcache poisoning**：已知堆地址和 safe-linking 编码时，直接改空闲 chunk 的 `next` 更短；TSU+ 的优势是不需要堆地址泄露/编码，且能绕过只允许固定 size 的分配器。
- **tcache_perthread_struct 直接劫持**：先用 poisoning 让 malloc 返回管理结构本身，再改 entries；见 [[binary-pwn-heap-glibc243-tcache-perthread-struct-hijack]]。TSU+ 走的是 smallbin 链路，不依赖 tcache next 的 safe-linking。
- **高版本 glibc**：2.34+ 移除 `__free_hook`，可改 `_IO_list_all`/`exit_funcs`/`__printf_function_table` 等；2.42+ tcache 管理结构布局变化，entries 偏移和 bin 数量需重算。
- **关联**：[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（拿到 free_hook 后的栈迁移）、[[binary-pwn-heap-scanf-scratch-buffer-malloc-sorting]]（制造 sorting 的分配原语）。

## 检测与防御

- **利用侧识别**：题目只允许固定 size、只能 UAF 写最后释放的 chunk、且地址检查挡住 libc 时，优先考虑 TSU+；在 `tcachebins`/`smallbins` 中观察假 chunk 是否被塞入。
- **防御侧**：升级 glibc 以获得更严格的 bin 完整性检查；启用 tcache double-free 检测与 hardened allocator；对堆管理结构做完整性校验（smallbin 的 `bk->fd == chunk`、`fd->bk == chunk` 等不变量）。
- **检测**：监控 `tcache_perthread_struct` 区域被业务数据覆盖、smallbin 链表出现非堆地址/非对齐地址、或 `tcachebins` 指向异常低地址，均可作为堆漏洞利用线索。
