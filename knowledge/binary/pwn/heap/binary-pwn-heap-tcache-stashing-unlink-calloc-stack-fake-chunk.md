---
id: binary-pwn-heap-tcache-stashing-unlink-calloc-stack-fake-chunk
title: Tcache Stashing Unlink Attack：calloc 触发 smallbin→tcache 批量搬运，篡改 bk 实现任意地址写 libc 指针与栈上 fake chunk 分配
type: scenario
domain: binary
path: binary/pwn/heap
technique: tcache-stashing-unlink-calloc-stack-fake-chunk
aliases:
- Tcache Stashing Unlink Attack
- TSU
- tcache stashing unlink
- calloc 绕过 tcache
- smallbin 搬运 tcache
- stack_var fake chunk
- 任意地址写 main_arena
- 栈上 fake chunk 分配
tags:
- pwn
- heap
- glibc
- tcache
- smallbin
- calloc
- arbitrary-write
- fake-chunk
- stack
- how2heap
cve: []
severity: high
confidence: high
affected_versions: glibc 2.27 – 2.36（原文标记适用范围；PoC 在 2.27/2.29/2.31 测试）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T04:52:31+08:00'
  notes: 已对照原文与4张图核对：calloc绕过tcache进入_int_malloc、smallbin首个victim的bck->fd检查、stashing循环无bck->fd校验、stack_var[3]=&stack_var[2]使bck->fd写入stack_var[4]=main_arena+96、malloc(0x90)返回fake+0x10均与图01-04/源码一致；affected_versions按原文『到2.36可用、2.27/2.29/2.31测试』保留。未验证点：PoC未本机复跑；frontmatter无sources/source_url。
---

## 一句话结论

当程序至少能调用一次 `calloc`（它会绕过 tcache 直接进入 `_int_malloc`），且攻击者能改写某个 smallbin 堆块的 `bk` 指针时，可以触发 `_int_malloc` 的 tcache stashing 循环：`calloc` 先从 smallbin 正常取出最后一个堆块，随后在把剩余 smallbin 堆块批量搬进 tcache 的循环中，对被篡改 `bk` 指向的 fake chunk 执行 `bck->fd = bin`，从而把 `main_arena+96` 的 libc 地址写到目标地址；同时 fake chunk 被链入 tcache，下一次同大小 `malloc` 会返回 fake chunk 的用户区（可放在栈上），得到任意写与可控分配。

## 原理

- **tcache 优先与 calloc 的例外**：`malloc` 在 tcache 非空时会优先从 tcache 取块；`calloc` 则直接走 `_int_malloc`（并用 `chunk_is_mmapped` 等逻辑处理清零），因此即使 tcache 里还有空位，也能强制进入 smallbin 分配路径。
- **smallbin 分配与初始检查**：`_int_malloc` 对 smallbin 取 `victim = last(bin)`（即 `bin->bk`），脱链前检查 `bck = victim->bk; if (bck->fd != victim) malloc_printerr("malloc(): smallbin double linked list corrupted")`。所以第一个被取出的 victim 必须是合法节点，攻击者篡改的 `bk` 不能用于这一步。
- **tcache stashing 循环（漏洞点）**：取出 victim 后，如果 `tc_idx < mp_.tcache_bins` 且 `tcache->counts[tc_idx] < mp_.tcache_count`（tcache 未满），循环把 smallbin 剩余尾部堆块搬进 tcache：
  ```c
  while (tcache->counts[tc_idx] < mp_.tcache_count
         && (tc_victim = last(bin)) != bin) {
      bck = tc_victim->bk;
      set_inuse_bit_at_offset(tc_victim, nb);
      bin->bk = bck;
      bck->fd = bin;              // 未校验 bck->fd，可写任意地址
      tcache_put(tc_victim, tc_idx);
  }
  ```
  该循环**不检查** `bck->fd == tc_victim`，只要求 `bck` 可写。攻击者把某个即将被搬运的堆块的 `bk` 改成 fake chunk 地址，循环就会把 fake chunk 当作 smallbin 节点处理。
- **fake chunk 的两个作用**：
  1. 当循环把 fake chunk 当作 `tc_victim` 时，`bck = fake->bk`（即 `fake+0x18` 处的内容），执行 `bck->fd = bin`，把 `main_arena+96`（smallbin 链表头地址，libc 指针）写到 `bck+0x10`；把 `fake->bk` 指向一个可写地址即可控制写入位置。
  2. `tcache_put(fake, tc_idx)` 把 fake chunk 链入 tcache；之后 `malloc(同大小)` 返回 `fake+0x10`（用户区）。若 fake 位于栈上，就能得到栈上分配，为后续 ROP 提供可控内存。
- **toctou 与检查位置**：初始的 `bck->fd != victim` 只针对第一个 victim；攻击者篡改的是**第二个**（或更靠前被搬进 tcache 的）堆块的 `bk`，该值在 stashing 循环中才被使用，绕过了唯一的一致性检查。
- **calloc 与 tcache 计数**：触发时 tcache 对应 size 的 count 必须小于 7（有槽位），否则循环不执行；PoC 先填满 7 个 tcache，再制造 2 个 smallbin 块，然后 malloc 两次腾出 2 个 tcache 槽位（剩 5 个），最后 calloc 触发。
- **为什么适用到 2.36**：该路径在 2.27–2.36 的 smallbin/tcache stashing 逻辑基本一致；2.32+ 的 safe-linking 只影响 tcache `next` 指针的编码，fake chunk 仍能被 tcache_put/取出，`bck->fd = bin` 的任意写也仍然成立。原文称到 2.36 操作方式不变。

## 触发条件

- glibc 2.27–2.36（不同版本 tcache 结构/计数、safe-linking 细节可能需微调）。
- 程序至少有一次 `calloc` 分配，且大小落在目标 smallbin/tcache 范围；或能通过其他方式强制进入 `_int_malloc` 的 smallbin 路径。
- 攻击者能改写 smallbin 中某个非首个堆块的 `bk` 指针（UAF、堆溢出、任意写原语等）。
- 目标 size 对应的 tcache 有可用槽位（count < 7），smallbin 中至少有 2 个同大小堆块（一个用于通过初始检查并被分配，一个用于触发 stashing）。
- 有可写目标地址用于放置 fake chunk 的 `bk` 可写指针（如栈上 `stack_var[3] = &stack_var[2]`），并知道其地址。

## 利用步骤

1. 准备 9 个同大小堆块（PoC 为 0x90 请求，实际 chunk 0xa0）。
2. 先释放 6 个（如 chunk3–8）填 tcache，再释放 1 个（chunk1）填满 7 个 tcache；随后释放 chunk0、chunk2 进入 unsorted bin。释放顺序要避免相邻空闲块合并。
3. `malloc(0xa0)`（大于 0x90）触发 unsorted bin 处理，把 chunk0、chunk2 放入 0xa0 smallbin。
4. `malloc(0x90)` 两次从 tcache 取出 2 个，使 tcache 剩 5 个、空出 2 个槽位；smallbin 保留 2 个块。
5. 在 fake chunk（如栈上 `stack_var`）的 `bk` 位置（`fake+0x18`）写入一个可写地址（PoC 为 `&stack_var[2]`），保证 stashing 循环对 fake 执行 `bck->fd = bin` 时 `bck` 可写。
6. 用漏洞改写 smallbin 中第二个堆块（PoC 的 chunk2）的 `bk` = fake chunk 地址。
7. `calloc(1,0x90)` 触发攻击：calloc 绕过 tcache 进入 `_int_malloc`；第一个 smallbin 块正常分配，stashing 循环处理被篡改的块与 fake chunk，把 `main_arena+96` 写到 `fake->bk + 0x10`，并把 fake chunk 链入 tcache。
8. 再次 `malloc(0x90)`，返回 fake chunk 的用户区（`fake+0x10`），验证可在栈上写入；若 fake 的 `bk` 指向目标地址-0x10，则完成了对目标的 libc 指针写入。

## PoC

原文 how2heap PoC 结构（glibc 2.27/2.29/2.31，未在本机执行）：

```c
unsigned long stack_var[0x10] = {0};
unsigned long *chunk_lis[0x10] = {0};
unsigned long *target;

// fake chunk 的 bk 指向一个可写地址，供 bck->fd = bin 写入
stack_var[3] = (unsigned long)(&stack_var[2]);

for (int i = 0; i < 9; i++)
    chunk_lis[i] = malloc(0x90);

for (int i = 3; i < 9; i++)   // 6 个进 tcache
    free(chunk_lis[i]);
free(chunk_lis[1]);           // 填满 tcache（7 个）
free(chunk_lis[0]);           // unsorted
free(chunk_lis[2]);           // unsorted（不与 0 相邻）

malloc(0xa0);                 // 把 0、2 放入 smallbin
malloc(0x90);                 // 从 tcache 取，腾出槽位
malloc(0x90);

chunk_lis[2][1] = (unsigned long)stack_var;  // 改写 smallbin 块的 bk

calloc(1, 0x90);              // 触发 tcache stashing unlink
target = malloc(0x90);        // 返回 fake chunk 用户区
```

Python/CTF 模板（按目标偏移调整）：

```python
for i in range(9):
    add(0x90)
for i in range(3, 9):
    free(i)
free(1)
free(0)
free(2)
add(0xa0)
add(0x90)
add(0x90)
edit(2, p64(fake_chunk))      # 改写 smallbin 某块的 bk
calloc(1, 0x90)               # 触发
malloc(0x90)                  # 返回 fake_chunk+0x10
```

## 变体与关联

- **无 show / 无堆地址变体**：先用 largebin attack 在目标 fake chunk 的 `bk` 预置合法堆指针，再用 TSU 把固定 mmap 地址塞进 tcache；见 [[binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write]]。
- **TSU+ 变体**：让 fake chunk 与 `tcache_perthread_struct.entries[]` 重叠，一次 UAF 改写即可把 entries 改成 `__free_hook-0x10` 等目标；见 [[binary-pwn-heap-tcache-stashing-unlink-plus-tcache-perthread-entries]]。
- **目标变体**：写入 `main_arena+96` 可泄露 libc（若目标可读）；把 `fake->bk` 指向 `__free_hook-0x10`、`__malloc_hook-0x10`、返回地址等可做后续劫持；fake chunk 可放堆、栈或 mmap 固定地址。
- **其他 House 系列**：House of Botcake、House of Orange、House of Storm 等 tcache/smallbin 组合；见 [[binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system]]、[[binary-pwn-heap-glibc235-botcake-malloc-consolidate-io-list-all-apple2]]。
- **边界**：tcache 已满、smallbin 不足 2 块、无法改写 bk、目标不可写或 safe-linking 细节变化时可能失败；glibc 2.36 后版本需按实际 `_int_malloc` 逻辑复核。

## 检测与防御

- **利用条件检测（CTF/防御）**：监控 smallbin 链表的 `bk` 指针是否指向非堆/非合法 chunk；在 `_int_malloc` 的 stashing 循环中校验 `bck->fd == tc_victim`（该检查在旧版本缺失）；对 tcache 链中的地址做堆范围校验。
- **缓解**：升级 glibc 到包含更严格一致性检查的版本；启用 safe-linking（2.32+）增加指针伪造难度；减少可改写 smallbin bk 的堆溢出/UAF 原语；对 `calloc` 与 tcache 计数异常做监控。
- **程序侧**：避免把用户可控数据写到已释放 chunk 的 `bk`；对堆块元数据做完整性校验；CTF 中重点检查 smallbin/tcache 链表在 calloc 前后的变化。
