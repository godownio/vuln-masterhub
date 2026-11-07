---
id: binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison
title: House of Einherjar：off-by-null 清 PREV_INUSE + 伪造 prev_size/fake chunk 向前合并，堆重叠后 tcache poisoning 任意地址分配
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-einherjar-offby-null-fake-chunk-tcache-poison
aliases:
- House of Einherjar
- einherjar
- 向前合并攻击
- backward consolidation
- 伪造 prev_size
- fake chunk 自指 unlink
- 单字节溢出清 PREV_INUSE
- 堆重叠后 tcache 投毒
tags:
- pwn
- heap
- glibc
- glibc235
- off-by-null
- house-of-einherjar
- prev-inuse
- prev-size
- unlink
- chunk-overlap
- tcache
- safe-linking
- arbitrary-alloc
- ctf
cve: []
severity: high
confidence: high
status: verified
affected_versions: glibc 2.32（原文标记：开启 tcache 仍可用）；原文测试环境 glibc 2.35
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V232
  verified_at: '2026-11-07T09:24:22+08:00'
  notes: 已对照原文与12张图核对：off-by-null 写 0 清 c->PREV_INUSE(0x101→0x100)、fake chunk prev_size/size 一致、fd=bk=自身通过 unlink 检查、填满 0xf8 tcache 后 free(c) 向前合并、重叠块 d 改写 b->fd 做 safe-linking 编码 tcache poisoning、target 需 16 字节对齐，均与原文 C PoC 一致。glibc 版本表述核对：原文 PoC 注释称该变种在开启 tcache 的 glibc-2.32 仍可用，测试环境为 Ubuntu 22.04/glibc 2.35，卡内 affected_versions 与正文表述一致；未编译运行 C PoC。
---

## 一句话结论

当一处单字节溢出（off-by-null）清掉下一个已分配 chunk 的 `PREV_INUSE`，而该 chunk 的 `prev_size` 已被攻击者改写为指向一块伪造 chunk 时，`free` 的向前合并会回退到 fake chunk 并与其合并，形成覆盖多个 chunk 的重叠块；随后改写仍挂在 tcache 上的 chunk 的 `fd`，即可让 `malloc` 返回一个几乎任意（需 16 字节对齐）的地址。

## 原理

- **可被覆盖的元数据位置**：glibc 的 malloc chunk 中，已分配 chunk 的用户区会“借用”下一个 chunk 的 `prev_size` 字段，因此用户区最后 8 字节就是下一 chunk 的 `prev_size`，再多 1 字节就是下一 chunk 的 `size` 最低字节。对 `size` 最低字节写 `0x00`，即可把 `PREV_INUSE` 位清零，同时不改变 chunk 的实际大小（前提是该 chunk 的 size 低字节本来就是 `0x00`，例如 `malloc(0xf8)` 得到 `size=0x101`，写 `0` 后变 `0x100`）。
- **free 的校验顺序**：`_int_free` 先检查 `p != av->top`、`nextchunk` 不越过 top、`prev_inuse(nextchunk)` 为真（否则报 `double free or corruption (!prev)`）、`nextsize` 不小于 chunk 头且小于 `av->system_mem`。这些检查针对的是“释放参数是否合理”，并不会校验被释放 chunk 自己的 `prev_size` 字段是否真实。
- **向前合并（backward coalescing）**：当 `p` 的 `PREV_INUSE` 为 0 时，`_int_free` 读取 `p->prev_size`，令 `size += prevsize`，并执行 `p = chunk_at_offset(p, -prevsize)` 回退；随后检查 `chunksize(p) == prevsize`，再调用 `unlink_chunk(p)`。攻击者把 fake chunk 的 `size` 与写入的 `prev_size` 设为同一个值，即可通过一致性检查。
- **unlink 双链表校验的绕过**：`unlink_chunk` 要求 `fd->bk == p` 且 `bk->fd == p`。把 fake chunk 的 `fd` 和 `bk` 都写成 fake chunk 自身的地址（自指），就有 `fd->bk = p->bk = p`、`bk->fd = p->fd = p`，检查通过，随后 `fd->bk = bk`、`bk->fd = fd` 只是把 fake chunk 从自己构成的“链表”里摘除，不会破坏其他内存。
- **重叠块的形成**：fake chunk 被放置在较早分配的 chunk `a` 的用户区内，合并后空闲块从 fake chunk 头开始，大小等于 fake chunk size 加上被释放 chunk 的 size，覆盖了 `a` 的剩余用户区、中间的 `b` 以及 `c`。该块进入 unsorted bin 后，用一次合适大小的 `malloc` 取回，就得到一块与 `b` 重叠的可写区域。
- **tcache poisoning**：先释放一个同 size 的 pad 块，再释放位于重叠区内的 `b`，使 tcache 链为 `b -> pad`；通过重叠块 `d` 覆写 `b` 的 `fd` 为 `target ^ (pos >> 12)`（glibc 2.32+ 的 safe-linking 编码），之后连续两次 `malloc`：第一次返回 `b` 并让 tcache 头变成 `target`，第二次直接返回 `target`。`tcache_get` 会检查目标对齐，因此 `target` 必须 16 字节对齐；这也是原文 PoC 在栈上挑选 `& 0xf == 0` 的地址的原因。
- **为什么必须先填满 tcache**：`free(c)` 时若对应 size 的 tcache 未满，`c` 会直接进入 tcache，根本不会走到 unsorted bin 的合并分支；先申请并释放 7 个同 size chunk 填满 tcache，才能迫使 `free(c)` 走合并路径。

## 触发条件

- 程序存在 off-by-null，或存在可精确清掉下一 chunk `size` 最低字节/`PREV_INUSE` 位的单字节越界写。
- 攻击者可控制被释放 chunk 的 `prev_size`（通常借助前一个 chunk 的用户区末尾 8 字节写入）。
- 目标 glibc 使用 `prev_size` + `PREV_INUSE` 的向后合并逻辑；启用 tcache 时需先填满对应大小的 tcache，且合并后的 chunk 要能进入 unsorted bin。
- 需要 heap 地址泄露：fake chunk 的 `fd/bk` 自指需要知道其自身地址；glibc 2.32+ 的 safe-linking 也需要 heap 地址来计算编码后的 `fd`。
- 能申请足够大的 chunk（原文条件：可分配大于等于 unsorted bin 大小的 chunk），以便取回合并后的重叠块。
- `target` 需要满足 tcache 的对齐要求（16 字节对齐）。

## 利用步骤

1. 泄露 heap 基址（原文示例用 largebin + 一次 edit/show 泄露堆地址；也可用 unsorted bin、tcache 链表等任意堆泄露）。
2. 申请三块连续 chunk：`a`（如 `0x38`，作为 fake chunk 容器）、`b`（如 `0x28`，溢出源）、`c`（如 `0xf8`，size 低字节为 `0x00` 的受害者）。在 `a` 的用户区布置 fake chunk 头：`prev_size=0`、`size=fake_size`、`fd=bk=a`。
3. 计算 `fake_size = (c - 2*sizeof(size_t)) - a`（即 `c` 的 chunk 头地址减去 fake chunk 地址），把该值写到 `b` 用户区的最后 8 字节，覆盖 `c->prev_size`；再把 fake chunk 的 `size` 改成同一个 `fake_size`，保证 `chunksize(fake) == prev_size(c)`。
4. 填满 `c` 对应 size 的 tcache（malloc/free 7 次同 size），然后对 `b` 做 off-by-null（`b[malloc_usable_size(b)] = 0`），清掉 `c` 的 `PREV_INUSE`。
5. `free(c)`：`_int_free` 依据 `c->prev_size` 回退到 fake chunk，通过 size 一致性与 unlink 双链表检查后完成合并；合并块进入 unsorted bin。
6. `malloc` 一个覆盖合并块的大小（原文 `0x158`），得到与 `b` 重叠的块 `d`；释放 pad 和 `b`，使 tcache 链为 `b -> pad`。
7. 通过 `d` 覆盖 `b->fd = target ^ ((addr_of_b->fd) >> 12)`；连续 `malloc` 两次，第二次返回 `target`，之后向该地址写入 GOT/返回地址/one_gadget 等完成控制流劫持（原文 PoC 仅用 `assert(e == target)` 证明可分配栈地址）。

## PoC

原文给出可直接在 Ubuntu 22.04 / glibc 2.35 编译运行的完整 C 程序；下面是去掉打印后的最小骨架，偏移按目标二进制与 libc 重新核对：

```c
intptr_t *a = malloc(0x38);          // fake chunk 容器
uint8_t  *b = malloc(0x28);          // 溢出源
uint8_t  *c = malloc(0xf8);          // 受害者，chunk size = 0x100

a[0] = 0;                            // fake prev_size
a[1] = 0x60;                         // fake size（等于 c 的 prev_size）
a[2] = (intptr_t)a;                  // fd -> 自己
a[3] = (intptr_t)a;                  // bk -> 自己

size_t real_b = malloc_usable_size(b);
size_t fake_size = (size_t)((c - 2 * sizeof(size_t)) - (uint8_t *)a);
*(size_t *)&b[real_b - sizeof(size_t)] = fake_size;   // 覆盖 c->prev_size
a[1] = fake_size;                                     // fake size 与 prev_size 一致

intptr_t *x[7];
for (int i = 0; i < 7; i++) x[i] = malloc(0xf8);       // 填满 0x100 tcache
for (int i = 0; i < 7; i++) free(x[i]);

b[real_b] = 0;                       // off-by-null：c->size 0x101 -> 0x100
free(c);                             // 向前合并 fake chunk，进入 unsorted bin

intptr_t *d = malloc(0x158);         // 取回重叠块（d 与 b 重叠）
uint8_t  *pad = malloc(0x28);
free(pad);
free(b);                             // tcache[0x30] = b -> pad

intptr_t *target = /* 16 字节对齐的可写目标 */;
d[0x30 / 8] = (intptr_t)target ^ ((intptr_t)&d[0x30 / 8] >> 12);  // 覆写 b->fd
malloc(0x28);                        // 取出 b
intptr_t *e = malloc(0x28);          // 返回 target，后续可写
assert(e == target);
```

## 变体与关联

- **只清 PREV_INUSE 一比特的 off-by-one**：当下一 chunk size 低字节不是 `0x00` 时，可用只写 1 bit 的 off-by-one 清掉 `PREV_INUSE`，其余位保持不变；原文指出部分特殊大小的 chunk 允许 off-by-one 同时改到 `prev_size` 和 `PREV_INUSE`。
- **glibc 版本差异**：glibc 2.32 引入 safe-linking，tcache `fd` 需要按 `target ^ (pos >> 12)` 编码；更老的 glibc（如 2.23/2.27）可直接写目标地址，且常以 `__malloc_hook`/`__free_hook` 收尾。
- **收尾目标变体**：得到任意地址分配后，可打 GOT（如 `strlen@got`/`free@got`）、`__malloc_hook`、`environ` 泄露栈后 ROP、FSOP（`_IO_list_all`）等；具体选择取决于目标 glibc 与保护。
- **不依赖 tcache 的变体**：若 tcache 未开启或已被填满，合并块直接进入 unsorted bin，重叠后可用 unsorted bin attack、largebin attack 或直接复用空闲链表完成后续利用。
- 关联：[[binary-pwn-heap-vfs-offby-null-einherjar-largebin-io-list-all-fsop]]（同一 House of Einherjar 向前合并原语，后续接 largebin + wide FILE FSOP，目标 glibc 2.41）、[[binary-pwn-heap-newline-size-diff-0xa-offbyone-prev-inuse-overlap]]（单字节清 PREV_INUSE 造重叠，但没有 fake chunk 自指 unlink）、[[binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop]]（glibc 2.35 off-by-null + 高版本 unlink）、[[binary-pwn-heap-house-of-botcake-tcache-poison]]（tcache 填满后合并/重投毒）。

## 检测与防御

- **检测**：关注 `free(): invalid next size (normal)`、`double free or corruption (!prev)`、`corrupted size vs. prev_size while consolidating`、`corrupted double-linked list`、`unaligned tcache chunk detected` 等 glibc 报错；堆上出现 `prev_size` 与前一 chunk 实际大小不一致、fake chunk 的 `fd/bk` 指向自身或堆内非 bin 地址、tcache `fd` 解码后指向非堆区，都是典型特征。
- **防御**：修复所有 off-by-null/单字节越界写，长度校验以实际可写字节数为准；对 `read`/字符串拷贝使用显式长度并检查边界；开启 AddressSanitizer、MTE 或堆一致性检查；高版本 glibc 的 safe-linking、tcache key、对齐检查只能提高门槛，不能替代根因修复；对高风险进程可关闭 tcache 或使用 hardened allocator。
