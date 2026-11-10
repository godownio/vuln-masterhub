---
id: binary-pwn-heap-house-of-lore-smallbin-fake-chunk
title: House of Lore：伪造 small bin 的 bk/fd 链把目标地址挂入 smallbin，两次 malloc 在栈等任意地址分配 chunk（glibc 2.23-2.30）
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-lore-smallbin-arbitrary-allocation
aliases:
- House Of Lore
- house of lore
- small bin attack
- smallbin 任意地址分配
- bck->fd != victim
- malloc smallbin 伪造 bk
- glibc 堆利用
tags:
- binary
- pwn
- heap
- glibc
- malloc
- smallbin
- arbitrary-alloc
- house-of-lore
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: glibc 2.23-2.30（原文标记 2.23-2.31，不含 2.31；2.31 起该手法被 ban）
verification:
  verified_by: verifier-V306
  verified_at: '2026-11-08T11:40:34+08:00'
  notes: 已对照原文与 4 张图核对：smallbin 取出路径 bck->fd 检查、victim->bk/目标+0x10 布置、2.23 demo 两次 malloc 返回栈地址均与图一致；2.27 tcache stashing 与 2.31 被 ban 的描述与原文一致；PoC 未在本机复跑
---

## 一句话结论

House of Lore 利用 small bin 的双向链表：控制某个 small bin chunk 的 `bk` 指向目标地址、并在目标地址 `+0x10` 写入该 chunk 的地址，`_int_malloc` 的 smallbin 取出路径会把目标地址链入 bin；第一次 `malloc` 返回原 chunk，第二次 `malloc` 就把目标地址（demo 中为栈上 `stack_buffer_1`）当作 chunk 返回，实现任意地址分配，可用于覆盖栈变量/函数指针。

## 原理

- **small bin 取出路径**（glibc 2.23 `_int_malloc`）：当请求大小落在 small bin 范围且对应 bin 非空时，`victim = last(bin)`（即 `bin->bk`）、`bck = victim->bk`，检查 `bck->fd == victim` 后执行 `bin->bk = bck; bck->fd = bin;`，返回 `victim`。
- **伪造 bk**：把 `victim->bk` 改成目标地址 `target`，则 `bck = target`；检查要求 `target + 0x10`（chunk 的 fd 字段偏移）处的值等于 `victim` 的地址。第一次 `malloc` 返回 `victim`，同时 `bin->bk = target`、`target->fd = bin`。
- **第二次 malloc 取得目标地址**：再次申请同尺寸时，`victim = last(bin) = target`，只要 `target->bk` 可控（如栈上 `stack_buffer_1[3] = &stack_buffer_2`），检查 `bck->fd == victim`（即 `stack_buffer_2->fd == &stack_buffer_1`）通过后，`malloc` 返回 `target` 作为 chunk，攻击者即可在栈/任意地址写入。
- **为什么 demo 的第三次 malloc 失败**：`stack_buffer_2->bk` 未设置，`bck = victim->bk` 取到不可控值，`bck->fd != victim` 触发 `malloc(): smallbin double linked list corrupted`；这正说明每次取链都要求下一节点的 fd 指回当前 victim。
- **版本差异**：glibc 2.27 在 smallbin 取出后增加 tcache stashing 循环，若 tcache 未满会继续从 bin 尾部搬 chunk，需让 `tc_victim == bin` 或 `tcache->counts[tc_idx] >= mp_.tcache_count`，否则可能因非法内存访问崩溃；2.31 起该手法被 ban（检查与 tcache 机制使利用条件苛刻）；2.32+ 引入 safe-linking，需先泄露堆地址。

## 触发条件

- 目标使用 glibc 2.23-2.30（原文范围），程序存在可控制 small bin chunk `bk` 的堆溢出/UAF/编辑原语，并能控制目标地址 `+0x10` 的 fd 值。
- 能触发 `free` + 一次较大的 `malloc`（如 0x400）把 unsorted bin 转入 small bin；目标地址所在内存可写。
- 目标地址不需要可执行，只需在后续被程序当作内存写入/函数指针使用。
- 利用者知道 `victim` 与目标地址（demo 中为栈地址，需栈泄露或固定环境）。

## 利用步骤

1. 分配 `victim = malloc(0x100)`，再分配一个隔离 chunk，`free(victim)` 使其进入 unsorted bin。
2. `malloc(0x400)` 触发 unsorted bin 整理，victim 进入 small bin（0x110）。
3. 用堆编辑原语设置：`victim->bk = target`；并在 `target + 0x10` 写入 `victim` 的地址（chunk 头 fd 位置）。
4. 申请同尺寸 `malloc(0x100)`，返回 victim；此时 `bin->bk = target`。
5. 再次 `malloc(0x100)`，返回 target（demo 中为栈上 `stack_buffer_1`），向该 chunk 写入即可覆盖栈变量/返回地址/函数指针。
6. 若要继续分配下一目标，需提前设置 `target->bk = next` 且 `next->fd = target`，否则下一次 malloc 会触发 smallbin 链表损坏检查。

## PoC

原文 demo（glibc 2.23；结合图片中 dem05.c 的完整布置）：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
    intptr_t *stack_buffer_1[4] = {0};
    intptr_t *stack_buffer_2[4] = {0};

    intptr_t *victim = malloc(0x100);
    malloc(0x10);
    free(victim);
    malloc(0x400);            // unsorted -> small bin

    victim[1] = &stack_buffer_1;       // victim->bk = stack_buffer_1
    stack_buffer_1[2] = victim - 2;    // stack_buffer_1->fd = victim
    stack_buffer_1[3] = &stack_buffer_2; // stack_buffer_1->bk = stack_buffer_2
    stack_buffer_2[2] = &stack_buffer_1; // stack_buffer_2->fd = stack_buffer_1

    intptr_t *p1 = malloc(0x100);      // 返回 victim
    intptr_t *p2 = malloc(0x100);      // 返回 stack_buffer_1（栈上 chunk）
    malloc(0x100);                     // failed: bck->fd != victim
}
```

## 变体与关联

- **相关 House 系列**：House of Rabbit（`malloc_consolidate` + 伪造 largebin 实现任意分配）见 [[binary-pwn-heap-house-of-rabbit-malloc-consolidate-fake-chunk-largebin-arbitrary-alloc]]；House of Orange/Apple2 等 largebin/IO 链可作对比。
- **smallbin 相关**：fastbin/smallbin `PREV_INUSE` 构造重叠见 [[binary-pwn-heap-fastbin-smallbin-prev-inuse-free-overlapping]]。
- **后续利用**：任意地址分配后可覆盖栈返回地址、`__malloc_hook`/`__free_hook`（老版本）、函数指针或 IO 结构；2.32+ 需先绕 safe-linking。
- **边界**：glibc ≥2.31 该手法被禁用/极难利用；无 `bk` 写原语、目标地址 `+0x10` 不可写、或 small bin 未成功转入时无法布置。

## 检测与防御

- **版本与缓解**：升级到 2.31+（含 tcache 加固）与 2.32+（safe-linking）；开启 ASLR、FULL RELRO、堆保护。
- **代码审计**：修复堆溢出/UAF/越界写，避免给攻击者提供 `bk` 与目标地址写原语；对 `free` 后的指针置空，使用安全分配器/加固 malloc。
- **运行时检测**：关注 `malloc(): smallbin double linked list corrupted`、`malloc_printerr` 崩溃；监控异常堆布局/栈地址 chunk；CTF 环境可用 glibc 2.31+ 复现失败作为版本判断。
