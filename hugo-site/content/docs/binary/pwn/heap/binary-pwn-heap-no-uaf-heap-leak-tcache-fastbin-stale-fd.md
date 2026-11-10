---
id: binary-pwn-heap-no-uaf-heap-leak-tcache-fastbin-stale-fd
title: tcache/fastbin 取出 chunk 不清 next/fd：无 UAF 也能从申请出的块残留指针泄漏堆地址
type: scenario
domain: binary
path: binary/pwn/heap
technique: no-uaf-heap-leak-stale-next-fd
tags:
- glibc
- heap
- pwn
- heap-leak
- tcache
- fastbin
- stale-pointer
- info-leak
- 2.29
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-9
  verified_at: '2026-11-08T01:15:48+08:00'
  notes: 已对照原文核对；原文图01-04 显示 tcache 取出只清 key 不清 next、残留堆地址 0x405260，图12-14 显示 fastbin 取出只更新 fastbinsY 链首、fd 残留 0x405250，有 gdb 完整验证，构成无 UAF 从合法持有块泄漏堆地址的执行证据，非纯理论示意；卡结论为信息泄漏原语未包装成 RCE，confidence high、severity medium 合理；dedup recommendation=new，related 候选为 reverse into fastbin、safe-linking、tcache stashing 等不同技术，非同一链；原文未明确写受影响区间（仅示例 2.29），省略 affected_versions；未验证点：PoC 结构示意未独立复跑、卡未含 sources 字段。
url: /docs/binary/pwn/heap/binary-pwn-heap-no-uaf-heap-leak-tcache-fastbin-stale-fd/
draft: false
kb_aliases:
- 无 UAF 泄漏堆地址
- tcache_get 不清 next
- fastbin 取出不修改
- stale fd 堆泄漏
- 残留指针信息泄漏
---

## 一句话结论

在 glibc 2.29 及相近版本，`tcache_get` 只把取出的 chunk 的 `key` 清 0、完全不清 `next`，fastbin 取出时也只是更新 `main_arena.fastbinsY` 的链首而不修改被取出 chunk 本身；因此把一个释放过的 chunk 重新申请出来后，原 `next`/`fd` 位置仍残留指向堆内另一 chunk 的堆地址，程序即使没有 UAF、没有越界读、也不打印已释放内存，只需正常读回自己申请到的块即可稳定泄漏 heap 地址。

## 原理

- **tcache_get 的清理范围**：glibc 2.29 的 `tcache_get(tc_idx)` 做三件事：`tcache->entries[tc_idx] = e->next`（换链首）、`--tcache->counts[tc_idx]`、`e->key = NULL`（用于 double free 检查）。它**唯独不写 `e->next`**。而 tcache 的 `next` 就存放在 chunk 用户数据区起始 8 字节，所以重新 `malloc` 拿回该 chunk 后，用户数据的头 8 字节仍是上一次 free 时写入的 `next`（一个堆地址）。
- **fastbin 的同类情况**：从 fastbin 取头 chunk 时，`REMOVE_FB` / `*fb = victim->fd` 只改 `main_arena` 里的链首指针，对取出的 `victim` 不做任何字段清理；其 `fd`（用户区头 8 字节）同样残留堆地址。这就是正文「没有 UAF 漏洞的话无法泄漏地址」不成立的原因——泄漏发生在**重新申请之后**，用的是合法持有块。
- **为什么能稳定拿到地址**：同一个 size 的 tcache/fastbin 链上至少有两个节点时，第一个节点的 `next`/`fd` 指向第二个节点的堆地址（如 `0x405260`）。申请出第一个节点后读其前 8 字节即得该地址；由低位固定可反推 heap 基址（示例 `0x405000`）。
- **为什么属于完整可用原语**：它不依赖 UAF、不依赖 show-after-free、不依赖越界读，只需要「释放两个同尺寸 chunk → 再申请回来 → 读回内容」这一组合法操作，输出是一个确定的堆地址，可直接用于后续 safe-linking 解密、tcache poisoning 目标地址换算等。
- **版本边界**：`e->key` 检查从 glibc 2.30 起引入 double free 检测、`tcache` 空链判断从 2.30 起改用 `counts`；glibc 2.32 起 `next` 受 safe-linking（`PROTECT_PTR`，`pos>>12 ^ ptr`）保护，残留值不再是明文堆地址但仍可配合泄漏恢复。示例调试基于 glibc 2.29，明文残留成立。

## 触发条件

- 目标 glibc 的 tcache/fastbin 取出逻辑不清理取出 chunk 的 `next`/`fd`（示例 2.29；2.32+ 需先绕过 safe-linking 才能得到明文地址）。
- 同一 size 的 tcache/fastbin 链中至少有两个已释放 chunk，使第一个节点的 `next`/`fd` 指向一个堆地址。
- 程序能再次 `malloc` 到该节点，并能读回/输出其用户数据前 8 字节（如普通的打印自身内容、或题目自带的 show 功能作用于合法持有块）。
- 不要求 UAF、不要求已释放块的读权限。

## 利用步骤

1. 申请两个同尺寸 chunk A、B；先后 `free(A)`、`free(B)`，使 tcache（或 fastbin）链为 `B -> A`，B 的 `next`/A 的 `fd` 写入堆地址。
2. `malloc(same_size)` 取回链首 chunk（`tcache_get` 只清 `key`，`next` 残留；fastbin 只更新 `fastbinsY`）。
3. 读回该 chunk 用户区前 8 字节，得到残留的堆地址（指向链中下一个 chunk）。
4. 由该地址的低 12 位与已知对齐反推 heap 基址；后续用于 safe-linking 的 `PROTECT_PTR` 解密或 tcache poisoning 目标计算。
5. fastbin 路径同理：释放两个 0x20 chunk 后申请回第一个，其 `fd` 仍为第二个 chunk 的堆地址。

## PoC

结构示意（glibc 2.29，未在本文档环境编译执行）：

```c
// tcache 路径
void *a = malloc(0x18);
void *b = malloc(0x18);
free(a); free(b);                 // tcache[0x20]: b -> a，b->next = a 的堆地址
void *p = malloc(0x18);           // 取回 b，next 未清
printf("leak: %p\n", *(void**)p); // 读出残留堆地址（a 的地址）

// fastbin 路径（需先填满对应 tcache 或直接控制 entries 为空）
void *c = malloc(0x18);
void *d = malloc(0x18);
free(c); free(d);                 // fastbin[0x20]: d -> c
void *q = malloc(0x18);           // 取回 d，fd 未清
printf("leak: %p\n", *(void**)q); // 读出残留堆地址（c 的地址）
```

说明：glibc 2.29 的 tcache 链空判断看 `entries[tc_idx] != NULL`（2.30 起看 `counts`）；高版本若启用 safe-linking，读出的是 `(chunk_addr >> 12) ^ next_addr` 形式的混淆值，需另做恢复。PoC 仅表达字段关系，未独立复跑。

## 变体与关联

- **safe-linking 后的对应技术**：glibc 2.32+ 的 `PROTECT_PTR` 让残留值不再是明文；本库 `binary-pwn-heap-safe-linking-self-xor-heap-address` 讲同页双 free 自异或恢复堆地址，`binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack` 讲用 environ 泄漏栈并把 chunk 分配到栈上。
- **与 libc 泄漏的区别**：本卡泄漏的是 heap 地址；unsorted bin 残留 `fd/bk` 指向 `main_arena` 用于泄漏 libc，见 `binary-pwn-heap-uaf-unsorted-bin-libc-leak`。两者常在同一题里配合使用。
- **后续用途**：拿到 heap 基址后用于 tcache poisoning 的目标地址换算、`_IO_list_all`/`__free_hook` 等任意地址分配，见 `binary-pwn-heap-tcache-poison-io-list-all-house-of-apple2`。
- **同源码系列**：本文还讲解 tcache 无 size 检查任意地址申请、tcache stashing unlink attack、malloc_consolidate unlink overlapping 等，属同一 malloc.c 分析的不同分支。

## 检测与防御

- 检测：分配返回后立刻读取该块用户区头 8 字节并输出/参与运算的行为；同一 size 的连续「free-free-malloc」序列后紧跟对返回指针首 8 字节的读取。
- 缓解/防御：glibc 2.32+ 的 safe-linking（`PROTECT_PTR`）使 `next` 不再是明文堆地址；编译器/分配器可在 `malloc` 返回前清零用户区头 8 字节；题目设计上避免把刚分配块的内容原样输出给攻击者。
- 注意：这只是信息泄漏原语，本身不造成代码执行或越权；其价值在于为后续任意地址写/分配链提供 heap 基址，结论不把它包装成 RCE。
