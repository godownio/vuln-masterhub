---
id: binary-pwn-heap-house-of-botcake-tcache-poison
title: House of Botcake：填满 tcache + unsorted bin 合并绕过 double free 检查，重新投毒 tcache
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-botcake-tcache-double-free-bypass
aliases:
- house of botcake
- botcake
- tcache 双释放绕过
- tcache key 绕过
- unsorted bin 合并复用
- tcache poisoning botcake
tags:
- pwn
- heap
- glibc-2.31
- tcache
- double-free
- unsorted-bin
- consolidation
- tcache-poisoning
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:45:31+08:00'
  notes: 已对照原文及15张图核对：glibc 2.31 tcache_entry next/key、tcache_put 的 key=tcache、_int_free 的 key 检查与链表扫描、填满 tcache→A 入 unsorted→free(prev) 合并→腾槽→再次 free(A) 的 botcake 流程均与图08-10/源码一致；EXP 的 0x180 尺寸、free 顺序、UAF 投毒段与原文一致。小瑕疵：卡片称'没有常规 edit 时机'，但原文程序有 edit 且作者注释为'我们有 edit 的话没必要这样搞'，该表述不准确但不影响技术链；另'再申请6个腾空tcache'实为腾出6个槽位而非清空。未验证点：EXP 未本机复跑；CTF题无组件受影响版本；frontmatter无sources/source_url。
---

## 一句话结论

House of Botcake 通过“填满 tcache → 让目标 chunk 第一次 free 落入 unsorted bin → 释放相邻 chunk 触发合并 → 再 free 一次目标 chunk 使其进入 tcache”制造同一个 chunk 同时存在于 tcache 与 unsorted bin/合并块中的错位；在 glibc 2.31（无 safe-linking）下，随后即可用 UAF 改写该 tcache entry 的 `next`，把下一次分配投毒到任意地址（如 `_IO_2_1_stdout_`）。

## 原理

- **tcache 结构与检查**：glibc 2.31 的 `tcache_entry` 覆盖在 freed chunk 的用户区：前 8 字节 `next`（明文指针，无 safe-linking），后 8 字节 `key`。`tcache_put` 会把 `e->key = tcache`（当前线程 tcache 指针）作为“在 tcache 中”的标志。`_int_free` 遇到 `e->key == tcache` 时并不立即报错，而是先遍历该 bin 的链表；只有真的在链表中再次遇到 `e` 才判定 `double free detected in tcache 2`。
- **botcake 的目标**：让目标 chunk `A` 在第一次 free 时不进入 tcache（因为 tcache 已满），而是进入 unsorted bin；随后释放与它相邻的 `prev`，`prev` 与 `A` 合并成一个更大的 unsorted chunk（`A` 的用户区被合并元数据覆盖，`key` 不再是 `tcache`）。再从 tcache 取走一个 chunk 腾出槽位，第二次 `free(A)`：此时 `e->key != tcache`，检查通过，`A` 被 `tcache_put` 加入 tcache；但 `A` 同时仍是那个合并 unsorted 块的一部分，形成“同一块内存两套视图”。
- **为什么能投毒**：tcache entry 的 `next` 在 2.31 是明文。UAF 写（或再次分配后写）把 `A->next` 改成目标地址 `target`，下一次 `malloc` 返回 `A`，再下一次 `malloc` 返回 `target`，即任意地址分配/写。
- **为什么必须控制释放顺序**：`A` 与 `prev` 必须相邻且 `A` 在 `prev` 之后（释放 `A` 后再释放 `prev` 才能向后合并）；`A` 后面还需要 guard 或已分配块，避免与 top chunk 合并。tcache 要先填满，否则 `free(A)` 直接进 tcache，不会进入 unsorted bin。
- **本题变体**：程序提供稳定的 UAF 写（`delete` 不置空 `notes[idx]`，`edit` 只检查指针非空），libc 2.31 无 safe-linking。作者在 0x180 尺寸上用“先填 6 个、free(2) 填满第 7 个、free(1)/free(0) 落入 unsorted、再申请 6 个腾空 tcache、再次 free(1)”的顺序构造出可投毒 entry；由于没有常规 edit 时机，还借助 unsorted bin 切割残留 libc 指针（`fd/bk`），再用 `edit(1, b'\xa0\x66')` 等小覆写推进布局。
- **边界**：高版本 glibc 有 safe-linking，`next` 被异或编码，需要泄露堆地址；glibc 2.32+ 的 `key` 检查/随机化也会影响；tcache 尺寸上限（0x410）与合并行为随版本变化。无 UAF 写就无法改 `next`，botcake 本身只解决“重新进入 tcache”，不直接给任意写。

## 触发条件

- 目标为 glibc 2.31 或类似无 safe-linking 的版本；目标尺寸的 tcache bin 可被填满（每线程 7 个）。
- 存在可控的 UAF 写（free 后仍可 edit/写 freed chunk），或能在重新分配后改写 tcache entry 的 `next`。
- 能按顺序分配/释放多个同尺寸 chunk，并控制相邻关系（victim 与 prev 相邻，victim 后方有 guard）。
- 目标地址（如 `_IO_2_1_stdout_`、`__free_hook`、GOT）在分配时满足对齐要求（tcache 对 size 有校验，`next` 需指向合法 chunk 头）。
- 已知 libc 基址或能先泄露，用于确定投毒目标。

## 利用步骤

1. 选择目标尺寸（示例 0x180），连续分配 7 个同尺寸 chunk 并全部释放，填满对应 tcache bin。
2. 分配 victim `A` 与其相邻的 `prev`（`A` 在 `prev` 之后），并在 `A` 后方保留 guard，防止与 top 合并。
3. `free(A)`：tcache 已满，`A` 进入 unsorted bin（或相应 bin），不会进 tcache。
4. `free(prev)`：`prev` 与 `A` 向后合并成一个更大的 unsorted chunk。
5. 从 tcache 分配一个 chunk（或若干），腾出一个 tcache 槽位。
6. 再次 `free(A)`：`A` 的 `key` 已被合并元数据覆盖，不等于 `tcache`，检查通过，`A` 进入 tcache。
7. 通过 UAF 写或重新分配后写，把 `A` 的 `next` 改成目标地址（示例 `_IO_2_1_stdout_` 或 `__free_hook`）。
8. 连续 `malloc` 两次：第一次返回 `A`，第二次返回 `target`；向 `target` 写入伪造数据，完成 stdout 泄露或 hook 劫持。

## PoC

原文 EXP 的 botcake 构造段（0x180 尺寸，glibc 2.31，未在本机执行）：

```python
for i in range(9):
    add(i, 0x180)
for i in range(6):
    delete(i + 3)      # tcache[0x190] 填 6 个
delete(2)              # 填满第 7 个
delete(1)              # 落入 unsorted bin
delete(0)              # 与相邻块整理/合并
for i in range(6):
    add(i + 2, 0x180)  # 腾空 tcache
delete(1)              # 再次 free，绕过 key 检查进入 tcache

# 通过 UAF/小覆写调整布局，随后把 tcache next 指向 stdout
edit(1, b'\xa0\x66')
add(0, 0x180, b'\xa0')
add(0, 0x180, b'\xa0')
```

gdb 观察（原文）：`tcachebins` 中 0x190 链表与 `unsortedbin` 同时存在重叠块；`tcache_entry` 前 16 字节为 `next/key`，`key` 被 `tcache_put` 写成 tcache 指针，`_int_free` 只有在链表中再次找到同一 entry 时才报 double free。

## 变体与关联

- **无 edit 的题目**：需借助 unsorted bin 切割残留 libc 指针与一次性的 UAF 写来覆盖 `key/next`；原文即为此变体。
- **有 edit 的题目**：直接 UAF 改 `next` 即可，botcake 只用于让目标 chunk 重新进入 tcache。
- **高版本 glibc**：safe-linking 需先泄露堆地址并按 `(addr >> 12) ^ next` 编码；tcache key 随机化需先清 key 或换 tcache dup 手法。
- **关联**：stdout 泄露见 [[binary-pwn-heap-stdout-partial-overwrite-libc-leak]]；`__free_hook`/setcontext 链见 [[binary-pwn-heap-freehook-setcontext61-bridge-orw]]；其他 tcache 攻击见 [[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]] 与 [[binary-pwn-heap-safe-linking-self-xor-heap-address]]。
- **防御/修复**：修复 UAF（free 后置空、从数组移除）；升级 glibc 启用 safe-linking；对 tcache 链表完整性做检测。

## 检测与防御

- **代码审计**：查找 free 后未置空、edit 只判断非空的 UAF；关注 tcache 填满→相邻块合并→再次 free 的调用序列。
- **运行时检测**：同一 chunk 同时出现在 tcache 与 unsorted bin；tcache `next` 指向非堆地址；`_int_free` 的 double free 检查被绕过后的异常分配。
- **防御**：升级到带 safe-linking/tcache key 随机化的 glibc；启用 MALLOC_CHECK_/tcache 完整性校验；CTF 服务对异常分配/释放序列做监控。
