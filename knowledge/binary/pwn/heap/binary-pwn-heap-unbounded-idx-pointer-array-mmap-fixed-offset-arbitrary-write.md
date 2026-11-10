---
id: binary-pwn-heap-unbounded-idx-pointer-array-mmap-fixed-offset-arbitrary-write
title: 指针数组 idx 无上限 + mmap/堆固定偏移：把受控缓冲区中的 qword 当 chunk_ptr[idx]，实现任意地址写任意值并打 stderr FSOP
type: scenario
domain: binary
path: binary/pwn/heap
technique: unbounded-index-pointer-array-fixed-mmap-offset-arbitrary-write
aliases:
- 无 idx 上限任意写
- 指针数组越界任意地址写
- chunk_ptr idx 无限
- mmap 区固定偏移任意写
- 任意地址写任意值
- NO PIE 堆题任意写
- edit 越界索引任意写
tags:
- pwn
- heap
- glibc-2.23
- oob-index
- arbitrary-write
- chunk-pointer-array
- no-pie
- mmap
- fsop
- stderr
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: glibc 2.23
verification:
  verified_by: verifier-V298
  verified_at: '2026-11-08T08:35:54+08:00'
  notes: 已对照原文与15张图核对：edit 无 idx 上限、chunk_ptr 固定 BSS 0x4040E0、edit(1,0x40,p64(stderr))、offset=(heapbase-chunklist+0x21010)//8、payload(/bin/sh、write_base=0/write_ptr=1、+0x88 lock、+0xd8 vtable=heapbase+0x50)、edit(3,0x50,p64(sys_addr)*8)、edit(offset,0x1000,payload)、exit(0)走IO 与原文exp逐项一致；图14/15 为 edit 越界写 stderr 的调试证据。原文明确 libc2.23，已补 set-versions='glibc 2.23'（与 staging cards.json 一致）。dup-scan pair 101 与本篇 heap leak 卡 related，非同链，判并列保留。未在本地复跑exp。
---

## 一句话结论

当 edit 直接用用户提供的 idx 访问全局 `chunk_ptr[idx]` 且完全不检查上界，而 `chunk_ptr` 位于 NO PIE 的固定 BSS 地址时，可以先把任意目标地址（如 `_IO_2_1_stderr_`）写进一块地址已知的受控缓冲区（示例为距 heap base 固定偏移 0x21010 的 mmap 区），再令 `idx = (buffer_addr - &chunk_ptr[0]) / 8`；这样 `chunk_ptr[idx]` 读出的就是目标地址，`edit(idx, data)` 即变成“向任意地址写任意值”。用它覆盖 `_IO_2_1_stderr_` 伪造 FILE，程序退出时经 `_IO_flush_all_lockp -> _IO_OVERFLOW` 调用 system。

## 原理

- **索引运算没有边界**：edit 的实现是 `read(0, chunk_ptr[idx], size)`，其中 idx 由 `scanf("%d")` 读入、可为负数或很大的正数；C 的数组下标在汇编层就是 `chunk_ptr + idx*8`，因此 idx 可以指向程序地址空间中的任意 qword。
- **读取的是“指针槽”而非直接写目标**：要写某地址，必须让 `chunk_ptr[idx]` 这个槽里存放目标地址。槽地址 = `&chunk_ptr[0] + idx*8`。若某个可写区域的地址已知且内容可控，把目标地址放在那里，再反解 idx，就能让该槽的值等于目标地址。
- **固定偏移的来源**：原文示例中，大块分配得到的 mmap 区与 heap base 的距离在当前分配器布局下固定（`buffer = heapbase + 0x21010`）；heap base 已通过元数据数组 off-by-one 泄露，因此该缓冲区地址可计算。
- **NO PIE 的作用**：`chunk_ptr` 数组位于 BSS 固定地址 0x4040E0，只有知道它才能真正算出 idx；若 PIE 开启则需要先泄露二进制基址。
- **为什么可以实现任意值写入**：`edit` 的 size 允许到 0x1000，且 `read` 直接写到 `chunk_ptr[idx]` 指向的位置，内容不受限制；因此一次 edit 即可向目标地址写入最多 0x1000 字节的任意数据。
- **FSOP 收尾**：把 `_IO_2_1_stderr_` 整体覆盖为 fake FILE：起始 8 字节放 `"/bin/sh\x00"`，使 FILE 指针本身即命令字符串；`_IO_write_base=0`、`_IO_write_ptr=1` 满足 flush 条件；+0xd8 的 vtable 指向一块填满 system 指针的堆内存（`_IO_OVERFLOW` 槽为 vtable+0x18）。程序 exit 或触发 flush 时即以 stderr 为参数调用 system。

## 触发条件

- edit（或 show）用全局指针数组 + 用户索引，且索引没有上界/负数校验。
- 指针数组本身位于 NO PIE 固定地址，或已泄露二进制基址。
- 存在一个地址可计算、内容可控的缓冲区（示例：与 leaked heap base 固定偏移的 mmap 区；也可以是任意已知可写全局区）。
- 已知 heap base（否则算不出 buffer 地址与 idx）；目标 libc 地址已知（如通过 House of Orange 泄露）。
- 目标进程最终会走到 `_IO_flush_all_lockp`（exit、main 返回、malloc_printerr 等）。
- 目标 glibc 2.23（`__malloc_hook`/FILE vtable 无校验；更高版本需换 House of Apple 等）。

## 利用步骤

1. 先通过 House of Orange 泄露 libc 基址，并计算 `_IO_2_1_stderr_`、`system` 等地址。
2. 用元数据数组 off-by-one 泄露 heap base（见关联卡片）。
3. 把目标地址写进固定的受控缓冲区：示例 `edit(1, 0x40, p64(stderr_addr))`，其中 chunk 1 的地址为 `heapbase + 0x21010`。
4. 计算下标：`chunklist = 0x4040E0`（NO PIE 下 `&chunk_ptr[0]`）；`offset = (heapbase - chunklist + 0x21010) // 8`。此时 `chunk_ptr[offset]` 读出第 3 步写入的 `stderr_addr`。
5. 在另一块可控堆内存填好 fake vtable：`edit(3, 0x50, p64(system_addr) * 8)`，使 vtable+0x18 的 `_IO_OVERFLOW` 槽为 system。
6. 构造 fake FILE 数据：`"/bin/sh\x00" + p64(0)`、`_IO_write_base=0`、`_IO_write_ptr=1`，在 +0x88 放 lock 指针、+0xd8 放 vtable 指针（示例 `heapbase + 0x50`），其余补零。
7. `edit(offset, 0x1000, payload)`：经越界索引把 payload 写到 `_IO_2_1_stderr_`。
8. 触发程序退出（或 malloc_printerr 等 flush 路径），`_IO_flush_all_lockp` 遍历到被覆盖的 stderr，经 `_IO_OVERFLOW` 调 `system("/bin/sh")`。

## PoC

原文 exp 的关键骨架（glibc 2.23、NO PIE，未在本机复跑；偏移按原题）：

```python
# 前置：libc_base 与 heapbase 已泄露
stderr = libc_base + libc.symbols['_IO_2_1_stderr_']
sys_addr = libc_base + libc.symbols['system']

edit(1, 0x40, p64(stderr))                 # 受控缓冲区 buffer = heapbase + 0x21010 存目标地址
chunklist = 0x4040E0                       # &chunk_ptr[0]，NO PIE
offset = (heapbase - chunklist + 0x21010) // 8

payload  = b'/bin/sh\x00' + p64(0)
payload += p64(0) + p64(0)                 # old top chunk fd & bk 位置
payload += p64(0) + p64(1)                 # _IO_write_base & _IO_write_ptr
payload  = payload.ljust(0x88, b'\x00') + p64(heapbase + 0x1500)  # lock
payload  = payload.ljust(0xd8, b'\x00') + p64(heapbase + 0x50)    # vtable
edit(3, 0x50, p64(sys_addr) * 8)           # fake vtable，vtable+0x18 为 system
edit(offset, 0x1000, payload)              # 任意地址写：覆盖 _IO_2_1_stderr_
# 触发 exit/FSOP -> system("/bin/sh")
```

调试时在 `edit` 的 `read` 下断，确认 `chunk_ptr[offset]` 已等于 `stderr` 地址；再在 `_IO_flush_all_lockp`、`_IO_OVERFLOW` 下断确认调用 system。

## 变体与关联

- 变体：若没有 mmap 固定偏移，可利用任意一个“地址已知且内容可控”的全局缓冲区/堆块作为指针槽来源。
- 变体：同一原语可直接打 `__malloc_hook`/`__free_hook`（glibc <2.34）或 `exit_funcs`，无需 FILE 结构。
- 变体：若索引为有符号 int，可用负索引向低地址方向选择槽位；需注意不要命中不可读写页。
- 关联：[[binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin]]（无 free 时伪造 top size 经 sysmalloc 泄 libc/heap）、[[binary-pwn-heap-metadata-array-offbyone-chunkptr-low-byte-heap-leak]]（heap 泄露）、[[binary-pwn-heap-edit-oob-freed-largebin-house-of-apple2-orw]]（另一类 edit 越界索引利用）、[[binary-pwn-heap-custom-manager-array-overflow-next-pointer-stack-chunk-orw]]（自定义管理器数组越界后的任意分配）。
- 版本边界：glibc 2.24+ 的 vtable 校验会阻断直接伪造 FILE vtable，需改用合法 vtable 或 House of Apple/Cat 等变体；2.34+ 移除 malloc/free hooks。

## 检测与防御

- **修复根因**：edit/show 必须校验 `0 <= idx < MAX_CHUNKS`（对无符号类型同时拒绝负数）；禁止把用户输入直接用于数组下标。
- **加固**：PIE + Full RELRO 使 BSS/指针数组地址不可预测；把指针数组放入只读页或做指针完整性校验（分配时把指针与基址异或）。
- **检测**：`read`/`write` 的目标地址落在 libc 或程序 BSS 而非堆区；idx 超过已分配块数量；`chunk_ptr[idx]` 的值不在堆映射范围；`_IO_2_1_stderr_` 等 FILE 结构被改写。
- **响应**：出现越界索引访问立即终止进程并保留 core，检查是否已写入 hook/FILE/atexit 结构并升级 glibc。
