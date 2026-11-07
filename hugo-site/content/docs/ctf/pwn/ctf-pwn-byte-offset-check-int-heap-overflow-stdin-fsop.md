---
id: ctf-pwn-byte-offset-check-int-heap-overflow-stdin-fsop
title: 单字节 offset 校验 vs int 类型：负数/大偏移绕过 add 边界，libc 堆溢出 + stdin FSOP 栈迁移
type: scenario
domain: ctf
path: ctf/pwn
technique: byte-offset-check-int-heap-overflow-fsop
tags:
- pwn
- heap-overflow
- offset-check
- fsop
- stdin
- stack-pivot
- glibc
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:55:58+08:00'
  notes: 已对照原文核对：offset 只比较低字节、写入长度截成 unsigned __int16、libc 堆 show 泄露、stdin FSOP 与 push [rcx];pop rsp gadget 均一致；修正 PoC 为原文 -0x3200（对应 pdata = stdio + 0x31c0，落点 stdio - 0x40，前 0x40 字节 shellcode 后接 fake_io），原 0x120 与 pdata 距离不符；未在本机复跑。
url: /docs/ctf/pwn/ctf-pwn-byte-offset-check-int-heap-overflow-stdin-fsop/
draft: false
kb_aliases:
- offset 单字节比较
- int 类型堆溢出
- libc 堆 show 泄露
- stdin FSOP 栈迁移
- compress
- push [rcx] pop rsp gadget
---

## 一句话结论

菜单堆题的 add 接口把 `int offset` 截成单字节与 `0x20` 比较，攻击者用 `-0x3200`、`0x120` 等低字节能通过检查的偏移越界写堆；堆块恰好靠近 libc，show 可直接泄露 libc 地址，随后伪造 `_IO_2_1_stdin_` 的 FILE/vtable，借 `push qword ptr [rcx]; ...; pop rsp; ret` gadget 把栈迁到 stdin 缓冲区，执行 mprotect+shellcode/ORW。

## 原理

- **校验类型收窄**：`if ((unsigned __int8)offset <= 0x20)` 只检查低 8 位，`offset` 本身是 int；`0x120` 的低字节是 0x20，`-0x3200` 的低字节是 0x00，均能通过。实际写入地址是 `pdata + offset`，于是可写到分配块之外；写入长度还会被截成 `unsigned __int16`。
- **libc 堆布局**：程序的大块 `malloc` 由 mmap/brk 分配，地址与 libc 接近；show 功能直接输出堆内容，泄露 libc 指针，省去常规 unsorted bin 泄露。
- **FSOP 目标**：glibc 2.39 的 `_IO_2_1_stdin_` 结构可被伪造；把 `_IO_read_ptr/_IO_read_end`、`_wide_data`、vtable 等字段布置成攻击者控制的值，使下一次 stdio 操作进入 `_IO_wfile_overflow`/`_IO_wdoallocbuf` 等路径。
- **栈迁移 gadget**：`push qword ptr [rcx]; rcr byte ptr [rbx+0x5d],0x41; pop rsp; ret` 把 `rcx` 指向的值压栈，再用 `pop rsp` 把栈指针切到该值；`rcx` 由 FILE 结构/寄存器控制，指向 stdin 缓冲区中的 ROP 链。
- **mprotect + shellcode/ORW**：迁移后先 `mprotect` 把某页改为 RWX，再跳到 shellcode；沙箱只允许 open/read/write 时用 ORW 读取 flag。
- **前提**：offset 检查确实只取低字节；堆可越界写并覆盖到 FILE 结构；libc 版本/偏移已知；存在可用的 `pop rsp`/FSOP gadget。

## 触发条件

- 菜单堆题存在 `add(offset, content)`，offset 为 int 但只做 byte 级比较。
- 堆块地址与 libc 接近或可通过 show 泄露 libc。
- 程序使用 stdio（stdin/stdout）且 glibc 版本可 FSOP。
- 沙箱允许 mprotect 或 open/read/write；目标有可写可执行页或 RWX 映射。
- 能控制 FILE 结构字段并触发一次 stdio 操作（如 `scanf`/`puts`/`exit`）。

## 利用步骤

1. 用 show 泄露 libc 地址，计算 libc 基址与 `_IO_2_1_stdin_`、gadget、`mprotect`、`system` 偏移。
2. 计算越界 offset：让 `(unsigned __int8)offset <= 0x20`，实际指向目标 FILE 结构或堆上伪造区域；原文用 `offset = -0x3200`（低字节 0x00），对应 `pdata = stdio + 0x31c0`，写入落点为 `stdio - 0x40`：前 0x40 字节 shellcode，随后 fake_io 覆盖 `stdio`。偏移要按 show 泄露的 pdata 与 stdio 距离选择，不能照搬。
3. 在 stdin 缓冲区布置 ROP 链/伪造 FILE 结构：`_flags`、`_IO_read_ptr`、`_IO_read_end`、`_wide_data`、vtable 指针等按 FSOP 要求填写。
4. 用 add/edit 把伪造结构写到目标地址，覆盖 `_IO_2_1_stdin_` 或相关指针。
5. 触发 stdio 操作，进入 `_IO_wfile_overflow`/`_IO_wdoallocbuf` 路径，执行 `push [rcx]; ...; pop rsp; ret`，栈迁到 stdin 缓冲区。
6. 执行 mprotect(0x404000,0x1000,7) 后跳到 shellcode，或直接 ORW 读 flag。

## PoC

关键 payload 骨架（偏移/地址按目标 libc 调整）：

```python
libc_base = leaked - 0x292e50
stdio = libc_base + 0x292200
gadget = libc_base + 0x43e6a   # push qword ptr [rcx]; rcr byte ptr [rbx+0x5d],0x41; pop rsp; ret
target = libc_base + 0x193ce   # mov rcx, rdi; ...; jmp ...

fake_io = flat({
    0x00: p64(stdio + 0xa0),
    0x20: p64(libc_base),
    0x28: p64(libc_base),
    0x38: p64(0),
    0x40: p64(gadget),
    0x48: p64(target),
}, filler=b"\x00").ljust(0xa0, b"\x00")

payload  = p64(pop_rdi) + p64(stdio & ~0xfff)
payload += p64(add_rsp_0x18) + p64(0)*3
payload += p64(pop_rsi) + p64(0x4000)
payload += p64(pop_rdx) + p64(7)
payload += p64(mprotect)
payload += p64(stdio - 0x40)

edit(-0x3200, shellcode.ljust(0x40, b"a") + fake_io + payload)  # pdata = stdio + 0x31c0，落点 stdio - 0x40
```

## 变体与关联

- 变体：offset 用 `int8_t`/`uint8_t` 截断、`offset % 0x100`、`offset & 0xff` 等不同写法；负数偏移可向低地址越界。
- 变体：FSOP 目标换成 stdout/stderr、`_IO_list_all`、`__exit_funcs`、TLS/atexit；glibc 2.39 需注意 vtable 校验与 `_wide_data` 布局。
- 变体：若无 FSOP 条件，可直接用堆溢出改 GOT/函数指针/栈返回地址。
- 关联：[[binary-pwn-heap-stdout-partial-overwrite-libc-leak]]（stdout 部分覆写泄露）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（stderr FSOP）、[[ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system]]（负数索引堆溢出的另一种写法）。

## 检测与防御

- 防御：offset 必须按完整 int/ssize_t 做上下界检查，不能只比较低字节；add/edit 前校验目标在分配块内。
- 防御：开启 Full RELRO、PIE、Canary、safe-linking；使用 glibc 的 vtable 校验/`_IO_vtable_check`；限制堆与 libc 的可预测布局。
- 检测：监控异常的 add offset（负数、>0x100 的偏移）、堆块头被改写、stdio 结构/vtable 被覆盖。
- 响应：隔离服务，审计堆操作与崩溃日志，修复 offset 校验，升级 glibc。
