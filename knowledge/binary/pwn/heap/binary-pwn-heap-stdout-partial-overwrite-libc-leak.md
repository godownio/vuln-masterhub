---
id: binary-pwn-heap-stdout-partial-overwrite-libc-leak
title: stdout 部分覆写泄露 libc：改 _flags 与 _IO_write_base 低字节扩大输出窗口
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-stdout-file-partial-overwrite-libc-leak
aliases:
- stdout 泄露
- _IO_2_1_stdout_ 打 libc
- _IO_write_base 部分覆写
- 4222425088
- FILE 结构泄露
- 无 show 泄露 libc
tags:
- pwn
- heap
- libc-leak
- stdout
- file-structure
- io-write-base
- glibc-2.31
- fsop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:45:33+08:00'
  notes: 已对照原文及15张图核对：_IO_FILE 偏移(_flags+0x00、read_ptr+0x08、read_end+0x10、read_base+0x18、write_base+0x20、write_ptr+0x28)、0xfbad1800+三个清零指针+1字节低字节覆写的0x21字节payload、_IO_new_file_overflow→_IO_do_write→_IO_SYSWRITE 输出[write_base,write_ptr)窗口、减0x1ec980(_IO_2_1_stdin_)得libc基址均与图11-13及原文一致。未验证点：EXP未本机复跑；泄露符号依目标libc版本可能不同；CTF题无组件受影响版本；frontmatter无sources/source_url。
---

## 一句话结论

在没有 `show` 的堆题里，可以把 tcache/任意分配投毒到 `_IO_2_1_stdout_`，只覆写 `_IO_FILE` 头部的 `_flags`（设为 0xfbad1800）、三个读指针（清零）和 `_IO_write_base` 的最低字节；由于高位仍保留原 libc 前缀，`_IO_write_base` 被向前移动，`_IO_write_ptr - _IO_write_base` 形成一个覆盖 libc 内存的输出窗口，之后任意一次 stdout flush（如菜单 `puts`）就会把这段 libc 数据打印出来，从而泄露 libc 基址。

## 原理

- **`_IO_FILE` 关键字段偏移（x86_64）**：`+0x00 _flags`、`+0x08 _IO_read_ptr`、`+0x10 _IO_read_end`、`+0x18 _IO_read_base`、`+0x20 _IO_write_base`、`+0x28 _IO_write_ptr`、`+0x30 _IO_write_end`。stdout 泄露不需要伪造完整 FILE，只改头部这些字段即可。
- **payload 的含义**：`p64(0xfbad1800) + p64(0)*3 + b'\x00'` 依次设置 `_flags = 0xfbad1800`，`_IO_read_ptr/_read_end/_read_base = 0`，最后一个 `b'\x00'` 覆写 `_IO_write_base` 的最低字节。
- **为什么只改最低字节**：`_IO_write_base` 原本指向 libc 内某处（如 stdout 缓冲区），只改最低字节会让它仍在同一页/libc 内，但向前移动若干字节；`_IO_write_ptr` 保持原来的 libc 内部旧值，于是 `_IO_write_ptr > _IO_write_base`，两者之间形成一个可输出的内存窗口。若整个清零/改成任意地址，反而可能越界或破坏 flush 逻辑。
- **glibc 如何输出**：`_IO_new_file_overflow` 在需要写出时调用 `_IO_do_write(f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)`；`_IO_new_do_write`/`new_do_write` 最终 `_IO_SYSWRITE(fd, data, to_do)` 把 `[write_base, write_ptr)` 区间写到文件描述符。因此起始地址是 `_IO_write_base`、长度是 `write_ptr - write_base`。
- **触发时机**：本题没有 show，但后续菜单提示、`puts("Choice: ")`、状态输出等都会触发 stdout flush，等于 glibc 替攻击者“show”了这段内存。
- **泄露内容不一定是 stdout 自身**：窗口里可能包含 `_IO_2_1_stdin_`、vtable 指针、其他 FILE 关联指针等 libc 内部指针。脚本常见 `libc.address = leak - 0x1ec980`，减的是 `_IO_2_1_stdin_` 偏移，因为抓到的是窗口中某个稳定符号，而不是 `_IO_2_1_stdout_` 的地址本身。
- **前提**：能向 stdout 结构体写入（tcache poisoning/任意分配），且知道 `_IO_2_1_stdout_` 地址或能通过堆布局定位；glibc 2.31 的 FILE vtable 检查较松，部分覆写头部即可。高版本有 vtable 校验/`_IO_validate` 等限制，需要调整。

## 触发条件

- 堆题无 `show`/读接口，但存在任意分配或 tcache poisoning，可把一次 `malloc` 返回到 `_IO_2_1_stdout_` 附近。
- 目标为 glibc 2.31 或类似版本，`_IO_2_1_stdout_` 可写且 vtable 校验不严格。
- 程序后续会调用 `puts`/`printf`/菜单输出等触发 stdout flush。
- 已知 libc 版本（用于确定 `_IO_2_1_stdin_`/stdout 偏移）或能识别泄露指针属于哪个符号。
- 覆写长度足够覆盖到 `_IO_write_base`（至少 0x21 字节），且不会破坏后续必需字段。

## 利用步骤

1. 通过 tcache poisoning 或任意分配，让某个 chunk 返回到 `_IO_2_1_stdout_`（或 `_IO_2_1_stdout_ - 0x20` 等可控偏移，视分配对齐与字段布局）。
2. 构造 payload：`p64(0xfbad1800) + p64(0)*3 + b'\x00'`，即改 `_flags`、清三个读指针、只改 `_IO_write_base` 最低字节。
3. 发送 payload 写入 stdout 结构体。
4. 触发一次菜单输出/`puts`/`printf`，使 stdout flush；读取输出中多出来的 libc 指针（通常以 `\x7f` 结尾）。
5. 用泄露值减去对应符号偏移（示例 `_IO_2_1_stdin_` 偏移 0x1ec980）得到 libc 基址；校验低 12 位为 0。
6. 用 libc 基址解析 `__free_hook`、`system`、`setcontext`、`/bin/sh` 等，进入后续控制流劫持（见关联卡）。

## PoC

原文 EXP 的泄露段（glibc 2.31，未在本机执行）：

```python
pay = p64(0xfbad1800)
pay += p64(0) * 3
pay += b'\x00'          # 只改 _IO_write_base 最低字节
lib = leak_stdout(0, pay) - 0x1ec980
log.success(f'libc base = {lib:#x}')
```

```python
def leak_stdout(index, payload):
    edit(index, payload)
    data = io.recvuntil(b'\x7f')
    return u64(data[-6:].ljust(8, b'\x00'))
```

原文说明：泄露窗口里抓到的往往是 `_IO_2_1_stdin_` 或 vtable 等稳定 libc 指针，所以减 `0x1ec980`（`_IO_2_1_stdin_` 偏移）而不是 stdout 自身偏移。

## 变体与关联

- **有 show 的题**：直接读堆/任意地址，不需要 stdout 技巧。
- **高版本 glibc**：FILE vtable 校验、`_IO_2_1_stdout_` 只读/加固、largebin/FSOP 路径不同；需改用 House of Apple、`_IO_wfile_jumps` 等。
- **其他 FILE**：stderr/stdin、`_IO_list_all`、`_IO_2_1_stdout_->vtable` 也可作为泄露或 FSOP 入口。
- **关联**：投毒来源见 [[binary-pwn-heap-house-of-botcake-tcache-poison]]；泄露后控制流劫持见 [[binary-pwn-heap-freehook-setcontext61-bridge-orw]]；FSOP 变体见 [[binary-pwn-heap-house-of-apple-2-stderr-fsop]] 与 [[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]。
- **防御/检测**：修复任意写/堆漏洞是根本；高版本启用 FILE vtable 校验与 FORTIFY；监控 stdout 结构体被异常写入与输出中出现 libc 指针。

## 检测与防御

- **内存完整性**：检查 `_IO_2_1_stdout_` 的 `_flags/_write_base/_write_ptr` 是否被改成异常值（如 0xfbad1800、write_base 低字节被改）。
- **行为检测**：程序输出中出现大量非预期二进制/libc 指针；同一进程在菜单输出前发生对 stdout 结构体的写操作。
- **防御**：使用高版本 glibc 的 FILE 加固与 vtable 校验；启用 ASLR、堆保护；修复 UAF/任意分配漏洞。
- **取证**：捕获输出中的 libc 指针与 stdout 结构体内容，可判断是否使用了部分覆写泄露；结合堆布局与 tcache 链表分析投毒路径。
