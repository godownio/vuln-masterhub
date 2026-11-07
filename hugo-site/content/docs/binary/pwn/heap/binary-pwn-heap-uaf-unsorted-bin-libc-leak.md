---
id: binary-pwn-heap-uaf-unsorted-bin-libc-leak
title: UAF 悬空指针配合 unsorted bin 泄露 libc 基址
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-uaf-unsorted-bin-libc-leak
tags:
- pwn
- heap
- glibc
- uaf
- unsorted-bin
- libc-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-E
  verified_at: '2026-11-04T19:15:57+08:00'
  notes: 已对照原文核对：UAF 悬空指针、0x500 进 unsorted bin、fd/bk=main_arena+0x60（2.35-0ubuntu3.8 为 libc+0x21ace0）与图 04 一致；PoC 未在本机执行，偏移仅适用于文中 libc。
url: /docs/binary/pwn/heap/binary-pwn-heap-uaf-unsorted-bin-libc-leak/
draft: false
kb_aliases:
- unsorted bin 泄露
- libc 基址泄露
- 悬空指针
- UAF 读
- main_arena 泄露
---

## 一句话结论

`free` 后不置空指针形成的 UAF，如果还能 `show` 读回 chunk 内容，把一块大于 tcache 上限的 chunk free 进 unsorted bin，其 `fd`/`bk` 会指向 `main_arena` 内的 unsorted bin 头，读一次即可算出 libc 基址。

## 原理

- `delete_note` 只执行 `free(notes[idx].content)`，没有把 `notes[idx].content` 置 NULL；`show_note` 仍然 `write(1, content, size)`。于是已释放 chunk 的元数据可被读回。
- glibc 的 tcache 默认覆盖到 0x410 的 chunk size（请求约 ≤0x408）。更大的 chunk 释放后不进 tcache，而进入 unsorted bin。
- unsorted bin 为空时，首个进入的 chunk 的 `fd` 和 `bk` 都指向 `main_arena + 0x60`（unsorted bin 链表头）。`main_arena` 位于 libc 数据段，因此该指针减去固定偏移即得 libc 基址。
- 前提是该 chunk 释放时不能与 top chunk 合并：释放前需要在它后面保留已分配的 guard chunk，否则会并入 top，`fd`/`bk` 不再是 arena 指针。

## 触发条件

- 存在 UAF：对象释放后指针仍可被读接口使用；
- 读接口按原 size 输出，能读到 chunk 头部 8 字节；
- 能申请超过 tcache 上限（chunk size > 0x410，如请求 0x500）的 chunk；
- 目标 chunk 释放时不是 top 的相邻前块，或其后方有 guard 分配阻止合并；
- 已知目标 libc 版本的 `main_arena+0x60` 偏移（或能通过符号/调试确定）。

## 利用步骤

1. 申请一个大 chunk（如请求 0x500）作为 idx0，并在其后申请至少一个 guard chunk，避免 idx0 与 top 合并。
2. `delete(0)` 后通过 `show(0)` 读取前 8 字节；此时内容应为 `0x7f...` 的 libc 指针。
3. 用 `leak - (main_arena + 0x60 的 libc 偏移)` 计算基址；检查结果低 12 位为 0。
4. 若结果不对齐，可能读到了 `bk`、读偏 8 字节，或目标 libc 偏移不同；用 libc 符号表/调试器确认 `main_arena` 偏移。
5. 后续用 libc 基址解析 `system`、`/bin/sh`、`_IO_2_1_stderr_`、`_IO_wfile_jumps` 等符号，进入 tcache 毒化或 FSOP。

## PoC

```python
# 菜单题伪代码，add(idx, size, data) / delete(idx) / show(idx)
add(0, 0x500, b'A' * 0x500)      # 大于 tcache 上限
add(1, 0x20, b'guard')           # 防止 chunk0 与 top 合并
delete(0)

leak = u64(show(0)[:8])          # chunk0->fd
libc_base = leak - 0x21ace0      # glibc 2.35-0ubuntu3.8: main_arena+0x60
assert libc_base & 0xfff == 0, hex(leak)
```

```text
# gdb 现场判读
chunk0->fd == chunk0->bk == main_arena + 0x60 == libc + 0x21ace0
libc base = 0x7f...1ace0 - 0x21ace0
```

## 变体与关联

- 变体：large bin 泄露、tcache/fastbin 泄露堆地址、stdout `_IO_2_1_stdout_` 泄露 libc、通过未初始化栈/格式化字符串泄露 libc。
- 关联：[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（拿到 libc 后再恢复堆地址）；[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（把 libc 泄露转化为 FSOP 代码执行）。
- 版本差异：tcache 上限、`main_arena` 偏移随 glibc 版本变化；示例偏移只适用于文中 2.35-0ubuntu3.8，其他版本须重新确认。

## 检测与防御

- 防御：释放后立即把指针置 NULL；对象与长度一起失效；使用带边界和生命周期检查的容器；开启 ASLR 之外再叠加堆保护（safe-linking、tcache key 等只能提高门槛）。
- 检测：对同一对象连续 free/show/edit 的异常调用序列；堆题/服务中出现 use-after-free 的崩溃堆栈；对高版本 glibc 的堆元数据完整性校验。
