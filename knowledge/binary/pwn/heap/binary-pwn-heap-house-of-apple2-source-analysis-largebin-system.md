---
id: binary-pwn-heap-house-of-apple2-source-analysis-largebin-system
title: House of Apple2 源码级复现：largebin attack 改 _IO_list_all + _IO_wfile_overflow/_IO_wdoallocbuf 劫持 _wide_vtable
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-apple2-largebin-io-list-all-wide-vtable
aliases:
- house of apple2
- HoA2
- _IO_list_all
- _IO_wfile_overflow
- _IO_wdoallocbuf
- _wide_vtable
- largebin attack
- glibc 2.35
tags:
- pwn
- heap
- fsop
- house-of-apple2
- io-file
- wide-data
- largebin
- glibc235
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:24:41+08:00'
  notes: 已对照原文核对：_IO_FILE_plus/_wide_data 偏移、IO_validate_vtable、_IO_wfile_overflow->_IO_wdoallocbuf->_wide_vtable+0x68、largebin bk_nextsize=_IO_list_all-0x20、fake_io 模板与 2.35/2.39 rdx 差异均一致；未在本机复跑
---

## 一句话结论

在 glibc 2.35 的堆题中，先用 largebin attack 把 `_IO_list_all` 改成可控堆地址，在该堆块伪造 `_IO_FILE_plus`：主 vtable 指向合法的 `_IO_wfile_jumps` 绕过 `IO_validate_vtable`，`_wide_data` 指向伪造的 `_IO_wide_data`，其 `_wide_vtable` 指向堆上的假跳表；程序 `exit()` 时经 `_IO_flush_all_lockp → _IO_wfile_overflow → _IO_wdoallocbuf → _wide_vtable+0x68` 调用 `system(fp)` 拿 shell。

## 原理

- **主 vtable 校验**：glibc 2.24 起 `IO_validate_vtable` 要求主 `vtable` 落在 `__libc_IO_vtables` 段内，直接伪造主 vtable 不可行；但 `_wide_data->_wide_vtable` 没有同样的校验，是 House of Apple2 的突破口。
- **结构布局**：`_IO_FILE_plus` 的 `file` 大小 0xd8，`vtable` 在 +0xd8；`_IO_FILE_complete` 的 `_wide_data` 在 +0xa0、`_mode` 在 +0xc0；`_IO_wide_data` 的 `_wide_vtable` 在 +0xe0，`__doallocate` 槽在 `_wide_vtable+0x68`。
- **触发链**：`exit()` → `_IO_cleanup` → `_IO_flush_all_lockp` 遍历 `_IO_list_all`；对每个 FILE 判断 `_mode <= 0 && _IO_write_ptr > _IO_write_base` 等条件，满足则 `_IO_OVERFLOW(fp, EOF)`；主 vtable 为 `_IO_wfile_jumps` 时进入 `_IO_wfile_overflow`。
- **进入 wdoallocbuf**：`_IO_wfile_overflow` 在 `f->_flags & _IO_CURRENTLY_PUTTING == 0` 且 `f->_wide_data->_IO_write_base == 0` 时调用 `_IO_wdoallocbuf(f)`；`_IO_wdoallocbuf` 在 `_wide_data->_IO_buf_base == 0` 且 `_flags & _IO_UNBUFFERED == 0` 时执行 `(wint_t)_IO_WDOALLOCATE(f)`，即 `*(_wide_vtable+0x68)(f)`。
- **伪造条件**：`_wide_data` 指向可控堆地址 A；`*(A+0x18)=0`（`_IO_write_base`）、`*(A+0x30)=0`（`_IO_buf_base`）、`*(A+0xe0)=B`（`_wide_vtable`）、`*(B+0x68)=C`（system 或 magic gadget）；主 vtable = `_IO_wfile_jumps`；`_mode` 为非正数/宽字符路径正确。
- **largebin attack**：把一个 largebin chunk 的 `bk_nextsize` 设为 `_IO_list_all-0x20`，插入时 `victim->bk_nextsize->fd_nextsize = victim`（`fd_nextsize` 在 chunk+0x20）把 `_IO_list_all` 写成 victim 地址，victim 指向伪造 FILE 的堆块。
- **2.35 与 2.39 差异**：2.35 可通过 `_IO_wfile_overflow`/`_wide_vtable` 控制 `rdx`，直接接 `setcontext+61`/ORW；2.39 不再能控制 `rdx`，需要改用 `svcudp_reply` 控制 `r12`、`swapcontext` 控制 `rsp` 等 magic gadget 组合。

## 触发条件

- glibc 2.35（或相近版本），`_IO_FILE`/`_IO_wide_data` 偏移与目标 libc 匹配。
- 存在堆 UAF/任意分配或 largebin attack 条件，能把 `_IO_list_all` 改为可控堆地址。
- 已知 libc/heap 基址，能构造 fake FILE、fake `_IO_wide_data`、fake `_wide_vtable`。
- 程序最终 `exit()`/main 返回触发 `_IO_flush_all_lockp`；`system`/magic gadget 可用。
- `_mode`、`_flags`、`_IO_write_ptr/_base` 等字段满足 `_IO_flush_all_lockp` 与 `_IO_wfile_overflow` 的分支条件。

## 利用步骤

1. 泄露 libc/heap，解析 `_IO_list_all`、`_IO_wfile_jumps`、`system`、`_IO_stdfile_2_lock` 等偏移。
2. 用 largebin attack 把 `_IO_list_all` 写成 victim 堆块地址（`bk_nextsize = _IO_list_all-0x20`）。
3. 在 victim 堆块伪造 `_IO_FILE_plus`：`_flags` 满足刷新条件，`_mode` 置非正，`_IO_write_base=0`、`_IO_write_ptr=1`，`vtable=_IO_wfile_jumps`，`_wide_data=可控堆 A`。
4. 在 A 伪造 `_IO_wide_data`：`_IO_write_base=0`、`_IO_buf_base=0`、`_wide_vtable=可控堆 B`。
5. 在 B+0x68 写 `system`（或 magic gadget），并把 `fp` 指向的命令串放在 `_flags`/已知地址。
6. `exit()` 触发链，执行 `system(fp)` 或栈迁移到 ORW；若 2.39 需改用 `svcudp_reply`/`swapcontext` 组合。

## PoC

```python
fake_io  = p64(0)              # _IO_read_end
fake_io += p64(0)              # _IO_read_base
fake_io += p64(0)              # _IO_write_base
fake_io += p64(1)              # _IO_write_ptr
fake_io += p64(0)              # _IO_write_end
fake_io += p64(0)              # _IO_buf_base
fake_io += p64(0)              # _IO_buf_end
fake_io += p64(0) * 4
fake_io += p64(0)              # _chain
fake_io += p32(2) + p32(0)     # _fileno/_flags2
fake_io += p64(-1)             # _old_offset
fake_io += p16(0) + b"\x00" + b"\n" + p32(0)
fake_io += p64(IO_stdfile_2_lock)
fake_io += p64(-1)             # _offset
fake_io += p64(0)              # _codecvt
fake_io += p64(IO_wide_data_addr)
fake_io += p64(0) * 3
fake_io += p32(0xFFFFFFFF)     # _mode
fake_io += b"\x00" * 19
fake_io = fake_io.ljust(0xc8, b"\x00")
fake_io += p64(lib + libc.sym["_IO_wfile_jumps"])  # 0xd8
fake_io += p64(wide_vtable_addr)                   # 0xe0
fake_io += p64(system)
```

largebin attack 关键：`bk_nextsize = _IO_list_all - 0x20`；原文在 glibc 2.35 验证 `system` 路径，并给出 2.39 的 `svcudp_reply`/`swapcontext` 适配思路；PoC 未在本机复跑。

## 变体与关联

- 覆盖目标变体：`_IO_2_1_stderr_` 直接覆盖（tcache poisoning）、largebin 改 `_IO_list_all` 指向堆块、chunk header partial 覆盖。
- 调用变体：`system` 直接执行命令串、`setcontext+61` 栈迁移 ORW、`svcudp_reply+26`/`swapcontext`（2.39）。
- 关联：[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（stderr 覆盖版）、[[binary-pwn-heap-house-of-apple2-chunk-header-svcudp-reply-xdr-ops-orw]]（chunk header + svcudp_reply ORW）、[[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]（largebin + wide file + setcontext ORW）。
- 边界：Full RELRO/PIE 不影响 FSOP；但 glibc 版本偏移不匹配、`_IO_list_all` 写入失败、`_mode`/flags 分支不满足、2.39 的 rdx 限制未适配时会失败。

## 检测与防御

- 检测：堆题中出现 largebin attack 改 `_IO_list_all`、伪造 `_IO_FILE_plus`/`_IO_wide_data`、vtable 指向堆；程序退出时异常调用 `system`/栈迁移。
- 防御：开启 Full RELRO/PIE、glibc 更新（2.35+ 对 FSOP 有缓解）、堆隔离/CFI；生产程序避免 `exit()` 遍历不可信 FILE 链。
- 加固：使用最新 glibc、开启 `_IO_validate_vtable` 相关缓解；监控异常 `_IO_list_all` 写与堆布局。
