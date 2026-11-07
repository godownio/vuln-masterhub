---
id: binary-pwn-heap-fsop-house-of-some-arbitrary-read-write
title: 高版本 glibc FSOP 任意地址读写：fake IO_FILE 读链 + House of Some 经 _wide_vtable=_IO_file_jumps-0x48 走到 _IO_SYSREAD 写
type: scenario
domain: binary
path: binary/pwn/heap
technique: fsop-house-of-some-arbitrary-read-write
aliases:
- House of Some
- FSOP 任意地址读写
- IO_FILE 任意读
- IO_FILE 任意写
- _wide_vtable 劫持
- _IO_wfile_overflow
- _IO_new_file_underflow
- _IO_SYSREAD 任意写
- _IO_flush_all
- 高版本 glibc FSOP
tags:
- pwn
- glibc
- io-file
- fsop
- house-of-some
- arbitrary-read
- arbitrary-write
- heap
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T22:48:11+08:00'
  notes: 已对照原文全文核对：fake FILE 0x00/0x20/0x28/0x68/0x70/0x88/0xd8 偏移与原文 flat 模板一致；写模板 0x38/0x40/0xa0/0xc0 与 fake_wide_data 0x18/0x20/0xe0 一致；_wide_vtable=_IO_file_jumps-0x48→+0x68 落 __underflow→_IO_SYSREAD 链与原文总结一致。原文仅称高版本glibc、无具体版本号，故未设 affected_versions；未执行完整利用。
---

## 一句话结论

高版本 glibc 的 FSOP 不必直接劫持主 vtable 到 system：伪造 `_IO_FILE` 时把 `_flags` 置为 `_IO_CURRENTLY_PUTTING|_IO_IS_APPENDING`、`_IO_write_base`/`_IO_write_ptr` 指向目标区间，`_IO_flush_all` 走 `_IO_OVERFLOW→_IO_new_file_overflow→_IO_do_write` 即可把该区间写到 `_fileno` 实现任意地址读；任意写则把主 vtable 换成合法的 `_IO_wfile_jumps`，伪造 `_wide_data` 使 `_wide_vtable = _IO_file_jumps - 0x48`，让 `_IO_WDOALLOCATE` 的 `__doallocate` 槽落到 `_IO_new_file_underflow`，其 `_IO_SYSREAD` 会把攻击者输入写入 `_IO_buf_base`，形成 House of Some 任意地址写。

## 原理

- **FSOP 的入口**：`exit`/`main` 返回会调用 `_IO_flush_all`，它遍历 `_IO_list_all` 链表：
  ```c
  for (fp = _IO_list_all; fp != NULL; fp = fp->_chain) {
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
        || (_IO_vtable_offset(fp) == 0 && fp->_mode > 0
            && fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base))
        && _IO_OVERFLOW(fp, EOF) == EOF)
          result = EOF;
  }
  ```
  只要 `_IO_list_all` 指向攻击者可控的 fake `_IO_FILE_plus`，就能控制 `vtable->__overflow` 的调用目标。
- **任意地址读（普通 FILE 路径）**：把 fake FILE 的 `_flags` 设为 `_IO_CURRENTLY_PUTTING(0x800) | _IO_IS_APPENDING(0x1000)`，`_IO_write_base = 起始地址`、`_IO_write_ptr = 结束地址`、`_fileno = 1`（stdout）、`_lock` 填有效锁、`vtable = _IO_file_jumps`，`_mode` 保持 0。`_IO_OVERFLOW` 调用 `_IO_new_file_overflow`，由于 `_IO_CURRENTLY_PUTTING` 已置位，它进入 `_IO_do_write`，把 `[write_base, write_ptr)` 的字节写到 fd 1，即把目标内存泄露到标准输出。
- **为什么 `_flags` 要这样设**：`_IO_new_file_overflow` 会检查 `_IO_CURRENTLY_PUTTING`；未置位时它会尝试分配/调整缓冲区，不会直接输出用户指定的区间。`_IO_IS_APPENDING` 让 `_IO_do_write` 走追加路径，避免 seek/offset 逻辑干扰。
- **任意地址写（House of Some）**：主 vtable 必须换成合法范围内的 `_IO_wfile_jumps`（绕过 `IO_validate_vtable` 的 `__libc_IO_vtables` 检查），这样 `_IO_OVERFLOW` 变成 `_IO_wfile_overflow`；后者在 `_wide_data->_IO_write_base == 0` 或未置 `_IO_CURRENTLY_PUTTING` 时调用 `_IO_wdoallocbuf`。`_IO_wdoallocbuf` 通过 `_IO_WDOALLOCATE` 宏从 `_wide_data->_wide_vtable` 取 `__doallocate`（`_IO_jump_t` 偏移 0x68）调用。
- **把 `__doallocate` 偏移挪到 underflow**：把 `_wide_vtable` 设为 `_IO_file_jumps - 0x48`，则 `_wide_vtable + 0x68 = _IO_file_jumps + 0x20`，正好是 `_IO_jump_t` 的 `__underflow` 槽，即 `_IO_new_file_underflow`。这一步是整个 House of Some 的关键：合法 vtable 段内的错位让 `doallocate` 调用落到 `underflow`。
- **`_IO_new_file_underflow` 的写原语**：该函数在处理读缓冲时把 `_IO_read_base/_IO_read_ptr/_IO_read_end` 与 `_IO_write_base/_IO_write_ptr/_IO_write_end` 都设为 `_IO_buf_base`，然后调用：
  ```c
  count = _IO_SYSREAD(fp, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base);
  ```
  `_IO_SYSREAD` 即 `_IO_file_read`，最终 `read(fp->_fileno, buf, count)`。把 `_fileno` 设为 0（stdin）、`_IO_buf_base` 设为写入目标、`_IO_buf_end` 设为目标+长度，FSOP 触发时从标准输入读取攻击者数据，直接写到任意地址。
- **绕过 `_IO_flush_all` 的分支条件**：由于 `_IO_new_file_underflow` 内部的 `_IO_switch_to_get_mode` 会在 `write_ptr > write_base` 时再次调用 `_IO_OVERFLOW`，不能走普通 FILE 的第一分支；要把 fake FILE 的 `_mode` 设为 2（>0），并伪造 `_wide_data->_IO_write_ptr(0xff) > _wide_data->_IO_write_base(0)`，从而命中 `_IO_flush_all` 的 wide 分支，进入 `_IO_wfile_overflow`。
- **必要的字段**：`_lock` 不能为 0，`_IO_flush_all` 会调用 `_IO_flockfile(fp)`；`_chain` 可为 0 结束遍历（或指向下一个 fake FILE）；`_fileno=0`；`_wide_data` 指向可控的 fake `_IO_wide_data`；`_mode=2`；vtable=`_IO_wfile_jumps`。
- **stdin 低位覆盖变体**：数据从 stdin 读入时先存到 `_IO_buf_base`，数据量大时再 malloc。若把 `stdin->_IO_buf_base` 的最低字节覆盖为 `\x00`，它会落到同一 FILE 结构内的 `_IO_write_base` 附近，使后续输入覆盖到 `_IO_buf_base`/`_IO_buf_end` 自身；改完这两个字段即可再次获得任意地址写。该路径需要 `fgets` 等触发 stdin 刷新的函数。

## 触发条件

- 目标为 64 位 Linux glibc（高版本，具备 `_IO_wfile_jumps`/`_wide_data` 布局），程序存在可写 fake `_IO_FILE` 的内存区域（堆、BSS 或可控缓冲区）。
- 攻击者能控制 `_IO_list_all`（通过 tcache/largebin/unsorted bin 攻击、任意写或程序自身的写原语），使其指向 fake FILE。
- 程序退出/调用 `_IO_flush_all` 时能走到该链表；写原语还要求此时 fd 0 有攻击者可控输入。
- 需要知道 libc 基址（`_IO_file_jumps`、`_IO_wfile_jumps`、`_IO_list_all` 偏移）与一个可用的 `_lock` 地址。
- 任意读不要求输入，只需要能触发 `_IO_flush_all` 并观察 stdout。

## 利用步骤

1. **泄露 libc/堆**：用题目原有的 UAF/堆溢出/格式化字符串等拿到 libc base 与可控堆地址；确认目标 glibc 版本的 `_IO_file_jumps`、`_IO_wfile_jumps`、`_IO_list_all` 偏移。
2. **准备 fake `_IO_wide_data`**：在可控内存写 `_IO_write_base=0`、`_IO_write_ptr=0xff`、`_wide_vtable=_IO_file_jumps-0x48`。
3. **准备 fake `_IO_FILE`**：`_flags=0`、`_IO_buf_base=写入目标`、`_IO_buf_end=目标+长度`、`_chain=0`、`_fileno=0`、`_lock=有效锁地址`、`_wide_data=fake_wide_data`、`_mode=2`、`vtable=_IO_wfile_jumps`。
4. **把 `_IO_list_all` 指向 fake FILE**：用堆攻击（如 tcache 投毒、largebin attack、unsorted bin attack）或已有的任意写完成。
5. **触发 FSOP**：让程序退出/调用 `_IO_flush_all`；`_IO_wfile_overflow→_IO_wdoallocbuf→_IO_WDOALLOCATE→_IO_new_file_underflow→_IO_SYSREAD` 会从 stdin 读取数据写到 `_IO_buf_base`。
6. **发送写入内容**：在触发前/触发时通过 stdin 发送目标数据（如 ROP 链、GOT 项、函数指针），FSOP 把它写到指定地址。
7. **任意读**：另建一个 fake FILE，`_flags=0x1800`、`_IO_write_base=泄露起点`、`_IO_write_ptr=泄露终点`、`_fileno=1`、`_lock=有效锁`、`vtable=_IO_file_jumps`、`_mode=0`，把 `_IO_list_all` 指向它并触发 `_IO_flush_all`，目标区间会从 stdout 输出。

## PoC

fake `_IO_FILE` 任意读模板（pwntools `flat`，偏移对应 64 位 `_IO_FILE_plus`）：

```python
fake_read = flat({
    0x00: 0x800 | 0x1000,  # _flags: _IO_CURRENTLY_PUTTING | _IO_IS_APPENDING
    0x20: leak_start,      # _IO_write_base
    0x28: leak_end,        # _IO_write_ptr
    0x68: 0,               # _chain
    0x70: 1,               # _fileno = stdout
    0x88: lock_addr,       # _lock
    0xd8: io_file_jumps,   # vtable
}, filler=b"\x00")
```

fake `_IO_FILE` + `_IO_wide_data` 任意写模板（House of Some）：

```python
fake_wide_data = flat({
    0x18: 0,                        # _IO_write_base
    0x20: 0xff,                     # _IO_write_ptr
    0xe0: io_file_jumps - 0x48,     # _wide_vtable → +0x68 = _IO_file_jumps+0x20
}, filler=b"\x00")

fake_write = flat({
    0x00: 0,                        # _flags
    0x38: write_target,             # _IO_buf_base
    0x40: write_target + 0x100,     # _IO_buf_end
    0x68: 0,                        # _chain
    0x70: 0,                        # _fileno = stdin
    0x88: lock_addr,                # _lock
    0xa0: wide_data_addr,           # _wide_data
    0xc0: 2,                        # _mode > 0，走 wide 分支
    0xd8: io_wfile_jumps,           # vtable
}, filler=b"\x00")
```

完整调用链：

```text
_IO_flush_all
  → _IO_OVERFLOW(fp)                     (fp->vtable = _IO_wfile_jumps)
  → _IO_wfile_overflow
  → _IO_wdoallocbuf
  → _IO_WDOALLOCATE                      (_wide_vtable = _IO_file_jumps-0x48)
  → _IO_new_file_underflow               (_wide_vtable+0x68 = _IO_file_jumps+0x20)
  → _IO_SYSREAD(fp, _IO_buf_base, _IO_buf_end - _IO_buf_base)
  → read(0, write_target, size)          (任意地址写)
```

文章给出了 fake FILE 模板与完整调用链，但未附完整利用脚本/题目二进制；上述模板按原文 `flat` 字段还原，未在本库执行。

## 变体与关联

- **stdin `_IO_buf_base` 低位覆盖**：把 `stdin->_IO_buf_base` 最低字节写成 `\x00`，使其指向自身 `_IO_write_base`，再用大量输入覆盖 `_IO_buf_base`/`_IO_buf_end`，配合 `fgets` 触发任意写；这是不需要伪造完整 FILE 的轻量变体。
- **vtable 合法化变体**：主 vtable 可用 `_IO_wfile_jumps`、`_IO_wstrn_jumps` 等 `__libc_IO_vtables` 段内地址；`_wide_vtable` 用 `_IO_file_jumps - 0x48` 或类似错位，把 `__doallocate` 映射到 `underflow`/其他可写函数。
- **House of Orange/Apple 变体**：同样通过伪造 FILE 触发 FSOP，但 `_IO_list_all` 的改写方式（unsorted bin attack、largebin attack、stderr 伪造）不同；本卡聚焦 `_IO_list_all` 已可控后的任意读写。
- **任意读替代**：可用 `_IO_write_base/_IO_write_ptr` 的普通 FILE 路径，也可用 `_IO_wfile_overflow` 的 wide 路径把数据写到 stdout；关键是 `_fileno` 与 `_flags` 的配合。
- **利用目标**：任意写可改 GOT、`__malloc_hook`/`__free_hook`（老版本）、`_IO_list_all` 自身、返回地址或 ROP 链；任意读可泄露 libc/stack/flag。
- 关联：[[binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile]]（以 House of Some 为最终阶段的完整堆题链）、[[binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system]]（unsorted bin 改 `_IO_list_all` + FSOP system）、[[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]（largebin attack 改 `_IO_list_all` + wide FILE + setcontext）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（stderr 伪造 FSOP）。

## 检测与防御

- **glibc 防护**：保持 glibc 更新，确保 `IO_validate_vtable`/_IO_vtable_check 生效；`_IO_wfile_jumps` 等合法 vtable 仍在白名单内，FSOP 无法仅靠 vtable 校验完全阻断，需结合其他缓解。
- **编译/运行缓解**：Full RELRO + PIE + `_FORTIFY_SOURCE` 提高泄露与 GOT 改写难度；`seccomp` 限制 `read`/`write`/`open` 等系统调用只能操作预期 fd；`glibc` 的 `_IO_cleanup` 行为可通过 `__libc_freeres` 等观察。
- **堆检测**：监控 `_IO_list_all` 指向非 `__libc_IO_vtables`/非合法 FILE 的写；检测 `_wide_vtable` 落在 `__libc_IO_vtables` 边界附近（如 `_IO_file_jumps-0x48`）的异常值；对 tcache/largebin/unsorted bin 的 fd/bk 异常写做堆完整性校验。
- **利用侧注意**：FSOP 触发点通常在 `exit`/`main` 返回，题目若在退出前清理/校验 FILE 链表会失效；写链要求 fd 0 可读，交互式题目需提前准备 stdin 数据；不同 glibc 版本的 `_IO_FILE`/`_IO_wide_data` 偏移可能变化，需按目标 libc 重新计算。
