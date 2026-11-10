---
id: binary-pwn-heap-house-of-cat-wfile-seekoff-wide-vtable-bypass-vtable-check
title: House of Cat：伪造 IO_FILE 借 _IO_wfile_seekoff → _IO_switch_to_wget_mode → _IO_WOVERFLOW 无 vtable 检查劫持 _wide_vtable，经 FSOP / __malloc_assert 触发并 setcontext 栈迁移 RCE
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-cat-wfile-seekoff-wide-vtable-hijack
aliases:
- House of Cat
- _IO_wfile_seekoff
- _IO_switch_to_wget_mode
- _IO_WOVERFLOW
- _wide_vtable 无 vtable 检查
- glibc 2.24 vtable check 绕过
- _IO_wfile_jumps+0x30 / +0x10
- setcontext+61 / +53 栈迁移
- FSOP exit
- __malloc_assert sysmalloc
tags:
- binary
- pwn
- heap
- glibc
- io-file
- fsop
- house-of-cat
- wide-vtable
- vtable-check-bypass
- setcontext
- stack-pivot
- malloc-assert
- orw
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:03:50+08:00'
  notes: 已对照原文与37张图核对：_IO_wfile_jumps 表项偏移0x48(图01)、_IO_WOVERFLOW 宏展开经_wide_data->wide_vtable(图03)、_wide_data偏移+0xa0/+0xe0与+0x18/0x20判断(图02/09/15)、FSOP路径_IO_wfile_jumps+0x30->+0x38且_IO_flush_all_lockp以_IO_wide_data_2.write_base装rcx得mode=1(图06/07/11/12)、__malloc_assert路径stderr伪造_flags=0x8005且vtable+0x10(图18/19/20/23)、setcontext+61/+53栈迁移(图16/25/34)、例题largebin attack改_IO_list_all(图29)与本地getshell/读flag(图17/37)均一致；PoC/EXP与原文一致且完整。未验证点：EXP仅作者本地glibc2.32复现成功，远程libc不一致未打通；frontmatter无sources/source_url；affected_versions留空符合原文(仅提及glibc2.24+背景与调试版本)。
---

## 一句话结论

glibc 2.24 之后直接把 `FILE.vtable` 覆盖成 `system` 会被 `_IO_vtable_check` 拦截；House of Cat 改为让控制流走 **`_IO_wfile_jumps` 内合法的 `_IO_wfile_seekoff`（+0x48）→ `_IO_switch_to_wget_mode` → `_IO_WOVERFLOW`**，而 `_IO_WOVERFLOW` 取的是 `fp->_wide_data->_wide_vtable->__overflow`（虚表 +0x18），这个 `_wide_vtable` **不受 vtable 范围检查**、可被任意覆盖；把伪造 `IO_FILE`/`_IO_wide_data`/`_wide_vtable` 布在堆上并让 `exit`（FSOP）或 `sysmalloc` 失败（`__malloc_assert`）触发该链，即可 call 到 `setcontext+61`/`+53` 完成 rdi→rdx→rsp 栈迁移，执行堆上 ROP（system 或 ORW）。

## 原理

- **绕过点**：`_IO_WOVERFLOW(FP, CH)` 宏展开为 `((struct _IO_FILE*)fp)->_wide_data->_wide_vtable->__overflow(fp, WEOF)`（图 03）。glibc 2.24 的 `_IO_vtable_check` 只校验 `FILE.vtable` 是否落在 `__libc_IO_vtables` 段内，而 `_wide_vtable` 是 `_IO_wide_data` 结构里的独立字段、不在被检查的 vtable 段里，因此可以指向堆上的伪造虚表，甚至直接指向 `setcontext+61`、`system`。
- **调用链**：`_IO_wfile_seekoff`（`_IO_wfile_jumps` 第 10 项、偏移 0x48，图 01）开头 `if (mode == 0) return do_ftell_wide(fp);`（mode 必须非 0）；随后 `was_writing = (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base) || _IO_in_put_mode(fp)`；当 `was_writing` 为真调用 `_IO_switch_to_wget_mode(fp)`。该函数在 `fp->_wide_data->_IO_write_ptr > _IO_write_base` 时执行 `_IO_WOVERFLOW(fp, WEOF)`，即经 `rdi(fp) → rax=[rdi+0xa0](_wide_data) → rax=[rax+0xe0](_wide_vtable) → call [rax+0x18]` 完成间接调用（图 09/15）。
- **伪造字段（最小检查集）**：只需满足 `fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base` 这一条（`_IO_wfile_seekoff` 与 `_IO_switch_to_wget_mode` 用的是同一个条件）。典型布置：`FILE+0xc0 = -1`（`_mode != 0`）、`FILE+0xa0 = 堆地址`（`_wide_data`）、`wide_data+0x18 = 1`（`_IO_write_ptr`）、`wide_data+0x20 = 0`（`_IO_write_base`）；再把 `_wide_vtable`（`wide_data+0xe0`）指向 `setcontext+61` 所在伪虚表，使其 +0x18 处为 `setcontext+61`。
- **栈迁移**：`_IO_switch_to_wget_mode` 前段汇编把 `rdi`（FILE 地址）经 `[rdi+0xa0]`、`[...+0x20]` 转换到 `rdx`（图 15/33），恰好满足 `setcontext+61` 从 `[rdx+0xa0]` 取 `rsp`、从 `[rdx+0xa8]` 取 `rcx`（push 的 ret 地址）；于是在堆上预置 `rsp`/`rcx` 与 ROP 链即可把栈迁到堆（图 16/34/35），无需 `malloc_hook`/`free_hook`。
- **触发路径一 FSOP**：`exit → __run_exit_handlers → _IO_cleanup → _IO_flush_all_lockp` 刷新所有 FILE 时，用 `largebin attack` 把 `_IO_list_all` 指向伪造 FILE，并把 `vtable` 设为 `_IO_wfile_jumps + 0x30`，使刷新时调用到 +0x38 处的 `_IO_wfile_seekoff`（图 05/06）。关键在 mode：第一判断分支下 rcx 恒 0 不可用，改用第二判断分支——`_IO_flush_all_lockp` 会把 `_IO_wide_data_2+0x20`（`_IO_write_base`）装入 rcx，令 `mode != 0`（图 07/11/12），gdb 中可见 `_IO_wfile_seekoff(fp, ..., mode=1)`。
- **触发路径二 __malloc_assert**：`_int_malloc → sysmalloc → __malloc_assert → __fxprintf → __vfxprintf → locked_vfxprintf → __vfprintf_internal → _IO_file_xsputn`（图 19 调用栈）。把 `stderr` 覆盖为堆上伪造的 `_IO_2_1_stderr_`，`_flags` 置 `0x8005`（绕过 `__vfprintf_internal` 两处检查，图 18/21/22），`vtable` 用 `_IO_wfile_jumps + 0x10` 使 +0x38 命中 `_IO_wfile_seekoff`；`__vfprintf_internal` 经 `_IO_vtable_check` 后 `call [rax+0x38]` 进入 `_IO_wfile_seekoff`（mode 非 0，图 23），再到 `_IO_switch_to_wget_mode` 衔接 `setcontext+53`（图 25）。例题因拿不到 stderr 地址而用 FSOP，但两条路径机制并列。
- **为什么成立（本质）**：把"被校验的 `FILE.vtable`"换成"未被校验的 `_IO_wide_data._wide_vtable`"作为间接调用源，同时借合法 `_IO_wfile_jumps` 函数把 `rdi` 变成 `rdx` 供 `setcontext` 使用，绕过了 2.24+ 的 vtable 硬化与 hook 被移除后的控制流劫持难题。
- **已验证**：gdb 逐步确认 mode=1、`call _IO_switch_to_wget_mode`、`call [rax+0x18]` 命中 `setcontext+61`、栈迁移后 ret→`pop rdi`→`/bin/sh`→`system` 拿到 shell（图 17）；例题后续 ORW 读到 flag（图 37）。

## 触发条件

- glibc 2.24 之后（存在 vtable 检查）、且 `_IO_wfile_jumps`/`_IO_switch_to_wget_mode`/`setcontext` 可用；例题调试用 glibc 2.29/2.31/2.32。
- 已有堆任意写/UAF/largebin attack 等能力，能伪造 `IO_FILE`、`_IO_wide_data`、`_wide_vtable` 与栈迁移数据，并能改写 `_IO_list_all`（FSOP）或 `stderr`（__malloc_assert）。
- 能触发 `exit`（程序主动调用或 FSOP）或让 `sysmalloc` 失败触发 `__malloc_assert`。
- 已知 libc 基址（算 `_IO_wfile_jumps`、`setcontext`、gadget）与堆地址（布置伪造结构）。
- 若要 RCE 但无 execve（seccomp），改用 ORW ROP 链。

## 利用步骤

1. 泄露 libc（unsorted/large bin fd）与堆地址（large bin `bk_nextsize`/`fd`），计算 `_IO_wfile_jumps`、`setcontext+61/+53`、各 `pop rdi/rsi/rdx/rax; ret` 与 `ret` gadget。
2. 用 largebin attack 把 `_IO_list_all` 覆盖为堆上伪造 FILE 地址（或覆盖 `stderr` 为伪造 FILE）。
3. 在堆上布置：`FILE`（`_mode=-1`、`_wide_data=堆地址`、`vtable=_IO_wfile_jumps+0x30` 或 `+0x10`、`_flags=0x8005` 用于 __malloc_assert 路径）、`_IO_wide_data`（`_IO_write_ptr=1 > _IO_write_base=0`）、`_wide_vtable`（指向伪虚表，其 +0x18 = `setcontext+61`）、以及 `setcontext` 用的 `rsp`/`rcx` 与 ROP 链（system("/bin/sh") 或 ORW）。
4. 触发 `exit`（`_IO_flush_all_lockp`）或制造 `sysmalloc` 失败（`__malloc_assert`），进入 `_IO_wfile_seekoff`（mode 非 0）→ `_IO_switch_to_wget_mode` → `_IO_WOVERFLOW` → `call [wide_vtable+0x18]` = `setcontext+61`。
5. `setcontext` 从 `rdx`（= 伪造 wide_data 区域）取 `rsp` 完成栈迁移，`ret` 落到堆上 ROP，执行 system 或 ORW。

## PoC

```python
# 前置：libc_base / heap_addr / _IO_wfile_jumps / setcontext+61 已算出
file  = p64(0)*2                       # _IO_read_*
file += p64(0) + p64(1) + p64(0)      # _IO_write_base/ptr/end
file += p64(0)*2 + p64(0)*11          # _IO_buf_* 与中间字段
file += p64(heap_addr + 0x370)        # _wide_data (+0xa0)
file += p64(0)*3 + p64(1) + p64(0)*2 # _mode (+0xc0) = 1
file += p64(IO_wfile_jumps_addr + 0x30)   # vtable（FSOP 路径）
# _IO_wide_data（紧随其后）
wd  = p64(0)*3 + p64(1) + p64(rdx) + p64(setcontext_addr)  # +0x18 write_ptr=1 > +0x20 write_base=0
wd += p64(0)*16 + p64(stack_change) + p64(ret)             # setcontext 的 rsp / rcx
wd += p64(0)*4 + p64(wide_vtable) + p64(0)
payload = file + wd + orw_rop          # orw_rop = open/read/write 或 system("/bin/sh")
# largebin attack: 改 large bin 的 bk_nextsize 使 _IO_list_all = heap 上 payload 地址
edit(freed_idx, p64(addr)*2 + p64(0) + p64(IO_list_all_addr - 0x20))
# 触发：exit() 或 sendline("5")
```

验证：gdb 中 `_IO_wfile_seekoff(fp, ..., mode=1)` → `call _IO_switch_to_wget_mode` → `call [rax+0x18]` = `setcontext+61` → `mov rsp,[rdx+0xa0]` → 堆上 ROP → shell / flag。

## 变体与关联

- **触发路径变体**：FSOP（`_IO_list_all`、`vtable+0x30`、`setcontext+61`、system/ORW）与 `__malloc_assert`（`stderr`、`_flags=0x8005`、`vtable+0x10`、`setcontext+53`）是同一伪造机制的两条入口，触发条件（exit vs malloc 失败）与虚表偏移不同。
- **载荷变体**：`_wide_vtable+0x18` 可直接填 `system`（若 `rdi` 指向 "/bin/sh" 字符串）或 `setcontext+61`（栈迁移到 ORW）；seccomp 禁 execve 时用 ORW ROP 读 flag。
- **同源技巧**：House of Apple2 走 `_IO_wfile_overflow`/`_IO_wdoallocbuf` 劫持 `_wide_vtable`、House of Emma/FSOP 走 `_IO_cookie_jumps` 等，均属"vtable 硬化后改走 `_IO_wide_data`/其它未校验函数表"的同一思路；库内 `binary-pwn-heap-house-of-apple2-source-analysis-largebin-system`、`binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw` 等是各题应用，本卡聚焦 `_IO_wfile_seekoff → _IO_switch_to_wget_mode` 的 House of Cat 核心机制与两条触发路径。
- **边界**：glibc 版本差异会改变 `_IO_wide_data` 字段偏移（0xa0/0xe0/0x18/0x20 等）与 `setcontext` 入口（+53/+61）、`_IO_wfile_jumps` 表项顺序；开启 vtable 校验的新版 libc 或拿不到 libc/heap 泄露时链不成立。

## 检测与防御

- **修复/加固**：对 `_IO_wide_data._wide_vtable` 也做 `__libc_IO_vtables` 范围/完整性校验；对 `stderr`/`_IO_list_all` 等关键全局做写保护或校验；升级到已修补的 glibc。
- **检测**：进程退出/分配失败前出现 `_IO_list_all` 或 `stderr` 指向堆地址、FILE 的 `vtable` 为 `_IO_wfile_jumps+0x30/+0x10` 等错位值、`_flags=0x8005`、`_wide_data->_IO_write_ptr > _IO_write_base` 且 `_wide_vtable` 落在堆/非 libc 区域、控制流出现 `setcontext+61` 从非栈地址取 `rsp`、堆上出现 ROP/`/bin/sh`/ORW 片段。
- **缓解**：Full RELRO + PIE + NX + seccomp 白名单（禁 execve）不能阻止控制流劫持但可限制危害，应结合 CFI/影子栈与堆元数据完整性检查。
