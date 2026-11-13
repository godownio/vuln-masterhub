---
id: binary-pwn-heap-house-of-emma-cookie-jumps-pointer-guard
title: House of emma：伪造 _IO_cookie_jumps 虚表 + PTR_MANGLE 函数指针，largebin attack 改写 stderr 与 pointer_guard 后经 malloc_assert 触发任意调用
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-emma-io-cookie-jumps-pointer-guard
tags:
- binary
- pwn
- heap
- glibc
- io-file
- fsop
- house-of-emma
- cookie-jumps
- pointer-guard
- malloc-assert
- setcontext
- orw
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V673
  verified_at: '2026-11-13T10:40:11+08:00'
  notes: 已对照原文与图04核对：_IO_cookie_jumps+0x40 虚表偏移、两次 largebin attack 改 stderr 与 guard（libc_base+0x2035f0）、fake _IO_cookie_file 的 __cookie= srop_addr 与 ROL(gadget^guard,0x11) 回调编码、top chunk 改 0x300 触发 malloc_assert、setcontext+61+ORW 均与 exp 一致；图04 为 _IO_list_all=堆地址的调试状态。修正 PTR_MANGLE/DEMANGLE 措辞（MANGLE=异或后循环左移 0x11）。边界：与 House of Cat（_IO_wfile_jumps/_wide_vtable）、Apple2（exit FSOP）、leakless mp-tcache 卡（stdout FSOP）非同链；dup-scan 无 pair。无最终读 flag 截图，confidence medium；未复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-house-of-emma-cookie-jumps-pointer-guard/
draft: false
kb_aliases:
- House of emma
- _IO_cookie_jumps
- _IO_cookie_file
- __io_functions
- PTR_MANGLE
- __pointer_chk_guard
- pointer_guard 覆盖
- glibc 2.34 hook 移除
- 湖湘杯 house_of_emma
---

## 一句话结论

glibc 2.34 删除常用 hook 后，若高版本堆题难以做任意地址分配，可用 House of emma：伪造 `_IO_cookie_file`（`_IO_FILE_plus` 扩展 + `__cookie` + `__io_functions.read/write/seek/close`），让 `vtable` 指向 `_IO_cookie_jumps + 0x40`（仍在合法 vtable 段内，绕过 vtable 检查）；再用 largebin attack 分别把 `stderr` 指针改为堆上伪 FILE、把 TLS 的 `__pointer_chk_guard` 改为已知值，并把 cookie 函数指针按 PTR_MANGLE 编码（异或 guard 后循环左移 0x11；调用侧 PTR_DEMANGLE 为循环右移 0x11 再异或 guard）为迁移 gadget；最后用 `__malloc_assert` 触发 IO 流，经 cookie 回调 → gadget → `setcontext+61` → 堆上 SROP/ROP 完成 ORW。

## 原理

- **背景**：glibc 2.34 之后 `__free_hook`/`__malloc_hook` 等被删除；高版本堆题又常限制任意地址分配，无法轻松构造 IO_FILE。需要找一个"函数指针存储在可控数据里、调用时第一参数也来自该数据"的合法结构来替代 hook——`fopencookie` 的 `_IO_cookie_file` 正符合。
- **`_IO_cookie_file` 结构**：

  ```c
  struct _IO_cookie_file {
    struct _IO_FILE_plus __fp;
    void *__cookie;
    cookie_io_functions_t __io_functions;  // read/write/seek/close
  };
  ```

  `_IO_cookie_read/write/seek/close` 都会先取 `cfile->__io_functions.<cb>`，再以 `cfile->__cookie` 作为第一个参数调用。也就是说，只要控制伪 FILE 的这段内存，就得到一个"第一个参数可控的任意函数调用"原语，类似 `__free_hook`。
- **vtable 检查的宽松点**：`_IO_cookie_jumps` 本身位于 `__libc_IO_vtables` 段，属于合法 vtable；把伪 FILE 的 vtable 设为 `_IO_cookie_jumps + 0x40`（表内偏移）仍能通过 `_IO_vtable_check`，但后续按固定偏移取到的函数项被"平移"到表内其他函数（House of emma 的核心思想：改 vtable 起始位置，使固定偏移命中想要的表项/调用点）。
- **函数指针加密**：cookie 回调指针在调用前会被 `PTR_DEMANGLE` 处理（循环右移 0x11 再异或 `__pointer_chk_guard`）。要构造可用指针，需知道 guard 的值。攻击者用 largebin attack 把 TLS 中的 `__pointer_chk_guard` 覆写成已知的堆地址，再按 `mangled = ROL(target ^ guard, 0x11)`（原文 `ROL(gadget_addr ^ (heap_base + 0x22a0), 0x11)`）编码目标 gadget。
- **触发与迁移**：用 largebin attack 把 `stderr` 指针改为堆上伪 FILE；伪造 `_IO_write_base=0`、`_IO_write_ptr=0xffffffffffffffff` 等使 `_IO_flush_all_lockp` 满足"需要溢出刷新"的条件；再修改 top chunk size（原文改为 0x300 并清 inuse）触发 `__malloc_assert`（与 House of kiwi 相同的触发点）。assert 过程中刷新 stderr → 经 cookie 虚表调用到被加密的 gadget；gadget（原文注释 `mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]`）把 `rdi`（伪 FILE 中 `__cookie` 指向的 SROP 区域）转换成 `rdx`，再 call 到 `setcontext+61`，由 `setcontext` 从 SROP 帧恢复寄存器/栈，执行堆上 ROP（ORW 读 flag）。
- **原文例题 [湖湘杯 2021] house_of_emma**：菜单堆题，`malloc(0x2000)` 后按 opcode 分发 add/delete/show/edit/运算；add 只允许 0x410-0x500 的块，delete 后存在 UAF，主循环无法退出（不能靠返回值触发 IO），因此采用 House of kiwi 的 assert 触发 + House of emma 的 cookie 虚表链。exp 先泄露 libc（unsorted bin 的 `main_arena+1104`）与 heap，再做两次 largebin attack（stderr、guard），构造 fake IO_FILE 与 SROP 帧，最后改 top chunk 触发 `malloc_assert`。
- **为什么成立**：vtable 检查只验证 `FILE.vtable` 落在合法段，`_IO_cookie_jumps + 0x40` 满足；cookie 回调的函数指针与参数都在攻击者可控的堆内存里；guard 被覆盖后加密不再构成障碍；`setcontext+61` 提供从任意可读结构恢复栈的能力，从而把控制流彻底转到堆上 ROP。

## 触发条件

- glibc 2.34 及以上（hook 被移除；原文例题为高版本堆题），具备 UAF/堆溢出等堆原语，能做 largebin attack。
- 已知 libc 基址、堆地址，并能读取/覆写 TLS 的 `__pointer_chk_guard`（通常在 libc 基址固定偏移，如原文 `libc_base + 0x2035f0`）。
- 能触发 `__malloc_assert`（修改 top chunk size 或破坏 largebin bk）。
- 程序路径中存在会刷新 `stderr` 的 IO 调用（assert 内的 `fflush(stderr)` 即可）。
- 仅限 CTF/授权环境。

## 利用步骤

1. 泄露 libc 基址与堆地址（unsorted bin 的 `main_arena+1104`、heap 指针等）。
2. 第一次 largebin attack：把 `stderr` 指针覆盖为堆上伪 `_IO_FILE` 地址。
3. 第二次 largebin attack：把 `__pointer_chk_guard` 覆盖为已知值（如某个堆地址）。
4. 在堆上布置：
   - fake `_IO_FILE`：`_IO_write_base=0`、`_IO_write_ptr=0xffffffffffffffff`、`_chain=0`、`_lock` 可写、`_mode=0`、`vtable=_IO_cookie_jumps+0x40`；
   - `__cookie` 指向 SROP/ROP 区域（即 `rdi`）；
   - cookie 回调指针槽写入 `ROL(gadget ^ guard, 0x11)`；
   - SROP 帧（`rdi/rsi/rdx/rsp/rip` 按迁移 gadget 与 `setcontext+61` 的取值布置）与 ORW ROP 链。
5. 修改 top chunk size（如 `0x300`），申请超过 top 的块触发 `__malloc_assert`。
6. assert 刷新 stderr → cookie 回调 → 迁移 gadget → `setcontext+61` → 堆上 ROP → ORW 读 flag。

## PoC

原文 exp 关键片段（湖湘杯 2021 house_of_emma，glibc 高版本）：

```python
def ROL(content, key):
    tmp = bin(content)[2:].rjust(64, '0')
    return int(tmp[key:] + tmp[:key], 2)

guard = libc_base + 0x2035f0      # __pointer_chk_guard
gadget_addr = libc_base + 0x146020  # mov rdx, [rdi+8]; mov [rsp], rax; call [rdx+0x20]
setcontext_addr = libc_base + 0x50bc0

# largebin attack: 改写 stderr 与 guard 为可控堆地址
# ...

fake_IO_FILE  = 2 * p64(0)
fake_IO_FILE += p64(0)                    # _IO_write_base = 0
fake_IO_FILE += p64(0xffffffffffffffff)   # _IO_write_ptr = 0xffffffffffffffff
fake_IO_FILE += p64(0) * 3                # write_end / buf_base / buf_end
fake_IO_FILE  = fake_IO_FILE.ljust(0x58, '\x00') + p64(0)          # _chain
fake_IO_FILE  = fake_IO_FILE.ljust(0x78, '\x00') + p64(heap_base)  # _lock
fake_IO_FILE  = fake_IO_FILE.ljust(0xB0, '\x00') + p64(0)          # _mode
fake_IO_FILE  = fake_IO_FILE.ljust(0xC8, '\x00')
fake_IO_FILE += p64(libc.sym['_IO_cookie_jumps'] + 0x40)           # vtable
fake_IO_FILE += p64(srop_addr)            # __cookie -> rdi
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(ROL(gadget_addr ^ (heap_base + 0x22a0), 0x11))  # 加密后的回调

frame = SigreturnFrame()
frame.rdi = srop_addr + 0xF8
frame.rsi = 0
frame.rdx = 0x100
frame.rsp = srop_addr + 0xF8 + 0x10
frame.rip = pop_rdi_addr + 1              # ret

# 改 top chunk size 触发 __malloc_assert 进入 House of Emma 链
edit(7, 'a' * 0x438 + p64(0x300))
add(8, 0x450)
```

原文完整 exp 给出了两次 largebin attack、fake IO、SROP 与 top chunk 修改的完整流程；调试截图仅展示 `_IO_list_all` 等中间状态，未附最终读 flag 截图，故置信度 medium。

## 变体与关联

- 变体：cookie 回调可换成 `_IO_cookie_read/write/seek/close` 中任一触发点；vtable 偏移可调整以命中不同表项；迁移 gadget 可换其他把 `rdi` 转成 `rdx` 的指令；无 seccomp 时 ROP 可直接 `system("/bin/sh")`。
- 关联：[[binary-pwn-heap-house-of-kiwi-malloc-assert-file-jumps-sync-setcontext]]（同源触发与 setcontext 迁移；emma 是其"hook 替代"演进）、[[binary-pwn-heap-house-of-cat-wfile-seekoff-wide-vtable-bypass-vtable-check]]（另一条 vtable 检查绕过）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（stderr FSOP 的经典路线）。
- 边界：需要能覆盖 TLS guard（否则 PTR_DEMANGLE 后指针不可控）；vtable 指针必须仍落在 `__libc_IO_vtables` 段内，否则被 `_IO_vtable_check` 拦截；无堆地址泄露时难以布置 fake FILE。

## 检测与防御

- 这是 CTF/漏洞利用技术；防御侧关注：`stderr` 等全局 FILE 指针与 TLS `__pointer_chk_guard` 被异常改写、堆上出现 cookie 回调形态的伪 FILE、top chunk 元数据被破坏后进程断言 abort。
- 缓解：保持 ASLR/不泄露 heap 与 libc；编译期/运行期启用堆完整性检查；对 `fopencookie` 使用场景做审计；及时跟进 glibc vtable/指针保护演进（但本链依赖合法 cookie 虚表与可控数据，常规 vtable 检查不足以阻止）。
- 检测信号：进程 `/proc/<pid>/maps` 中 stderr 指向堆区、`_IO_cookie_jumps` 回调被调用、assert/abort 前出现异常 IO 刷新。
