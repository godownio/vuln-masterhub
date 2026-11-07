---
id: binary-pwn-heap-glibc243-tcache-perthread-struct-hijack
title: glibc 2.43 tcache_perthread_struct 劫持：改写 entries 实现任意地址分配与栈 ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc243-tcache-perthread-struct-hijack
tags:
- pwn
- heap
- glibc
- tcache
- safe-linking
- arbitrary-alloc
- stack-rop
- orw
cve: []
severity: high
confidence: medium
affected_versions: glibc 2.43（实测 2.43-2ubuntu1）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V93
  verified_at: '2026-11-05T19:40:57+08:00'
  notes: 已对照原文全文（无图片）核对：tcache_perthread_struct 76+76/0x2f8、entries 偏移0x98、unsortedbin泄露libc、safe-linking泄露heap、毒化后第二次malloc返回管理结构、0x2136a0栈泄露与pop rsp+ORW exp均与原文一致；未复跑exp，0x212ac8/0x2136a0/heap+0x570等偏移为题目与libc特定需按目标复核
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc243-tcache-perthread-struct-hijack/
draft: false
kb_aliases:
- tcache_perthread_struct 劫持
- tcache 管理结构
- 任意地址分配
- tcache entries 改写
---

## 一句话结论

glibc 2.43 的 `tcache_perthread_struct` 是一个约 0x2f8 字节的堆上管理结构（76 个 `num_slots` + 76 个 `entries` 指针）；一旦能通过 tcache poisoning 让一次 `malloc` 返回该结构本身，就能改写 `entries[]` 指向任意地址，使后续 `malloc` 直接返回目标地址，从而把 tcache 变成任意地址读写原语，配合 unsorted bin/safe-linking 泄露 libc、heap、stack 后完成栈上 ROP ORW。

## 原理

- glibc 2.26 起有 tcache；2.42+ 为支持 tcache large bins 把 bin 数量扩到 76，`tcache_perthread_struct` 布局为 `uint16_t num_slots[76]; tcache_entry *entries[76];`，`pwndbg` 中 `sizeof` 为 0x2f8；`entries` 数组从结构体偏移 0x98 开始。
- `tcache_get` 的分配逻辑是：取 `entries[tc_idx]` 作为返回块，并把 `entries[tc_idx]` 更新为该块 user data 前 8 字节里的 next 指针（2.32+ 对 next 做 safe-linking 解码）。`entries[tc_idx]` 本身是原始 chunk 指针，不是 safe-linked 值。
- 因此，只要能覆盖 `tcache_perthread_struct.entries[tc_idx]`，就能让下一次对应大小的 `malloc` 返回任意地址；若该地址可读，就能泄露；若可写，就能改写（GOT、栈、`_IO_list_all` 等）。
- 典型获取方式：先用堆溢出/UAF 改写一个已释放 chunk 的 fd（next），按 safe-linking 编码为 `target ^ (chunk_addr >> 12)`，把 tcache 链毒到 `tcache_perthread_struct` 地址；连续 `malloc` 两次，第二次就返回该结构，随后 edit 它即可改写 entries。
- 泄露链：先用伪造的大 chunk 进入 unsorted bin，读 fd 得到 `main_arena+offset` 算 libc；再读某个 tcache 块的 safe-linked fd，解码 `real = encoded ^ (chunk_addr >> 12)` 得到堆地址；最后把 entries 指向 libc 中保存栈指针的地址（如 `libc_base+0x2136a0`），分配并读出栈地址。
- 最终劫持：把 entries 指向栈上目标，`malloc` 返回栈地址后写入 ORW ROP 链（open/read/write 或 openat），再用 `pop rsp; ret` 等 pivot 跳到堆上的长链，读取 flag。

## 触发条件

- 目标为 glibc 2.42/2.43（tcache large bins、76 bins）；本卡按 2.43 描述，偏移需按具体版本核对。
- 存在堆溢出/UAF/任意写等原语，能改写已释放 chunk 的 fd 或直接覆盖 tcache 管理结构。
- 能获得堆基址或至少能计算 safe-linking 编码所需的 chunk 地址（否则无法正确毒化 next）。
- 程序有对应的 malloc/edit/show/delete 菜单，能在目标地址上分配并读写；目标地址所在页可读写。
- 有可用的 libc 泄露与栈泄露路径；最终 ROP 需要可执行 gadget 与足够栈空间。

## 利用步骤

1. 泄露 libc：用大 chunk/伪造 size 进入 unsorted bin，读取 fd/bk 的 `main_arena+offset`，减去偏移得到 libc 基址。
2. 泄露 heap：读取一个 tcache free chunk 的 safe-linked next，按 `encoded ^ (chunk_addr >> 12)` 解码，推导堆基址与 `tcache_perthread_struct` 地址。
3. 毒化 tcache：把某个已释放 chunk 的 fd 写成 `tcache_struct_addr ^ (chunk_addr >> 12)`，连续两次 `malloc` 使第二次返回 `tcache_perthread_struct`。
4. 改写 entries：在返回的“chunk”（即 tcache 结构）上 edit，把 `entries[tidx(size)]` 写成目标地址；注意 `tidx` 与请求 size 的映射（如 size 0x30 → 0x40 的 chunk → index 2）。
5. 任意读写：`malloc(size)` 返回目标地址，随后 edit/show 即可读写；先用它读 libc 中的栈指针（如 `libc_base+0x2136a0`）得到栈地址。
6. 栈 ROP：把 entries 指向栈目标，`malloc` 后写入 ORW ROP 链，或写入 `pop rsp; ret` + 堆上长链地址完成 pivot；最后触发返回/退出，open/read/write flag。

## PoC

```python
from pwn import *
# 假设已有 add/edit/show/delete 菜单封装，libc/堆偏移按目标版本替换
libc_base = u64(leak6.ljust(8, b"\x00")) - 0x212ac8

# 1) 泄露 heap（读 tcache free chunk 的 safe-linked fd）
heap_base = u64(leak5.ljust(8, b"\x00")) << 12

# 2) 把一个 tcache fd 毒到 tcache_perthread_struct（示例地址 heap_base+0x570）
edit(2, b"a" * 0xa0 + flat(0, 0xb1) + p64((heap_base + 0x570) ^ (heap_base >> 12)))
add(3, 0xa0)
add(4, 0xa0)                      # 第二次 malloc 返回 tcache_perthread_struct

# 3) 改写 entries：tidx(size) = (req2size(size)-0x20)//0x10，entries 从 0x98 开始
def req2size(s): return max(0x20, (s + 8 + 0xf) & ~0xf)
def tidx(s):     return (req2size(s) - 0x20) // 0x10
def set_tcache_entry(ptr, size=0x30):
    buf = bytearray(b"E" * 0xe0)
    off = 0x98 + tidx(size) * 8
    buf[off:off + 8] = p64(ptr)   # entries 头指针为原始指针，不是 safe-linked
    return bytes(buf)

leak_target = libc_base + 0x2136a0   # 该 libc 中保存栈指针的地址，需按版本找
edit(4, set_tcache_entry(leak_target, 1))
add(5, 1)
leak = show_data(4)
stack_copy = u64(leak[0x98:0x9e].ljust(8, b"\x00")) ^ (leak_target >> 12)

# 4) 栈上布置 ORW 链（open/read/write），再用 pop rsp 或直接覆盖返回地址触发
```

## 变体与关联

- 变体：不改 tcache 管理结构，直接毒化 `entries` 对应的 free chunk 链到 GOT/栈（需要已知目标地址且能处理 safe-linking）；管理结构劫持的优点是 entries 头指针不编码，写入更直接。
- 变体：glibc 2.32+ 的 safe-linking 要求堆地址泄露；没有泄露时可用 unsorted bin 的 libc 指针推导堆、或利用同页关系暴力低字节。
- 变体：劫持 `_IO_list_all`/`_IO_2_1_stderr_` 走 FSOP（见 House of Apple 2），或用 `environ` 泄露栈（需满足对齐）；本卡使用 libc 中另一个栈指针以省 edit 次数。
- 关联：[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 编解码）、[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（2.42+ tcache_key 绕过）、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（tcache poisoning + 栈 ROP）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（FSOP 替代路线）。

## 检测与防御

- 检测：监控堆上 tcache 管理结构的异常改写（`entries` 指向非堆地址）；崩溃时 `entries` 指向 libc/栈/非堆页；堆题中检查 `num_slots` 与 `entries` 的一致性。
- 修复：glibc 升级到带 tcache 加固的版本；程序层对索引、size 做严格边界校验；避免可溢出/可 UAF 的堆操作。
- 加固：Full RELRO + PIE + ASLR；启用 safe-linking（2.32+ 默认）、tcache_key；seccomp 限制 open/read/write 之外的 syscall；对 setuid/服务程序使用现代 glibc 与编译加固。
