---
id: binary-pwn-heap-fastbin-fd-fake-chunk-bss-arbitrary-alloc
title: Arbitrary Alloc：UAF 改写 fastbin fd 指向 BSS 假块（size=0x7f），单次 free 也能实现任意地址分配并改 GOT
type: scenario
domain: binary
path: binary/pwn/heap
technique: fastbin-fd-fake-chunk-arbitrary-alloc
aliases:
- Arbitrary Alloc
- 任意地址分配
- fastbin fd 劫持
- 假 chunk 分配
- 单次 free 堆利用
- BSS fake chunk
- fastbin attack
tags:
- pwn
- heap
- fastbin
- arbitrary-alloc
- uaf
- fake-chunk
- got-hijack
- glibc
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V475-fix
  verified_at: '2026-11-10T17:44:08+08:00'
  notes: V475 指出 glibc 版本表述错误：tcache 自 2.26 起默认启用（2.27 已有），原文 exp 用 2.23-ubuntu3。已把原理改为『旧版 glibc（本例 2.23）的两道检查』，触发条件改为『glibc <=2.25 未引入 tcache；2.26+ 需先填满 tcache 或改 tcache poisoning；2.32+ 有 safe-linking』，并注明 check_remalloced_chunk 在 release 构建通常为 no-op。其余 Arbitrary Alloc 链核对不变。
---

## 一句话结论

当程序存在 UAF 且能编辑已释放 fastbin chunk 时，把它的 `fd` 改成 .bss 中一个 size 字段恰好是合法 fastbin 尺寸（如 0x7f）的地址，glibc 下一次 malloc 就会把这个假 chunk 分配返回，使后续写操作变成对任意地址（本例 .bss/GOT）的写；整条链不需要 double free，因此"只允许 free 一次"的题目也能打通。

## 原理

- **fastbin 是单链表**：空闲 chunk 的 `fd` 指向下一个空闲 chunk。`malloc` 从对应 fastbin 取出头节点，并把 `victim->fd` 设为新的头。
- **fd 可控即任意分配**：UAF 下把已释放 chunk 的 `fd` 改成一个伪造 chunk 头的地址 `fake`，第一次 malloc 返回真 chunk 后 fastbin 头变成 `fake`；第二次同尺寸 malloc 就会把 `fake` 当空闲块返回。malloc 返回的是 `chunk2mem(victim) = victim + 0x10`，所以真正的写入起点是 `fake + 0x10`。
- **旧版 glibc（本例 2.23）的两道检查**（`_int_malloc`）：
  1. `fastbin_index(chunksize(victim))` 必须等于当前 bin 的索引——即假 chunk 的 size 字段必须落在当前 fastbin 的尺寸范围内。申请 0x60 字节对应 chunk size 0x70、fastbin index 5，假 size 必须在 `[0x70, 0x7f]`。
  2. `check_remalloced_chunk`：size 的 `PREV_INUSE` 位必须为 1；fastbin 尺寸本身是奇数，天然满足（该检查在 release 构建中通常为 no-op，本例按原文保留）。
- **去哪找天然的合法 size**：延迟绑定完成后的 GOT 项保存 libc 地址，libc 地址最高字节是 `0x7f`。以 GOT 区某个位置作为"假 chunk 头"时，取其 +8 处的那一个字节正好是某个 libc 指针的最高字节 `0x7f`，于是 `size=0x7f`：既在 `[0x70,0x7f]` 内，又满足 `PREV_INUSE=1`，两道检查都过。
- **实例布局**：.bss 0x60207d 作 fake chunk 头，其 +8（0x602085）是 0x602080 处 stdout 指针的高字节 0x7f；malloc(fake) 返回 0x60208d，程序的 `read(0, p, 0x60)` 从 0x60208d 起写 0x60 字节，正好覆盖 .bss 中的全局指针 `p`（0x6020a8）与一次性标记 `has2/has4`，把"假块分配"升级为对 .bss 的受控写。
- **为什么单次 free 也够**：double free 只是把同一个真 chunk 反复挂进 fastbin 的一种手段；本链只需要"一次 free 得到 fastbin 空闲块 + UAF 改 fd"，不需要第二次 free。
- **收尾**：把全局 `p` 改成 `free_got-8` 后，用程序的写功能在 `free_got-8` 处写 `"/bin/sh\0"`、在 `free_got` 处写 `system`，再触发 `free(p)` 即等价于 `system("/bin/sh")`；泄露环节用 `p=free_got-8` 读 GOT 中的 libc 指针算基址。

## 触发条件

- glibc ≤2.25（未引入 tcache；本例 exp 使用 2.23-ubuntu3）。tcache 自 2.26 起默认启用，2.26+ 需先填满 tcache 或改用 tcache poisoning；2.32+ 还有 safe-linking，fd 需按堆地址编码。
- 存在 UAF（free 后指针未置空）或堆溢出，能改写已释放 fastbin chunk 的 `fd`。
- 能再次申请相同的 fastbin 尺寸（如 malloc(0x60)）。
- 目标地址附近存在可充当 size 的字节（GOT 中 libc 指针的 `0x7f` 高字节等），使假 size 落在当前 fastbin 范围且 `PREV_INUSE=1`。
- 程序保留可用的写原语（菜单式 fill/read）和至少一个可泄露 GOT 的原语（show/print），以便完成泄露和 GOT 覆写。

## 利用步骤

1. 确认 libc 版本与保护（本例 Partial RELRO、No PIE、NX；GOT 可写但 PIE 关闭地址固定）。
2. 用 `malloc(0x60)` 申请 chunk 并 `free`，确认释放后指针仍可被读写（UAF）。
3. 在 .bss/GOT 区用 gdb 扫描找假 chunk 头：`x/gx <addr>` 看 `addr+8` 处是否为 `0x7f`（本例如 0x60207d 处，`*(0x602085)=0x7f`）。
4. 通过 UAF 写把已释放 chunk 的 `fd` 覆盖为假 chunk 头地址。
5. 再 malloc 一次取回真 chunk，再 malloc 一次即返回假 chunk（写入起点 `fake+0x10`）；构造 payload 覆盖 .bss 全局指针与标记，本例 `b'a'*0x1b + p64(free_got-8) + b'a'*0x10`。
6. 用 show/print 从 `p=free_got-8` 读出 GOT 中 libc 指针，按对应符号偏移算 libc base。
7. 用写原语往 `free_got-8` 写 `"/bin/sh\0"`、往 `free_got` 写 `system`，触发 `free(p)` 得到 shell。

## PoC

```python
# 伪代码：核心步骤，地址来自示例题目（No PIE）
fake_chunk = 0x60207d      # *(0x602085) == 0x7f，来自 stdout GOT 指针高字节
free_got_8 = 0x602010      # free_got - 8

create()                   # p = malloc(0x60)，chunk size 0x70
dele()                     # free(p)；指针不置空（UAF）
fill(p64(fake_chunk))      # 改写已释放 chunk 的 fd -> 假 chunk 头

create()                   # malloc 返回真 chunk，fastbin 头变为 fake
func5(b'a'*0x1b + p64(free_got_8) + b'a'*0x10)
# malloc(0x60) 返回 fake+0x10=0x60208d；payload 覆盖全局 p=free_got-8 与一次性标记

show()                     # 从 free_got-8 读 libc 指针，计算 libc base
fill(b'/bin/sh\x00' + p64(system))
# free_got-8 处放 "/bin/sh"，free_got 覆写为 system
dele()                     # free(p) -> system("/bin/sh")
```

说明：示例载荷按 0x60 申请、假 size 0x7f、写入起点 0x60208d 推导；未在本机复跑。

## 变体与关联

- 变体：假 chunk 放在其他可控区（栈、堆内已知地址）；size 字节来自其他内容为 `0x7f` 的指针；申请尺寸变化时假 size 范围随之变化（0x70 对应 `[0x70,0x7f]`，0x50 对应 `[0x50,0x5f]`）。
- 变体：能 free 两次时直接 fastbin dup；有 tcache 时用 tcache poisoning，glibc 2.32+ 需按 safe-linking 构造 fd。
- [[binary-pwn-heap-house-of-spirit-bss-counter-fake-chunk-strlen-got]]：House of Spirit 是"free 一个假 chunk"的反向路径；本卡是"改 fd 让 malloc 分配假 chunk"。
- [[binary-pwn-heap-house-of-rabbit-malloc-consolidate-fake-chunk-largebin-arbitrary-alloc]]：借 malloc_consolidate 与 largebin 改写 size 的任意分配变体。
- [[binary-pwn-heap-house-of-orange-fastbin-got-onegadget]]：无 del、用 house_of_orange 把 top 送入 fastbin 后改 fd 分配 fake chunk，同属 fastbin 任意分配。
- [[binary-pwn-heap-chunk-extend-size-overlap-unsorted-leak-fastbin-malloc-hook]]：fastbin attack 打 `__malloc_hook` 的另一种落点。
- 边界：假 size 不在当前 fastbin 范围或 `PREV_INUSE=0` 会触发 `malloc(): memory corruption (fast)`；glibc 2.32+ safe-linking 下直接写裸地址会崩。

## 检测与防御

- 检测：free 后仍可编辑/读取该指针（UAF）；fastbin 链中出现指向 .bss/GOT/栈等非堆区的 fd；GOT 项在运行期被改写；程序报 `malloc(): memory corruption (fast)`。
- 防御：free 后立即置空指针；升级 glibc 启用 tcache 与 safe-linking；Full RELRO 保护 GOT；PIE/ASLR；使用 hardened allocator（如 Scudo/hardened_malloc）；对菜单式 read 增加长度与状态校验。
