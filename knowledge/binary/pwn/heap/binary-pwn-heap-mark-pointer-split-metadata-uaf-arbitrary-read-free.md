---
id: binary-pwn-heap-mark-pointer-split-metadata-uaf-arbitrary-read-free
title: mark 与指针分离的 note 管理器 UAF：delete 只清 mark、元数据小堆块可被重新分配，变成任意读与任意 free
type: scenario
domain: binary
path: binary/pwn/heap
technique: mark-pointer-split-metadata-uaf
aliases:
- mark 清除型 UAF
- 元数据块可重分配
- chunk_list 悬空指针
- 任意地址读
- 任意地址 free
- it's myheap
tags:
- pwn
- heap
- uaf
- metadata
- arbitrary-read
- arbitrary-free
- glibc
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-08T00:29:56+08:00'
  notes: 已对照原文 it's myheap/pro/plus 核对：add先malloc(0x18)元数据[ size,mark,data_ptr ]、delete只清mark不置空chunk_list、0x18 data与0x20 meta同size class可覆盖复活、show按meta+0x10指针读任意长度、delete free指定pointer形成任意free；img06-10源码与PoC一致。未复跑。
---

## 一句话结论

当 note 管理器为每个 note 额外分配一个 0x18/0x20 元数据块保存 `[size, mark, data_ptr]`，而 delete 只把 mark 置 0、不把 `chunk_list[idx]` 置空，并且该元数据块与普通小堆块的 size class 相同（0x20）时，攻击者可以在 free 后用同尺寸 `add(..., 0x18)` 重新占据这个元数据块，写入 `[任意 size, mark=1, 任意 pointer]`，让残留索引复活成“假 note”；show 因此变成任意地址读，delete 因此变成任意地址 free，可进一步构造 fastbin/tcache dup 与任意分配。

## 原理

- **分配结构**：`add(idx, size)` 先 `meta = malloc(0x18)`，把 `size` 写到 `meta+0`，再 `data = malloc(size)` 并把指针写到 `meta+0x10`，最后 `chunk_list[idx] = meta`、`meta+8 = 1`（mark=1）。用户写入的是 data 缓冲区，不是 meta。
- **删除逻辑**：`delete(idx)` 在 `chunk_list[idx] != NULL && mark != 0` 时执行 `free(meta)`、`free(meta->data)`，然后只把 `mark`（`meta+8`）置 0，`chunk_list[idx]` 保持原值。之后该索引“看起来未使用”，但指针仍然指向已被 free 的 meta 块。
- **为什么 meta 可被攻击者重写**：`malloc(0x18)` 得到的是 0x20 的 chunk（用户可用 0x18 字节）。普通 note 若以 `size=0x18` 调用 `add`，其 data 缓冲区同样是 0x20 chunk，与释放后的 meta 属于同一个 tcache/fastbin bin。因此后续 `add(x, 0x18, payload)` 的 data 分配可以正好落在某个旧的 meta 块上，用户写入的 0x18 字节就覆盖了 `[size, mark, data_ptr]` 三个字段。
- **为什么 show 变成任意读**：show 只检查 `chunk_list[idx]` 非空且 `mark != 0`，然后 `write(1, *(meta+0x10), *(size_t*)meta)`。mark 和 size/pointer 都是攻击者刚写入的，于是可以读任意地址的任意长度（受写入的 size 限制）。
- **为什么 delete 变成任意 free**：delete 用 `free(chunk_list[idx])` 释放 meta，再 `free(*(meta+0x10))` 释放攻击者指定的 pointer。即使 pointer 指向另一个已释放 chunk，也能制造 fastbin/tcache dup；配合 slab 布局即可拿到任意分配。
- **利用成立的关键**：程序把“是否已释放”的标记（mark）与被释放的指针分开保存，且标记本身存放在一个可被用户数据覆盖的堆块中；只要这两点同时存在，就不需要传统的 UAF edit 接口。

## 触发条件

- note 管理器使用“元数据块 + 数据块”的两级分配，元数据块尺寸与某个可申请的 data 尺寸相同（原文为 0x18 → 0x20 chunk）。
- delete 只清 mark/flag，不把索引指针置空；show/delete 只凭 mark 判断对象是否可用，不校验指针来源。
- 元数据块被 free 后进入 tcache/fastbin，且攻击者能通过正常 add 请求重新分配到它。
- 至少有一个残留索引（mark 已被清 0）等待复活；无需 PIE 泄露即可先做堆内任意读/free，BSS 地址已知时可直接读 GOT/libc 指针。

## 利用步骤

1. 申请两个同尺寸 note（原文 0x70），让它们的 meta（0x20）和数据块都进入可复用状态：`add(0,0x70,'a'); add(1,0x70,'a'); delete(0); delete(1)`。此时 `chunk_list[0]/[1]` 仍指向已释放的 meta，mark=0。
2. 用 `add(x, 0x18, p64(0x18) + p64(1) + p64(target))`：data 缓冲区复用旧 meta，写入伪造元数据；残留索引 0/1 的 mark 变为 1、size 变为 0x18、pointer 变为 target。
3. 用 `show(残留索引)` 读 target：把 target 设为 `chunk_list` 数组本身（原文 `0x404060`）可读出一个堆指针，减去固定偏移得到 heapbase；把 target 设为 `stdout`（原文 `0x404020`）可读出 libc 指针并算 libcbase。
4. 用 `delete(残留索引)` 触发 `free(meta)` 与 `free(target)`：若 target 是一个已经释放、仍在 fastbin 中的 chunk，就形成 fastbin dup；随后按 fastbin reverse into tcache 或 botcake 的方式即可获得任意地址分配（详见关联卡）。
5. 后续把任意分配打到 `_IO_2_1_stderr_`/`_IO_list_all` 等 FSOP 目标，或打 GOT（Partial RELRO）完成 RCE。

## PoC

原文 pro 题的泄露片段（地址为题目布局；`elf` 无 PIE，BSS 固定）：

```python
# chunk_list = 0x404060, stdout = 0x404020
add(0, 0x70, b'a')
add(1, 0x70, b'a')
delete(0)
delete(1)

# 用 0x18 的 data 覆盖释放后的 meta：size=0x18, mark=1, ptr=chunk_list
add(3, 0x18, p64(0x18) + p64(1) + p64(0x404060))
show(0)
heapbase = u64(p.recv(3).ljust(8, b'\x00')) - 0x2a0

# 再复活一次，把 ptr 指向 stdout，读 libc 指针
add(0, 0x70, b'a')
add(1, 0x70, b'a')
delete(0)
delete(1)
add(3, 0x18, p64(0x18) + p64(1) + p64(0x404020))
show(0)
libcbase = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x21b780
```

> 说明：0x18 的 data 与 meta 同属 0x20 chunk 是前提；原文还给出 plus 变体（PIE + sandbox）用 `ptr=heapbase+0x1cf0` 读取 unsorted bin 的 fd 泄露 libc。片段未在本机复跑。

## 变体与关联

- **任意 free 的用法**：把 pointer 指向已在 fastbin 的 chunk 可做 fastbin dup；指向 fastbin 链尾可配合 fastbin reverse into tcache 改 fd（[[binary-pwn-heap-glibc235-fastbin-reverse-into-tcache-last-fd-arbitrary-alloc]]）。
- **UAF 复用的其他形态**：stale slot、结构体复用、删除压缩后末槽不清等都会产生类似“索引仍可信”的问题，可参考 [[binary-pwn-heap-stale-slot-create-failure-uaf]]、[[binary-pwn-heap-uaf-struct-reuse-data-pointer]]、[[binary-pwn-heap-delete-compaction-stale-slot-fastbin-dup]]。
- **与 XOR 指针数组的对比**：[[binary-pwn-heap-xor-chunklist-lucky-number-arbitrary-free-uaf]] 是 pointer 编码 + 用户可控 free 目标，本卡是 mark/pointer 分离 + 元数据块复用，触发条件与 PoC 不同。
- 关联：[[binary-pwn-heap-glibc235-botcake-malloc-consolidate-io-list-all-apple2]]（本原语 + botcake 的完整链）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（最终 FSOP）。

## 检测与防御

- 修复：delete 时把 `chunk_list[idx]` 置 NULL；mark 与指针放在同一被清除的结构中，或使用引用计数/句柄表；show/delete 重新校验对象是否在生命周期内。
- 加固：元数据块单独使用与用户数据不同的 size class 或保护页；对 free 指针做合法性校验；启用 tcache/fastbin 完整性检查与 MALLOC_CHECK_。
- 检测：同一索引在 delete 后被 show/delete；元数据堆块中出现用户可控的 size/pointer；free 的目标不在堆范围或指向已释放 chunk；tcache/fastbin 出现重复 chunk。
- 该场景为 CTF/授权测试利用；生产代码中“标记清除 + 悬空指针”与直接 UAF 等价，不能作为安全释放。
