---
id: binary-pwn-heap-safe-linking-self-xor-heap-address
title: 同页 tcache 双 free 自异或恢复精确堆地址（safe-linking 免泄露）
type: scenario
domain: binary
path: binary/pwn/heap
technique: safe-linking-self-xor-heap-address
aliases:
- safe-linking 密钥泄露
- 无堆泄露
- 堆地址恢复
- tcache 自异或
- PROTECT_PTR 绕过
tags:
- pwn
- heap
- glibc
- tcache
- safe-linking
- heap-address
- xor
cve: []
severity: high
confidence: high
affected_versions: glibc >= 2.32
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-E
  verified_at: '2026-11-04T19:16:00+08:00'
  notes: 已对照原文核对：safe-linking PROTECT_PTR 公式、同页双 free 的 fd3^fd4 推演与图 05 数值一致；PoC 未在本机执行，需保证两 fd 字段同 4K 页且 tcache bin 初始为空。
---

## 一句话结论

glibc 2.32+ 的 safe-linking 把 tcache `fd` 编码为 `(fd字段地址 >> 12) ^ 目标指针`；当同一个 tcache bin 先放入一个空后继的 chunk（`fd` 直接暴露密钥）再放入同页的另一个 chunk 时，两次读到的 `fd` 异或即可还原第一个 chunk 的精确地址，无需独立堆泄露。

## 原理

- safe-linking 编码：`PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`，其中 `pos` 是 `fd` 字段自身地址，`ptr` 是下一个空闲 chunk 地址。解码需要 `pos >> 12` 这个密钥。
- 当 tcache bin 为空时释放 chunk3：`fd3 = ((chunk3+0x10) >> 12) ^ NULL`，结果就是密钥本身（`chunk3` 所在页号），明文可读。
- 随后释放同页的 chunk4：`fd4 = ((chunk4+0x10) >> 12) ^ chunk3`。
- 两个 `fd` 字段位于同一 4K 页时，`(chunk3+0x10) >> 12 == (chunk4+0x10) >> 12`，于是：
  `fd3 ^ fd4 = key ^ key ^ chunk3 = chunk3`。
- 一次异或得到 chunk3 的精确地址，不依赖任何独立的堆地址泄露原语；若两 chunk 相邻且大小已知，还可推出 chunk4 地址。

## 触发条件

- 目标为 glibc 2.32 及以上，tcache/fastbin 启用了 safe-linking；
- 存在 UAF 读：能读回已释放 chunk 的前 8 字节；
- 能连续释放两个同尺寸 chunk，且该尺寸的 tcache bin 初始为空；
- 两个 chunk 的 `fd` 字段落在同一 4K 页（地址高 56 位相同）；
- 释放顺序必须是“先 chunk3（空 bin 裸密钥），后 chunk4”，且 tcache 计数未满。

## 利用步骤

1. 选择同一尺寸（如请求 0xe0，chunk 0xf0）的两个 chunk，布置在同一 4K 页内；可再放 guard 防止与 top 合并。
2. 确认该尺寸 tcache bin 为空，先 `free(chunk3)`，再 `free(chunk4)`。
3. 用 UAF `show(chunk3)` 读前 8 字节得到 `fd3`，`show(chunk4)` 得到 `fd4`。
4. 计算 `chunk3 = fd3 ^ fd4`；用调试器核对是否等于真实地址。
5. 已知相邻布局时 `chunk4 = chunk3 + 0xf0`（按实际 chunk size），并计算毒化所需的密钥 `(chunk4+0x10) >> 12`。
6. 用 UAF `edit(chunk4, p64(key ^ target))` 把 tcache 链头改到目标地址，两次 `malloc` 后第二次返回目标。

## PoC

```python
# add(idx, size, data) / delete(idx) / show(idx) / edit(idx, data)
add(0, 0xe0, b'A' * 0xe0)   # chunk3
add(1, 0xe0, b'B' * 0xe0)   # chunk4，与 chunk3 同页
# ... 确保 0xe0 尺寸的 tcache bin 为空
delete(0)                    # fd3 = chunk3 >> 12（裸密钥）
delete(1)                    # fd4 = (chunk4 >> 12) ^ chunk3

fd3 = u64(show(0)[:8])
fd4 = u64(show(1)[:8])
chunk3 = fd3 ^ fd4
print(hex(chunk3))           # 与 gdb 中 chunk3 地址一致
```

```text
# 布局要求（示例）
chunk3 @ heap+0x9f0, chunk4 @ heap+0xae0
chunk3->fd = 0x555593052              # chunk3 >> 12
chunk4->fd = 0x5550c65c19a2           # (chunk4 >> 12) ^ chunk3
fd3 ^ fd4  = 0x5555930529f0           # chunk3 精确地址
```

## 变体与关联

- 变体：fastbin 双 free 的同类自异或；利用已知堆偏移直接推算密钥；结合其他泄露恢复页号后再异或。
- 关联：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（同一 UAF 先泄 libc）；[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（用恢复的堆地址构造 fake wide data 并毒化 tcache 到 stderr）。
- 限制：两 chunk 跨页时密钥不同，异或结果不再是地址；tcache bin 非空时第一次 free 的 `fd` 不是裸密钥；glibc 版本的 safe-linking 实现需一致。

## 检测与防御

- 防御：UAF 仍是根因，释放后置空指针、避免悬空引用；safe-linking 只是提高利用门槛，不能替代生命周期管理；可叠加 tcache key、随机化分配与更细的堆完整性检查。
- 检测：连续 free 同尺寸对象后仍发生读写的调用序列；堆元数据中出现非规范 `fd`；崩溃堆栈指向 tcache 链表解析。
- 认知：safe-linking 的密钥在“空 bin 首次 free”时以裸值出现，设计上并不能单独阻止同页双 free 的地址恢复。
