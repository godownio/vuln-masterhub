---
id: binary-pwn-heap-metadata-array-offbyone-chunkptr-low-byte-heap-leak
title: 元数据数组相邻 + 索引上界 off-by-one：add 第 33 块时 size 低字节覆写 chunk_ptr[0] 最低字节，show 改读新地址泄露 heap base
type: scenario
domain: binary
path: binary/pwn/heap
technique: metadata-array-offbyone-chunkptr-low-byte-overwrite-heap-leak
aliases:
- chunk_size 溢出 chunk_ptr
- 数组相邻 off-by-one
- chunk_ptr 低字节改写
- 堆指针数组越界写
- show 泄露 heap base
- 第 33 个块溢出
tags:
- pwn
- heap
- glibc-2.23
- off-by-one
- metadata-array
- chunk-pointer-array
- heap-leak
- bss
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V298
  verified_at: '2026-11-08T08:35:51+08:00'
  notes: 已对照原文148行与15张图核对：图09 add 检查 chunk_number>0x20、chunk_size[chunk_number]=size[0]；图10 chunk_size@0x4040C0(char[32]) 与 chunk_ptr@0x4040E0 相邻；图11/12 显示 chunk_ptr[0] 0x23c9010→0x23c9040；图13/正文 show(0) 读8字节、heapbase=u64(leak)-0x20 一致。原文 libc2.23/no PIE；本卡原语本身非版本专属，未设versions（cards.json 亦为 null）。dup-scan pair 101 与本篇任意地址写卡 related(0.889)，两者为不同原语，判并列保留。未在本地复跑exp。
---

## 一句话结论

当 add 把请求大小存进紧邻指针数组之前的 `char chunk_size[32]`，而索引检查写成 `chunk_number > 0x20`（允许第 33 个索引 0x20）时，`chunk_size[32]` 正好落在 `chunk_ptr[0]` 的最低字节上；由于是 char 数组赋值，只有 size 的低字节被写入，把 `chunk_ptr[0]` 从 0x...10 改成 0x...40。此时 `show(0)` 不再读原 chunk，而是读新地址处的 8 字节，若该地址恰好保存着一个堆指针，就能泄露 heap base。

## 原理

- **数组布局**：BSS 中 `chunk_size` 位于 0x4040C0，`chunk_ptr` 位于 0x4040E0，两者相差 0x20，即 `chunk_size` 恰好有 32 个字节元素，`chunk_size[32]` 与 `chunk_ptr[0]` 首字节重叠。
- **越界索引被放行**：add 的检查是 `if (chunk_number > 0x20) exit()`，索引 0x20（第 33 个块）合法通过，随后执行 `chunk_size[chunk_number] = size[0]`。
- **只有低字节被改写**：`chunk_size` 是 `char` 数组，C 赋值会把 `size[0]` 截断成 1 字节再存储，所以只覆盖 `chunk_ptr[0]` 的最低字节，其余 7 字节不变。示例把大小设为 0x40，使 `chunk_ptr[0]` 的低字节从 0x10 变成 0x40。
- **为什么能泄露**：改后的 `chunk_ptr[0]` 指向同一页内 +0x30 的位置（示例 0x23c9010 → 0x23c9040）。该位置处于相邻 chunk 的头部/被释放 chunk 的数据区，存着一个堆地址；`show(0)` 读取该地址的 8 字节即得到 heap base 相关的指针（示例减 0x20 得到堆基址）。
- **成功前提**：新低字节对应的地址必须落在可控/可读的堆页内，且该处保存的是有意义的堆指针；否则 show 会读到垃圾或崩溃。示例中通过精确控制分配顺序让 0x...40 处保存堆地址。

## 触发条件

- 程序把每块的 size 存进一个紧贴在指针数组之前的 char 小数组（或存在类似相邻的元数据数组）。
- 数组长度与索引上界差 1：检查使用 `>` 而不是 `>=`，允许写入下标等于数组长度。
- size 的存储是窄类型（char/byte），高字节被截断，从而只改指针的低字节；若存的是完整 qword，则会破坏指针高位导致崩溃。
- 需要 show（或其它读接口）可以按索引读取 8 字节以上内容。
- 堆内目标地址处确实存在堆指针（通常利用刚释放/切分块的 fd/bk 或 chunk 头的 prev_size）。

## 利用步骤

1. 先完成 libc 泄露等前置步骤（示例用 House of Orange 把旧 top 放进 unsorted bin 并泄 libc）。
2. 连续 add 小块，使 `chunk_number` 递增到 0x1f；最后一次 add 的索引为 0x20。
3. 这次 add 的 size 设为期望的新低字节（示例 0x40）；`chunk_size[0x20] = 0x40` 只改写 `chunk_ptr[0]` 的最低字节，0x...10 → 0x...40。
4. `show(0)`：程序按被改后的指针读取，输出该地址处的 8 字节；根据输出计算 heap base（示例 `heapbase = u64(leak) - 0x20`）。
5. 拿到 heap base 后，利用它与 mmap 区/其它缓冲区的固定偏移，继续做任意地址写或伪造结构（见关联卡片）。

## PoC

原文 exp 中该原语的关键骨架（glibc 2.23 示例，未在本机复跑）：

```python
# 前置：已通过 House of Orange 泄露 libc
for i in range(0x20 - 2):
    add(0x40, 'a')      # 使下一次 add 的索引为 0x20
# 第 33 个块：size 的低字节 0x40 写入 chunk_size[0x20]，
# 即 chunk_ptr[0] 最低字节 0x10 -> 0x40
show(0)
print(io.recv(8))       # 原指向地址的输出
heapbase = u64(io.recv(8)) - 0x20
```

实际调试时用 `telescope 0x4040E0` 观察 `chunk_ptr[0]` 的低字节变化，并在 `show` 中确认读取地址已从 0x...10 变为 0x...40。

## 变体与关联

- 变体：若 size 数组与指针数组之间还有其它字段，可利用相同思路按偏移改写更靠后的指针或标志位。
- 变体：若无法精确控制低字节，可通过多次 add/free 调整目标地址，使 `chunk_ptr` 低位落在含堆指针的 chunk 头上。
- 关联：[[binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin]]（无 free 时伪造 top size 经 sysmalloc 释放旧 top 并泄露 libc/heap 的同类前置）、[[binary-pwn-heap-unbounded-idx-pointer-array-mmap-fixed-offset-arbitrary-write]]（拿到 heap base 后的任意地址写）、[[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]（同为 BSS 元数据/长度校验缺陷类）。

## 检测与防御

- **修复根因**：索引检查改为 `chunk_number >= 0x20`（或 `< MAX`）；把 size 数组定义为与指针数组相同宽度的类型，避免窄类型截断；两组数组之间加填充/哨兵。
- **加固**：PIE 使 BSS 地址不可预测；元数据放入只读/受保护页；开启 FORTIFY/编译器数组边界检查。
- **检测**：add 次数超过数组容量但程序未拒绝；`chunk_ptr[0]` 等指针出现非对齐或低位异常变化；show 读取地址不在本进程堆映射内。
- **响应**：发现元数据数组越界写立即终止进程并保留 core，检查是否已进一步被用于任意地址读写。
