---
id: binary-pwn-heap-newline-size-diff-0xa-offbyone-prev-inuse-overlap
title: 换行符 off-by-one：size 差 0xA 多写 1 字节，清 PREV_INUSE 造 unsorted bin 重叠泄露
type: scenario
domain: binary
path: binary/pwn/heap
technique: newline-size-diff-0xa-offbyone-prev-inuse-overlap
aliases:
- 回车符溢出
- newline off-by-one
- size 差 0xA
- 单字节溢出清 PREV_INUSE
- smallbin reverse
- 伪 prev_size 向后合并
tags:
- pwn
- heap
- off-by-one
- glibc
- unsorted-bin
- prev-in-use
- chunk-overlap
- malloc-hook
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:37:12+08:00'
  notes: 已对照原文pwn2/pwn6源码与exp核对：compare对requested-stored==0xA返回stored+1、单字节溢出清下一块PREV_INUSE、p64(0x110)伪造prev_size、delete(2)向后合并进unsorted bin、add(0x98)取重叠块+show泄露libc均一致；pwn6尺寸变体亦一致；无CVE、无sources/source_url；未在本地复跑exp。
---

## 一句话结论

当菜单程序的 `edit` 用 `compare(stored_size, requested_size)` 校验长度，并对“请求值比存储值大 0xA（换行符）”的分支返回 `stored_size + 1` 时，`read` 会多写 1 字节；这一字节正好落在下一个 chunk 的 size 低字节，可清除 `PREV_INUSE`，配合可控的 `prev_size` 让 `free` 向后合并进已释放的 unsorted bin，形成重叠块并泄露 libc。

## 原理

- 漏洞代码形态：
  ```c
  int compare(int stored, int requested) {
      if (stored > requested) return requested;
      if (requested - stored == 0xA) return stored + 1;   // 多返回 1 字节
      return stored;
  }
  ```
  之后 `input2(ptr, compare(...))` 按返回值读取。正常输入 size 时，`read` 会把行尾换行 `0x0A` 一并算进缓冲区，差值恰好 0xA 时进入特判；本意可能是处理换行，但返回 `stored + 1` 造成单字节越界写。
- 为什么这 1 字节能改到下一块的 size：glibc 的 malloc chunk 中，一个已分配 chunk 的可用区会“借用”下一个 chunk 的 `prev_size` 字段（8 字节）。因此：
  - 用户区最后 8 字节 = 下一块的 `prev_size`；
  - 再多 1 字节 = 下一块 `size` 的最低字节。
  多写的这一字节可把下一块 `size` 的 `PREV_INUSE` 位（最低位）清 0。
- 向后合并：`free(next)` 看到 `PREV_INUSE=0`，会读取 `next->prev_size` 作为“前一块”的大小，并把指针回退该大小执行合并。若 `prev_size` 由攻击者在上一步填入（如 0x110），回退后会落进此前已 `free` 的 unsorted bin 块，产生一个覆盖 `next` 的大空闲块/重叠块。
- 重叠后的利用：重新申请一个与 `next` 重叠的块，`show` 读取 unsorted bin 的 `fd` 得到 libc 地址；再按目标 glibc 版本覆写 `__malloc_hook` 为 one_gadget（或走 tcache/free_hook 等）。
- 案例（pwn2）：`add(0x98)`、`add(0x68)`、`add(0xf0)`、`add(0x20)`，`delete(0)` 把 chunk0 放入 unsorted bin；`edit(1, 0x68+0xa, 'a'*0x60 + p64(0x110) + '\x00')`：
  - 0x60 处 8 字节写入 chunk2 的 `prev_size = 0x110`；
  - 0x68 处 `\x00` 把 chunk2 的 size 低字节从 `0x01` 改为 `0x00`（0x101 → 0x100），清掉 `PREV_INUSE`；
  - `delete(2)` 触发向后合并，`add(0x98)` 拿到重叠块，`show(1)` 泄露 unsorted bin。
- 案例（pwn6）是同一模式的不同尺寸：`add(0x90)/add(0x28)/add(0x60)`，`edit(1, 'a'*0x20 + p64(0x20+0x30+0xa0) + p8(0x90))`，用 0x28 的块越界清下一块 `PREV_INUSE`，同样得到重叠/合并。

## 触发条件

- 菜单堆题存在 `edit(index, size, content)`，长度校验函数对“请求 size 比记录 size 大 0xA”有特判并返回 `size+1`。
- 输入函数按行读取，换行符会进入长度计算（这是 0xA 差值的来源）。
- 目标 glibc 使用 `PREV_INUSE` + `prev_size` 的向后合并逻辑；下一块在 `free` 时可被合并。
- 能控制越界字节前的 8 字节（写 `prev_size`），并能申请/释放相邻 chunk。
- 存在 `show`/`read` 可读重叠块内容，用于泄露 libc。

## 利用步骤

1. **确认溢出**：反编译 `edit`，看 `compare` 是否对 `requested - stored == 0xA` 返回 `stored+1`；用本地 gdb 在 `read` 后检查下一块 size 低字节是否被改写。
2. **布置三块**：申请前块（被 edit）、目标块（下一块）、后块（防止 top chunk 干扰），并另申请一个块用于制造 unsorted bin；释放合适块把 unsorted bin 填好。
3. **构造 payload**：用户区长度 `stored`；在偏移 `stored-8` 写入目标 `prev_size`（例如 `目标块地址 - unsorted 块地址` 或伪造块大小）；在偏移 `stored` 写入 1 字节，使下一块 size 低字节清 0（即把 `0x...01` 改成 `0x...00`）。
4. **触发合并**：`delete` 目标块，让 `free` 按 `prev_size` 向后合并；用 `show` 或重新 `add` 检查是否出现大小异常/重叠。
5. **泄露 libc**：申请与目标重叠的块，读取 unsorted bin 的 `fd`，按目标 libc 版本减去 `main_arena` 偏移。
6. **收尾**：按目标 glibc 选择 `__malloc_hook`/`__free_hook`/tcache 投毒/FSOP 等路径写入 one_gadget 或 system；注意 `prev_size` 与 size 必须自洽，否则 `free` 会报 `malloc(): invalid size`。

## PoC

```python
from pwn import *

# 以 pwn2 为例：0x98 / 0x68 / 0xf0 / 0x20 四块
add(0x98)   # 0: chunk0 0xa0, 先释放进 unsorted bin
add(0x68)   # 1: 被 edit 的块（stored=0x68）
add(0xf0)   # 2: 目标块（size 0x101，PREV_INUSE=1）
add(0x20)   # 3: 隔离块

delete(0)   # chunk0 -> unsorted bin

# stored=0x68，请求 0x68+0xa -> compare 返回 0x69，多写 1 字节
payload  = b'a' * 0x60
payload += p64(0x110)      # chunk2 的 prev_size
payload += b'\x00'         # chunk2 的 size 低字节：0x01 -> 0x00，清 PREV_INUSE
edit(1, 0x68 + 0xa, payload)

delete(2)   # 按 prev_size=0x110 向后合并，与 unsorted bin 重叠
add(0x98)   # 取回重叠块
show(1)     # 读 unsorted bin fd
# lib = u64(leak) - main_arena_offset
```

案例 pwn2/pwn6 的完整 exp 还包含 `__malloc_hook` + one_gadget；具体 libc 偏移与 one_gadget 需按题目环境确定。本卡不执行样本。

## 变体与关联

- 差值不一定是 0xA：取决于输入函数如何处理 `\n`、`\r\n`、空格或长度字段；关键是找到“多返回 1”的分支。
- 也可以多返回 2/4/8 字节（例如对齐逻辑），此时可覆盖 `prev_size` 或更多 size 字节，利用方式相应变化。
- 清 `PREV_INUSE` 后若 `prev_size` 指向 top chunk，可能触发 top chunk 扩展/收缩；案例 pwn6 提到需要“微操恢复 top chunk 标志位”，本质是保证合并目标与 size 自洽。
- 与 off-by-null（清整个 size 低字节）不同：这里只改 1 字节的最低位，`prev_size` 完全可控，适合 smallbin/unsorted bin 的“向后合并”利用。
- 关联：[[binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile]]（off-by-one 改 size + unlink）、[[binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop]]（off-by-null）、[[binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget]]（__malloc_hook/one_gadget 收尾）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（unsorted bin 泄露）。
- 边界：若 glibc 版本对 `prev_size`/size 一致性检查更严格，或程序在 `free` 前清零指针/校验 size，该利用会失败；需要按目标版本调整 `prev_size` 与 fake chunk 布局。

## 检测与防御

- 代码审计：搜索 `size + 1`、`== 0xA`、`\n` 参与长度比较的分支；长度校验应以“实际可写字节数”为准，不能因换行特判放大。
- 实现：`read`/`fgets` 后显式去掉换行，并重新计算长度；用 `malloc_usable_size` 或固定上限校验；避免把“请求长度”直接作为写入长度。
- 编译/运行：启用 glibc 的 `MALLOC_CHECK_`/`glibc.malloc.check`、AddressSanitizer 检测越界；高版本 glibc 的 `tcache`/`safe-linking` 增加利用难度但非根本防御。
- 检测：监控 `free` 时的 `invalid size`/`corrupted size vs. prev_size` 报错、异常大的 `prev_size`、同一堆块被多次分配；CTF 之外可用 heap hardening 与分配器审计。
