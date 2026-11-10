---
id: binary-pwn-heap-fake-unsorted-chunk-prev-inuse-merge-bypass
title: 伪造 unsorted bin chunk 释放时衔接 top chunk：用「下下个 chunk」的 PREV_INUSE=1 跳过 free 合并检查
type: scenario
domain: binary
path: binary/pwn/heap
technique: fake-unsorted-chunk-prev-inuse-merge-bypass
tags:
- glibc
- heap
- pwn
- unsorted-bin
- top-chunk
- prev_inuse
- fake-chunk
- unlink
- libc-leak
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-3
  verified_at: '2026-11-07T21:35:31+08:00'
  notes: 已对照原文核对；图 12-18/24-28 的 free+997 corrupted size vs. prev_size、free+1011 段错误、test byte ptr [r15+rcx+8],1 判定下下个 chunk 的 PREV_INUSE、置 1 后伪造 chunk 正常进 unsorted bin(图 19)、填充 size 0x11 仍正常释放并拿 flag(图 22/23) 与卡一致；dedup 除草稿自身 exact duplicate 外 related 候选(newline-size-diff 清 PREV_INUSE 触发合并、house-of-peach sysmalloc、uaf-unsorted-bin-libc-leak 直接 free 真实大块)结论均为不同链或方向相反，dedup_review 成立。未验证点：结论绑定 glibc 2.27 与该题布局，原文仅显示调试环境 libc-2.27.so，属目标环境版本、未声明组件受影响区间，卡未设置 affected_versions、cve 为空(不猜)；frontmatter 无违规 sources/source，路径 binary/pwn/heap 合法。
url: /docs/binary/pwn/heap/binary-pwn-heap-fake-unsorted-chunk-prev-inuse-merge-bypass/
draft: false
kb_aliases:
- fake chunk 与 top chunk 衔接
- 伪造 unsorted bin chunk
- corrupted size vs. prev_size 绕过
- 下下个 chunk 的 prev_inuse
- 伪造 size 释放进 unsorted bin
---

## 一句话结论

堆题中当只能申请小 chunk、需要伪造或篡改 size 造一个 unsorted bin 大小的 chunk 并 `free` 以泄漏 libc 时，free 会因「高地址相邻 chunk 被判定为已释放」进入向前合并与 unlink 完整性检查，触发 `corrupted size vs. prev_size` 或段错误；常规做法是在 `伪造chunk地址 + 伪造size` 处填 `top chunk地址 - 该地址` 的 size 使其「衔接 top chunk」，但真正起作用的只是让该处高地址方向「下下个 chunk」的 size 里 `PREV_INUSE=1`——只要在该位置填 1，glibc 就判定高地址相邻 chunk 未释放、跳过合并，伪造 chunk 即可正常进入 unsorted bin，填充的 size 甚至可以是 0x11 这类不合理值。

## 原理

- glibc `free` 流程：先判断待释放 chunk 是否紧邻 top chunk（相邻则直接合并回 top chunk）；否则判断前后相邻 chunk 是否已被释放，若已释放则做向后/向前合并（unlink），并对被合并的 chunk 做完整性检查。
- **低地址相邻 chunk**：用当前待释放 chunk 的 `size` 字段 `PREV_INUSE` 位判断（为 0 表示低地址 chunk 已释放，启用当前 chunk 的 `prev_size`，并校验 `prev_size` 与那个 chunk 的 `size` 一致）。
- **高地址相邻 chunk**（文中记作 chunk￥ = `chunk + chunk.size`）：不是看 chunk￥ 自己的标志，而是用**下下个 chunk**（`chunk￥ + chunk￥.size`）的 `size` 字段 `PREV_INUSE` 位判断，对应汇编 `test byte ptr [r15 + rcx + 8], 1`；该位为 0 时 glibc 判定 chunk￥ 已被释放，进入向前合并。
- 一旦判定 chunk￥ 已释放，glibc 会做两类检查，伪造 chunk 都过不了：
  1. `cmp rdx, qword ptr [r15 + rdx]`（`free+997`）：chunk￥ 的 size（去掉标志位）与「chunk￥ 的下一个 chunk 的 `prev_size`」比较，不符即 `malloc_printerr("corrupted size vs. prev_size")`。
  2. unlink 时的双向链表完整性 `fd->bk == chunk￥ && bk->fd == chunk￥`（`free+1011` 处取 `rdx = chunk￥->fd`、`rsi = chunk￥->bk` 再 `cmp r15, [rdx+0x18]`）；伪造 chunk 的 fd/bk 是普通堆数据，会解引用到 `0x18` 之类非法地址而 SIGSEGV。
- 因此关键不是「真的与 top chunk 相接」，而是**不要让 glibc 进入合并分支**：在 `&chunk￥ + chunk￥.size + 8`（即下下个 chunk 的 size 字段）写 1，把 `PREV_INUSE` 置 1，glibc 就认为 chunk￥ 未释放，跳过向前合并与上述完整性检查，直接把伪造 chunk 链入 unsorted bin。
- 常规「衔接 top chunk」之所以有效，本质也是 top chunk 的 `PREV_INUSE` 位为 1 起到同样作用；所以填充的 size 不必精确等于到 top chunk 的距离，只要保证那个 prev_inuse=1 被置上即可。
- 低地址方向同理：若把伪造 chunk 的 size 由 `0x451` 改成 `0x450`（`PREV_INUSE=0`）且 `prev_size` 为 0，glibc 会判定低地址 chunk 已释放、去比较 `prev_size` 与 size 并尝试向后合并；把 `prev_size` 与相邻 size 伪造一致（或保持 `PREV_INUSE=1`）可避免/通过。

## 触发条件

- glibc 2.x 堆题（文中为 2.27），需要伪造/篡改 chunk size 造出 unsorted bin 范围（如 0x450）的 chunk 并 `free` 以泄漏 libc。
- 能向伪造 chunk 之后的可控内存写数据（堆溢出、UAF、结构体字段写入），以布置 size 与 `PREV_INUSE`。
- 目标 libc 版本未引入更严格的额外检查（高版本 glibc 的 unlink/size 校验更多，需相应调整伪造字段）。

## 利用步骤

1. 在堆上可控区域伪造 chunk：写 `prev_size`、`size`（如 `0x451`，含 `PREV_INUSE=1`）及 fd/bk 占位。
2. 在 `fake + size` 处布置衔接数据，最简形式 `p64(0x10) + p64(0) + p64(1)`：让该位置的「chunk￥」size 为 `0x11`，并在 `&chunk￥ + 0x10 + 8`（下下个 chunk 的 size 低位）填 1。传统做法则填 `top_chunk_addr - (fake + size)` 作为 size。
3. `free` 伪造 chunk；glibc 因下下个 chunk 的 `PREV_INUSE=1` 判定高地址相邻未释放，跳过合并，chunk 正常进入 unsorted bin。
4. 通过 UAF/show 读出 fd/bk（`main_arena` 附近地址），计算 `libc_base`。
5. 后续用 overlapping / tcache poisoning 打 `__free_hook` 等完成 getshell。

## PoC（最小化）

```python
# 伪造 0x450 大小的 chunk（size=0x451，含 PREV_INUSE）
payload = p64(0)*21 + p64(0x451) + p64(0) + p64(0xf0)
add(1, payload)                      # 经堆溢出/结构体写入伪造 chunk

# 在 fake+size 处布置：size=0x11，其后下下个 chunk 的 prev_inuse 置 1
add(1, p64(0)*6*2 + p64(0)*11 + p64(0x11) + p64(0) + p64(1))

free(fake_idx)                       # 不再报 corrupted size vs. prev_size，正常进 unsorted bin
show(fake_idx)                       # fd/bk 泄漏 main_arena → libc_base
```

原文对照实验：填充 size `0x31`/`0x30` 且未置 prev_inuse 时，`free+997` 报 `corrupted size vs. prev_size`、`free+1011` 因 `rdx+0x18=0x18` 段错误；改为 `... p64(0x31) + p64(0)*4 + p64(0) + p64(1)`（把下下个 chunk 的 `PREV_INUSE` 置 1）后正常 free；进一步把填充 size 改成 `0x11` 仍能正常释放 0x450 伪造 chunk 并拿到 flag。

## 变体与关联

- House of Einherjar（off-by-null 清 `PREV_INUSE` + 伪造 `prev_size`/fake chunk 触发向后合并）、unsafe unlink（glibc 2.23 伪造 chunk 劫持指针）、House of Peach（借 sysmalloc 释放旧 top chunk 造 unsorted/large bin）同为「伪造 chunk + 合并检查」技巧，但方向相反：它们要**触发**合并/unlink，本技巧要**避免**合并以安全释放伪造 chunk。
- 与 `corrupted size vs. prev_size`、unlink 完整性检查（`fd->bk`/`bk->fd`）同源；高版本 glibc 还有 size 对齐、tcache key 等额外校验。
- 与 UAF 泄漏 libc、unsorted bin overlapping、`__free_hook` one_gadget 链组合成完整堆题利用。

## 检测与防御

- 这是利用技巧而非产品漏洞；防御侧依靠 glibc 高版本加强的 unlink/size 检查与堆元数据完整性校验，以及应用避免 UAF、堆溢出与可控 size 字段（结构体读入长度与分配长度一致、`free` 后指针置空）。
- 调试/检测特征：`free+997` 的 `corrupted size vs. prev_size`、`free+1011` 的非法地址解引用、异常 size 字段、unsorted bin 中出现来源不明的 chunk、堆上被手工布置的 `prev_inuse=1`。
