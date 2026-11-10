---
id: binary-pwn-heap-topchunk-exhaustion-malloc-consolidate-fastbin-unsorted-libc-leak
title: 只能申请 fastbin 大小时用耗尽 top chunk 触发 malloc_consolidate：fastbin 块被合并进 unsorted bin，借 UAF-Read 读出 main_arena 指针
type: scenario
domain: binary
path: binary/pwn/heap
technique: top-chunk-exhaustion-malloc-consolidate-libc-leak
tags:
- pwn
- heap
- glibc
- fastbin
- malloc-consolidate
- unsorted-bin
- top-chunk
- libc-leak
- uaf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:22:57+08:00'
  notes: 已对照原文核对：malloc_consolidate 两个触发点（largebin 请求与 use_top 不足）、2092 次 0x30 申请耗尽 top、9 次 free 填满 tcache 后进 fastbin、add(10,1) 触发合并、show(8) 读 unsorted bin fd 泄 libc 均与原文一致；PoC 与原文 dump 摘录一致。未验证点：未在本机复现该 2092 次申请序列，泄露偏移 0x1d2cc0/0x1f6cc0 依赖目标 libc，原文未标注 glibc 版本区间故未设 affected_versions。
url: /docs/binary/pwn/heap/binary-pwn-heap-topchunk-exhaustion-malloc-consolidate-fastbin-unsorted-libc-leak/
draft: false
kb_aliases:
- malloc_consolidate 触发时机
- fastbin chunk 合并
- top chunk 不够时合并
- 无法申请 largebin 时如何泄露 libc
- fastbin 合并进 unsorted bin
- Complaint Conglomerate
- 2092 个 0x40 chunk 耗尽 top
---

## 一句话结论

当题目只允许申请 fastbin 范围内的两种大小（如 0x30 与 0x50）时，无法用「申请大于 fastbin 的块」来让释放的块自然进入 unsorted bin；此时可以先 free 一批 fastbin 块，再反复申请同尺寸小块把 top chunk 消耗到不足，迫使 `malloc` 走 `use_top` 分支并因 `have_fastchunks` 为真而调用 `malloc_consolidate`，把 fastbin 链表里的块合并成一个进 unsorted bin，最后用 UAF-Read 读出 `main_arena` 指针算出 libc 基址。

## 原理

- **fastbin 里释放的块不会自动进 unsorted bin**：fastbin 的释放只把块头插进 `fastbinsY[idx]`，不写 `fd`/`bk` 为 arena 指针；只有经 `malloc_consolidate` 合并后才被插入 unsorted bin，此时它的 `fd`/`bk` 才是 `main_arena + 0x60` 一类 libc 地址。
- **两个触发点**：`_int_malloc` 中，一是请求大小属于 largebin（`idx = largebin_index(nb)` 后若 `have_fastchunks` 则 consolidate）；二是走 `use_top` 时 top chunk 剩余不足以满足 `nb + MINSIZE`，若存在 fastbin 块就 consolidate 后再重试。只允许 fastbin 大小的程序只有第二条路可走。
- **耗尽 top 的做法**：连续申请与目标块同尺寸的小块（不释放），每次只从 top 切走一小段，直到 top 剩余 `size < nb + MINSIZE`。此时下一次申请会进入 `use_top` 的 else 分支，`malloc_consolidate` 逐个把 fastbin 块取出、按 `prev_inuse`/`next inuse` 向前后合并、再插入 unsorted bin；合并后的大块被新请求切走一部分，剩下的头部落进 unsorted bin。
- **为什么能泄露**：合并后的块在 unsorted bin 链表里，`fd`/`bk` 指向 `main_arena`（libc 数据段）内的 bin 头；程序本身存在 free 后不清指针的 UAF-Read，直接把该块内容打印出来，读到的就是 libc 指针。
- **tcache 的影响**：现代 glibc 中被 free 的同尺寸块会先进 tcache（每 size 最多 7 个），只有超出 7 个的部分才进 fastbin。因此要保证真正被 consolidate 的块在 fastbin 里，free 数量要按目标尺寸的 tcache 容量设计（例如先填满 tcache 再继续 free）。
- **combined 后的形态**：原文 dump 显示合并结果中有 `unsortedbin[all][0]` 的 `fd=bk=libc+0x1d2cc0`，同时前面几个仍是 tcache 中的 0x40 块——说明「tcache 填满 + 剩余进 fastbin + top 不足触发合并」这条路径同时成立。

## 触发条件

- 程序只能申请 fastbin 范围内的尺寸（本场景 0x30 请求得到 0x40 chunk、0x50 请求得到 0x60 chunk），无法直接申请 largebin 尺寸。
- 存在 free 不清空指针的 UAF-Read（或任意读），能读到已释放块的内容（至少前 16 字节）。
- 能反复申请不释放的小块，且总申请量足以把 top chunk 消耗到不足。
- 目标 glibc 版本的 `main_arena+0x60`（或对应 bin 头）相对 libc 基址的偏移已知，或能通过调试/符号确定。
- 释放的块不能被直接并入 top（需要保留相邻已分配块或按顺序 free，使 consolidate 时前后邻居状态符合预期）。

## 利用步骤

1. 先申请 N 个目标尺寸块（不释放），按索引保存指针。
2. 释放其中若干块（数量要覆盖该尺寸的 tcache 容量并留出 fastbin 中的块）。
3. 反复申请同尺寸块但不释放（循环上千次），持续从 top 切走内存；可在关键步骤暂停并查看 `top chunk` 剩余与 `fastbinsY` 状态。
4. 当 top 剩余不足以容纳一次 `nb + MINSIZE` 时，再申请一次：`malloc_consolidate` 触发，fastbin 块被合并并落入 unsorted bin。
5. 用 UAF-Read 读取其中一个已释放索引（此时该块已位于 unsorted bin），取前 8 字节作为 leak。
6. 用 `leak - offset` 得到 libc 基址（偏移需按目标 libc 版本核对；原文给出的两个候选偏移对应不同 libc）。
7. 后续按题目漏洞继续（本例是 memcpy 固定 0x50 字节到 16 字节栈缓冲的栈溢出，无 canary，用 ROP 做 ret2libc）。

## PoC

```python
for i in range(9):
    add(i, 0, "add")          # 0x30 请求 -> 0x40 chunk

for i in range(2092):
    add(9, 0, "emm")          # 反复申请同尺寸小块，耗尽 top chunk

for i in range(9):
    dele(i)                   # 释放，填满 tcache 后剩余进 fastbin

add(10, 1, "11111111")        # 0x50 请求：top 不足 -> use_top -> malloc_consolidate

show(8)                       # UAF-Read，读回已合并块头的 libc 指针
leak = ru("\x7f\x0a")[-7:-1]
leak = u64(leak.ljust(8, b"\x00"))
libc.address = leak - 0x1d2cc0      # 偏移需与目标 libc 匹配
```

关键内存形态（原文 dump 摘录，合并后 unsorted bin 头即 `main_arena` 内地址）：

```text
0x55bc...e4a0  0x00007f9119d4ecc0  0x00007f9119d4ecc0   <-- unsortedbin[all][0] fd/bk
0x55bc...e4b0  0x0000000000000000  0x0000000000000021
```

说明：`0x40` chunk 中已有一批停留在 `tcachebins[0x40]`（`[0/7]`~`[6/7]`），同时合并结果进入 unsorted bin，两者并存即本手法的典型现场。

PoC 未在本机执行；原文在本地打通并 `pause()` 时用调试器核对了上述状态。

## 变体与关联

- **触发点变体**：若目标允许申请 largebin 尺寸（> 0x400 左右），可直接在申请时走第一条 consolidate 分支，无需耗尽 top。
- **不依赖 UAF-Read**：若没有读接口，可改用 unsorted bin 的 `fd` 写入类攻击（unsorted bin attack），或借合并产生重叠块做后续利用。
- **tcache 时代调整**：先填满 tcache 再 free 进 fastbin；若程序调过 `tcache_count` 或 glibc 版本较老（无 tcache），free 直接进 fastbin，所需 free 数量更少。
- **关联**：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（UAF 读 unsorted bin 泄 libc 的通用前提，本卡解决「块怎么进 unsorted bin」）、[[binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin]]（靠 sysmalloc 释放旧 top 的另一条「无 free 也能拿到 unsorted/largebin」路径）、[[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]（fastbin 场景下的后续利用）、[[binary-pwn-heap-unsorted-bin-global-max-fast-bss-fake-fastbin-free-hook]]（unsorted bin 的写侧利用）。
- **边界**：top chunk 极大（申请次数不够）时不会触发；目标 glibc 中 `malloc_consolidate` 有「fastbin 块必须对齐/大小与链表匹配」的检查，若堆布局被破坏会直接 abort；块若在 free 时被并入 top 就不会出现在 unsorted bin。

## 检测与防御

- 本卡为漏洞利用侧技巧。防守重点是消除前提：释放后立即置空指针（避免 UAF-Read）、读接口按实际分配长度而非固定长度输出、栈拷贝用实际长度并做边界检查。
- 现代 glibc 的 `safe-linking`、tcache key 校验等会让「伪造/复用已释放块」更难，但本手法只要求真实释放与真实 top 耗尽，缓解有限；升级 glibc 并配合编译期加固（canary、FORTIFY）可提高门槛。
- 检测视角（对 CTF/沙箱环境）：短时间内海量同尺寸 malloc 且不 free（top 耗尽特征）、随后出现异常 unsorted bin 访问；生产环境中此类模式通常意味着堆喷射或漏洞利用正在发生。
