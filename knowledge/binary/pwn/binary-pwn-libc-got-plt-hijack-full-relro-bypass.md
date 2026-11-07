---
id: binary-pwn-libc-got-plt-hijack-full-relro-bypass
title: Full RELRO 绕过：改写 libc 自身 .got.plt 的 strlen 槽为 one_gadget
type: scenario
domain: binary
path: binary/pwn
technique: libc-internal-got-plt-hijack-full-relro-bypass
aliases:
- libc GOT 劫持
- hijack_libc_got
- Full RELRO 绕过
- 改写 libc .got.plt
- j_strlen off_21A098
- strlen GOT one_gadget
- libc 内部函数指针覆写
tags:
- binary
- pwn
- got
- plt
- libc
- relro
- one-gadget
- arbitrary-write
- bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:22:59+08:00'
  notes: 已对照原文与图02/04/06核对：puts 调 j_strlen、j_strlen 通过 .got.plt off_21A098 跳 strlen、劫持该槽为 one_gadget/条件 gadget；卡中已注明需确认 libc 自身 .got.plt 可写。未在本机复跑。
---

## 一句话结论

Full RELRO 只保护主程序自己的 GOT；如果 libc 内部仍通过可写的 `.got.plt` 槽间接调用某个函数（如 `j_strlen` 通过 `off_21A098` 跳到 `strlen`），在获得任意写后可以把该槽改成 one_gadget 或设置条件的 gadget，下一次 libc 调用该函数（如 `puts` 内部调用 `strlen`）就会跳转到攻击者指定的地址，从而绕过主程序 Full RELRO。

## 原理

- **Full RELRO 的保护范围**：`-z relro -z now` 让主程序的重定位在启动时全部完成，并把主程序 GOT 相关页 `mprotect` 为只读。但共享库 libc 有自己独立的映射与 RELRO 状态；主程序的 Full RELRO 不会把 libc 的 `.got.plt` 变成只读。
- **libc 内部也有 PLT/GOT**：libc 的 `puts` 等函数内部会调用 `strlen`、`memcpy` 等；在部分构建中，这些调用通过 libc 自己的 `.got.plt` 槽间接跳转。样例中 `j_strlen` 的代码是 `bnd jmp cs:off_21A098`，而 `off_21A098` 位于 `.got.plt`，初始值指向 `strlen`。只要该页可写，覆写这个槽就能劫持 libc 内部调用。
- **为什么能绕过 Full RELRO**：攻击者写的不是主程序 `puts@got.plt`（已被 RELRO 保护），而是 libc 内部的 `strlen` 槽；主程序的 RELRO 检查不会覆盖 libc 的映射权限。是否成功取决于目标 libc 是否也启用了 full RELRO/`-z now`，需先用 `/proc/pid/maps` 或试写确认该页权限。
- **one_gadget 条件**：one_gadget 通常要求特定寄存器/内存条件（如 `rdx==0`、`r10==0`）。若一次不满足，可劫持两个 libc GOT 槽，或对同一函数劫持两次：第一次跳到设置条件的 gadget，第二次跳到 one_gadget；也可以选择满足当前寄存器状态的 one_gadget 偏移。
- **触发路径**：覆写 `libc.got['strlen']` 后，调用 `puts(buf)` 等会内部调用 `strlen` 的函数，控制流进入 one_gadget；由于 `puts` 的调用上下文寄存器状态可预测，可据此挑选 one_gadget。
- **地址计算**：`strlen_got = libc.address + <off_21A098 相对偏移>`；`one_gadget = libc.address + <one_gadget 偏移>`。需要先泄漏 libc 基址（GOT 泄漏、`__environ`、格式化字符串等）。

## 触发条件

- 已有任意地址写（堆 UAF/溢出、格式化字符串、栈 ROP 写等）和 libc 基址泄漏。
- 目标 libc 内部的 `.got.plt` 槽可写（未对该库启用 full RELRO/`-z now`，或该页权限为 rw）。
- 知道目标 libc 版本，能定位 `j_strlen`/`strlen` 的 GOT 槽偏移与可用 one_gadget。
- 程序在覆写后会调用经过该槽的 libc 函数（如 `puts`/`printf` 内部调用 `strlen`）。

## 利用步骤

1. 泄漏 libc 基址，确定 libc 版本与 `strlen` 的 GOT 槽偏移（如样例 `off_21A098`）。
2. 检查该槽所在页权限：`/proc/<pid>/maps` 或 gdb `info proc mappings`，确认可写；若只读，换其他仍可写的 libc 内部槽。
3. 用任意写把 `strlen` 槽覆盖为 one_gadget 地址或设置条件的 gadget。
4. 触发经过该槽的 libc 函数（如调用 `puts` 输出一段字符串，`puts` 内部会调用 `strlen`）。
5. 若 one_gadget 条件不满足，劫持第二个槽或第二次触发，先设置 `rdx/r10` 等条件再执行 one_gadget。
6. 得到 shell 后验证权限；失败时用 gdb 检查槽值、页权限与寄存器条件。

## PoC

```python
from pwn import *

libc = ELF("./libc.so.6")
io = process("./chall")

# 假设已通过漏洞泄漏 puts 地址并算出 libc base
libc.address = leaked_puts - libc.sym["puts"]

strlen_got = libc.address + 0x21a098       # j_strlen 的 GOT 槽（按目标 libc 调整）
one_gadget = libc.address + 0xe3afe        # 按 one_gadget 工具输出选择

# 任意写：把 strlen GOT 槽改成 one_gadget
write_primitive(strlen_got, one_gadget)

# 触发 puts -> 内部 strlen -> one_gadget
io.sendline(b"trigger")
io.interactive()
```

> 具体偏移、one_gadget 与写原语按目标环境调整；关键是确认 libc 内部 GOT 槽可写。

## 变体与关联

- 变体：覆写 libc 的 `memcpy`、`free`、`__strlen_avx2` 等内部 GOT 槽，选择调用频繁且参数可控的函数。
- 变体：用两个槽/两次调用满足 one_gadget 的寄存器条件（第一次 gadget 设置 `rdx/r10`，第二次 one_gadget）。
- 变体：若 libc 也启用 Full RELRO，可转向 `__malloc_hook`/`__free_hook`（旧版 glibc）或其他可写函数指针。
- 关联卡片：[[binary-pwn-setuid-got-plt-lazy-binding-hijack]]、[[binary-pwn-format-string-got-hijack]]、[[binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget]]、[[binary-pwn-elf-copy-relocation-writable-security-state]]。

## 检测与防御

- 检测：libc `.got.plt` 页出现写入；`strlen`/`memcpy`/`free` 的 GOT 槽值不再指向 libc 代码段。
- 检测：`puts`/`printf` 等调用后控制流跳到 one_gadget 常见地址（`execve("/bin/sh")` 附近）。
- 防御：对 libc 也启用 Full RELRO/`-z now`；使用静态链接或 musl 等不同实现；开启 CFI/Shadow Stack。
- 防御：消除任意写漏洞；开启 ASLR/PIE；监控 GOT/函数指针完整性。
