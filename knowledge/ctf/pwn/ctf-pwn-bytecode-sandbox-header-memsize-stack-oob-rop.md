---
id: ctf-pwn-bytecode-sandbox-header-memsize-stack-oob-rop
title: 字节码沙箱边界取自输入头部：mem_size 与真实栈缓冲尺寸脱钩导致越界写与无泄漏 ROP
type: scenario
domain: ctf
path: ctf/pwn
technique: bytecode-vm-header-memsize-stack-oob-rop
aliases:
- SBX1 沙箱逃逸
- mem_size 边界失效
- 字节码 VM 栈越界
- 无泄漏 ROP
- 沙箱边界信任根污染
tags:
- pwn
- vm
- bytecode
- sandbox
- out-of-bounds-write
- stack
- rop
- non-pie
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:46:16+08:00'
  notes: 已对照原文核对；mem_size clamp 与 rbp-0x90 尺寸脱钩、0x98 偏移覆盖返回地址、非 PIE 无 canary ROP 链均一致
---

## 一句话结论

字节码解释器用输入文件头部里的 `mem_size` 作为内存访问指令的唯一边界，但数据区实际分配在栈帧 `rbp-0x90`、只有 0x90 字节；把 `mem_size` 填成 0x1000 即可从栈缓冲越界写到 `rbp+0x08` 的返回地址，在非 PIE、无 canary 的程序里直接拼 ROP 链拿到隐藏打印函数，全程不需要信息泄漏。

## 原理

- **执行模型**：程序从 `argv[1]` 读入 `.sbx` 文件到 `.bss:0x403000`（最多 0x1000 字节），校验魔数 `SBX1` 后交给解释器。头布局为 `magic[4] + version + code_len + mem_size + code[]`。
- **指令集**：`SET/MOV/ADD/XOR/JMP/JZ` 与四条内存指令 `LOAD8/STORE8/STORE64/WRITE`。跳转表在 0x402000，逐项读出即可还原 opcode；内存指令是唯一的越界面，算术与跳转不访问内存。
- **边界根被污染**：四条内存指令都把寄存器值与 `r11` 比较，`r11` 来自头部的 `mem_size`，只做 `cmp r11d, 0x1000; jbe ...; mov r11d, 0x1000` 的上限 clamp，没有下界与对齐检查，也没有和真实分配尺寸比对。
- **尺寸脱钩**：设计者以为 `.bss` 缓冲是 0x1000 字节，clamp 到同尺寸就安全；但解释器把数据区复制到了 `rbp-0x90` 的栈帧，真实长度只有 0x90。保护对象（.bss）和保护者（栈缓冲）不是同一块内存。
- **为什么能到返回地址**：数据区基址 `rbp-0x90`，返回地址在 `rbp+0x08`，偏移正好 0x98；`mem_size=0x1000` 给出的读写窗口覆盖该偏移，`STORE64` 可写 8 字节，连续四次即可覆盖返回地址及后续栈槽。
- **为什么不需要泄漏**：二进制静态链接、非 PIE（基址 0x400000）、无 canary、无 RELRO；所有 gadget 与隐藏函数地址都是编译期常量。NX 只禁止栈上 shellcode，改用程序内 `pop rdi; pop rsi; pop rdx; ret` 收尾序列即可。
- **静默失败**：越界检查失败时解释器只是跳过该指令而不是报错，偏移算错时程序会正常 HALT 返回，调试时应先用 `WRITE` 把目标位置内容回读确认落点。

## 触发条件

- 特权或隔离进程加载攻击者可控的字节码/脚本文件，头部字段（内存大小、代码长度、版本）由输入决定。
- 解释器的内存访问指令用该字段作为边界，未与真实分配长度、下界、对齐做交叉校验。
- 数据区位于栈帧且与返回地址距离落在可写窗口内；或数据区与敏感全局变量相邻。
- 二进制非 PIE/无 canary 时可直接 ROP；若开启 PIE/canary，则需要先构造泄漏或改走其他原语。

## 利用步骤

1. 逆向头部与解释器：确认 `mem_size` 的读取位置、clamp 逻辑、四条内存指令共用 `r11` 的检查代码，以及数据区基址（本题 `rbp-0x90`）。
2. 计算目标偏移：返回地址相对数据区基址为 `0x90 + 0x08 = 0x98`；确认 `STORE64` 的操作数编码（寄存器号 + 基址寄存器）与小端序。
3. 选 gadget：在非 PIE 二进制中找 `pop rdi; pop rsi; pop rdx; ret` 一类收尾序列与隐藏打印函数（本题 0x4010f0 读取 0x402190 密文并用 8 字节密钥解密输出）。
4. 构造脚本体：用 `SET` 分两次装载 64 位常量到寄存器，用 `STORE64` 依次写偏移 0x98、0xA0、0xA8 等；把 gadget 地址、密钥值、隐藏函数地址按栈布局排好。
5. 头部填 `mem_size=0x1000`、`code_len=实际长度`，套上 `SBX1` 头，按正常加载流程提交。
6. 解释器执行到 `HALT` 返回时，返回地址已被替换为 ROP 链，跳转到隐藏函数输出解密结果。
7. 调试技巧：先向越界位置写标记值，用 `WRITE` 读回栈内容确认偏移，再替换成真实链，避免静默跳过导致的“看似正常返回”。

## PoC

漏洞检查的核心形态：

```asm
mov  r11d, [rbx+0xC]   ; mem_size，来自攻击者头部
mov  eax, 0x1000
cmp  r11d, eax
jbe  short check
mov  r11d, eax         ; 只 clamp 上限
; 四条内存指令统一用 r11 做边界，未与 rbp-0x90 的 0x90 比较
```

栈帧与写入偏移：

```text
data base = rbp - 0x90
saved rip = rbp + 0x08
offset    = 0x90 + 0x08 = 0x98
STORE64 at 0x98, 0xA0, 0xA8 ...
```

链布局（示意）：

```text
rbp+0x08  0x401340   ; pop rdi; pop rsi; pop rdx; ret
rbp+0x10  0x5342582d41554449  ; 弹栈占位值，同时是隐藏函数解密密钥
rbp+0x18  0
rbp+0x20  0
rbp+0x28  0x4010f0   ; 隐藏打印函数
```

原文用该链读取 0x402190 的密文并解出 flag；未在本机复跑，但偏移、指令语义与栈布局均来自原文逆向结果。

## 变体与关联

- **边界来源变体**：`mem_size`、`code_len`、`stack_depth`、`reg_count` 等任何由输入头部声明的尺寸字段，只要被当作边界而未与真实分配比对，都可能复现同类问题。
- **越界方向**：本题向高地址写覆盖返回地址；若数据区在全局变量之前，也可向低地址写覆盖函数指针/命令缓冲区（参见已有“字节码 VM 8 位有符号偏移越界写”卡）。
- **有 PIE/canary 时**：先用 `LOAD8`/`WRITE` 读取栈上 canary 与返回地址做泄漏，再二次写入；或改打 GOT/函数指针。
- **检测思路**：对解释器输入做头部字段与真实缓冲尺寸的一致性校验，是所有字节码沙箱的第一道边界。

## 检测与防御

- **边界锚定真实分配**：内存指令的边界必须来自解释器自己分配的缓冲区长度，不能使用输入文件声明的 `mem_size`；同时做下界、上限、对齐和整数溢出检查。
- **数据区与元数据分离**：不要把数据区放在栈帧返回地址附近；使用独立映射的只读/读写页，并在页边界设置 guard page。
- **控制流保护**：开启 PIE、canary、RELRO、CET/Shadow Stack；对解释器返回路径做完整性校验。
- **输入校验**：限制 `mem_size` 不得超过实际缓冲区，拒绝异常大的头部；对 `.sbx` 做长度与字段一致性校验。
- **检测特征**：字节码中出现连续的 `STORE64` 写入接近数据区末尾/返回地址偏移；解释器进程在 HALT 后跳转到非预期函数；栈上出现程序内 gadget 地址序列。
