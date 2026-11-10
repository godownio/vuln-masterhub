---
id: code-analysis-reverse-obfuscation-junk-instruction-equivalence-cancellation
title: 花指令识别：按等价指令替换、运算抵消与栈平衡判定垃圾代码
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: junk-instruction-equivalence-cancellation-identification
aliases:
- 花指令识别
- 垃圾代码 JunkCode
- 等价指令替换
- 运算抵消花指令
- 栈平衡花指令
- 花指令阅读
tags:
- reverse
- obfuscation
- anti-disassembly
- junk-code
- x86
- ida
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T08:42:57+08:00'
  notes: 已对照原文第二至四节全文核对：JunkCode 示例(mov eax,eax/xchg esp,esp/jmp $+0/xor eax,0)、算术拆分(add/shl/寄存器中转)、等价解释(push/pop、jmp、call、retn、enter/leave、xor A,A、inc/dec、pushad 顺序、and 对齐、call 0h、mov push/pop、xor 位运算)、抵消对与栈平衡示例均与原文一致；识别判定(净效果/活跃性/标志位)为对原文的合理归纳。原文未给版本，已 clear。单卡为识别方法论一个主题，未混入具体 jmp-db/call5 gadget(单独成卡)。
  unverified:
  - PoC/原理中 xor ebx,ebx; add ebx,2; mul ebx,2 的 'mul ebx,2' 系沿用原文的伪指令写法，x86 无此双操作数编码(应为 imul ebx,ebx,2)，不影响识别方法本身，建议后续订正为合法指令或标注为伪代码。
---

## 一句话结论

判断一段指令是不是垃圾代码/花指令，不看它“像不像混淆”，而看它的净效果：同操作数空操作、可等价拆分的算术、成对逆运算（push/pop、add/sub、xor/xor、inc/dec、shl/shr、not/not 等）以及净栈差为 0 的保存-恢复序列；对不写内存、不调用 API、不改变后续使用的标志位的序列，可整体跳过或 NOP，只保留真实的数据流与控制流。

## 原理

- **垃圾代码（Junk Code）与花指令的区分**：垃圾代码是没有实际意义的冗余指令（`mov eax,eax`、`xchg esp,esp`、`jmp $+0`、`xor eax,0`），主要膨胀代码、干扰阅读；花指令是专门干扰调试器/反汇编器边界识别的构造（如跳进 `E8` opcode 中间的 jmp-db、`call $+5` 改返回地址），可能同时具有垃圾代码形态。识别时先看“是否有语义”，再看“是否破坏分析”。
- **等价指令替换**：同一语义可用多条指令表达，混淆器借此把一个操作拆成多个：
  - `push imm`（x86）≈ `sub esp,4; mov [esp],imm`；`pop reg` ≈ `mov reg,[esp]; add esp,4`；
  - `jmp addr` ≈ `mov eip,addr`，也常写成 `push addr; retn`；
  - `call addr` ≈ `push next_opcodeAddr; jmp addr`（压入返回地址，这也是栈溢出劫持返回地址的原理）；
  - `retn` ≈ `mov eip,[esp]; add esp,4`；`retn imm` 再额外 `add esp,imm`；
  - `enter n,0` ≈ `push ebp; mov ebp,esp; sub esp,n`；`leave` ≈ `mov esp,ebp; pop ebp`；
  - `xor A,A` ≈ `mov A,0`；`add/sub A,1` ≈ `inc/dec A`；
  - `pushad` 按 EAX、ECX、EDX、EBX、ESP、EBP、ESI、EDI 顺序保存通用寄存器；`and esp,0xFFFFFFF0` 做 16 字节栈对齐；
  - `call $+5`（`E8 00 00 00 00`）用于获取下一条指令地址（EIP），`[esp]-5` 即 call 指令地址；
  - `mov op1,op2` ≈ `push op2; pop op1`。
- **算术拆分**：`add eax,5` 可写成 `add eax,2; add eax,1; inc eax; inc eax`；`shl eax,5` 可写成 `shl eax,3; shl eax,1; shl eax,1`；也可借其他寄存器中转：`xor ebx,ebx; add ebx,2; mul ebx,2; add eax,ebx` 等价于 `add eax,4`。识别时把这些序列折叠回单条运算即可。
- **抵消型**：成对出现、净效果为零的运算：`push`/`pop`、`add`/`sub`、`adc`/`sbb`、`mul`/`div`（`imul`/`idiv`）、`inc`/`dec`、`shl`/`shr`、`xor`/`xor`、`not`/`not`；也可用间接赋值构造：`b=a; c=b` 等价于 `c=a`。
- **栈平衡型**：按后进先出成对 `push/pop`（`pushad; pushfd; push eax; push ecx; ... pop ecx; pop eax; popfd; popad`），或动态保存/恢复栈指针：`push ebp; mov ebp,esp; sub esp,1000h; ...; mov esp,ebp; pop ebp`。判定标准是整段执行后 `esp` 恢复原值。
- **为什么可判定**：这些序列不写内存（除栈上临时槽）、不调用外部 API、对最终寄存器值/标志位没有可观察影响；混淆器只是用它们填充字节、拉长指令流。只要跟踪数据流和栈指针的净变化，就能把整段视为透明。
- **误判风险**：`push/pop` 可能是真实保存现场、`xor reg,reg` 可能是真实清零、`add/sub` 可能改变标志位供后续条件跳转使用；必须确认这些指令的结果没有被后续代码读取（寄存器活跃性、EFLAGS 使用、栈槽后续访问），不能只凭形态删除。

## 触发条件

- 反汇编/伪代码中出现大量无意义运算、寄存器自操作、重复的 push/pop、成对逆运算或异常长的算术序列。
- 需要快速定位真实逻辑，或准备批量 NOP/折叠花指令以恢复反编译。
- 有基本的指令语义与栈平衡判断能力（IDA/OD 静态或动态辅助）。

## 利用步骤

1. 在反汇编中标记候选：同操作数指令、只写不读的寄存器运算、成对逆运算、无目标的 jmp/call、异常栈操作。
2. 做数据流/栈流检查：确认候选不写关键内存、不调用 API、不影响后续使用的标志位；计算整段 `esp` 净变化是否为 0。
3. 对等价替换序列，按语义折叠为单条指令（在笔记/伪代码中还原）；对抵消对，成对删除或在分析中忽略。
4. 对确实要修改二进制的场景，把花指令整段 patch 成 `0x90`，再按 `C`/`P` 重新定义指令与函数；patch 前备份并确认该段没有被其他跳转复用。
5. 重新 F5/动态单步验证：恢复后的控制流、寄存器与栈状态应与原程序真实语义一致。

## PoC

```text
; 垃圾代码（净效果为零）
mov eax,eax
xchg esp,esp
jmp $+0
xor eax,0

; 等价拆分
add eax,5   ==  add eax,2; add eax,1; inc eax; inc eax
shl eax,5   ==  shl eax,3; shl eax,1; shl eax,1
add eax,4   ==  xor ebx,ebx; add ebx,2; mul ebx,2; add eax,ebx

; 抵消型
push eax / pop eax
add eax,2 / sub eax,2
xor eax,2 / xor eax,2
inc ebx; inc ebx / sub ebx,2
shl ebx,2 / shr ebx,2

; 栈平衡（LIFO）
pushad; pushfd; push eax; push ecx; push ebx; push esi
pop esi; pop ebx; pop ecx; pop eax; popfd; popad

; 动态恢复栈指针
push ebp; mov ebp,esp; sub esp,1000h; ...; mov esp,ebp; pop ebp
```

无二进制级 PoC；以上为识别与折叠的判定样例。

## 变体与关联

- **反汇编错位型花指令**：jmp-db（跳转落到 `E8` 等 opcode 中间）、`call $+5` 改返回地址、无效条件跳转；它们不只是“无意义”，还会破坏线性扫描/递归遍历，单独成卡。
- **关联**：[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]（jz 跳过 E8 与 IDA 修复）、[[ctf-reverse-oep-junk-code-call-add-retn]]（call $+5/add [esp]/retn）、[[code-analysis-reverse-obfuscation-tcc-junk-controlflow-idc-deobfuscation]]（编译器批量生成的等价替换与无效跳转）、[[code-analysis-reverse-obfuscation-arm64-jni-onload-junk-jump-br-patch]]（ARM64 跳板花指令）。
- **边界**：带副作用的“看似垃圾”指令（写内存、改标志位、调用 API）不能按垃圾处理；多线程/信号处理场景下栈与寄存器的“净效果”可能被其他执行流观察。

## 检测与防御

- 这是本地逆向分析方法，不产生攻击面。混淆设计侧若想提高成本，应避免使用固定、可折叠的等价序列，改用数据相关或运行时解密的构造（但会增加性能与体积开销）。
- 分析侧：先做寄存器活跃性与标志位使用分析，再决定 NOP/折叠；批量 patch 前小范围验证，保留原始样本与 patch 记录；动态执行验证 patch 后语义。
- 检测信号（蓝队识别混淆二进制）：异常高的“只写寄存器”运算密度、成对逆运算、与功能无关的栈保存/恢复、大量 `pushad/pushfd` 与 `xor reg,reg` 组合。
