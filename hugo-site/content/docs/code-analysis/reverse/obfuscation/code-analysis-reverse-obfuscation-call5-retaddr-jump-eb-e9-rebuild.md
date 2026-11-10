---
id: code-analysis-reverse-obfuscation-call5-retaddr-jump-eb-e9-rebuild
title: call $+5 改写返回地址型 jmp 花指令：按 imm 宽度计算目标并用 E9/EB 重建跳转
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: call5-retaddr-jump-eb-e9-rebuild
tags:
- reverse
- obfuscation
- anti-disassembly
- junk-code
- x86
- x64
- idapython
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T08:42:59+08:00'
  notes: 已对照原文第五节与例题 NCTF cccha 的 img/09-12、junk_jmp_change_1/2 反汇编核对：布局 53 53 9C E8 00000000 5B 48 81/83 C3 imm 48 89 5C 24 10 9D 5B C3 与原文一致；目标 T=ea+8+Δ、E9 rel=Δ+3、EB rel=Δ+6 的推导复核正确(原文脚本 patch_jmp_1 取 ea+12 dword+3、patch_jmp_2 取 ea+12 byte+6 与之一致)；imm8/imm32 宽度由 48 81/48 83 区分正确。与既有 ctf-reverse-oep-junk-code-call-add-retn(call $+5;add [esp];retn 整段 NOP)字节布局与 patch 策略不同，非重复。原文未给版本，已 clear。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-call5-retaddr-jump-eb-e9-rebuild/
draft: false
kb_aliases:
- call $+5 花指令
- call 0h 获取 EIP
- add rbx imm 改写返回地址
- mov [rsp+var] retn 花指令
- jmp 变型花指令
- E9 EB 重建跳转
---

## 一句话结论

`call $+5; pop reg; add reg, Δ; mov [rsp+var], reg; popfq; pop reg; retn` 用 `call` 压入的“下一条指令地址”加上偏移，覆盖栈上的返回地址槽，`retn` 时跳到计算出的目标，净效果等价于一条 `jmp`；IDA 会因返回地址被动态改写而出现栈不平衡/异常 `retn`，patch 时应按 `add` 的立即数宽度算出原目标，把整段 NOP 后在起始处写 `E9 rel32`（imm32 版）或 `EB rel8`（imm8 版），保留跳转语义，而不是让执行流直落到下一条指令。

## 原理

- **指令序列语义**：`call $+5`（`E8 00 00 00 00`）压入下一条指令地址 `A_next`；`pop reg` 取出；`add reg, Δ` 得到 `A_next + Δ`；`mov [rsp+var], reg` 把该值写回返回地址槽（覆盖 `call` 压入的值）；`popfq`/`pop reg` 恢复标志位与被保存的寄存器；`retn` 弹出返回地址槽中的值作为 EIP/RIP。净效果 = `jmp A_next + Δ`。
- **两种机器码宽度**：
  - imm32 版：`add rbx, imm32` 为 `48 81 C3 imm32`，整段典型布局 `53 53 9C E8 00 00 00 00 5B 48 81 C3 ?? ?? ?? ?? 48 89 5C 24 10 9D 5B C3`（24 字节）；
  - imm8 版：`add rbx, imm8` 为 `48 83 C3 imm8`，整段 `53 53 9C E8 00 00 00 00 5B 48 83 C3 ?? 48 89 5C 24 10 9D 5B C3`（22 字节）。
- **目标与重建偏移**：原目标 `T = (ea + 8) + Δ`（`call` 位于 `ea+3`，长 5 字节，`pop` 从 `ea+8` 开始）。在段首 `ea` 重建跳转：
  - 写 `E9 rel32`（5 字节）时，下一条指令在 `ea+5`，`rel32 = T - (ea+5) = Δ + 3`；
  - 写 `EB rel8`（2 字节）时，下一条指令在 `ea+2`，`rel8 = T - (ea+2) = Δ + 6`（须保证跳转距离在 ±127 内）。
- **为什么不能只 NOP**：整段 NOP 后执行流会落到段后的下一条指令，而原语义是跳到 `T`（可能在前方或别处）；只有把花指令当作“真实跳转”重建，才能保持原控制流。若经动态/数据流确认原跳转的目标就是段后指令，则可以整段 NOP。
- **为什么 IDA 会看错**：`retn` 的目标由运行时栈内容决定，静态栈分析无法跟踪 `mov [rsp+var], reg` 的写入，于是报 `sp-analysis failed`、把函数体截断或显示 `JUMPOUT`；重建为显式 `E9`/`EB` 后，反汇编器能恢复基本块与交叉引用。
- **实现注意**：`pushfq/popfq` 与外层 `push/pop` 是保存现场，patch 时一并 NOP 掉；`mov [rsp+var], reg` 的栈槽偏移随编译器/函数变化，但重建跳转不依赖该偏移；必须确保 `add` 的立即数读取位置与宽度和实际机器码一致，否则目标算错。

## 触发条件

- 目标为 x86/x64 PE/ELF，反汇编中出现 `call $+5` 后跟 `pop`、`add reg, imm`、`mov [rsp+var], reg`、`retn` 的固定组合。
- IDA/Ghidra 显示异常 `retn`、栈不平衡（`sp-analysis failed`）、`JUMPOUT` 或函数边界被截断。
- 需要恢复真实控制流（静态 F5 或动态调试前修复）。
- 有 IDAPython/IDC 或十六进制编辑能力，patch 前可备份。

## 利用步骤

1. 在 IDA 中定位 `E8 00 00 00 00` 后紧跟 `pop reg`、`add reg, imm`、`mov [rsp+var], reg`、`retn` 的序列，确认是 jmp 变型而非真实调用。
2. 判断 `add` 是 `48 81 C3 imm32` 还是 `48 83 C3 imm8`（或其他寄存器的对应编码），读取 Δ 及其在指令中的偏移。
3. 计算目标 `T = ea + 8 + Δ`；按所选跳转形式计算重建偏移（`E9`: Δ+3，`EB`: Δ+6）。
4. 用 `ida_bytes.patch_byte` 把整段 22/24 字节 NOP，再在段首写 `E9 rel32` 或 `EB rel8`；或按字节精确改写。
5. `C`/`P` 重新定义指令与函数，`F5` 验证控制流；动态单步确认跳转目标与原始执行一致。
6. 若目标在 ±127 内优先用 `EB`（2 字节），否则用 `E9`（5 字节，注意覆盖段首后续字节）。

## PoC

```python
import ida_bytes, ida_idaapi, idc

def patch_imm32(ea, total_len=24):
    delta = idc.get_wide_dword(ea + 12)          # add rbx, imm32 的 imm
    for i in range(total_len):
        ida_bytes.patch_byte(ea + i, 0x90)
    rel = (delta + 3) & 0xFFFFFFFF              # E9 下一条在 ea+5，原目标在 ea+8+delta
    ida_bytes.patch_byte(ea, 0xE9)
    for i in range(4):
        ida_bytes.patch_byte(ea + 1 + i, (rel >> (8 * i)) & 0xFF)

def patch_imm8(ea, total_len=22):
    delta = idc.get_wide_byte(ea + 12)           # add rbx, imm8 的 imm
    for i in range(total_len):
        ida_bytes.patch_byte(ea + i, 0x90)
    rel = (delta + 6) & 0xFF                     # EB 下一条在 ea+2，原目标在 ea+8+delta
    ida_bytes.patch_byte(ea, 0xEB)
    ida_bytes.patch_byte(ea + 1, rel)
```

以上为按固定布局（`53 53 9C E8 00 00 00 00 5B 48 81/83 C3 ...`）重建的最小骨架；实际样本寄存器与栈槽可能不同，需先按字节确认偏移。

## 变体与关联

- **变体（不改返回地址）**：`call $+5; add [esp], imm; retn`（直接把栈顶返回地址加偏移后 retn）、`call $+5; pop reg; add reg, imm; push reg; jmp target`（压回后 jmp），见 [[ctf-reverse-oep-junk-code-call-add-retn]] 与 [[code-analysis-reverse-obfuscation-tcc-junk-controlflow-idc-deobfuscation]]。
- **变体（寄存器/宽度）**：x86 下 `add eax, imm32`、`mov [esp+var], eax`；x64 下 `add rbx/rax/rcx, imm8/imm32`；重建时始终按实际 `add` 编码读立即数。
- **关联**：[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]（jmp-db 型）、[[code-analysis-reverse-obfuscation-junk-instruction-equivalence-cancellation]]（等价替换基础）、[[ctf-reverse-nctf2022-cccha-flower-patch-chacha20]]（该花指令的完整 CTF 应用）。
- **边界**：目标距离超出 `EB` 范围时必须用 `E9`；段后指令若被其他路径引用，patch 后需重新检查交叉引用；`mov [rsp+var]` 若被后续真实代码复用，NOP 前要确认该栈槽不再被读取。

## 检测与防御

- 逆向侧：把 `call $+5` 组合列为重点扫描模式；先用动态执行读取实际 `retn` 目标做对照，再静态重建；保留原始字节与 patch 记录。
- 混淆设计侧：该类花指令的字节模式固定，容易被脚本批量识别；提高成本需让 Δ 运行时计算或与数据相关，而不是立即数。
- 检测信号（蓝队/样本分析）：二进制中大量 `E8 00 00 00 00` 后接 `pop`/`add`/`mov [rsp+var]`/`retn`；IDA 报栈不平衡的函数密集出现；`add reg, imm` 的立即数与函数实际逻辑无关。
