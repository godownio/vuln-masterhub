---
id: code-analysis-reverse-obfuscation-broken-code-alignment-opcode-swallow
title: 代码对齐扰乱：用多字节指令操作码吞掉后续字节使反汇编错位，单步进入正确指令边界绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: broken-code-alignment-opcode-swallow
aliases:
- Breaking Code Alignment
- 代码对齐扰乱
- 反汇编错位
- 操作码吞字节
- A3 扰乱反汇编
- 单步进入正确代码
tags:
- reverse
- obfuscation
- anti-disassembly
- x86
- opcode
- disassembler
- ollydbg
- single-step
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V485
  verified_at: '2026-11-10T21:32:47+08:00'
  notes: 已对照原文全文与31张图核对：代码对齐扰乱例（图22）中 0041510F FFE3 JMP EBX(EBX=415117)、00415115 A3 68 72 01 FF 被线性反汇编解析为5字节MOV吞掉后续字节、00415117 72 01 为真实指令(JB)，与卡片PoC逐字节一致；图23单步进入415117显示正确代码，与绕过方法一致；A3=MOV moffs32,EAX长度5字节的原理正确；无 sources/source_url、无文章ID/URL长摘录；dedup两候选(jz-skip-E8花指令、x86-64指令重叠双流)机制不同，dedup_review成立；原文其余反调试技术跳过理由经抽查成立（引用的11张既有卡均存在且verified）；原文未涉版本，未设affected_versions；dup-scan.json早于建卡且无本卡pair。未验证点：未复跑样本
---

## 一句话结论

在跳转目标前故意放一个多字节指令的操作码（如 `A3` 对应 `MOV [disp32], EAX`），让线性反汇编从这个“假边界”解析并把后续真实指令的字节吞进操作数，静态视图就会出现错位/乱码；程序实际通过 JMP 直接跳到正确地址执行，分析时从跳转目标重新反汇编或单步进入即可恢复真实指令。

## 原理

- **x86 变长指令**：同一条指令的长度取决于操作码与寻址方式，`A3` 后跟 4 字节立即数/地址，整条长度为 5 字节；反汇编器若从错误边界开始解析，就会把后续字节当作自己的操作数消耗掉。
- **线性扫描 vs 实际执行流**：静态反汇编通常从入口或已知跳转目标线性扫描；攻击者在 `JMP` 前插入一个不会被执行的 `A3` 字节，反汇编器在 `415115` 处把它解析成 5 字节 `MOV`，从而吞掉 `415117` 的真实指令（如 `72 01`），静态视图与 CPU 实际执行流不一致。
- **程序为什么能正常运行**：`41510F` 的 `JMP` 直接跳到 `415117`，`415115` 的扰乱字节根本不会被执行；它们只污染静态反汇编，不影响运行逻辑。
- **分析者为什么会被误导**：在错误视图上下断点/读代码会得到错误指令，单步时调试器也可能按错误边界显示；但 CPU 从跳转目标取指，单步进入 `415117` 后就会暴露真实指令。
- **绕过本质**：不要相信单一线性反汇编视图，从每个分支/跳转目标重新同步反汇编（IDA 的 U/取消定义后重新分析、OllyDbg 从目标地址跟进），或用单步/动态执行确认真实指令边界。

## 触发条件

- 目标是 x86/x86-64 变长指令集程序，且静态反汇编器未从所有跳转目标递归同步。
- 恶意代码/保护器在跳转前插入了扰乱字节，且这些字节不会被实际执行。
- 分析者依赖线性反汇编视图下断或阅读。

## 利用步骤

1. 在跳转指令（如 `41510F JMP ...`）后看到反汇编显示异常（指令吞并、后续代码乱码/未显示）。
2. 记录跳转目标地址（如 `415117`），在其上重新反汇编或下断点。
3. 单步进入目标地址，确认 CPU 实际执行的指令（如 `72 01` = `JB`），而不是线性视图显示的长指令。
4. 在 IDA 中把错误位置取消定义（U），从跳转目标重新创建代码；在 OllyDbg 中从目标地址右键“Follow”/重新分析。
5. 清理这类扰乱后继续分析真实控制流。

## PoC

```text
0041510F  FFE3                 JMP EBX              ; EBX = 00415117
00415111  C9                   LEAVE
00415112  C2 0800              RET 8
00415115  A3 68 72 01 FF       MOV DWORD PTR DS:[FF017268], EAX   ; 扰乱字节，不执行
00415117  72 01                JB SHORT 0041511A    ; 真实指令
```

## 变体与关联

- 变体：用其他多字节操作码（`C7`、`E8`、`E9` 等）吞掉后续字节；或把跳转目标指到某条指令的中间字节，形成指令重叠/隐藏流。
- 变体：与花指令、SMC 解密循环组合，进一步干扰静态分析。
- 关联：指令重叠的双流隐藏见 [[code-analysis-reverse-obfuscation-x86-64-instruction-overlap-dual-stream]]；`jz` 跳过 `E8` 的线性扫描花指令见 [[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]；`call $+5` 改写返回地址型花指令见 [[code-analysis-reverse-obfuscation-call5-retaddr-jump-eb-e9-rebuild]]。
- 边界：原文只给出一段 OllyDbg 截图与单步说明，未给出样本；具体地址/字节随程序不同，需按实际跳转目标重新同步。

## 检测与防御

- 分析侧：使用递归下降反汇编、从所有跳转目标同步；对可疑位置单步执行或动态跟踪确认真实边界。
- 检测：代码段中出现大量不会被执行的多字节操作码/跳转前的垃圾字节；反汇编视图与运行轨迹不一致。
- 防御（对软件保护）：这类手法只提高分析成本，不能替代真正的代码加密/虚拟化；对恶意样本检测可结合动态行为而非静态字节。
