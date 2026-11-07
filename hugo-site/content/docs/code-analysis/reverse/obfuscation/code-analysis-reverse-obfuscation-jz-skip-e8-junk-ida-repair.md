---
id: code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair
title: jz 跳过 E8 的线性扫描花指令：xor/jz/E8 垃圾字节与 IDA 修复
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: jz-skip-e8-junk-ida-repair
tags:
- reverse
- obfuscation
- anti-disassembly
- ida
- junk-code
- x86
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:45:13+08:00'
  notes: 已对照原文与唯一图片(IDAT 0x140001505 xor/0x140001507 jz+2/0x140001509 call 14177FF06h)核对：xor/jz/E8 花指令字节布局、jz 跳过 2 字节落点、IDA 误识 CALL、U/C/F5/Alt+P 修复步骤均与原文一致；PoC 中 0x1400015FC 例子与原文一致。原文另有 qiandao(PyInstaller)与两处自定义 Base64，作者跳过理由成立(已有 ctf-reverse-base64-table-index-mutation、code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract 卡)。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair/
draft: false
kb_aliases:
- E8 花指令
- jz 跳过 call
- 线性扫描花指令
- IDA JUMPOUT 修复
- 反汇编错位
- Roses 花指令
---

## 一句话结论

当正常代码中插入 `31 C0 74 02 E8 05`（`xor eax,eax; jz +2; E8 05`）时，CPU 的 `jz` 会跳过 `E8 05` 两个垃圾字节，但 IDA 的线性扫描会把 `E8` 当作 5 字节 `CALL` 的开头、把后续正常指令字节误读成巨大目标地址，导致反汇编错位/`JUMPOUT`；在 `E8` 处按 `U`、在真实目标处按 `C`，再按 `F5`（必要时 `Alt+P` 重新分析函数）即可恢复。

## 原理

- **x86 指令长度可变**：`E8` 是 `CALL rel32` 的 opcode，占 5 字节（`E8 + 4 字节相对地址`）；`74 xx` 是 `JZ rel8`，占 2 字节。反汇编器必须知道指令边界，线性扫描（从前往后逐字节解码）在遇到数据/花指令时容易错位。
- **花指令字节序列**：`31 C0`（`xor eax,eax`，清零并置 ZF=1）→ `74 02`（`jz +2`，ZF=1 时跳过下 2 字节）→ `E8 05`（两个字节，CPU 永远不执行）。CPU 从 `jz` 结束地址 +2 落到真实指令；IDA 从 `E8` 开始解码，把后面 4 字节当作 `rel32`，得到一个远超模块范围的 `CALL` 目标。
- **典型症状**：
  - `call near ptr 14177FF06h` 之类远超模块大小的目标；
  - `jz short near ptr loc_xxx+2`（跳进指令中间）；
  - 反汇编出现大段灰色 `db`/空白；
  - `F5` 反编译出现 `JUMPOUT(0x...)`；
  - Hex View 中 `E8` 后跟的是 `E9`/`48`/`C7` 等正常指令开头，而不是有规律的 4 字节地址。
- **为什么修复有效**：在 `E8` 处 `U`（Undefine）把错误指令还原为字节，在真实目标处 `C`（Code）重新定义指令起点，IDA 会从正确边界重新解码；`Alt+P` 让 IDA 重新分析函数，刷新交叉引用/栈帧。
- **注意**：不是所有 `jz` 后跟 `call` 都是花指令；要先计算 `jz` 的相对偏移，确认它确实跳过了 `E8` 的 5 个字节（或至少跳过 `E8` 开头），否则可能误删真实调用。

## 触发条件

- 目标为 x86/x64 PE/ELF，经过花指令/混淆处理；IDA/Ghidra 反汇编出现上述症状。
- 花指令模式为 `xor reg,reg; jz +2; E8 xx` 或类似“条件跳转跳过 CALL opcode”的变体。
- 需要静态分析真实逻辑，或动态调试前先修复反汇编。
- 有 IDA（U/C/F5/Alt+P）或等价的反汇编器编辑能力。

## 利用步骤

1. 在 IDA 中看到异常 `CALL` 目标/`JUMPOUT`/大段 `db` 时，切到 Hex View 检查该地址字节。
2. 识别 `31 C0 74 02 E8 05`（或类似 `xor/jz/E8`）模式；计算 `jz` 的目标地址，确认它跳过了 `E8` 及其后字节。
3. 在 `E8` 所在地址按 `U`（Undefine），把误识别的 CALL 还原为字节。
4. 在 `jz` 的目标地址（真实指令开头）按 `C`（Code），让 IDA 从正确边界解码。
5. 按 `F5` 反编译；若仍不可读，按 `Alt+P` 重新分析函数，或对函数头按 `P` 重新创建函数。
6. 对多处相同花指令重复；修复后用动态调试/单步验证执行流与静态分析一致。
7. 本题修复后 `sub_1400014E7` 显示 `aRoses[i%5] ^ Buffer[i]` 的 XOR 循环，继续分析自定义 Base64。

## PoC

```text
; 花指令字节（x86-64）
31 C0          xor eax, eax        ; ZF=1
74 02          jz  +2              ; 跳过下 2 字节
E8 05          (垃圾字节)          ; CPU 不执行；IDA 误读为 CALL 开头
<真实指令>                          ; jz 落点

; IDA 误读示例
1400015FC: E8 05 E9 77 01 00     call near ptr 14177FF06h
; 修复：1400015FC 按 U；1400015FE 按 C；F5
```

```text
; 修复后伪代码（示例）
for ( i = 0; i < size; ++i )
    dst[i] = key[i % 5] ^ src[i];
```

## 变体与关联

- **变体（其他条件跳转）**：`jmp +2`、`jz +1`、`jnz`、`loop` 等跳过 `E8`/`E9`/`0F 05` 等多字节 opcode；核心是“跳转目标落在 opcode 中间”。
- **变体（call/add/retn）**：`call $+5; add [esp],7; retn` 是另一类花指令，见 [[ctf-reverse-oep-junk-code-call-add-retn]]。
- **变体（数据混淆）**：`E8` 后插入合法指令字节（`E9`/`48`/`C7`）让线性扫描继续错位；Hex View 检查可区分。
- **关联卡片**：[[ctf-reverse-oep-junk-code-call-add-retn]]（call/add/retn 花指令）、[[code-analysis-reverse-obfuscation-silverfox-vm-call-idapython-restore]]（IDAPython 恢复混淆）、[[ctf-reverse-base64-table-index-mutation]]（Roses 后续的自定义 Base64）。
- **边界**：x86 可变长指令使花指令种类繁多；修复前务必计算跳转偏移，避免把真实 `call` 误判为垃圾；反调试/自修改代码可能需要动态修复。

## 检测与防御

- **逆向方法**：遇到异常 CALL/JUMPOUT/灰色 db，先看 Hex View；用 `U`/`C`/`F5`/`Alt+P` 逐步修复；写 IDAPython 批量识别 `xor/jz/E8` 模式。
- **混淆设计**：花指令只能提高静态分析成本，不能阻止动态调试；可结合控制流平坦化、自修改代码、反调试。
- **检测**：二进制扫描 `31 C0 74 02 E8`、`E8` 后非地址字节、跳转落入指令中间的模式；沙箱动态执行观察真实控制流。
