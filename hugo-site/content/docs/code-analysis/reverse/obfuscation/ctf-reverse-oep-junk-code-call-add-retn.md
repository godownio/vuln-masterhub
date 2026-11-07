---
id: ctf-reverse-oep-junk-code-call-add-retn
title: OEP 识别与 call/add/retn 花指令：按编译器特征找入口并 NOP 掉跳转
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: oep-junk-code-call-add-retn
tags:
- reverse
- obfuscation
- oep
- anti-disassembly
- junk-code
- ida
- unpacking
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:54:51+08:00'
  notes: 已对照原文动态调试/OEP 节与图 55-61 核对：MSVC call _security_init_cookie、GCC xor ebp/pop esi/call __libc_start_main、Delphi push ebp/add esp,-0Ch/call __InitExe 三类入口特征、call $+5 (E8 00 00 00 00)/add byte ptr [esp],7 (80 04 24 07)/retn (C3) 花指令、00A310E0→00A310E7、整段 NOP、CFF Explorer/UPX 壳处理均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/obfuscation/ctf-reverse-oep-junk-code-call-add-retn/
draft: false
kb_aliases:
- OEP 识别
- 花指令
- call $+5
- add byte ptr [esp], 7
- retn 花指令
- 入口点特征
- anti-disassembly
---

## 一句话结论

OEP 不一定是 `push ebp; mov ebp, esp`：MSVC 常见 `call _security_init_cookie`、GCC 常见 `xor ebp, ebp; pop esi; call __libc_start_main`、Delphi 常见 `push ebp; add esp, -0Ch; call __InitExe`；遇到 `call $+5; add byte ptr [esp], 7; retn` 这类花指令，把整段 NOP 掉即可让 IDA 恢复真实执行流。

## 原理

- **OEP 是壳跳回原程序的入口**：脱壳/动态调试时，需要在壳代码执行完后找到原程序的第一条真实指令；不同编译器/运行库的启动代码有固定特征，可据此识别。
- **MSVC**：入口常是 CRT 启动，先 `call _security_init_cookie`（/GS 安全 Cookie），再 `jmp _mainCRTStartup`；看到指向只做位运算/取系统时间的 `call` 基本可判定。
- **GCC/MinGW**：`_start` 固定为 `xor ebp, ebp; pop esi; mov ecx, esp; push eax; call __libc_start_main`，`ebp` 置零是 ABI 标记最外层调用栈。
- **Delphi/C++ Builder**：`push ebp; mov ebp, esp; add esp, -0Ch; mov eax, offset _InitExe; call @__InitExe`，入口就建栈帧并初始化 VCL。
- **call/add/retn 花指令**：`call $+5` 把下一条指令地址压栈；`add byte ptr [esp], 7` 把返回地址加 7；`retn` 弹出并跳到 `$+7`，跳过中间的垃圾字节。反汇编器若线性扫描会把垃圾字节当指令，导致后续代码错位。
- **为什么 NOP 有效**：把 `call/add/retn` 整段替换为 `0x90` 后，执行流自然落到真实目标地址，IDA 的线性反汇编也能对齐到正确指令边界。

## 触发条件

- 目标经过加壳/混淆，OEP 被隐藏或入口点被改到壳代码。
- 反汇编出现 `call $+5`、`add [esp], imm`、`retn` 组合，或大量 `db` 垃圾字节。
- 需要动态调试到 OEP 后 dump/修复 IAT，或静态 patch 花指令恢复反汇编。
- 已知/可推断编译器类型（PE 头、运行时库、字符串、节区特征）。

## 利用步骤

1. 看 PE 入口点与编译器特征（MSVC/GCC/Delphi），判断启动代码形态。
2. 动态调试运行到壳尾，观察 `call`/`jmp` 目标；结合栈上返回地址确认是否跳到原程序入口。
3. 静态遇到 `call $+5; add byte ptr [esp], 7; retn`：计算 `$+5` 的下一条地址，加 7 后即真实目标；把这段（含垃圾字节）全部 NOP 掉。
4. 在 IDA 中对花指令段按 `D` 转为数据/按 `C` 重新分析，或写 IDAPython 批量 patch `90`。
5. 继续跟踪到 OEP，dump 进程内存、修复 IAT、重建导入表。
6. 用反汇编/动态执行双重验证 patch 后代码与原始执行流一致。

## PoC

```text
; 花指令示例（x86）
E8 00 00 00 00        call $+5          ; 压入下一条指令地址
80 04 24 07           add byte ptr [esp], 7
C3                    retn              ; 跳到 $+7，跳过中间垃圾字节
```

```text
; patch 后
90 90 90 90 90
90 90 90 90
90
```

```python
# IDAPython 批量 NOP 示意
import ida_bytes
start, end = 0x00A310E0, 0x00A310E9
for ea in range(start, end):
    ida_bytes.patch_byte(ea, 0x90)
```

原文实测：入口 `call $+5`（E8 00 00 00 00）压入 `00A310E0`，`add byte ptr [esp], 7`（80 04 24 07）改为 `00A310E7`，`retn`（C3）跳到 `00A310E7`；将 `call/add/retn` 段 NOP 后反汇编恢复正常。

## 变体与关联

- **花指令变体**：`push imm; retn`、`jmp $+2`、`call $+5; pop reg; add reg, imm; jmp reg`、`pushad/pushfd` 保护寄存器后再恢复。
- **OEP 变体**：MSVC/GCC/Delphi/Borland C++、Go/Rust 启动代码；加壳器（UPX/VMProtect/Themida）OEP 位置不同。
- **关联卡片**：[[code-analysis-reverse-unpacking-upx-manual]]（UPX 手动脱壳）、[[code-analysis-reverse-obfuscation-silverfox-vm-call-idapython-restore]]（IDAPython 还原混淆调用）、[[code-analysis-reverse-vm-vmprotect-identification-behavior-analysis]]（VMProtect 识别）。
- **边界**：花指令可能嵌套/多层，需逐层还原；若垃圾字节被其他跳转复用，NOP 可能破坏其他路径；OEP 识别需结合动态验证，不能只靠特征码。

## 检测与防御

- **逆向侧**：用动态执行确认 OEP，静态 patch 后用 IDA 重新分析；保留原始样本副本，记录 patch 偏移与字节。
- **防御/检测视角**：花指令是反分析手段，不是安全边界；EDR 可监控 `VirtualProtect`/`WriteProcessMemory`/OEP 跳转等脱壳行为。
- **检测信号**：入口点附近出现 `call $+5`、`add [esp]`、`retn` 组合；大量 `db` 垃圾字节；节区熵异常；IAT 在运行时被重建。
- **复盘**：先识别编译器启动代码，再找壳跳转；遇到花指令按“栈上返回地址 + 偏移”计算真实目标。
