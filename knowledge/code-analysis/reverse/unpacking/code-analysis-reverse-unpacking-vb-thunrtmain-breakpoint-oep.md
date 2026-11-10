---
id: code-analysis-reverse-unpacking-vb-thunrtmain-breakpoint-oep
title: VB 程序特征脱壳：断 MSVBVM60/50 .text 的 ThunRTMain，从栈返回地址定位 OEP
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: vb-thunrtmain-breakpoint-oep
aliases:
- VB 特征脱壳
- PUSH VBHeader CALL ThunRTMain
- MSVBVM60 .text 内存断点
- Visual Basic OEP
- VB 程序找 OEP
tags:
- reverse
- unpacking
- oep
- ollydbg
- visual-basic
- msvbvm60
- pe
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V293
  verified_at: '2026-11-08T07:52:34+08:00'
  notes: 已对照原文及图 49-59 核对：未加壳VB入口 004019A0 PUSH 0x40A8 / 004019A5 CALL msvbvm60.ThunRTMain；对 MSVBVM60.dll .text 内存访问断点后命中 ThunRTMain，栈返回地址 0x004019AA；UPX/ASPack/VMProtect 2.12.3 三壳演示均一致（VMProtect 后仍需 IAT 修复）。未验证点：未在本机运行 OllyDbg/样本复现，VMProtect 的 IAT 修复未展开验证。
---

## 一句话结论

Visual Basic 编译的 PE，其原始入口固定为 `PUSH <VBHeader 指针>` 后 `CALL MSVBVM60.dll/MSVBVM50.dll!ThunRTMain` 两条指令；因此对加壳的 VB 程序，可在 OllyDbg 中对 `MSVBVM60.dll`（或 `MSVBVM50.dll`）的 `.text` 段下内存访问断点，运行后壳解压完成调用 `ThunRTMain` 时中断，此时栈上保存的返回地址就是 VB 程序 OEP（原文例 `0x004019AA`），转到该地址即原程序入口；VMProtect 等壳定位后仍需修复 IAT。

## 原理

- **VB 程序入口特征**：VB 编译器生成的 PE 入口不是普通 C 运行时启动代码，而是：
  ```asm
  68 <VBHeader 指针>       ; PUSH 指向 VBHeader 结构体的地址
  E8 F0FFFFFF             ; CALL MSVBVM60!ThunRTMain
  ```
  `ThunRTMain` 负责根据 `VBHeader` 初始化 VB 运行时（变量、窗体、异常表等），之后才进入用户代码。
- **壳无法改变调用目标**：壳可以把入口改到自己的 stub，但最终必须把控制权交还给原程序，即执行上面两条指令。`ThunRTMain` 位于系统 VB 运行时 DLL 中，壳通常不会替换它（否则 VB 程序无法运行）。
- **断点位置**：对 `MSVBVM60.dll` 的 `.text` 段下内存访问/执行断点；壳解压完成、跳回原程序入口并执行 `CALL ThunRTMain` 时命中断点。此时栈顶/栈帧中保存的返回地址就是 OEP（`CALL` 压入的下一条指令地址）。
- **取 OEP**：在断点处查看栈，找到返回地址（原文 `0x004019AA`），在反汇编窗口 `Ctrl+G` 跳转该地址，即可看到 VB 程序的入口/用户代码。
- **为什么有效**：这是 VB 程序的“结构性必然事件”，与壳类型无关；UPX、ASPack、VMProtect 最终都要调用 VB 运行时初始化。
- **边界**：需要目标为 VB6/VB5 编译（依赖 `MSVBVM60.dll`/`MSVBVM50.dll`）；若程序是 VB.NET 则不适用；VMProtect 等强壳定位 OEP 后 IAT 可能仍是壳的，需要额外修复；若壳伪造/内联 `ThunRTMain` 调用，断点可能不命中。

## 触发条件

- 目标为 Visual Basic 6/5 编译的 32 位 PE（导入 `MSVBVM60.dll`/`MSVBVM50.dll`，或入口呈 `PUSH; CALL ThunRTMain` 特征）。
- 目标被压缩/加密壳保护，但壳最终仍调用系统 VB 运行时。
- 使用 OllyDbg（或支持内存断点的调试器）。
- 仅用于授权逆向分析与恶意样本分析。

## 利用步骤

1. 识别 VB：查看导入表是否有 `MSVBVM60.dll`/`MSVBVM50.dll`；未加壳样本入口应为 `PUSH <VBHeader>; CALL ThunRTMain`。
2. 载入加壳样本，打开 Memory Map，找到 `MSVBVM60.dll`（或 `MSVBVM50.dll`）的 `.text` 段。
3. 对该 `.text` 段设置内存访问断点（Set memory breakpoint on access）。
4. F9 运行；壳解压完成后调用 `ThunRTMain` 时中断（可能需要等待一段时间）。
5. 在栈区找到返回地址（原文 `0x004019AA`），在反汇编窗口跳转到该地址，确认是 VB 程序入口/用户代码，即 OEP。
6. dump 进程内存并修复 IAT；VMProtect 等壳尤其需要检查 IAT 是否仍指向壳。
7. 若第一次断点不是目标调用，检查是否命中其他 VB 运行时调用（如 `__vba*` 函数），继续 F9 或换 `.text` 内具体函数地址。

## PoC

```text
# 未加壳 VB 程序入口特征
004019A0   68 A8 400000    PUSH 0x0040A8        ; VBHeader 指针
004019A5   E8 F0FFFFFF    CALL MSVBVM60.ThunRTMain

# 加壳 VB 程序定位 OEP
Memory Map -> MSVBVM60.dll -> .text -> Set memory breakpoint on access
F9 -> 中断在 ThunRTMain
栈区返回地址: 004019AA
Ctrl+G -> 004019AA -> VB 程序 OEP
```

说明：原文对 UPX、ASPack、VMProtect 2.12.3 三种壳的 VB 程序分别演示；UPX/ASPack 可直接得到 OEP，VMProtect 定位到 `0x004019AA` 后程序仍未完成 IAT 修复，需要额外处理。

## 变体与关联

- **其它语言特征入口**：Delphi/C++ 也有可识别的启动序列（如 `__libc_start_main` 对应物），可按同样“断运行时初始化函数”的思路定位 OEP；本卡只针对 VB 的 `ThunRTMain`。
- **通用 OEP 定位**：ESP 定律、二次断点、末次异常法见 [[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]]、[[code-analysis-reverse-unpacking-two-stage-section-breakpoint-oep]]、[[code-analysis-reverse-unpacking-last-exception-count-oep]]。
- **VMProtect**：强壳脱壳后 IAT 修复见 [[code-analysis-reverse-unpacking-vmprotect-compression-sleep-cookie-oep-import-fix]]。
- **IAT 修复**：[[code-analysis-reverse-unpacking-iat-redirect-key-jump-nop-two-instance-copy]]。
- **边界**：VB.NET 程序入口不同（CLR），不适用。

## 检测与防御

- **检测（样本侧）**：壳可检测对 `MSVBVM60.dll` 的内存断点、检测调试器；可把 VB 运行时调用拆分为间接调用/内联以降低特征稳定性。
- **防御（防护方）**：加壳只是提高分析成本；对 VB 程序可结合反调试、代码加密与完整性校验。
- **注意**：对系统 DLL 下断点可能影响其他线程/模块，建议在干净快照上操作；命中后先确认返回地址属于目标模块（`0x00400000` 附近）再跳转。
