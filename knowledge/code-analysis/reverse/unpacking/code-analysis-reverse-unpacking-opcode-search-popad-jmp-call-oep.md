---
id: code-analysis-reverse-unpacking-opcode-search-popad-jmp-call-oep
title: 一步直达法：搜索 POPAD(0x61)/JMP(E9/EB/FF25)/CALL(E8/FF96) 机器码快速逼近 OEP
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: opcode-search-popad-jmp-call-oep
aliases:
- 一步直达法
- 搜索 POPAD 找 OEP
- Ctrl+B 机器码查找
- JMP/CALL 定位 OEP
- OllyDbg 查找所有命令
- SFX Trace real entry
tags:
- reverse
- unpacking
- oep
- ollydbg
- opcode-search
- pe
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V293
  verified_at: '2026-11-08T07:52:28+08:00'
  notes: 已对照原文及图 28-39 核对：UPX 入口0x00409C80 PUSHAD，Ctrl+B 搜 61 于 0x00409DF5 得 POPAD，后接 LEA PUSH/CMP/JE/SUB ESP,-80 与 0x00409E03 JMP 00401000；查找所有命令结果列表 004099FA/00409A50/00409A54/00409B6E/00409C80/00409DF5 与图35一致；SFX blockwise 失败、bytewise 成功与图37-39一致。原子性：本卡以 opcode 搜索为主、SFX 作为同类一步直达工具写入步骤7，属同一“一步直达定位OEP”原子，无需拆分。未验证点：未在本机运行 OllyDbg/样本复现。
---

## 一句话结论

对 UPX、ASPack 等以 `JMP`/`CALL` 结尾、入口用 `PUSHAD` 保存现场的壳，可绕过逐条单步：在 OllyDbg 中用 `Ctrl+B` 搜索 `POPAD` 的机器码 `61`、`JMP` 的 `E9`/`EB`/`FF25`、`CALL` 的 `E8`/`FF96`，用 `Ctrl+L` 迭代跳过误命中，或右键“查找所有命令”输入 `POPAD`，找到壳尾部恢复寄存器后的跳转，跳到原程序入口即 OEP；OllyDbg 的 SFX `Trace real entry` 也可作为同类“一步直达”工具。

## 原理

- **壳尾固定模式**：压缩壳入口通常 `PUSHAD` 保存全部寄存器，解压/解密结束后 `POPAD` 恢复，然后用一条 `JMP OEP`（或 `CALL OEP`/`RETN`）把控制权交还原程序。UPX 的典型尾部是 `POPAD; LEA ...; ...; JMP 00401000`。
- **机器码搜索**：`POPAD` 的 opcode 是 `0x61`；`JMP` 的直接长跳转是 `E9`、短跳转是 `EB`、间接跳转常见 `FF25`；`CALL` 的直接调用是 `E8`、间接调用常见 `FF96`。它们都是单字节/多字节固定前缀，可在反汇编窗口用二进制字符串搜索。
- **为什么不是一搜即中**：`0x61` 等字节在指令流/数据中会大量出现（例如立即数、字符串），第一个命中往往不是壳尾；需要 `Ctrl+L` 继续查找，或使用“查找所有命令”让调试器按反汇编语义过滤 `POPAD`。
- **与入口 `PUSHAD` 的对应**：入口第一条 `PUSHAD` 与壳尾 `POPAD` 成对；找到 `POPAD` 后紧跟的 `JMP/CALL` 通常就是跳向 OEP 的指令，执行它即可到达原程序代码。
- **SFX 跟踪**：OllyDbg 的 `Options → Debugging options → SFX → Trace real entry blockwise/bytewise` 让调试器自动跟踪自解压/自解密过程，块方式快但不一定准，字节方式慢但更精确；要求程序入口点位于代码段（`BaseOfCode`）之外，否则该选项不适用。
- **边界**：只适用于壳尾特征明显的壳（UPX、ASPack 等）；改版壳可能把 `POPAD/JMP` 拆开、加花指令或把 OEP 藏在 `CALL` 后；`POPAD` 可能与入口 `PUSHAD` 不配对（壳用连续 `PUSH`/`POP`）；搜索命中后仍需确认目标确实是原程序 OEP（而非壳内另一段代码）。

## 触发条件

- 目标为 32 位 PE，壳入口有 `PUSHAD` 或明确的 `JMP/CALL OEP` 尾部（原文以 UPX、ASPack 为例）。
- 使用 OllyDbg（或其他支持二进制搜索/命令查找的调试器）。
- 壳未对 `POPAD/JMP` 做拆分混淆，且 OEP 在代码段内。
- 仅用于授权逆向分析与恶意样本分析。

## 利用步骤

1. 载入样本，确认入口第一条是 `PUSHAD`（UPX 例 `0x00409C80`）。
2. 在反汇编窗口按 `Ctrl+B`，在 HEX 输入框输入 `61`（POPAD 机器码），点击确定。
3. 若第一个命中不在壳尾，按 `Ctrl+L` 查找下一个，直到看到 `POPAD` 后跟栈清理与 `JMP 00401000`（原文在 `0x00409DF5` 找到）。
4. 也可右键 → 查找 → 所有命令，输入 `POPAD`，在结果列表中按地址选择壳尾附近的一条（原文选 `0x00409DF5`）。
5. 对 `JMP` 同理搜索 `E9`（长跳转）、`EB`（短跳转）、`FF25`（间接跳转），用 `Ctrl+L` 排除误命中，定位跳向 OEP 的指令。
6. 在跳转指令处 F8/单步执行，落到原程序入口即 OEP；dump 并修复 IAT。
7. 变体：打开 OllyDbg SFX 的 `Trace real entry bytewise`（入口在代码段外时可用），让调试器自动追到真正入口；块方式失败时改字节方式（ASPack 例）。

## PoC

```text
# UPX 示例
入口: 00409C80  PUSHAD
Ctrl+B -> HEX: 61 -> 确定
Ctrl+L 多次 -> 00409DF5  POPAD
00409DF5  61        POPAD
00409DF6  8D4424 80 LEA EAX,DWORD PTR SS:[ESP-80]
...
00409E03  E9 F8F71FFF  JMP 00401000   ; OEP

# 查找所有命令
右键 -> 查找 -> 所有命令 -> 输入 POPAD
结果列表: 004099FA / 00409A50 / 00409A54 / 00409B6E / 00409C80(PUSHAD) / 00409DF5
```

```text
# OllyDbg SFX 设置（ASPack 示例）
Options -> Debugging options -> Exceptions: 忽略所有异常，范围 00000000-FFFFFFFF
Options -> Debugging options -> SFX:
  ( ) Trace real entry blockwise   ; 速度快、不一定准确（本例失败）
  (x) Trace real entry bytewise    ; 速度慢、定位精确（本例成功定位 OEP）
```

## 变体与关联

- **ESP 定律**：对 `PUSHAD` 后栈顶下硬件访问断点，等 `POPAD` 命中；比 opcode 搜索更精确，见 [[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]]。
- **二次断点法**：对 `.rsrc`/`.text` 下内存断点，不依赖壳尾特征，见 [[code-analysis-reverse-unpacking-two-stage-section-breakpoint-oep]]。
- **无 PUSHAD 壳**：搜索 `POPAD` 无效，改用条件记录断点，见 [[code-analysis-reverse-unpacking-fsg-conditional-log-breakpoint-oep]]。
- **IAT 修复**：找到 OEP 后仍需 Scylla/ImportREC 修复导入表，见 [[code-analysis-reverse-unpacking-iat-redirect-key-jump-nop-two-instance-copy]]。
- **边界**：`0x61/0xE9/0xE8` 在数据段/指令立即数中大量误命中，必须结合反汇编上下文确认。

## 检测与防御

- **检测（样本侧）**：壳可拆分 `POPAD`/`JMP`、插入花指令、把 OEP 跳转改为寄存器间接跳转，降低 opcode 搜索的有效性；可检测调试器加载与搜索行为（较难）。
- **防御（防护方）**：不要依赖单一壳作为保护；配合反调试、完整性校验、代码虚拟化；对恶意样本分析方，opcode 搜索只是快速定位手段，仍需动态确认。
- **注意**：`Ctrl+B` 搜索的是字节序列，不是指令语义；`Ctrl+L` 用于逐个排除。
