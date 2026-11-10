---
id: code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla
title: UPX 手动脱壳实战：x64dbg 栈硬件断点定位 POPAD/OEP 并用 Scylla 转储修复 IAT
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: upx-manual-unpack-esp-hardware-breakpoint
aliases:
- UPX 手动脱壳
- ESP 定律
- 栈断点找 OEP
- x64dbg 脱 UPX
- Scylla dump 修复 IAT
tags:
- reverse
- unpacking
- upx
- x64dbg
- oep
- scylla
- iat
- pe
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V267
  verified_at: '2026-11-07T18:43:16+08:00'
  notes: 已对照原文与全部17张图核对：DIE 识别 UPX(3.96)/PE64（图01）、ExeInfoPE EP Section=UPX1（图02）、upx -d（图03）、x64dbg 系统断点/入口 0000000000423D00 PUSH RBX/RSI/RDI/RBP+LEA [41C025]（图04-06）、RSP=000000000062FF08 下硬件访问断点（图07-08）、POP RDI/RSI/RBX+JNE 栈补齐+JMP 1.401500（图09-10）、OEP printf/puts（图11）、Scylla IAT Autosearch/Get Imports/Dump/Fix Dump（图12-13）均与卡片一致。核对中修正两处示例地址：入口改为图05/06 的 0000000000423D00、RSP 改为图07 的 000000000062FF08（原文卡误用 Scylla OEP 0x1400014E0 与错误 RSP）。dedup：与 code-analysis-reverse-unpacking-upx-manual（通用流程概述）为 related 非 duplicate，本卡补充了可执行的栈硬件断点/Scylla 细节，保留两卡；与区段名还原、Unicorn 仿真、DLL 脱壳卡为不同入口，不合并。原文未给受影响版本，affected_versions 未设置。未验证点：未复跑样本脱壳；Scylla 截图 OEP 0x1400014E0 属另一示例样本。
---

## 一句话结论

UPX 压缩壳入口先执行解压 stub（x86 为 `PUSHAD` 保存寄存器、解压后 `POPAD` 恢复；x64 为连续 `PUSH`/`POP`）；在 PUSH 序列后的栈顶下硬件访问断点，运行到 POP 序列之后单步跟到跳入原程序代码的瞬间即为 OEP，此时用 Scylla 转储进程内存并修复 IAT，即可得到可正常分析的原程序。

## 原理

- UPX 把原程序压缩后附加解压 stub，并修改入口点指向 stub。执行时 stub 先保存寄存器现场（x86 一条 `PUSHAD`，x64 用 `PUSH RBX/RSI/RDI/RBP` 等连续指令）、在内存中解压原始 section，再恢复寄存器（`POPAD`/连续 `POP`）并跳转到原始入口点 OEP。
- 因为 PUSH 序列把所有寄存器压栈，解压期间 ESP/RSP 指向保存现场的那块栈地址；解压完成后 POP 序列从该地址逐个读回寄存器，栈指针必然会访问它。对 PUSH 后的 ESP/RSP 指向地址下硬件“访问”断点（读或写都触发），即可在 POP 序列执行时准确中断，而不必在解压代码里反复单步。
- x64 没有 `PUSHAD`：stub 用连续 `PUSH` 代替，且常见一段栈补齐循环（`LEA RAX,[RSP-0x80]; PUSH 0; CMP RSP,RAX; JNE ...; SUB RSP,0x80`），之后才是 `POP` 与 `JMP OEP`。栈断点原理不变。
- 中断在 POP 序列之后，继续 F7/F8 单步，直到看到程序自身的函数调用（如 `printf`/`puts`）或跳进原代码段的远跳转，即到达 OEP；此时内存中的原始 section 已被还原。
- dump 出的内存镜像区段布局已还原，但导入地址表（IAT）仍指向壳的加载器，需要 Scylla 的 IAT Autosearch + Get Imports 识别导入，再用 Fix Dump 把修复后的 IAT 写回 dump 文件，程序才能独立运行。

## 触发条件

- 目标为 UPX 或改版 UPX 压缩的 PE（DIE/ExeInfoPE 显示 UPX，`EP Section` 为 `UPX1`）。
- 可在本地运行动态调试器（x64dbg/x32dbg），并有 Scylla/ImpREC 等 IAT 修复插件。
- 标准 `upx -d` 不可用（改版壳、区段名被改）或需要观察壳实际解压行为时使用。

## 利用步骤

1. 查壳：用 DIE/ExeInfoPE 确认 UPX、位数与入口点；若区段名被改，可先按关联卡恢复后再 `upx -d`，或直接走本手动流程。
2. x64dbg 打开样本，先停在系统断点；F9 运行到程序入口 `<样本>.OptionalHeader.AddressOfEntryPoint`（如 `0000000000423D00`）。
3. 入口即 UPX stub：x86 找 `PUSHAD`；x64 找连续 `PUSH` 保存寄存器区（如 `PUSH RBX; PUSH RSI; PUSH RDI; PUSH RBP`）及其后对 `[41C025]` 等地址的 `LEA`。
4. 在 PUSH 序列执行后查看 RSP/ESP（如 `000000000062FF08`），在栈窗口/内存窗口对该栈顶地址设置“硬件，访问”断点。
5. F9 继续运行；stub 解压过程中会命中该栈地址。命中后 F7/F8 跟随 POP 序列（x64 会经过 `POP RDI; POP RSI; POP RBX` 与 `JNE` 栈补齐循环）。
6. 单步到 `JMP 1.401500` 一类跳入原代码段的指令，随后看到原程序调用（如 `LEA RCX, ["hello_world"]; CALL <JMP.&printf>; CALL <JMP.&puts>`），此处即 OEP；记录 OEP 地址。
7. 用 Scylla 附加到进程：IAT Autosearch → Get Imports，删除显示红叉的无效导入项；Dump 转储内存镜像；Fix Dump 选择刚转储的文件，生成修复 IAT 的可执行文件。
8. 用 DIE 复查 dump 不再是 UPX，再用 x64dbg/IDA 验证程序可正常运行并分析原始逻辑。

## PoC

```text
# 样本：hello_world.c（printf/puts）先用 UPX 压缩
upx 1.exe

# x64dbg 手动脱壳（x64 样本）
# 1) F9 到入口 0000000000423D00，可见 PUSH RBX/RSI/RDI/RBP
# 2) PUSH 序列后 RSP=000000000062FF08，对该栈地址下硬件访问断点
# 3) F9 命中栈断点，F7/F8 走过 POP 序列与 JNE 栈补齐循环
# 4) 单步到 JMP 1.401500，进入 printf/puts 调用即 OEP
# 5) Scylla: IAT Autosearch -> Get Imports -> 删除红叉 -> Dump -> Fix Dump
```

x86 样本同理：入口处找 `PUSHAD`，对 ESP 指向的栈地址下硬件访问断点，命中后连续单步到 `POPAD` 之后的远跳转即 OEP。

## 变体与关联

- 自动脱壳：标准 UPX 可直接 `upx -d sample.exe`，无需动态调试；改版壳可能拒绝。
- x86 `PUSHAD/POPAD` 与 x64 连续 `PUSH/POP` 的指令差异；stub 中的 `JNE` 栈补齐循环不改变栈断点原理。
- 改版区段名导致 `upx -d` 失败：恢复 `UPX0/UPX1/UPX2` 后再工具脱壳，见 `code-analysis-reverse-unpacking-upx-section-name-restore`。
- 改版 stub/压缩数据：Unicorn 仿真 stub 或手动 dump + IAT 重建，见 `code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation`。
- 通用流程概述：`code-analysis-reverse-unpacking-upx-manual`；其它壳（ASPack/VMProtect/Themida）同样可借栈断点/内存断点找 OEP，但解压算法与修复方式不同。

## 检测与防御

- 检测：UPX 区段名/`UPX!` 标记、入口点落在 UPX1、导入表项异常少、运行中出现 RWX 解压区与 `VirtualProtect` 改权限后跳转。
- 防御：加壳只提高逆向成本，不是安全边界；关键校验应放在服务端或配合完整性校验、反调试与代码签名。
