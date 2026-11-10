---
id: code-analysis-reverse-unpacking-esp-law-seh-fallback-oep
title: ESP 定律失效时的回退：PUSHAD 后栈断点被 SEH 注册干扰，改用栈顶访问断点 + 代码段内存断点定位 OEP
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: esp-law-failure-seh-fallback-oep
aliases:
- ESP 定律失效
- PUSHAD 栈断点不触发
- SEH 注册 干扰脱壳
- 代码段内存断点 找 OEP
- Yoda's Crypter 1.3 脱壳
- 栈顶访问断点 OEP
tags:
- reverse
- unpacking
- esp-law
- oep
- seh
- ollydbg
- pe
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T05:00:50+08:00'
  notes: 已对照原文与56张图逐项核对：YodasCrypter1.3 PEID（图01）、EP 00465060 PUSHAD、0x0019FF70 栈访问断点首次未命中（图3-6）、重新对PUSHAD后栈顶下断命中 0x00465976 SEH 注册序列（图7-9）、代码段内存断点命中 OEP 0x004271B0（图10）、Dump（图11-12）。卡片的 ESP 定律失效机理与回退步骤与原文一致；本卡为单一「SEH干扰下的OEP定位回退」原子，未过粗。dedup new（UPX ESP/Scylla 等为 related），dup-scan 无本卡 pair。未执行样本。
---

## 一句话结论

对入口有 `PUSHAD` 的壳，标准做法是在 PUSHAD 后的栈顶下硬件访问断点（ESP 定律）等 `POPAD` 命中；但若壳在自解阶段先注册 SEH、改写了同一块栈数据，断点可能不触发。此时改为对 PUSHAD 后的栈顶设访问断点，命中 SEH 注册代码（`push handler; push fs:[0]; mov fs:[0],esp`）后，再对原代码段设内存断点 F9，即可在原始 `.text` 第一次执行处（OEP）中断。

## 原理

- ESP 定律：`PUSHAD` 把所有通用寄存器压栈，壳解压完用 `POPAD` 恢复；解压期间 ESP 指向保存现场的那块栈地址，解压结束前必然访问它。在该栈地址下硬件访问断点，就能在 POPAD 附近中断，而不必在解压循环里单步。
- 失效原因：壳在自解早期也使用同一块栈空间（典型是注册 SEH：`push 异常处理器; push dword ptr fs:[0]; mov dword ptr fs:[0],esp`），或在 POPAD 前改写栈数据，导致简单栈断点被提前消费/不再命中。原文对 `0x0019FF70` 设硬件访问断点后 F9 没有中断，日志也无有用信息，即属此类。
- 回退思路：继续对 `PUSHAD` 后的栈顶下访问断点，让壳的 SEH 注册动作把程序带到可识别的指令序列；SEH 注册后常见的 `JMP`/`INT3` 会主动触发异常，交异常处理器继续解压。确认壳仍在正常解压后，对原代码段（`.text`）设内存访问/执行断点，F9 等到壳跳回原程序代码的第一条指令——即 OEP。
- 为什么代码段断点可行：壳最终必须把控制权交给原程序入口，原程序代码段在解压前通常是不可执行/未写入的；在解压完成后第一次执行原 `.text` 时命中断点，地址就是 OEP。

## 触发条件

- 目标为 32 位 PE，入口处有 `PUSHAD`（常见于 Yoda's Crypter、老式压缩/加密壳）。
- 使用 OllyDbg/x32dbg 等支持硬件断点与内存断点的调试器。
- 标准 ESP 定律（对 PUSHAD 后 ESP 直接下断）不触发或停在错误位置。
- 壳在自解过程中会注册 SEH 或使用同一栈区域。

## 利用步骤

1. 载入样本，在入口看到 `PUSHAD`（本例 `0x00465060`），记录执行后的 ESP（本例 `0x0019FF70`）。
2. 按标准 ESP 定律对该栈地址下硬件访问断点，F9；若程序直接弹窗/运行而未中断，说明简单方法失效。
3. 重新运行，对 PUSHAD 后的栈顶设访问断点，F9；本例中断在 `0x00465976`，指令为 SEH 注册：
   `PUSH EAX; XOR EAX,EAX; PUSH DWORD PTR FS:[EAX]; MOV DWORD PTR FS:[EAX],ESP`。
4. 单步到其后的 `JMP SHORT`/`INT3`（本例 `0x0046597F JMP 0x00465982; 0x00465981 INT3`），确认壳通过异常继续。
5. 在内存窗口选中原代码段（如 `0x00401000` 的 `.text`），右键设置内存访问断点（或硬件执行断点），F9。
6. 程序在原始代码第一次执行处中断（本例 OEP `0x004271B0`），此时 dump 进程内存。
7. 用 ImportREC/Scylla 按 OEP、IAT 起止修复导入表，得到可运行的原程序。

## PoC

```text
样本：UnPackMe_YodasCrypter1.3.exe（PEID: yoda's Protector 1.3）
EP: 0x00465060  PUSHAD
PUSHAD 后 ESP: 0x0019FF70
标准 ESP 断点：对 0x0019FF70 下硬件访问断点 -> F9 不中断（失效）
回退：对栈顶设访问断点 -> 命中 0x00465976 SEH 注册
  00465976  PUSH EAX
  00465977  XOR EAX,EAX
  00465979  PUSH DWORD PTR FS:[EAX]
  0046597C  MOV DWORD PTR FS:[EAX],ESP
  0046597F  JMP SHORT 00465982
  00465981  INT3
代码段内存断点：0x00401000 -> F9 命中 OEP 0x004271B0
```

## 变体与关联

- 变体：最后一次异常法（Shift+F9 多次，直到异常处理链耗尽）也可绕过 SEH 干扰。
- 变体：对 `PUSHAD` 后的 ESP 下硬件断点后，若命中的是壳内部的早期访问，可先禁用断点、在 `POPAD` 附近再启用，或改用代码段执行断点。
- 变体：若壳不使用 SEH，标准 ESP 定律通常可直接成功；先用简单方法，失败再走本卡。
- 关联：[[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]]（ESP 定律标准流程与 Scylla 修复）。
- 关联：[[ctf-reverse-oep-junk-code-call-add-retn]]（OEP 附近花指令的识别）。

## 检测与防御

- 检测（分析侧）：入口 `PUSHAD`、早期 `fs:[0]` 写入、自解区 RWX、代码段在解压后被写入/改权限，都是壳的特征；在代码段设断点可快速确认 OEP。
- 检测（防护侧）：壳只能提高逆向成本，不是安全边界；关键逻辑应放服务端，配合完整性校验、反调试与代码签名。
- 边界：若壳在 OEP 前就把原代码段改回可执行并执行多次，代码段断点可能过早命中；需结合栈断点/单步确认。
