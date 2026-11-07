---
id: code-analysis-reverse-anti-debug-peb-fields-patch
title: Windows PEB 字段反调试：BeingDebugged/Ldr/ProcessHeap/NTGlobalFlag 的识别与内存补丁
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: peb-fields-patch-bypass
aliases:
- PEB 反调试绕过
- BeingDebugged 补丁
- NTGlobalFlag 0x70
- ProcessHeap Flags ForceFlags
- 0xEEFEEEFE 堆填充检测
- IsDebuggerPresent 绕过
tags:
- windows
- anti-debug
- peb
- isdebuggerpresent
- processheap
- ntglobalflag
- reversing
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:45:36+08:00'
  notes: 已对照原文与图片01核对：IsDebuggerPresent/ZF、PEB 偏移（Ldr 0x0C/0x18、ProcessHeap 0x18/0x30、NTGlobalFlag 0x68/0xBC）与补丁值一致；PoC 为调试器操作要点，未复跑。
---

## 一句话结论

大量 Windows 反调试只读 PEB（进程环境块）里的几个字段：`BeingDebugged`、`Ldr` 指向的堆区是否被调试器填成 `0xEEFEEEFE`、`ProcessHeap` 的 `Flags/ForceFlags`、以及 `NTGlobalFlag` 是否为 `0x70`；在调试器中把这些字段改回未调试时的值（`BeingDebugged=0`、`NTGlobalFlag=0`、`Flags=0x2`、`ForceFlags=0x0`，或把检测区清零），或直接在比较处改 ZF/跳转，即可绕过。

## 原理

- **PEB 的位置**：32 位进程通过 `fs:[0x30]` 取 PEB，64 位通过 `gs:[0x60]`；`IsDebuggerPresent` 只是读取 `PEB.BeingDebugged`（偏移 0x2）并返回。
- **BeingDebugged**：被调试时该字节为 1；把 0x2 处改为 0，或把 `test eax,eax; jz` 的 ZF 改为 1 / 直接把条件跳转改成 `jmp`，即可让后续退出分支不执行。
- **Ldr 堆填充检测**：调试状态下，未使用的堆内存常被填充为 `0xEEFEEEFE`；`PEB.Ldr`（x86 偏移 0x0C，x64 0x18）指向堆中的 `_PEB_LDR_DATA`，样本扫描该区域是否出现该模式来判断调试器。原文的绕过是把被改动的堆内存改为 NULL；更稳妥的是 patch 检测比较或跳过扫描函数，因为随意清零堆结构可能影响加载器。
- **ProcessHeap**：`PEB.ProcessHeap`（x86 0x18，x64 0x30）指向 `HEAP` 结构。被调试时 `Heap.Flags`/`Heap.ForceFlags` 会被设置；未调试的原始值分别是 `0x2` 和 `0x0`，把这两个字段改回原值即可通过检测。`HEAP` 内字段偏移随架构/版本变化，应按目标版本的符号或调试器结构视图定位。
- **NTGlobalFlag**：`PEB.NTGlobalFlag`（x86 0x68，x64 0xBC）在调试时通常为 `0x70`（`FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS`）；改为 0 即可。
- **为什么可行**：这些检查都发生在用户态，PEB 本身可写；调试器/内存补丁可以在检查前改变量，或在检查后改结果。检查通常只是“读字段→比较→退出”，因此改字段或改跳转都能达到目的。

## 触发条件

- 目标为 Windows PE，样本启动阶段读取 PEB 字段做反调试，命中后 `exit`/`TerminateProcess`/弹窗。
- 分析者能在调试器中读写目标进程内存（本地调试或注入）。
- 样本未对 PEB 字段做完整性校验（如与系统调用返回值交叉验证），或校验可一并 patch。

## 利用步骤

1. 在调试器中定位 PEB：x86 看 `fs:[0x30]`，x64 看 `gs:[0x60]`；用 WinDbg `!peb` 或 x64dbg 的 PEB 视图确认字段。
2. 在 `IsDebuggerPresent`、`NtQueryInformationProcess` 或直接读 PEB 的代码处下断点，观察比较与退出分支。
3. 修改字段：
   - `BeingDebugged`（0x2）= 0；
   - `NTGlobalFlag`（x86 0x68 / x64 0xBC）= 0；
   - `ProcessHeap->Flags = 0x2`、`ForceFlags = 0x0`；
   - 若检测 `0xEEFEEEFE`，清掉被扫描区域或直接跳过扫描函数。
4. 或者不改变量，在比较指令后把 ZF 置 1 / 把 `jz` 改成 `jmp`，让程序走正常分支。
5. 继续运行到 OEP/主逻辑；若还有二次检测，重复定位。

## PoC

原文未给出可直接复现的样本 PoC；以下为按原文偏移与补丁值给出的调试器操作要点（未在本机执行）：

```text
# x64dbg（x86 目标）
# 1) 在命令栏查看 PEB
peb()
# 2) 修改字段（地址以实际 PEB 为准）
#    BeingDebugged @ PEB+0x2 = 0
#    NTGlobalFlag   @ PEB+0x68 = 0
#    ProcessHeap->Flags @ HEAP+Flags = 2
#    ProcessHeap->ForceFlags @ HEAP+ForceFlags = 0
# 3) 或在 IsDebuggerPresent 返回后的 test/jz 处把 ZF 置 1
```

说明：`HEAP` 内 `Flags/ForceFlags` 的具体偏移随 Windows 版本与架构不同，需用调试器结构视图确认；原文只给出“改为 0x2/0x0”的结论，未给出样本与偏移。

## 变体与关联

- 变体（检查方式）：直接读 PEB、`IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess`；字段相同或由其派生。
- 变体（绕过方式）：内存补丁、条件断点改 ZF、hook `IsDebuggerPresent` 返回 0、在退出函数（如 `exit`/`TerminateProcess`）下断点回溯调用者。
- 关联：[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]（NtQueryInformationProcess DebugPort/DebugFlags 环境检测）；[[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]（调试器 API 组合检测）；[[code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch]]（NtQuery* 家族）；[[code-analysis-reverse-anti-debug-tls-callback-pe-null-patch]]（TLS 回调反调试）。
- 边界：x86/x64 偏移不同；样本若通过系统调用/驱动交叉验证 PEB，单纯改字段会被发现；清零 Ldr 堆区可能破坏加载器，优先 patch 比较。

## 检测与防御

- 检测：样本读取 PEB 固定偏移、扫描 `0xEEFEEEFE`、比较 `NTGlobalFlag==0x70`；调试器中出现对 PEB/HEAP 字段的写入。
- 防御（反反调试）：在关键字段读取处做冗余校验（系统调用返回值与 PEB 交叉验证）、在多个位置分散检测、对代码段做完整性校验；分析侧则优先用硬件断点与脚本化 patch，减少对堆结构的破坏。
