---
id: code-analysis-reverse-anti-debug-exception-timing-checksum-bypass
title: 动态反调试家族：SEH/INT 2D/TF、RDTSC 时序与 0xCC/CRC 校验的识别与绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: exception-timing-checksum-anti-debug-bypass
tags:
- windows
- anti-debug
- seh
- int2d
- trap-flag
- rdtsc
- timing
- checksum
- reversing
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:45:41+08:00'
  notes: 已对照原文与图片08核对：SEH/INT 2D/TF、RDTSC/QueryPerformanceCounter、0xCC/CRC 分支与绕过一致；PoC 为操作要点，未复跑。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-exception-timing-checksum-bypass/
draft: false
kb_aliases:
- SEH 反调试
- SetUnhandledExceptionFilter 反调试
- INT 2D 反调试
- 陷阱标志 TF 反调试
- RDTSC 时间差反调试
- 0xCC 断点检测
- CRC 校验反调试
---

## 一句话结论

动态反调试利用“调试器会先接管异常/断点、会拉长指令间耗时、会改写代码字节”这些差异来判断调试：异常流（SEH、`SetUnhandledExceptionFilter`、`int 3`、`INT 2D`、陷阱标志 TF）在调试与不调试时走不同分支；`RDTSC`/`QueryPerformanceCounter`/`clock` 比较两次计时差；`0xCC`/CRC 校验检测软件断点。绕过思路是按类型分别处理：异常类改比较/跳转或跟踪进入 SEH 正常路径，时序类跳过或改第二次计时值，校验类改用硬件断点或 patch 校验结果。

## 原理

- **异常流差异**：程序触发异常（非法访问、断点、非法指令、除零、单步）时，未调试进程由 OS 转给进程注册的 SEH/顶层异常处理器；调试进程则先由调试器接管。若样本在 SEH 中写入“正常”标记、在调试时该标记不被写入，就能判断调试状态。`SetUnhandledExceptionFilter` 注册的是“最后”异常处理器，样本可在其中检测调试并改变 EIP；`int 3`（0xCC）与 `int 2D` 也被用来制造这种差异。
- **INT 2D**：Windows 下的一条特殊中断指令；在调试器中执行时可能不触发异常而是跳过下一字节继续执行，未调试时则触发异常进入 SEH。样本利用该差异区分调试环境。原文流程图给出了 `INT 2D` 后根据 `[EBP-4]` 的 0/1 走 `"NotDebugging"`/`"Debugging"` 分支的例子。
- **陷阱标志 TF**：EFLAGS 第 8 位；置 1 后 CPU 单步执行，每条指令后触发异常并自动清零。样本可借 TF+SEH 制造“调试时继续执行、不调试时进入 SEH”的差异，或让分析者陷入大量无用的单步异常。
- **时序检测**：调试器单步/断点会显著拉长两条指令之间的时间。`RDTSC` 读取 CPU 时间戳计数器（EDX:EAX），两次调用的差值；`QueryPerformanceCounter`、`clock`、`time(NULL)` 也可用于比较。正常执行差值很小，调试时差值大，超过阈值即判定调试。
- **断点/校验和检测**：软件断点会把目标字节改成 `0xCC`（`int 3`）；样本可扫描代码段是否出现 `0xCC`，或对代码段计算 CRC/校验和并与预期值比较，发现断点导致的字节变化。
- **为什么这些方法可绕过**：它们都依赖“调试器行为与正常执行不同”这一可观测差异；只要消除差异（改分支、跳过检测、用硬件断点不改字节、patch 校验值），检测就失效。

## 触发条件

- 目标 Windows PE 在启动/关键路径中注册 SEH/顶层异常处理器、执行 `int 3`/`INT 2D`/TF 单步、读取 `RDTSC`/性能计数器，或对代码段做 `0xCC`/CRC 校验。
- 分析者能在调试器中观察异常分发、寄存器/时间值与代码段字节。
- 样本的检测结果只影响一个可定位的分支/返回值，未做多处交叉校验。

## 利用步骤

1. **异常类**：在 `SetUnhandledExceptionFilter`、`AddVectoredExceptionHandler`、`__try/__except` 注册处和异常触发指令（`int 3`、`int 2D`、非法访问）下断点；对比调试/非调试时是否进入 SEH。把检测比较后的 ZF/跳转改成正常分支，或直接跳到 SEH 内的正常路径；也可在调试器选项中忽略 `EXCEPTION_SINGLE_STEP`/`EXCEPTION_BREAKPOINT`，让程序按未调试路径走。
2. **INT 2D**：定位 `int 2D` 指令，单步观察下一条指令是否被跳过；按原文流程图，在 `CMP [EBP-4], 1`/`JE` 处修改标志或跳转，强制走 `"NotDebugging"`。
3. **TF**：在设置 EFLAGS.TF 的指令后下断，运行到异常分发；把 TF 清零或跳过单步循环，避免陷入无意义的单步异常。
4. **时序类**：定位 `RDTSC`/`QueryPerformanceCounter` 调用对，直接在第二次读取后修改 EDX:EAX（或比较结果），或 patch 阈值比较；也可用“run 到目标代码”而不是单步，减少时间差。
5. **0xCC/CRC**：改用硬件断点（DR0-DR3）避免改写代码字节；若样本仍检测 CRC，patch CRC 比较/预期值，或恢复被 `0xCC` 覆盖的字节后再计算。
6. 继续运行到主逻辑，确认检测不再触发。

## PoC

原文未给出完整样本 PoC；按原文描述整理的操作要点（未在本机执行）：

```text
# 异常/INT 2D（原文流程图）
INT 2D
...
CMP [EBP-4], 1
JE  "NotDebugging"   ; 调试时 [EBP-4]=0 -> 走 "Debugging"
                     ; 不调试时 [EBP-4]=1 -> 走 "NotDebugging"
# 绕过：把 [EBP-4] 改为 1，或把 JE 改成 JMP

# 时序（RDTSC）
rdtsc                ; 第一次
... 被检测代码 ...
rdtsc                ; 第二次
sub eax, saved_low   ; 差值超过阈值 -> 判定调试
# 绕过：第二次 rdtsc 后直接写入小差值，或 patch 比较

# 断点/校验和
# 软件断点会写入 0xCC；改用硬件断点，或 patch CRC 比较
```

说明：原文以概念和流程图为主，未提供可运行样本；上述为按原理整理的最小操作要点，具体寄存器/偏移需按目标调整。

## 变体与关联

- 变体（异常）：`int 3`、`INT 2D`、`EXCEPTION_ACCESS_VIOLATION`、`EXCEPTION_ILLEGAL_INSTRUCTION`、`EXCEPTION_INT_DIVIDE_BY_ZERO`、`EXCEPTION_SINGLE_STEP`；`SetUnhandledExceptionFilter`/VEH/SEH。
- 变体（时序）：`RDTSC`、`QueryPerformanceCounter`、`clock`、`time(NULL)`、`GetTickCount`；也可结合 `Sleep` 时间加速检测。
- 变体（完整性）：`0xCC` 扫描、代码段 CRC32/校验和、页哈希、内存与磁盘镜像比对。
- 关联：[[code-analysis-reverse-anti-debug-peb-fields-patch]]（PEB 字段检测）；[[code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch]]（API 检测）；[[code-analysis-reverse-anti-debug-tls-callback-pe-null-patch]]（TLS 回调中的异常/API 检测）；[[code-analysis-reverse-anti-debug-delayed-conditional-trigger]]（时间门控）；[[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]（组合环境检测）。
- 边界：样本使用硬件断点检测（DR 寄存器）、内核态异常回调、或把检测分散到多线程/多进程时，单一绕过可能失效；需要更细的动态跟踪与内存 patch。

## 检测与防御

- 检测：样本注册顶层异常处理器、执行 `int 3`/`INT 2D`、修改 TF、读取 TSC/性能计数器、扫描 `0xCC` 或计算代码段校验和；调试器中出现大量单步异常。
- 防御（反反调试）：多种检测交叉验证、把检测放入异常处理器/多线程、对代码段做完整性校验、检测硬件断点寄存器；分析侧优先硬件断点、脚本化 patch 与异常忽略选项，减少对代码/时间的扰动。
