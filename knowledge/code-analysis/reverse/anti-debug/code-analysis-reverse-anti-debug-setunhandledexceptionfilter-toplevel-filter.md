---
id: code-analysis-reverse-anti-debug-setunhandledexceptionfilter-toplevel-filter
title: SetUnhandledExceptionFilter 顶层异常过滤器反调试：过滤器的执行与否由 UnhandledExceptionFilter 内部 DebugPort 查询决定
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: setunhandledexceptionfilter-toplevel-filter-debugport
aliases:
- SetUnhandledExceptionFilter 反调试
- 顶层异常过滤器检测调试器
- UnhandledExceptionFilter DebugPort
- 注册码校验藏在异常过滤器
- Sphynx crackme 反调试
tags:
- windows
- anti-debug
- seh
- setunhandledexceptionfilter
- unhandledexceptionfilter
- zwqueryinformationprocess
- processdebugport
- crackme
- reversing
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:22:30+08:00'
  notes: 已对照原文与全部18张图片核对：Sphynx crackme 中 SetUnhandledExceptionFilter 注册回调 0x401108，错序列号触发异常后 UnhandledExceptionFilter 内 ZwQueryInformationProcess(7) 返回 0xFFFFFFFF，改缓冲区为0后回调执行注册校验，与卡内原理/步骤一致；PoC 为按机制构造的示意代码、未复跑。原文未声明组件版本区间，无 CVE。
---

## 一句话结论

样本用 `SetUnhandledExceptionFilter` 注册顶层未处理异常过滤器，把真正的校验/注册逻辑放进该回调，并在错误输入等关键路径主动触发一个无人处理的异常：未调试时系统经 `UnhandledExceptionFilter` 内部查询 `ProcessDebugPort` 判定“未调试”后调用回调，校验逻辑正常执行；被调试时异常先被调试器接管、回调不执行——回调“是否执行”本身编码了调试状态，关键逻辑也被藏在异常路径里，普通断点调试只能看到程序终止。

## 原理

- **异常分发顺序**：异常发生后先交给调试器；调试器不处理时才依次经过进程内的 VEH/SEH；所有进程内处理程序都不处理时，系统调用 `UnhandledExceptionFilter`。
- **UnhandledExceptionFilter 的调试判定**：它在把异常交给系统默认终止流程前，会通过 `ZwQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort /*7*/, &buf, 4, NULL)` 查询当前进程是否被调试。`buf` 为 `0xFFFFFFFF`（非 0）表示进程存在调试端口、正被调试；为 0 表示未调试。
- **两种走向**：被调试时异常先交给调试器，即使调试器把异常放回、系统继续走未处理异常流程，`UnhandledExceptionFilter` 查询到 `DebugPort` 非 0 也不会调用注册回调，程序最终按未处理异常终止；只有判定未调试时，`UnhandledExceptionFilter` 才调用该顶层回调。
- **为什么能反调试**：程序故意制造未处理异常（如非法内存访问、除零），并把注册码校验/注册成功逻辑放在顶层回调里。分析者用默认配置的调试器运行时，异常先到调试器，回调不执行，程序表现为崩溃/退出，看不到成功路径；只有在非调试环境（或绕过 DebugPort 判定后）回调才运行。因此“回调是否执行”本身就是一条隐蔽的调试状态判据。
- **为何绕过点是 DebugPort**：整条链的枢纽是 `UnhandledExceptionFilter` 对 `ProcessDebugPort` 的查询结果；只要让它拿到 0，系统就按“未调试”调用回调。这也解释了为什么对回调下断点不生效、而对 `ZwQueryInformationProcess` 返回值下断点有效。

## 触发条件

- 目标为 Windows PE，入口/校验函数调用 `SetUnhandledExceptionFilter` 注册顶层异常回调。
- 程序在关键路径主动触发未处理异常（典型是错误序列号/错误输入分支），且该异常没有被更早的 SEH/VEH 处理掉。
- 分析者使用会接管异常的调试器（OllyDbg、x64dbg 默认行为），且未在调试器设置中放行该异常。
- 样本没有额外交叉校验 `UnhandledExceptionFilter` 的调用路径，或交叉校验可一并 patch。

## 利用步骤

1. 在 `SetUnhandledExceptionFilter` 下断点，运行到调用处，读取其参数得到顶层回调地址（该类样本通常把校验代码就放在这个地址）。
2. 在回调地址与 `UnhandledExceptionFilter` 下断点；随后可禁用 `SetUnhandledExceptionFilter` 断点，避免重复中断。
3. 按样本要求的输入路径触发异常（例如填入错误序列号并点击校验按钮）；程序会中断在 `UnhandledExceptionFilter`。
4. 单步跟踪 `UnhandledExceptionFilter`，找到它对 `ntdll!ZwQueryInformationProcess` 的调用：第二个参数 `ProcessInformationClass = 7`（`ProcessDebugPort`），输出缓冲区大小 4 字节。
5. 被调试时缓冲区值为 `0xFFFFFFFF`；在调用返回后把该 4 字节改为 0（或把“是否为 0”的比较/条件跳转改掉），`UnhandledExceptionFilter` 即认为进程未调试，转而调用注册的顶层回调。
6. 回调执行后即可看到真正的校验/注册逻辑（如逐字符变换输入、与常量比较、成功弹窗）；继续静态分析回调或直接完成注册。
7. 历史环境也可用 HideOD 一类插件自动处理该检测；现代调试器可在异常设置中把该异常配置为放行/忽略，效果等同。

## PoC

按机制构造的最小示意（未执行）：

```c
#include <windows.h>

static LONG CALLBACK TopLevelFilter(EXCEPTION_POINTERS *ep) {
    /* 真正的校验/注册逻辑放在这里：只有非调试时才会被系统调用 */
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    SetUnhandledExceptionFilter(TopLevelFilter);
    /* 主动制造未处理异常，触发 UnhandledExceptionFilter 的调试判定 */
    *(volatile int *)0 = 0;
    return 0;
}
```

调试器侧绕过要点（伪代码，未在本机执行）：

```text
断点 SetUnhandledExceptionFilter -> 记录参数（顶层回调地址）
断点 UnhandledExceptionFilter 内对 ntdll!ZwQueryInformationProcess 的调用
当 ProcessInformationClass == 7（ProcessDebugPort）且返回后缓冲区 != 0:
    将缓冲区 4 字节改写为 0
继续运行 -> UnhandledExceptionFilter 判定“未调试” -> 调用顶层回调
```

## 变体与关联

- 变体：回调内做代码自解密/自修改，调试时不解密；把“回调是否执行”写成全局标志，后续逻辑据标志分支；与 VEH/SEH 组合，先由自己的处理器接管再复现同样的调试差异；把成功提示/注册写入也移入回调，使调试时完全观察不到。
- 关联卡片：[[code-analysis-reverse-anti-debug-exception-timing-checksum-bypass]]（SEH/INT 2D/TF/时序等异常类反调试家族，本卡是该家族中依赖 `UnhandledExceptionFilter` 内部 DebugPort 查询的具体机制）；[[code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch]]（`ZwQueryInformationProcess` 的 DebugPort/DebugFlags 参数与返回值篡改）；[[code-analysis-reverse-anti-debug-veh-custom-exception-debugger-detection-hijack]]（同样利用“调试器优先处理异常”的优先级差异）。
- 边界：若样本自己用 SEH 处理掉异常，`UnhandledExceptionFilter` 不会介入，本机制不成立；调试器把异常直接放行时回调会被执行，检测失效；`UnhandledExceptionFilter` 的内部实现细节随 Windows 版本演进，但“被调试时不调用顶层过滤器、未调试时调用”的行为长期稳定。

## 检测与防御

- 检测特征：导入/调用 `SetUnhandledExceptionFilter` 且回调地址位于代码段、回调内包含输入校验与成功提示；错误输入分支出现访问违例/除零等“故意异常”；`UnhandledExceptionFilter` 内部调用 `ZwQueryInformationProcess(7)`。
- 分析侧：在 `ZwQueryInformationProcess` 返回处把 DebugPort 缓冲区改 0；在调试器异常设置中放行该异常；用硬件断点减少代码扰动；脚本化 patch 比手工修改跳转更可复用。
- 样本侧加固（对抗分析）：多层检测交叉验证、把关键逻辑拆分到多线程或自解密壳中、对 `UnhandledExceptionFilter` 的调用结果做二次校验；但都会增加兼容性与稳定性成本。
