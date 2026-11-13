---
id: code-analysis-reverse-anti-debug-dbg-printexception-wide-c
title: DBG_PRINTEXCEPTION_C/W 调试打印异常反调试：RaiseException 触发 0x40010006/0x4001000A，调试器吞掉异常则继续执行
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: dbg-printexception-wide-c-debugger-detection
tags:
- windows
- anti-debug
- exception-handling
- seh
- dbg-printexception
- reverse-engineering
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V564
  verified_at: '2026-11-12T08:00:42+08:00'
  notes: 已对照原文与14张图片逐张核对：图01 IsDebuggerPresent.exe 在 OllyDbg 下输出 Is Debug Now、02 dt _PEB 显示 BeingDebugged@0x002、03 CheckRemoteDebuggerPresent.exe 输出 Is Debug Now、04/05 ReactOS debugger.c 中 CheckRemoteDebuggerPresent 以 NtQueryInformationProcess(ProcessDebugPort) 实现、06/07 PEB NtGlobalFlag@0x0bc 与 OllyDbg 下 0x70 判定、08/09 父进程 explorer.exe 与 OllyDbg.exe 对比、10/11 TLS 回调先于 main 输出与调试弹窗、12 PEBear TLS Callbacks[1 entry]、13/14 DBG_PRINTEXCEPTION_WIDE_C 代码与 Debugging 弹窗，均与正文/卡一致；卡内 0x40010006/0x4001000A 异常码、RaiseException(args[0]=len+1,args[1]=字符串指针,4参数)、调试器消费走 Debugging、无调试器走 __except Hello 的判定逻辑与原文代码一致。skipped 六项核对：IsDebuggerPresent→peb-fields-patch/thread-isdebuggerpresent-loop-exit、CheckRemoteDebuggerPresent+NtQuery→ntquery-debug-info-argument-patch（正文含 CheckRemoteDebuggerPresent 6处、ThreadHideFromDebugger 5处）、NtGlobalFlag→peb-fields-patch（NTGlobalFlag 0x70 已覆盖）、父进程→windows-sandbox-fingerprint-parent-check（explorer 父进程校验9处）/parent-process-terminate、TLS→tls-callback-pe-null-patch、NtSetInformationThread→ntquery-debug-info-argument-patch，均有既有卡覆盖，零新增合理。dedup仅自匹配duplicate，VEH
    自定义异常卡为 related（异常码/机制不同），非同链。未复跑；原文无组件版本，未set-versions。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-dbg-printexception-wide-c/
draft: false
kb_aliases:
- DBG_PRINTEXCEPTION_C
- DBG_PRINTEXCEPTION_W
- 1073807366
- 1073807370
- 调试打印异常反调试
- RaiseException 反调试
- OutputDebugString 异常检测
---

## 一句话结论

`DBG_PRINTEXCEPTION_C`（0x40010006）和 `DBG_PRINTEXCEPTION_W`（0x4001000A）本是 `OutputDebugString` 向调试器输出字符串时使用的特殊异常码；程序可用 `RaiseException(0x4001000A, 0, 4, args)` 主动抛出它——有调试器时异常被调试器消费、`__except` 不执行（走 "Debugging" 分支），无调试器时异常交给 SEH、进入 `__except`（走 "Hello" 分支），从而用一个普通异常处理结构判断是否被调试。

## 原理

- **这两个异常码的来源**：`OutputDebugStringA/W` 在用户态把字符串打包成异常记录并调用 `RaiseException`，异常码分别是 `DBG_PRINTEXCEPTION_C = 0x40010006` 与 `DBG_PRINTEXCEPTION_WIDE_C = 0x4001000A`，参数个数为 4（`args[0]` 为字符串长度、`args[1]` 为宽/窄字符串指针，其余保留）。调试器（WinDbg、x64dbg、OllyDbg 等）会识别这些异常并打印字符串，**不与程序共享异常处理**——它们属于调试器自身消费的通知。
- **反调试判定逻辑**：
  - 被调试时：`RaiseException(0x4001000A, ...)` 被调试器接走，控制流从 `RaiseException` 之后继续，执行 `MessageBox("Debugging")`。
  - 未被调试时：异常没有调试器消费，内核按 SEH 链分发给程序自己的 `__except`，执行 `MessageBox("Hello")`。
- **为什么能成立**：调试事件的优先级高于用户态 SEH；调试器对 `DBG_PRINTEXCEPTION_*` 默认"处理并继续"，不会把 `EXCEPTION_CONTINUE_SEARCH` 还给程序；而未调试时这类异常与普通异常一样进入 SEH 分发。于是"哪个分支被执行"就泄露了调试状态。
- **与 VEH/SEH 反调试的区别**：VEH 卡利用"调试器优先处理自定义异常、VEH 是否被调用"判断；本技巧是直接借用系统定义的调试打印异常码，不自定义异常码，也不需要注册 VEH，只需一个 `__try/__except`。
- **局限**：若调试器被配置为把该类异常传给程序（或忽略后放行），判定会失效；异常码/参数不合法可能被系统直接忽略；`/EHs` 等异常模型配置会影响 `__except` 是否生成。

## 触发条件

- Windows 用户态程序，使用 SEH（`__try/__except` 或等价异常处理）。
- 调试器按默认策略消费 `DBG_PRINTEXCEPTION_C/W`（WinDbg/x64dbg/OllyDbg 常见默认）。
- 攻击者/分析者需要识别样本是否在做此类判断时，二进制中出现 `0x40010006`/`0x4001000A` 常量与 `RaiseException` 调用是强特征。

## 利用步骤

1. 样本侧：在 `__try` 中调用 `RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, 4, args)`，参数按异常记录格式填字符串长度和指针。
2. `RaiseException` 之后放"被调试"分支（如弹 "Debugging"/退出），`__except(EXCEPTION_EXECUTE_HANDLER)` 中放"未调试"分支。
3. 运行验证：直接运行看到 "Hello"（未调试）；调试器加载后运行看到 "Debugging"（调试器吞掉了异常）。
4. 分析绕过：在该 `RaiseException` 处下断，跳过后续"调试器命中"分支；或把异常码改成普通自定义码让调试器放行给 SEH；或让调试器配置为不忽略 `DBG_PRINTEXCEPTION_*`（部分调试器可设置）。

## PoC

```c
#include <windows.h>
#include <stdio.h>
#define DBG_PRINTEXCEPTION_WIDE_C 0x4001000A

int main() {
    WCHAR* outputString = (WCHAR*)"Any text";
    ULONG_PTR args[4] = { 0 };
    args[0] = (ULONG_PTR)wcslen(outputString) + 1;
    args[1] = (ULONG_PTR)outputString;
    __try {
        RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, 4, args);
        MessageBox(NULL, "Debugging", "Debugging", MB_OK);   // 有调试器：异常被吞，走这里
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MessageBox(NULL, "Hello", "Hello", MB_OK);           // 无调试器：SEH 处理，走这里
    }
}
```

## 变体与关联

- 变体：ANSI 版 `DBG_PRINTEXCEPTION_C`（0x40010006）参数为窄字符串指针；也可组合多个不同异常码做多次判定，降低误判。
- 关联：[[code-analysis-reverse-anti-debug-veh-custom-exception-debugger-detection-hijack]]（自定义异常 + VEH 优先级判断）、[[code-analysis-reverse-anti-debug-setunhandledexceptionfilter-toplevel-filter]]（异常过滤器判断调试器）、[[code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch]]（NtQuery 系列调试端口/对象检测）。
- 边界：调试器放行该类异常、异常处理模型不生成 `__except`、或系统/EDR 拦截 `RaiseException` 时，判定失效。

## 检测与防御

- **检测**：二进制常量中出现 `0x40010006`/`0x4001000A` 且伴随 `RaiseException`；异常处理分支里出现 MessageBox/ExitProcess 等差异行为；调试器日志中出现异常的 DBG_PRINTEXCEPTION 记录。
- **防御**：客户端反调试只能提高分析成本，不能作为安全边界；分析时以调试器配置放行或直接 patch 分支绕过；检测侧可监控异常码使用与异常分发行为。
