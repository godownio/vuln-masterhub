---
id: code-analysis-reverse-anti-debug-veh-custom-exception-debugger-detection-hijack
title: VEH 反调试与反反调试：自定义异常判断调试器 + 劫持 VEH 双链表移除/抢先保护处理程序
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: veh-custom-exception-debugger-detection-hijack
aliases:
- VEH 反调试
- AddVectoredExceptionHandler 检测调试器
- VEH 链表劫持
- VEH 双链表遍历
- 隐形 VEH
- 异常优先级反调试
tags:
- windows
- anti-debug
- veh
- exception-handling
- reverse-engineering
- anti-anti-debug
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:50:01+08:00'
  notes: 已对照原文核对：VEH+RaiseException(0x12345678)/isDebugged检测逻辑与原文一致；VEH双链表头0x7FFDF000附近、摘链/抢先在原文中为概念性描述，未给完整结构体与PoC，卡内已标注为概念性操作；未复跑。
---

## 一句话结论

样本注册 VEH 后主动触发自定义异常（如 `RaiseException(0x12345678, ...)`），利用“调试器优先于 VEH 处理异常”的规则：若 VEH 未被调用或延迟超过阈值，就判定处于调试环境并退出/加密代码；反过来，分析者可遍历并修改进程堆中的 VEH 双链表，移除保护程序的 VEH 节点或在链表头插入自己的处理程序，让自定义 VEH 抢先执行，从而绕过保护/反调试。

## 原理

- **异常分发优先级**：异常触发后先给调试器；调试器未处理（或被配置为放行）才遍历 VEH 双链表（从头部开始，后注册的高优先级）；所有 VEH 返回 `EXCEPTION_CONTINUE_SEARCH` 后才进入线程 SEH；最后是系统默认处理。该顺序本身可被双方利用。
- **样本侧检测**：注册 VEH（`First=1` 放链表头），在全局变量 `isDebugged` 先置 `TRUE`，然后 `RaiseException(自定义码)`。若正常运行，VEH 被调用并把 `isDebugged` 置 `FALSE`、返回 `EXCEPTION_CONTINUE_EXECUTION`；若调试器优先接管并暂停/不继续，VEH 不会被调用，`isDebugged` 仍为 `TRUE`，样本判定被调试并退出。也可用“VEH 调用延迟超过阈值”作为辅助判据。
- **VEH 链表结构**：VEH 处理程序以双向链表节点存储在进程堆中，`AddVectoredExceptionHandler(First=1/0)` 向头部/尾部插入；链表头指针位于进程地址空间的固定区域（x86 通常在 `0x7FFDF000` 附近，需按目标版本/调试器确认）。遍历链表可找到保护程序注册的 VEH 节点。
- **反反调试（VEH 劫持）**：修改节点的 `Next`/`Prev` 指针把保护 VEH 从链表摘除，或在链表头插入自定义 VEH，使自己的处理程序先于保护程序执行，拦截其异常检测；也可在自定义 VEH 中修改 `ContextRecord` 让保护逻辑走向“正常”分支。
- **隐藏 VEH**：把处理程序代码注入合法模块（如 `kernel32.dll`）减少 DLL 特征；给处理程序加垃圾指令/混淆；或使用内核回调注册异常处理（“隐形 VEH”）绕过用户态 VEH 链表检测。
- **局限**：调试器可以选择“放行异常”并让 VEH 正常执行，检测可能失效；链表头位置与结构随 Windows 版本变化；直接改链表可能破坏结构导致崩溃；部分保护会校验链表完整性。

## 触发条件

- 目标为 Windows PE，样本使用 VEH + 自定义异常做反调试，或保护程序注册了多个 VEH 处理程序。
- 分析者能读写目标进程内存、定位 VEH 链表头与节点结构。
- 调试器可控（能配置异常放行/忽略，或使用脚本修改内存）。
- 目标未使用内核态异常回调/强完整性校验来保护 VEH 链表。

## 利用步骤

1. 在样本中定位 `AddVectoredExceptionHandler`、`RaiseException`、自定义异常码（如 `0x12345678`）与 `isDebugged` 全局变量。
2. 运行样本，观察调试器是否先接管异常、VEH 是否被调用；若样本退出，定位判断 `isDebugged` 的分支。
3. 绕过检测：
   - 配置调试器放行/忽略该异常，让 VEH 正常执行；
   - 或直接把 `isDebugged` 改为 `FALSE`、patch 判断跳转；
   - 或把 `RaiseException` 的自定义码改成不触发检测的值。
4. 若保护程序用 VEH 做反调试，定位 VEH 链表头（调试器内存搜索/跟踪 `AddVectoredExceptionHandler` 写入），遍历节点，按处理程序地址识别保护 VEH。
5. 修改节点 `Next`/`Prev` 把保护 VEH 摘除，或在链表头插入自定义 VEH；确保链表结构完整，避免崩溃。
6. 在自定义 VEH 中拦截保护程序的异常检测，返回 `EXCEPTION_CONTINUE_EXECUTION` 让程序走正常路径；必要时把处理程序代码放进合法模块并混淆以隐藏。

## PoC

自定义异常检测（文章示例）：

```c
BOOL isDebugged = FALSE;

LONG NTAPI CheckDebugVEH(_EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0x12345678) {
        isDebugged = FALSE; // VEH 被调用，说明无调试器（或调试器放行）
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

AddVectoredExceptionHandler(1, CheckDebugVEH);
isDebugged = TRUE;              // 先假定可能被调试
RaiseException(0x12345678, 0, 0, NULL);
if (isDebugged) {
    MessageBoxA(NULL, "检测到调试器！", "反调试", MB_OK);
    ExitProcess(0);
}
```

VEH 链表劫持为概念性操作（文章未给完整结构体/偏移，需按目标版本确认）：

```text
1. 定位 VEH 链表头 pHead（x86 常在 0x7FFDF000 附近，或跟踪 AddVectoredExceptionHandler 的写入）
2. 遍历 pHead->Next，读取每个节点的 Handler 地址
3. 找到保护程序的 Handler 节点，修改前驱/后继指针将其摘除
4. 构造自己的节点，插入 pHead 头部，使其优先执行
```

## 变体与关联

- **检测方式变体**：`SetUnhandledExceptionFilter` 顶层异常、SEH、`int 3`/`INT 2D`、TF 单步、RDTSC 时序；可与 VEH 组合交叉验证。
- **隐藏方式变体**：处理程序代码注入合法模块、加垃圾指令/混淆、使用内核回调注册“隐形 VEH”。
- **对抗方式变体**：调试器配置异常放行；直接 patch `isDebugged`/跳转；硬件断点替代软件断点减少异常扰动。
- **关联**：[[code-analysis-reverse-anti-debug-exception-timing-checksum-bypass]]（SEH/INT 2D/TF/RDTSC 反调试家族与绕过）、[[code-analysis-dynamic-debugging-veh-invisible-breakpoint-dynamic-patch]]（VEH 隐形断点/动态补丁的正向用法）、[[code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch]]（调试信息 API 检测）。

## 检测与防御

- **检测 VEH 链表**：枚举进程 VEH 节点，检查处理程序是否指向匿名/非模块内存、是否被异常注册/摘除；监控 `AddVectoredExceptionHandler` 调用。
- **检测异常行为**：进程主动 `RaiseException` 自定义码、异常频率异常、VEH 处理程序大量执行，可能是反调试或 VEH 劫持。
- **完整性**：保护 VEH 链表结构，校验节点指针与处理程序地址；关键代码段做哈希校验。
- **加固**：启用 CFG/CET、ACG；减少用户态异常处理被滥用的空间；对高价值进程使用内核态异常回调/EDR 监控。
- **分析侧**：优先配置调试器放行/忽略自定义异常，减少对 VEH 链表的直接修改；修改链表前备份原指针，避免结构损坏。
