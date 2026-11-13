---
id: defense-detection-callstack-dirty-vanity-process-reflection
title: 调用堆栈检测 Dirty Vanity 进程反射：RtlCreateProcessReflection/RtlCloneUserProcess + 子进程或网络活动
type: scenario
domain: defense
path: defense/detection
technique: callstack-dirty-vanity-process-reflection
tags:
- defense
- detection
- call-stack
- elastic
- eql
- edr
- windows
- process-injection
- process-forking
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:05+08:00'
  notes: 已对照原文与 img11-13 核对：父线程栈含 RtlCreateUserProcess/RtlCloneUserProcess+0x183/RtlCreateProcessReflection+0x68c；线程起始地址 ntdll.dll!RtlCreateProcessReflection+0x590；fork 出的 explorer.exe 派生子进程 cmd.exe /k msg * Hello from Dirty Vanity；两条 EQL（descendant of 规则、sequence maxspan=1m 规则）与 WerFault/faultrep 排除与原文逐字一致。dedup 候选为通用注入/线程处置卡，非同链。原文未给组件版本，未设 affected_versions；无 sources/source_url。
url: /docs/defense/detection/defense-detection-callstack-dirty-vanity-process-reflection/
draft: false
kb_aliases:
- Dirty Vanity 检测
- RtlCreateProcessReflection
- RtlCloneUserProcess
- 进程反射注入检测
- process forking 检测
- Elastic Defend 进程反射
---

## 一句话结论

Dirty Vanity 通过 `RtlCreateProcessReflection`/`RtlCloneUserProcess` 复制现有进程（process forking）并注入 shellcode，因 fork 进程的初始线程未执行，常规进程创建通知回调可能漏记；但注入后线程启动会触发进程事件，且父线程调用栈中出现 `ntdll.dll!RtlCreateProcessReflection`/`RtlCloneUserProcess`。以“fork 进程再派生子进程”或“fork 后 1 分钟内发生网络/DNS/网络库加载”为条件，可高置信度检出该注入。

## 原理

- **进程反射/fork 的盲区**：Dirty Vanity 滥用 `RtlCreateProcessReflection`/`RtlCloneUserProcess` 复制已运行或牺牲进程的地址空间和可继承句柄，再向副本注入 shellcode。fork 本身不执行新进程的初始线程，因此依赖进程创建通知回调（`PsSetCreateProcessNotifyRoutineEx`）的 EDR 可能看不到 fork 动作。
- **注入后必然暴露**：一旦 shellcode 在 fork 进程中创建线程并运行，就会触发进程/线程事件；此时父线程调用栈保留了 fork 路径的返回地址，出现 `ntdll.dll!RtlCreateProcessReflection`、`ntdll.dll!RtlCloneUserProcess` 等帧。
- **为何还要看后续行为**：单独的 fork 在诊断/崩溃处理中常见（如 WerFault 场景），不是强恶意信号；但 fork 出的进程再派生子进程，或在 1 分钟内发起网络/DNS 请求、加载 `ws2_32.dll`/`winhttp.dll`/`wininet.dll`，则非常可疑——正常 fork 很少紧接着做这些事。
- **示例**：文章截图显示被 fork 的 `explorer.exe` 自身作为父进程启动 `cmd.exe /k msg * Hello from Dirty Vanity`，Process Hacker 中 fork 出的 explorer.exe 线程起始地址为 `ntdll.dll!RtlCreateProcessReflection+0x590`；父线程栈 JSON 中包含 `RtlCreateUserProcess`、`RtlCreateProcessReflection+0x68c`、`RtlCloneUserProcess+0x183` 等帧。
- **为什么有效**：fork 的系统调用路径固定，注入后线程启动无法避免留下反射 API 的返回地址；把“fork”与“后续高风险行为”组合可以把误报压到可接受水平。

## 触发条件

- EDR 具备进程事件与父线程调用栈采集（Elastic Defend 的 `process.parent.thread.Ext.call_stack`、`call_stack_summary`）。
- 目标为 Windows；攻击者使用 Dirty Vanity 或同类基于进程反射/fork 的注入。
- 规则用于检测/狩猎，不要求攻击者配合。

## 利用步骤（检测步骤）

1. 部署规则一：查找“父进程栈含 RtlCreateProcessReflection/RtlCloneUserProcess 且其后代又启动子进程”的进程，排除 WerFault/faultrep/wersvc 的崩溃处理链。
2. 部署规则二：查找 fork 进程事件后 1 分钟内同实体发起网络/DNS 或加载 `ws2_32.dll`/`winhttp.dll`/`wininet.dll` 的序列。
3. 命中后采集 fork 进程的内存：检查未支持（unbacked）RWX 区域、线程起始地址是否落在反射 API 附近，以及注入的 shellcode。
4. 结合命令行（如 `cmd.exe /k msg * Hello from Dirty Vanity` 是公开 PoC 特征）、父进程为 explorer.exe 自身等上下文定性。

## PoC

```eql
// 规则一：fork 出的进程又派生子进程（很可疑）
process where event.action == "start" and
descendant of
  [process where event.action == "start" and
   _arraysearch(process.parent.thread.Ext.call_stack, $entry,
     $entry.symbol_info : ("*ntdll.dll!RtlCreateProcessReflection*",
                           "*ntdll.dll!RtlCloneUserProcess*"))] and
not (process.executable :
      ("?:\\WINDOWS\\SysWOW64\\WerFault.exe",
       "?:\\WINDOWS\\system32\\WerFault.exe") and
     process.parent.thread.Ext.call_stack_summary :
      "*faultrep.dll|wersvc.dl*")
```

```eql
// 规则二：fork 后 1 分钟内发起网络/DNS 或加载网络 DLL（很可疑）
sequence by process.entity_id with maxspan=1m
 [process where event.action == "start" and
  _arraysearch(process.parent.thread.Ext.call_stack, $entry,
    $entry.symbol_info : ("*ntdll.dll!RtlCreateProcessReflection*",
                          "*ntdll.dll!RtlCloneUserProcess*"))]
 [any where
  (event.category : ("network", "dns") or
   (event.category == "library" and
    dll.name : ("ws2_32.dll", "winhttp.dll", "wininet.dll")))]
```

## 变体与关联

- **同类注入面**：process hollowing、process doppelganging、process ghosting、herpaderping 等也有“进程事件时间线异常”的特征，但调用栈锚点不同；本卡只覆盖反射/fork。
- **规避**：攻击者可叠加调用栈欺骗（伪造 RtlCreateProcessReflection 帧的替代栈）；此时需结合内存扫描、线程起始地址与行为序列。
- **关联卡**：`pentest-c2-call-stack-spoofing-pdata-gadget-tls-cache`、`pentest-c2-cs-sleepmask-stack-spoof-unwind-fake-callstack`（栈欺骗让检测失效的角度）；`pentest-c2-windows-process-hollowing-pe-injection`（传统注入）。

## 检测与防御

- **检测**：上述两条 EQL 规则；额外监控 fork 进程的线程起始地址落在 `RtlCreateProcessReflection`/`RtlCloneUserProcess` 附近、unbacked 可执行内存、fork 后立即网络访问。
- **降噪**：WerFault/faultrep/wersvc 的崩溃转储链属于正常 fork；按环境基线补充白名单。
- **加固**：启用 CFG/CIG、ACG（任意代码防护）与代码完整性策略，限制未签名内存执行；及时更新 EDR 的调用栈采集与进程通知能力。
- **响应**：隔离主机，抓取 fork 进程内存与线程上下文，检查注入的 shellcode 与后续网络连接目的地。
