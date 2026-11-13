---
id: defense-detection-callstack-rop-gadget-library-load
title: 调用堆栈检测 ROP gadget DLL 加载：栈以 ntdll/win32u 开头且无 LdrLoadDll/NtMapViewOfSection（AtomLdr）
type: scenario
domain: defense
path: defense/detection
technique: callstack-rop-gadget-library-load
tags:
- defense
- detection
- call-stack
- elastic
- eql
- edr
- windows
- rop
- dll-load
- atomldr
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:16+08:00'
  notes: 已对照原文与 img20 核对：EQL（call_stack_summary 以 ntdll.dll|*/win32u.dll|* 开头，且排除 *ntdll.dll!Ldr*、*KernelBase.dll!LoadLibrary*、*ntdll.dll!*MapViewOfSection*）与原文一致；截图命中 rundll32.exe 加载 AtomLdr.bin，栈首 win32u.dll!NtUserGetOwnerTransformedMonitorRect+0x14、AtomLdr.bin!InitializeAtomSystem+0xea1，栈底 BaseThreadInitThunk/RtlUserThreadStart。dedup 候选为攻方 URLDownloadToFile/线程池代理加载卡，非同链。原文未给组件版本，未设 affected_versions；无 sources/source_url。
url: /docs/defense/detection/defense-detection-callstack-rop-gadget-library-load/
draft: false
kb_aliases:
- ROP gadget DLL 加载检测
- AtomLdr 检测
- win32u gadget 加载 DLL
- 异常模块加载检测
- Elastic Defend ROP 检测
---

## 一句话结论

正常 DLL 加载最终经 `LdrLoadDll`/`NtMapViewOfSection`；若库加载事件的调用栈摘要以 `ntdll.dll|*` 或 `win32u.dll|*` 开头，且整条栈中不存在 `ntdll!Ldr*`、`KernelBase!LoadLibrary*`、`ntdll!*MapViewOfSection*` 等正常加载 API，则说明加载走了 ROP gadget/手工映射路径（如 AtomLdr 用 win32u gadget），是高置信度的模块加载规避信号。

## 原理

- **正常加载路径**：`LoadLibrary` → `LdrLoadDll` → `NtMapViewOfSection`，调用栈中必然出现 `ntdll!LdrLoadDll`、`ntdll!NtMapViewOfSection`/`NtCreateSection` 或 `KernelBase!LoadLibrary*` 等帧，且栈底通常是 ntdll 线程启动帧。
- **ROP gadget 加载**：AtomLdr 等工具利用 `win32u.dll`/`ntdll.dll` 中的 gadget 构造调用链，直接执行 `NtMapViewOfSection`/`LdrLoadDll` 的等价操作或手工映射，绕过 API 监控；此时调用栈以 gadget 所在模块开头，缺少正常加载 API 帧，且栈中常出现工具自身模块（如 `AtomLdr.bin!InitializeAtomSystem`）。
- **为什么有效**：ROP 加载为了避开 `LdrLoadDll` 钩子，必须绕开该函数；栈中缺失正常加载 API 这一“阴性特征”本身就可作为检测依据，再叠加 `win32u.dll`/`ntdll.dll` 开头的栈形态，误报很低（正常加载不会以 win32u 开头）。
- **示例**：原文截图命中 `rundll32.exe` 加载 `AtomLdr.bin`：栈含 `win32u.dll!NtUserGetOwnerTransformedMonitorRect+0x14`、`AtomLdr.bin!InitializeAtomSystem+0xea1`、`kernel32.dll!BaseThreadInitThunk+0x14`、`ntdll.dll!RtlUserThreadStart+0x21`。
- **边界**：合法的底层加载器/安全软件也可能手工映射；需按模块签名与路径白名单；栈欺骗可伪造正常帧导致漏报。

## 触发条件

- EDR 采集库加载事件与调用栈符号（`process.thread.Ext.call_stack`、`call_stack_summary`）。
- 目标为 Windows；攻击者使用 AtomLdr 或类似 ROP gadget/手工映射加载器。
- 规则用于检测/狩猎。

## 利用步骤（检测步骤）

1. 部署 EQL：`library` 事件，`call_stack_summary` 以 `ntdll.dll|*` 或 `win32u.dll|*` 开头，且栈中不存在 `ntdll.dll!Ldr*`、`KernelBase.dll!LoadLibrary*`、`ntdll.dll!*MapViewOfSection*`。
2. 命中后检查被加载 DLL 的路径、签名、哈希与模块名（如 `AtomLdr.bin`），确认是否为攻击工具。
3. 检查加载进程（`rundll32.exe`、`explorer.exe` 等）的命令行、父进程与内存中的 gadget 链。
4. 结合 Atom Table（原子表）异常、未支持内存与后续执行行为定性。

## PoC

```eql
library where
// 攻击者试图用 ntdll.dll 或 win32u.dll 的 ROP gadget
// 构造看起来正常的调用栈
process.thread.Ext.call_stack_summary : ("ntdll.dll|*", "win32u.dll|*") and

// 排除正常的库加载 API：LdrLoadDll 与 NtMapViewOfSection
not _arraysearch(process.thread.Ext.call_stack, $entry,
 $entry.symbol_info: ("*ntdll.dll!Ldr*",
 "*KernelBase.dll!LoadLibrary*", "*ntdll.dll!*MapViewOfSection*"))
```

原文截图中命中 `rundll32.exe` 加载 `C:\Users\...\AtomLdr.bin`，调用栈为 `win32u.dll!NtUserGetOwnerTransformedMonitorRect+0x14` → `AtomLdr.bin!InitializeAtomSystem+0xea1` → ... → `kernel32!BaseThreadInitThunk` → `ntdll!RtlUserThreadStart`。

## 变体与关联

- **同类工具**：AtomLdr（原子表 + win32u gadget）；手工 PE 映射、sRDI、反射加载也可能缺失 `LdrLoadDll` 帧。
- **关联卡**：`pentest-c2-udrl-prepended-reflective-dll-injection`、`pentest-c2-srdi-reflective-dll-injection-shellcode-loader`、`pentest-c2-memorymodule-http-download-inmemory-dll-load-no-loadlibrary`（攻方加载器视角）。
- **绕过**：调用栈欺骗可伪造 `LdrLoadDll` 帧；此时需结合模块签名、内存属性、`win32u` 使用与行为链。

## 检测与防御

- **检测**：上述 EQL；补充对 `win32u.dll` gadget 使用、原子表异常、未支持内存与未签名模块加载的监控。
- **降噪**：排除已知安全产品/底层运行库的合法手工映射；按模块签名与路径加权。
- **加固**：启用 CFG/CIG/HVCI，限制未签名 DLL 与可执行内存；对 `rundll32` 等 LOLBin 的使用做策略限制。
- **响应**：提取被加载模块与加载进程内存，定位 gadget 链与后续载荷，排查持久化。
