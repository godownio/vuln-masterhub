---
id: defense-detection-callstack-ldrpkernel32-bootstrap-dll-hijack
title: 调用堆栈检测 LdrpKernel32 覆盖：BaseThreadInitThunk 由非系统 kernel32/恶意引导 DLL 导出
type: scenario
domain: defense
path: defense/detection
technique: callstack-ldrpkernel32-bootstrap-dll-hijack
tags:
- defense
- detection
- call-stack
- elastic
- eql
- edr
- windows
- dll-hijack
- bootstrapping
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:17+08:00'
  notes: 已对照原文与 img21 核对：EQL 的合法 kernel32 路径排除列表（System32/SysWOW64/WinSxS/WinSxS\Temp\PendingDeletes/\Device\*\Windows\*）与原文一致（原文 $entry.symbol_info 后漏冒号，本卡已补正）；截图命中 cmd.exe，栈含 C:\Users\bouss\Downloads\Ldrpkernel32DllName-main\Ldrpkernel32DllName-main\Ldrpkernel64.dll!BaseThreadInitThunk+0xf1，call_stack_summary 为 ntdll.dll|ldrpkernel64.dll|ntdll.dll。dedup 候选为调试事件取模块基址/EDR 假 DLL 保护页卡，非同链。原文未给组件版本，未设 affected_versions；无 sources/source_url。
url: /docs/defense/detection/defense-detection-callstack-ldrpkernel32-bootstrap-dll-hijack/
draft: false
kb_aliases:
- LdrpKernel32 检测
- LdrpKernel32DllName
- BaseThreadInitThunk 劫持检测
- 引导 DLL 名称覆盖
- Elastic Defend LdrpKernel32
---

## 一句话结论

LdrpKernel32 类规避通过覆盖 ntdll 引导阶段引用的引导 DLL 名称，强制进程加载恶意 DLL；该 DLL 必须导出 `BaseThreadInitThunk`（通常是 kernel32 的专属导出）。因此若库加载/模块事件调用栈中出现 `!BaseThreadInitThunk` 符号，但导出它的模块不是系统路径下的 kernel32（System32/SysWOW64/WinSxS/待删除路径），即可判定为引导 DLL 名称劫持。

## 原理

- **早期引导**：进程启动时 ntdll 的 `LdrpInitialize` 会加载引导 DLL（kernel32 等），随后通过 `LdrpRunInitializeRoutines`/`BaseThreadInitThunk` 进入用户线程。`BaseThreadInitThunk` 正常情况下由 kernel32 导出，是线程启动栈中的固定帧。
- **LdrpKernel32DllName 规避**：攻击者修改内存中引用的引导 DLL 名称（如把 `kernel32.dll` 改成恶意 DLL 名），使 ntdll 在早期加载攻击者 DLL；为让引导流程继续，恶意 DLL 必须伪造导出 `BaseThreadInitThunk`，于是调用栈中出现 `<恶意模块>!BaseThreadInitThunk`。
- **检测判据**：监控库加载事件（或进程/线程事件）的调用栈符号：存在 `*!BaseThreadInitThunk*`，但同一栈中没有来自合法 kernel32 路径的 `BaseThreadInitThunk`（`System32`、`SysWOW64`、`WinSxS`、`WinSxS\Temp\PendingDeletes`、`\Device\*\Windows\*`）。合法路径的排除列表用于避免把系统正常路径误报。
- **为什么有效**：`BaseThreadInitThunk` 是 kernel32 的独占导出语义；非 kernel32 模块导出同名函数在正常系统中不存在，出现即表明引导链被篡改。
- **示例**：原文截图命中 `C:\Users\bouss\Downloads\Ldrpkernel32DllName-main\...\Ldrpkernel64.dll!BaseThreadInitThunk+0xf1`，调用栈摘要为 `ntdll.dll|ldrpkernel64.dll|ntdll.dll`。
- **边界**：攻击者可改名/转发导出，但符号仍可能显示；合法第三方壳/保护器若伪造该导出会误报，需按签名与路径白名单。

## 触发条件

- EDR 采集库加载/进程事件的调用栈符号与模块路径。
- 目标为 Windows；攻击者使用 LdrpKernel32DllName 或类似引导 DLL 名称覆盖技术。
- 规则用于检测/狩猎。

## 利用步骤（检测步骤）

1. 部署 EQL：库事件中，调用栈存在 `*!BaseThreadInitThunk*`，且不存在来自合法 kernel32 路径的 `BaseThreadInitThunk`（排除列表见 PoC）。
2. 命中后检查导出 `BaseThreadInitThunk` 的模块路径、签名、哈希与创建时间，确认是否为恶意 DLL。
3. 检查进程的早期加载模块列表与 ntdll 引导名称是否被修改；抓取进程内存做模块比对。
4. 关联该 DLL 的后续行为（网络、持久化、注入）定性。

## PoC

```eql
library where

// BaseThreadInitThunk 必须由恶意引导 DLL 导出
 _arraysearch(process.thread.Ext.call_stack, $entry, $entry.symbol_info :
  "*!BaseThreadInitThunk*") and

// 排除正常导出 BaseThreadInitThunk 的 kernel32
not _arraysearch(process.thread.Ext.call_stack, $entry, $entry.symbol_info
 ("?:\\Windows\\System32\\kernel32.dll!BaseThreadInitThunk*",
  "?:\\Windows\\SysWOW64\\kernel32.dll!BaseThreadInitThunk*",
  "?:\\Windows\\WinSxS\\*\\kernel32.dll!BaseThreadInitThunk*",
  "?:\\Windows\\WinSxS\\Temp\\PendingDeletes\\*!BaseThreadInitThunk*",
  "\\Device\\*\\Windows\\*\\kernel32.dll!BaseThreadInitThunk*"))
```

原文截图中命中进程 `cmd.exe`，栈含 `C:\Users\bouss\Downloads\Ldrpkernel32DllName-main\Ldrpkernel32DllName-main\Ldrpkernel64.dll!BaseThreadInitThunk+0xf1`，`call_stack_summary` 为 `ntdll.dll|ldrpkernel64.dll|ntdll.dll`。

## 变体与关联

- **同类技术**：DLL 搜索顺序劫持、引导 DLL 替换、LdrLoadDll 名称覆盖；见 `pentest-privilege-escalation-windows-dll-search-order-hijack-lpe`、`pentest-persistence-dll-search-order-hijack-proxy-forwarding`。
- **攻方工具**：LdrpKernel32DllName（rbmm）。
- **绕过**：恶意 DLL 可转发到 kernel32 的真实导出，符号可能显示为转发；需结合模块路径与签名。

## 检测与防御

- **检测**：上述 EQL；补充监控非系统路径模块导出 `BaseThreadInitThunk`、进程早期加载模块异常、`ntdll` 引导名称修改。
- **降噪**：对合法壳/保护器与第三方软件建立签名/路径白名单。
- **加固**：启用 WDAC/AppLocker、DLL 签名强制与安全加载策略；限制用户可写目录的 DLL 加载。
- **响应**：隔离主机，提取恶意引导 DLL 与进程内存，排查持久化与同源投递。
