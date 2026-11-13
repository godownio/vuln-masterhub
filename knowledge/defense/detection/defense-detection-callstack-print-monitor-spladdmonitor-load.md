---
id: defense-detection-callstack-print-monitor-spladdmonitor-load
title: 调用堆栈检测打印监视器后门：spoolsv.exe 加载未签名 DLL 且栈含 localspl!SplAddMonitor
type: scenario
domain: defense
path: defense/detection
technique: callstack-print-monitor-spladdmonitor-load
aliases:
- SplAddMonitor 检测
- 打印监视器持久化检测
- spoolsv 未签名 DLL
- port monitor 后门
- Elastic Defend 打印监视器
tags:
- defense
- detection
- call-stack
- elastic
- eql
- edr
- windows
- print-spooler
- persistence
- dll
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:14+08:00'
  notes: 已对照原文与 img19 核对：EQL（spoolsv.exe System32/SysWOW64、not dll.code_signature.status:trusted、*localspl.dll!SplAddMonitor*）与原文一致；截图命中 spoolsv.exe 加载 C:\Windows\Logs\RunDllExe.dll，栈含 localspl.dll!SplAddMonitor+0x185、SplEnumPrinterDrivers+0x6ae、SplReenumeratePorts+0x389、spoolsv.exe!PrvAddMonitor+0x3f。与攻方卡 pentest-persistence-windows-print-monitor-driver-dll 为攻防两侧不同链，dedup 判 related/new 成立。原文未给组件版本，未设 affected_versions；无 sources/source_url。
---

## 一句话结论

攻击者可用 port monitor 在系统启动期间让打印后台处理程序加载其 DLL，实现持久化或权限提升；检测方法是监控 `spoolsv.exe` 加载未签名库，且调用栈中出现 `localspl.dll!SplAddMonitor`——该函数负责注册打印监视器，是“DLL 因监视器注册而被加载”的直接证据。

## 原理

- **打印监视器机制**：打印后台处理程序 `spoolsv.exe` 在启动时读取 `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`，加载各监视器注册的 Driver DLL；`AddMonitor`/`SplAddMonitor` 是注册监视器的 API。
- **攻击用法**：把恶意 DLL 放入 `System32`（或可写路径）并注册为 print monitor，系统启动/打印服务重启时由 `spoolsv.exe` 以 SYSTEM 权限加载；见攻方卡 `pentest-persistence-windows-print-monitor-driver-dll`。
- **栈锚点**：正常打印相关 DLL 加载的调用栈通常不以 `SplAddMonitor` 为锚；若一个未签名 DLL 的加载栈中出现 `localspl.dll!SplAddMonitor`，说明它是通过监视器注册路径被加载的，结合签名状态即可判定异常。
- **为什么有效**：`spoolsv.exe` 会加载大量微软签名 DLL，只对“未签名 + SplAddMonitor 锚点”告警可大幅降噪；攻击者要在启动时加载 DLL，很难绕开该注册路径（也可直接写注册表，但加载时仍会经过 localspl 的监视器初始化）。
- **边界**：第三方打印驱动/监视器可能是合法但未签名的企业软件，需按发布者白名单；攻击者若篡改已签名 DLL 或利用 DLL 搜索顺序，锚点仍可能命中但签名判断需结合文件哈希。

## 触发条件

- EDR 采集库加载事件、DLL 签名状态与调用栈符号。
- 目标为 Windows，打印后台处理程序服务运行（默认）。
- 规则用于检测/狩猎。

## 利用步骤（检测步骤）

1. 部署 EQL：`library` 事件、进程为 `spoolsv.exe`、DLL 签名非 trusted、调用栈符号含 `localspl.dll!SplAddMonitor`。
2. 命中后检查 DLL 路径（`C:\Windows\System32`、`C:\Windows\Logs`、临时目录）、签名、哈希与创建时间。
3. 检查 `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors` 下的 Driver 值与 `SplAddMonitor` 注册项，定位异常监视器名称。
4. 按持久化事件处置：删除监视器注册、隔离 DLL、重启打印服务。

## PoC

```eql
library where
process.executable : ("?:\\Windows\\System32\\spoolsv.exe",
"?:\\Windows\\SysWOW64\\spoolsv.exe") and not dll.code_signature.status :
"trusted" and _arraysearch(process.thread.Ext.call_stack, $entry,
$entry.symbol_info: "*localspl.dll!SplAddMonitor*")
```

原文截图中命中 `spoolsv.exe` 加载 `C:\Windows\Logs\RunDllExe.dll`（未签名），调用栈含 `localspl.dll!SplAddMonitor+0x185`、`SplEnumPrinterDrivers+0x6ae`、`SplReenumeratePorts+0x389` 等帧。

## 变体与关联

- **攻方卡**：`pentest-persistence-windows-print-monitor-driver-dll`（AddMonitor + 注册表 Driver 指向 System32 DLL）。
- **同类宿主**：`ServiceMain` 服务 DLL 落地检测见 `defense-detection-callstack-servicemain-unsigned-service-dll`。
- **变体**：打印处理器（print processor）、端口监视器、打印驱动 DLL 的未签名加载；也可用 `AddPrintProvidor` 等注册路径。
- **边界**：合法第三方打印软件可以是未签名，需维护发布者/路径白名单；仅监控 DLL 加载会漏掉已加载后注入的行为。

## 检测与防御

- **检测**：上述 EQL；补充注册表监控 `Control\Print\Monitors` 与 `SplAddMonitor` 相关键；记录 spoolsv 加载的非系统 DLL。
- **降噪**：按签名、发布者、路径、安装时间过滤；对企业打印软件建基线。
- **加固**：限制 `System32` 写权限；不需要打印服务的服务器禁用 Print Spooler；启用 WDAC/AppLocker 限制 spoolsv 加载路径；监控打印服务异常重启。
- **响应**：删除恶意监视器注册与 DLL，检查 SYSTEM 权限下的后续行为（服务、计划任务、网络）。
