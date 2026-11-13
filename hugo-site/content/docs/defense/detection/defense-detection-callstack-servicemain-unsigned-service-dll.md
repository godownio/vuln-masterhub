---
id: defense-detection-callstack-servicemain-unsigned-service-dll
title: 调用堆栈检测未签名服务 DLL 落地：svchost 创建 MZ 文件且栈含 !ServiceMain
type: scenario
domain: defense
path: defense/detection
technique: callstack-servicemain-unsigned-service-dll
tags:
- defense
- detection
- call-stack
- elastic
- kql
- edr
- windows
- service
- dll
- persistence
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:12+08:00'
  notes: 已对照原文与 img18 核对：KQL（event.category:file、file.Ext.header_bytes:4d5a*、process.name:svchost.exe、*!ServiceMain*）与原文逐字一致；截图命中 C:\Windows\SysWOW64\Remote_Data.exe，调用栈含 SysWOW64\209453.txt!ServiceMain+0x11f 与非系统路径模块。规则本身不校验签名，“未签名”取自原文小节标题，正文未作签名断言。dedup 候选为服务创建/启动攻方卡，非同链。原文未给组件版本，未设 affected_versions；无 sources/source_url。
url: /docs/defense/detection/defense-detection-callstack-servicemain-unsigned-service-dll/
draft: false
kb_aliases:
- ServiceMain 检测
- 服务 DLL 落地检测
- svchost 创建可执行文件
- 未签名服务 DLL
- Elastic Defend ServiceMain
---

## 一句话结论

恶意软件常把自己伪装成 Windows 服务 DLL：要由服务控制管理器（SCM）识别和管理，服务 DLL 必须导出 `ServiceMain`。若 `svchost.exe` 进程创建了以 `MZ`（`4d5a`）开头的可执行文件，且线程调用栈符号中出现 `*!ServiceMain*`，即可判定该文件是由服务 DLL 的 `ServiceMain` 路径落地的，是服务型持久化/载荷释放的强信号。

## 原理

- **服务 DLL 的加载模型**：SCM 按 `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\ServiceDll` 把 DLL 加载进 `svchost.exe`（或其他服务宿主），并调用其导出的 `ServiceMain` 进入服务主循环。
- **栈锚点**：当服务 DLL 的代码在 `ServiceMain` 上下文中创建/写入文件，调用栈中会保留 `ServiceMain` 的帧（符号如 `<模块>!ServiceMain`）。正常 `svchost` 释放文件的行为多来自系统 DLL 的其他导出，很少从 `ServiceMain` 直接写 PE。
- **文件类型判据**：`file.Ext.header_bytes : 4d5a*` 表示落地的是 PE（MZ）；结合 `process.name : svchost.exe` 与 `ServiceMain` 栈，可区分“服务创建普通数据文件”和“服务释放可执行载荷”。
- **为什么有效**：攻击者把恶意 DLL 注册为服务后，若还要释放下一阶段 EXE/服务 DLL，就必须在 `ServiceMain` 的调用上下文里执行文件操作；这个锚点与 PE 头组合误报极低。文章截图显示 `svchost.exe` 写出 `C:\Windows\SysWOW64\Remote_Data.exe`，调用栈含 `SysWOW64\...!ServiceMain+0x11f`。
- **边界**：服务也可能正常更新自身组件（如安装器），需按路径、签名与发布者过滤；纯内存加载不产生文件事件。

## 触发条件

- EDR 采集文件创建事件（含文件头字节）与调用栈符号。
- 目标为 Windows，存在服务 DLL 被注册并通过 `svchost` 加载。
- 规则用于检测/狩猎。

## 利用步骤（检测步骤）

1. 部署 KQL：`event.category:file`、文件头 `4d5a*`、进程 `svchost.exe`、调用栈符号 `*!ServiceMain*`。
2. 命中后检查文件路径（System32/SysWOW64/Temp/ProgramData）、签名与哈希，确认是否为恶意载荷。
3. 枚举该 `svchost` 实例承载的服务（`sc queryex`、`tasklist /svc`、注册表 `Services\*\Parameters\ServiceDll`），定位异常服务注册。
4. 检查服务 DLL 的导出表是否含 `ServiceMain`、签名与创建时间，确认持久化链。

## PoC

```kql
event.category : file and
file.Ext.header_bytes : 4d5a* and process.name : svchost.exe and
process.thread.Ext.call_stack.symbol_info : *!ServiceMain*
```

原文截图中命中 `svchost.exe` 写出的 `C:\Windows\SysWOW64\Remote_Data.exe`（`4d5a` 头），调用栈含 `SysWOW64\...!ServiceMain+0x11f` 与非系统路径模块。

## 变体与关联

- **服务持久化**：`ServiceDll` 指向可写目录；`sc create`/注册表直接写入；见 `pentest-persistence-*` 服务类卡片。
- **打印监视器**：同类“服务宿主加载未签名 DLL”思路，见 `defense-detection-callstack-print-monitor-spladdmonitor-load`。
- **边界**：合法的服务更新/安装器也会从 `ServiceMain` 写 PE，需要签名与路径白名单。

## 检测与防御

- **检测**：上述 KQL；补充监控 `Services\*\Parameters\ServiceDll` 的创建/修改、`sc create` 与服务注册事件（7045/4697）。
- **降噪**：按服务 DLL 签名、发布者、安装窗口与环境基线过滤。
- **加固**：启用 WDAC/AppLocker 限制服务 DLL 路径；保护 `System32`/`SysWOW64` 写权限；监控服务账户异常。
- **响应**：导出服务配置与 DLL 样本，删除恶意服务，排查同源持久化与横向。
