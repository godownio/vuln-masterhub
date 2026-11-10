---
id: code-analysis-reverse-windows-water-hydra-ocx-clsid-loader-tmp-dll-injection
title: Water Hydra OCX 加载链：HKCU CLSID InprocServer32 指向 soundtrack.ocx，rundll32 /sta 触发解密 WMFile01.tmp 并注入 WINDBVERS.EXE
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: ocx-clsid-loader-encrypted-tmp-dll-injection
tags:
- windows
- malware
- loader
- ocx
- com
- clsid
- rundll32
- process-injection
- vb6
- water-hydra
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V353
  verified_at: '2026-11-09T00:59:41+08:00'
  notes: 已对照原文核对；HKCU CLSID InprocServer32=soundtrack.ocx、info.txt 内容、Run 键 rundll32 /sta CLSID、ProcMon WMFile01.tmp->Public\Libraries\WMFile01.dll、WINDBVERS.EXE 注入 API 与 SetWindowsHookEx 均有截图；未本机复现
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-water-hydra-ocx-clsid-loader-tmp-dll-injection/
draft: false
kb_aliases:
- OCX CLSID 加载器
- soundtrack.ocx
- MAFWIKFNMUI9430.ocx
- rundll32 /sta CLSID
- WMFile01.tmp 解密
- WINDBVERS.EXE 注入
- Water Hydra loader
- VB6 OCX loader
---

## 一句话结论

MSI 释放到 `%APPDATA%\WMProjectFiles` 的两个 VB6 OCX 构成加载链：`MAFWIKFNMUI9430.ocx` 的导出 `RunDllEntryPointW` 用 `cmd /c cd ... & reg.exe import info.txt` 导入注册表，把 `HKCU\Software\Classes\CLSID\{AAE802DB-FB67-4407-A175-61223EFF30D4}\InprocServer32` 指向同目录的 `soundtrack.ocx`；`rundll32 /sta {CLSID}`（Run 键也会调用）按 CLSID 加载 `soundtrack.ocx`，后者读取并解密 `WMFile01.tmp`，在 `C:\Users\Public\Libraries` 写出 `WMFile01.dll`，再由该 DLL 启动 `WINDBVERS.EXE` 并注入恶意代码，最终内存中运行 DarkMe RAT。

## 原理

- **两个 VB6 OCX 分工**：`MAFWIKFNMUI9430.ocx` 是注册/配置加载器，导出 `RunDllEntryPointW`；`soundtrack.ocx` 是解密/释放加载器，被注册为 COM 进程内服务器。两者都用 Microsoft Visual Basic 6.0 编译，时间戳为 2024-05-20，名字伪装成多媒体组件。
- **注册表配置**：`MAFWIKFNMUI9430.ocx` 拼出 `cmd /c cd "%APPDATA%\WMProjectFiles" & reg.exe import info.txt`，用系统 `reg.exe` 导入 `info.txt`（注册表脚本）。导入后：
  - `HKCU\Software\Classes\CLSID\{AAE802DB-FB67-4407-A175-61223EFF30D4}` 默认值 `functions_under_review`；
  - `\InprocServer32` 默认值为 `C:\Users\<user>\AppData\Roaming\WMProjectFiles\soundtrack.ocx`，`ThreadingModel=Apartment`；
  - `ProgID=functions_under_review`、`TypeLib`、`Version=1.0`。
- **为什么用 HKCU**：`HKCU\Software\Classes` 是当前用户的 COM 注册视图，优先级高于 HKLM，普通用户即可写入；不需要管理员权限就能让 `rundll32 /sta {CLSID}` 加载指定 DLL。
- **`rundll32 /sta {CLSID}` 的含义**：`rundll32` 按 CLSID 实例化进程内 COM 服务器（`/sta` 指定单线程套间），实际加载 `InprocServer32` 指向的 `soundtrack.ocx` 并调用其入口；Run 键 `HomeDLL` 的值正是这条命令，所以登录时自动触发。
- **加密载荷容器**：`soundtrack.ocx` 读取同目录 `WMFile01.tmp`（约 8 MB），解密后在 `C:\Users\Public\Libraries\WMFile01.dll` 写出 DLL（Process Monitor 中可见 `rundll32.exe` 对该路径的连续 WriteFile）。用 `C:\Users\Public\Libraries` 这种不显眼但可写的公共目录存放 DLL，避免放在 `%APPDATA%` 引起注意。
- **启动与注入**：`WMFile01.dll` 启动 `%APPDATA%\ProductConfigurations\WINDBVERS.EXE`（VB6 编译的宿主程序），并使用 `SetWindowsHookEx`（ProcMon 标记“Suspicious use of SetWindowsHookEx”）与一套进程注入 API：`VirtualAllocEx`、`WriteProcessMemory`、`VirtualProtectEx`、`ReadProcessMemory`、`CreateProcessA`、`SuspendThread`/`ResumeThread`、`GetThreadContext`/`SetThreadContext`、`ZwUnmapViewOfSection`、`LoadLibraryA`/`GetProcAddress`、`RtlMoveMemory`——具备进程空壳/远程注入并运行内存 PE 的能力。
- **最终载荷**：从 `WINDBVERS.EXE` 内存 DUMP 出 VB6 编译（2024-05-11）的 DarkMe RAT，说明注入后的内存代码才是最终 RAT。
- **为什么隐蔽**：恶意组件用 `.ocx` 扩展名与多媒体名称，注册项在 HKCU；启动链是 `Run → rundll32 → COM CLSID → OCX → 释放 DLL → 合法命名宿主 EXE`，每一步都使用系统组件或常见文件类型。

## 触发条件

- 已通过 MSI 等把 `MAFWIKFNMUI9430.ocx`、`soundtrack.ocx`、`info.txt`、`WMFile01.tmp`、`WINDBVERS.EXE` 释放到目标用户可写目录。
- 执行过 `RunDllEntryPointW` 或等价注册步骤，`info.txt` 成功导入 HKCU CLSID/Run 键。
- 通过 Run 键或手动 `rundll32 /sta {CLSID}` 触发 COM 加载。
- 目标允许 `rundll32` 加载用户目录下的 OCX（未做严格的 DLL/COM 加载白名单）。

## 利用步骤

1. **释放文件**：把两个 OCX、info.txt、加密 TMP、宿主 EXE 放入 `%APPDATA%\WMProjectFiles`（MSI 完成）。
2. **导入注册表**：执行 `MAFWIKFNMUI9430.ocx` 的 `RunDllEntryPointW`，其内部运行 `cmd /c cd ... & reg.exe import info.txt`，写入 HKCU CLSID 与 Run 键。
3. **触发加载**：登录时由 Run 键执行 `rundll32 /sta {AAE802DB-...}`（或直接运行该命令）。
4. **解密释放**：`soundtrack.ocx` 读取 `WMFile01.tmp`，解密写出 `C:\Users\Public\Libraries\WMFile01.dll`。
5. **注入宿主**：`WMFile01.dll` 启动 `WINDBVERS.EXE`，用 `SetWindowsHookEx`/远程线程类 API 把最终载荷注入宿主并执行。
6. **取证**：用 ProcMon 过滤 `rundll32.exe` 的 WriteFile 观察 `.tmp → .dll`；对 `WINDBVERS.EXE` 进程做内存 DUMP 取最终 RAT。

关键注册表/命令示意：

```text
HKCU\Software\Classes\CLSID\{AAE802DB-FB67-4407-A175-61223EFF30D4}
  @ = "functions_under_review"
  \InprocServer32 @ = "C:\Users\<user>\AppData\Roaming\WMProjectFiles\soundtrack.ocx"
  \InprocServer32 ThreadingModel = "Apartment"
  \ProgID @ = "functions_under_review"
  \VERSION @ = "1.0"

Run: HomeDLL = C:\Windows\SysWOW64\rundll32 /sta {AAE802DB-FB67-4407-A175-61223EFF30D4}
```

## PoC

无 PoC（恶意样本分析）；复现需两个 VB6 OCX 与加密 TMP，核心触发命令为 `rundll32.exe /sta {AAE802DB-FB67-4407-A175-61223EFF30D4}`。

## 变体与关联

- **MSI Wrapper 安装与 Run 键写入**：本卡的前置链，见关联卡。
- **COM 劫持持久化**：HKCU CLSID 覆盖、任务计划 COM Handler、CLSID 文件夹伪装等同属 COM 持久化家族。
- **rundll32 加载器**：`rundll32` 调 OCX 导出、DLL 导出、CLSID 等变体；本卡用 `/sta {CLSID}` 走 COM。
- **进程注入**：`SetWindowsHookEx` 注入与 `VirtualAllocEx/WriteProcessMemory/SetThreadContext` 组合；`ZwUnmapViewOfSection` 提示可能做进程空壳。
- **最终载荷**：DarkMe RAT（见关联卡）。

## 检测与防御

- **注册表监控**：HKCU\Software\Classes\CLSID 下新增 `InprocServer32` 指向用户可写目录（AppData/Public/Temp）是高风险；Run/RunOnce 值为 `rundll32 ... /sta {CLSID}` 应告警。
- **进程行为**：`rundll32.exe` 加载 `.ocx`、从 `C:\Users\Public\Libraries` 写/读 DLL、启动 AppData 下 EXE 后出现 `SetWindowsHookEx`/跨进程内存写入，均可作为检测点。
- **文件检查**：VB6 OCX 的导出表含 `RunDllEntryPointW`、同名 `info.txt` 注册表脚本、大体积 `.tmp` 与 `C:\Users\Public\Libraries\*.dll` 的组合。
- **加固**：应用程序控制限制 rundll32 加载非系统目录 DLL/OCX；启用 COM 注册审计；限制普通用户对 HKCU\Software\Classes 的写入（视业务）；EDR 对跨进程注入 API 链告警。
