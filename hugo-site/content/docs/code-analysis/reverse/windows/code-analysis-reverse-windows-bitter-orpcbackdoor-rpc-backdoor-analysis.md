---
id: code-analysis-reverse-windows-bitter-orpcbackdoor-rpc-backdoor-analysis
title: 蔓灵花 ORPCBackdoor 样本分析：仿 version.dll 导出白加黑 + ts.dat/$cache.dat 标记 + COM 计划任务 + ncacn_ip_tcp:443 的 NdrClientCall2 RPC 远控
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: bitter-orpcbackdoor-rpc-c2-sample-analysis
tags:
- windows
- malware-analysis
- apt
- bitter
- rpc
- ndrclientcall2
- dll-sideload
- scheduled-task
- persistence
- c2
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V508
  verified_at: '2026-11-11T04:48:18+08:00'
  notes: 已对照原文与24张图逐张核对：流程图(图01)、MSOutlookServices.exe+OLMAPI32.dll(图02)、version.dll导出对比(图03)、DllMain->GetFileVersionInfoByHandleEx(图04)、HEX硬编码与ts.dat/Sleep 0xEA60(图05-07)、CreateToolhelp32Snapshot/OpenProcess(图08-11)、指令常量SIZE/HASH/.../cmd.exe /c(图12)、自建RPC服务端443+抓包(图13)、ncacn_ip_tcp:outlook-services.ddns.net[443](图14)、NdrClientCall2(图15)、$tmp.txt ID(图16)、INF上传(图17-18)、DWN/RUN/DLY/CMD(图19-24)均一致。修正卡片两处：qmemcpy拼写(qmempcy/qmempc)与CMD拼接格式(cmd.exe /c <指令> >> cr.dat)。dedup：候选均为不同技术/不同样本(计划任务RPC、DLL侧加载通用卡、LATRODECTUS等)，无同链重复；dup-scan 30对无本篇。样本分析类无组件affected_versions，不设。PoC为分析证据点，未复跑。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-bitter-orpcbackdoor-rpc-backdoor-analysis/
draft: false
kb_aliases:
- ORPCBackdoor
- 蔓灵花 RPC 后门
- BITTER APT 样本
- OLMAPI32.dll 白加黑
- MSOutlookServices.exe
- NdrClientCall2 远控
- ncacn_ip_tcp 后门
---

## 一句话结论

蔓灵花（BITTER）的 ORPCBackdoor 样本由 `MSOutlookServices.exe`（白）加载恶意的 `OLMAPI32.dll`（仿 `version.dll` 的导出集，DllMain → `GetFileVersionInfoByHandleEx` 承载主逻辑），用当前目录 `ts.dat` 与 `C:\ProgramData\$cache.dat` 两个标记文件防止重复持久化/多进程交互，经 COM TaskScheduler 注册每日零点的 "Microsoft Update" 计划任务，并以 `ncacn_ip_tcp:outlook-services.ddns.net[443]` 的 MS-RPC 绑定、通过 `rpcrt4.dll!NdrClientCall2` 与服务端通讯，实现 ID/INF/RUN/DLY/CMD/DWN 六类指令（关键字符串均以 HEX 硬编码运行时解码）。

## 原理

- **白加黑入口**：`MSOutlookServices.exe` 自身不含恶意功能，加载 `OLMAPI32.dll`；该 DLL 的导出表与系统 `version.dll` 对齐（GetFileVersionInfoA/W、GetFileVersionInfoByHandle、GetFileVersionInfoExA/W、GetFileVersionInfoSizeA/W/ExA/ExW、VerFindFileA/W、VerInstallFileA/W、VerLanguageNameA/W、VerQueryValueA/W、DllEntryPoint），实现 DLL 侧加载白加黑。`DllMain` 在 `fdwReason==1` 时调用 `GetFileVersionInfoByHandleEx()`，主恶意逻辑在该导出中。
- **防重入标记与持久化**：先在当前路径检查 `ts.dat` 是否存在，不存在则 `Sleep(60000)`（原文 0xEA60 毫秒）后创建计划任务，再创建 `ts.dat`；计划任务经 COM 初始化（`CoInitialize` + TaskScheduler CLSID）创建名为 `Microsoft Update` 的任务，每日零点执行 `MSOutlookServices.exe`。路径与文件名以 HEX 字符串硬编码（如 `433A5C5C50726F6772616D446174615C5C` → `C:\ProgramData\`、`74732E646174` → `ts.dat`），运行时经自定义 HexToAscii 解码。
- **系统信息收集**：`CreateToolhelp32Snapshot(2,0)` + `Process32First/Next` 枚举进程并用 `OpenProcess(0x1FFFFF)` 探测，同时调用 `GetSystemInfo`、`GetComputerName`、读取 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` 等，格式化出 Host Name、OS Name、OS Version、System Manufacturer/Model、Registered Owner/Organization、Product ID、Install Date、System Type、Processor、BIOS、进程列表（System、Registry、smss、csrss、wininit、services、lsass、svchost、explorer 等）等详尽信息，供 INF 指令上传。
- **RPC 通讯初始化**：检查 `C:\ProgramData\$cache.dat` 是否存在（防止多进程同时建立通讯会话），不存在则创建并初始化 RPC：`qmemcpy(…, "pct_pi_ncacn…")`、`strcpy(ProtSeq,"ncacn_ip_tcp")`、`qmemcpy(NetworkAddr,"outlook-services.ddns.net")`、`Endpoint="443"`，再 `RpcStringBindingComposeA` 生成绑定串 `ncacn_ip_tcp:outlook-services.ddns.net[443]`、`RpcBindingFromStringBindingA` 得到句柄。用 443 端口伪装 HTTPS，实际是 MS-RPC over TCP。
- **NdrClientCall2 调用**：`GetModuleHandleA("rpcrt4.dll")` 后拼接函数名 `Ndr` + `Client` + `Call2` 得 `NdrClientCall2`，`GetProcAddress` 取地址后调用，完成与服务端的 RPC 请求/响应；服务端无数据返回时 `Sleep(5 分钟)` 重试，进入交互后由服务端下发指令。
- **指令分发（if-else 链而非 switch）**：
  - **ID**：把服务端生成的 ID 写入 `c:\ProgramData\$tmp.txt`（若存在先删除再创建）。
  - **INF**：上传前面收集的系统基本信息（内存中带 `INF|SYSTEM INFORMATION` 等字段标记）。
  - **RUN**：`WinExec` 执行服务端指定文件并返回状态。
  - **DLY**：按服务端给定时长 `Sleep` 后继续。
  - **CMD**：拼接 `cmd.exe /c <服务端指令> >> c:\Users\Public\cr.dat`，`WinExec` 执行，回传 cr.dat 内容后删除。
  - **DWN**：文件下载，包含详细报错/下载状态回传。
  指令与状态常量（`SIZE`/`HASH`/`NETERR`/`ERROR`/`VERIFIED`/`OK`/`ERRORREPLACE`/`RUN`/`DLY`/`CMD`/`cmd.exe /c` 等）同样以 HEX 硬编码，运行时解码。
- **为什么用 RPC**：不再使用 socket/HTTP 自有协议，而是复用 Windows 自带 `rpcrt4` 的 MS-RPC 栈（绑定串、端点映射）；流量在 443 上，与 HTTPS 端口混淆，检测方若只按 HTTP 特征匹配会漏掉；但 RPC 有自身的绑定/调用报文特征（ncacn 协议、NDR 编码），流量侧仍可识别。

## 触发条件

- 目标为被投递恶意附件的 Windows 主机（本文为恶意邮件附件 5 种执行手法的后续载荷）。
- 白程序 `MSOutlookServices.exe` 与恶意 `OLMAPI32.dll` 同目录且可执行；DLL 侧加载成功（导出名满足白程序导入）。
- Task Scheduler 服务可用、当前用户可创建任务（默认允许）。
- 主机可出网访问 C2 域名 `outlook-services.ddns.net:443`（RPC over TCP），或攻击者已调整绑定地址。
- 分析/检测方需要样本、内存或流量；样本分析不要求目标在线。

## 利用步骤

（以下为分析复现步骤，非攻击执行步骤。）

1. 判断白加黑：比对 `MSOutlookServices.exe` 导入与同目录 `OLMAPI32.dll` 导出（与 `version.dll` 导出集一致）；IDA 确认 `DllMain` 调用 `GetFileVersionInfoByHandleEx` 等导出。
2. 静态/动态还原 HEX 字符串：定位 `FUN_HexToAscii`，批量把 `43 3A 5C 5C...` 形式常量还原为路径/指令；确认 `ts.dat`、`$cache.dat`、`$tmp.txt`、`cr.dat`、计划任务名与 RPC 地址。
3. 持久化验证：断点 `FUN_taskscheduler`（COM TaskScheduler），观察任务名 `Microsoft Update`、每日零点触发器与 `MSOutlookServices.exe` 动作；确认 `ts.dat` 标记文件创建。
4. 通讯验证：断点 `RpcStringBindingComposeA`/`NdrClientCall2`，确认绑定串 `ncacn_ip_tcp:outlook-services.ddns.net[443]` 与调用参数；可自写 RPC 服务端并改 hosts 捕获初始化报文（原文方式）。
5. 指令分析：在服务端返回不同指令，观察 ID/INF/RUN/DLY/CMD/DWN 分支与 `cmd.exe /c ... >> cr.dat` 拼接、`WinExec` 调用及回传内容。
6. 提取 IOC：域名、文件路径与文件名、计划任务名、绑定串、`NdrClientCall2` 调用链；输出行为时间线与 YARA/网络规则。

## PoC

```text
# 关键静态/动态证据点（分析用）
HEX 字符串解码：
  433A5C5C50726F6772616D446174615C5C  -> C:\ProgramData\
  74732E646174                      -> ts.dat
RPC 绑定（RpcStringBindingComposeA）：
  ncacn_ip_tcp:outlook-services.ddns.net[443]
RPC 调用：
  rpcrt4.dll!NdrClientCall2
CMD 指令拼接：
  cmd.exe /c <server_cmd> >> c:\Users\Public\cr.dat
```

```text
# 网络侧特征
- TCP 443 上不是 TLS，而是 DCE/RPC over TCP（ncacn_ip_tcp）；
- 目标域名 outlook-services.ddns.net（动态 DNS）；
- 进程 MSOutlookServices.exe 加载同目录 OLMAPI32.dll；
- 任务计划出现名为 "Microsoft Update" 的自定义任务。
```

## 变体与关联

- **持久化技术**：COM TaskScheduler 的 API 链（ITaskService → RegisterTaskDefinition → IExecAction）与伪装手法已有专卡 [[pentest-persistence-taskscheduler-com-api-iexecaction-logon]]；本卡是其在新样本中的实例（每日零点触发器）。
- **白加黑/侧加载**：仿 `version.dll` 导出集的 DLL 侧加载与 [[pentest-c2-dll-sideload-dllmain-fake-export-calculator]]、[[pentest-c2-dll-sideload-export-forwarding-host-whitelist]] 同族；本文额外展示了"导出函数承载主逻辑 + DllMain 触发"。
- **RPC 家族**：另有利用 RPC 接口做计划任务的技术（[[pentest-persistence-schrpcregistertask-rpc-scheduled-task]]、[[pentest-persistence-atsvc-netrjobadd-rpc-at-job]]），与本文"把 RPC 当 C2 传输"不同；ncalrpc 的逆向工具用法见 [[code-analysis-reverse-windows-ncalrpc-rpcview-midl-client]]。
- **同风格样本分析**：[[code-analysis-reverse-windows-latrodectus-loader-behavior-c2]]（加载器行为加密钥 C2 分析）。
- **边界**：RPC 绑定串以明文出现在内存中，易被字符串扫描；NdrClientCall2 调用与 443 上的非 TLS 流量是强特征；若 C2 域名失效则样本无法交互（仅保留持久化与信息收集）。

## 检测与防御

- **IOC**：文件 `MSOutlookServices.exe`/`OLMAPI32.dll`、`ts.dat`、`C:\ProgramData\$cache.dat`、`C:\ProgramData\$tmp.txt`、`C:\Users\Public\cr.dat`；计划任务 `Microsoft Update`（每日零点，动作指向同目录 exe）；域名 `outlook-services.ddns.net`；绑定串 `ncacn_ip_tcp:outlook-services.ddns.net[443]`。
- **主机检测**：计划任务创建（Event 106/200/201、Tasks 目录新增）；进程 `MSOutlookServices.exe` 加载非系统目录的 `OLMAPI32.dll` 且导出集与 `version.dll` 一致；进程快照 + `OpenProcess` 批量探测进程 + 注册表 CurrentVersion 读取的组合；`C:\ProgramData` 下 `$cache.dat`/`$tmp.txt` 与当前目录 `ts.dat` 成对出现。
- **网络检测**：443 端口上出现 DCE/RPC over TCP（非 TLS/HTTP），NDR 调用特征；DNS 查询 `outlook-services.ddns.net` 或类似 `*-services.ddns.net` 动态域名；从非服务器进程发起的 SMB/RPC 风格流量。
- **防御**：禁用不必要的动态 DNS 出站；对 443 做协议识别（TLS 版本、SNI）而非只看端口；限制用户创建计划任务（按需）；DLL 侧加载防护（DLL 搜索路径、签名校验、受控目录）；EDR 对"白进程加载同目录未签名 DLL + 计划任务 + RPC 出站"的行为链告警；邮件附件与本样本前置的 CHM/DDE/PPT/宏/公式编辑器链一并拦截。
- **响应**：隔离主机、删除计划任务与标记文件、轮换受影响账号、提取内存与 pcap 做 RPC/域名 IOC 排查，并检查同网段横向。
