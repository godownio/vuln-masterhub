---
id: defense-detection-callstack-remote-registry-service-modification
title: 调用堆栈检测远程注册表服务异常修改：regsvc.dll/rpcrt4.dll 栈 + 可疑注册表值/键
type: scenario
domain: defense
path: defense/detection
technique: callstack-remote-registry-service-modification
aliases:
- 远程注册表服务检测
- regsvc.dll 调用栈
- 远程注册表横向检测
- svchost RemoteRegistry
- Elastic Defend 远程注册表
tags:
- defense
- detection
- call-stack
- elastic
- kql
- edr
- windows
- remote-registry
- lateral-movement
- registry
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:19+08:00'
  notes: 已对照原文核对：KQL（event.action==modification、user.id S-1-5-21*/S-1-12*、process.name svchost.exe、*regsvc.dll|rpcrt4.dll*、可疑 registry.data.strings/registry.path/Start=4）与原文逐字一致。未验证点：原文称有“远程注册表修改 Run 键”截图，但抓取的 22 张图中 img22 实为第二组 KNIGHT 勒索重命名命中（7800 hits、explorer.exe、knight_1），未包含远程注册表示例截图（疑似图片顺序/缺失问题），卡片正文按原文文字保留该示例。dedup 候选为 DCOM/WMI 横向与日志足迹卡，非同链。原文未给组件版本，未设 affected_versions；无 sources/source_url。
---

## 一句话结论

远程注册表服务运行在 `svchost.exe` 中，攻击者可通过它远程修改目标主机的注册表实现横向移动/持久化；判断注册表修改事件是否来自远程注册表服务，可看进程调用栈是否包含 `regsvc.dll|rpcrt4.dll`。当这类事件同时写入指向可执行文件/脚本的值（ServiceDLL、ImagePath、InprocServer32、LocalServer32、Run）或把服务 `Start` 设为 4（禁用），即可高置信度判定为远程注册表滥用。

## 原理

- **远程注册表架构**：Remote Registry 服务（`RemoteRegistry`）托管在 `svchost.exe` 中，注册表访问经 RPC（`rpcrt4.dll`）进入 `regsvc.dll` 提供者；因此由远程注册表服务发起的修改，其调用栈摘要包含 `regsvc.dll|rpcrt4.dll`。
- **攻击用法**：攻陷一台主机后，通过远程注册表修改目标的服务 `ImagePath`/`ServiceDLL`、COM `InprocServer32`/`LocalServer32`、`Run` 键等实现代码执行或持久化；也可把服务 `Start` 改为 4 远程禁用服务（如杀软/备份），属于横向移动与破坏行为。
- **为什么需要调用栈**：注册表修改事件本身无法区分本地进程与远程注册表服务；`svchost.exe` 承载大量服务，单看进程名会误报。`regsvc.dll|rpcrt4.dll` 锚点精确指向远程注册表提供者。
- **可疑值/键组合**：值内容包含盘符路径、`.exe`/`.dll`、`rundll32`、`powershell`、`http`、`/c`、`COMSPEC`、UNC 路径，或键属于 Services/Run/COM 注册点，或 `Start=4`，这些是横向/持久化的典型写入。
- **示例**：原文截图命中通过远程注册表服务修改 Run key 的事件。
- **边界**：正常的远程管理/软件分发也会用远程注册表，需按源 IP、用户、值内容与变更频率降噪；RPC 栈可能被其他注册表提供者复用。

## 触发条件

- EDR 采集注册表修改事件、进程调用栈符号（`process.thread.Ext.call_stack_summary`）。
- 目标开启 Remote Registry 服务（默认手动/禁用，企业环境可能启用）。
- 规则用于检测/狩猎。

## 利用步骤（检测步骤）

1. 部署 KQL：注册表修改事件、用户 SID 为域/本地账户（`S-1-5-21*`/`S-1-12-*`）、进程 `svchost.exe`、栈摘要含 `regsvc.dll|rpcrt4.dll`，且值/键属于可疑集合或 `Start=4`。
2. 命中后确认源主机与账户：检查 4624 登录类型 3、RPC 连接、RemoteRegistry 服务日志。
3. 检查被修改的键值内容（服务路径、COM 服务器、Run 键），判断是持久化还是横向执行。
4. 关联源主机的后续行为（`sc.exe`、`reg.exe`、WMI、PsExec）与目标机的进程创建。

## PoC

```kql
registry where

event.action == "modification" and

user.id : ("S-1-5-21*", "S-1-12-*") and

 process.name : "svchost.exe" and

// regsvc.dll 表明该 svchost 是远程注册表服务宿主
process.thread.Ext.call_stack_summary : "*regsvc.dll|rpcrt4.dll*" and

 (
  // 可疑注册表值
  registry.data.strings : ("*:\\*\\*", "*.exe*", "*.dll*", "*rundll32*",
  "*powershell*", "*http*", "* /c *", "*COMSPEC*", "\\\\*.*") or

  // 可疑键：服务、Run、COM
  registry.path :
         ("HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL",
          "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath",
          "HKEY_USERS\\*Classes\\*\\InprocServer32\\",
          "HKEY_USERS\\*Classes\\*\\LocalServer32\\",
          "H*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*") or

  // 远程禁用服务
  (registry.value : "Start" and registry.data.strings : "4")
 )
```

## 变体与关联

- **横向工具**：`reg.exe` 远程、PowerShell `Invoke-Command`、WMI、PsExec/AtExec；见 `defense-detection-impacket-psexec-atexec-artifacts`。
- **攻击侧**：远程注册表修改服务 ImagePath/ServiceDLL 实现横向执行；Run 键/COM 劫持持久化。
- **边界**：远程软件分发、配置管理工具会正常写注册表；需按源 IP、账户、值内容与变更频率过滤。

## 检测与防御

- **检测**：上述 KQL；补充监控 RemoteRegistry 服务启动、RPC 端点、4624 类型 3 登录与 `reg.exe`/`sc.exe` 远程使用。
- **降噪**：按源主机、管理账户、维护窗口与软件分发白名单建立基线。
- **加固**：禁用不需要的 Remote Registry 服务；限制远程注册表 RPC 访问（防火墙/组策略）；启用注册表 ACL 与受保护键；监控服务启动类型变更。
- **响应**：回滚被修改的键值，排查源主机与同批横向目标，检查服务/COM 持久化与凭据滥用。
