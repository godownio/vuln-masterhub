---
id: tools-metasploit-getsystem-six-techniques-opsec
title: MSF getsystem 六种提权技术对比：服务命名管道/Dropper/令牌复制/RPCSS/PrintSpoofer/EFSRPC 的实现、前提与 OPSEC 检测特征
type: scenario
domain: tools
path: tools/metasploit
technique: msf-getsystem-six-techniques-opsec-comparison
aliases:
- getsystem 原理
- elevate_via_service_namedpipe
- elevate_via_service_namedpipe2
- elevate_via_service_tokendup
- elevate_via_service_namedpipe_rpcss
- elevate_via_namedpipe_printspooler
- elevate_via_namedpipe_efs
- EfsPotato getsystem
tags:
- metasploit
- meterpreter
- getsystem
- privilege-escalation
- token-impersonation
- named-pipe
- opsec
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V598
  verified_at: '2026-11-12T16:57:03+08:00'
  notes: '已对照原文与59张截图核对：六技术名称/顺序、getsystem -h 输出、实测 getuid/getsystem/drop_token 输出、技术1 cmd.exe /c echo>/pipe、技术2 rundll32 .dll,a /p: 与 Sigma EID4697 规则、技术3 x86+SeDebug+反射注入、技术4 RPCSS 源码 6.3+ 过滤与句柄表/LUID 筛选、技术5 打印路径规范化、技术6 EFS 6.0+ 与 PKT_PRIVACY 均一致；总览卡与 RPCSS 专卡交叉引用，非同链。总览卡不设单一 affected_versions（各技术门槛在正文分述）。未实测利用。'
---

## 一句话结论

Meterpreter 的 `getsystem` 默认以 `ELEVATE_TECHNIQUE_ANY` 依次尝试六种令牌窃取：服务命名管道（内存/落 DLL 两式）、令牌复制（SeDebug + 服务进程注入）、RPCSS 句柄窃取、PrintSpoofer 路径规范化、EFSRPC 诱 lsass；六者的系统版本门槛、落地文件、所需特权与日志/ProcMon 可见特征各不相同——理解这些差异才能按环境选择技术、判断失败原因，并按 OPSEC 重写以规避通用检测。

## 原理

- **总入口**：`elevate_getsystem()` 解析 `-t` 参数（0=All，1-6 对应具体技术），为 0 时按顺序尝试 `elevate_via_service_namedpipe → service_namedpipe2 → service_tokendup → service_namedpipe_rpcss → namedpipe_printspooler → namedpipe_efs`，任一返回 `ERROR_SUCCESS` 即带出 SYSTEM 令牌并退出。
- **技术 1：服务命名管道（内存/管理员）**。创建 `\\.\pipe\<serviceName>`，把服务启动参数设为 `cmd.exe /c echo <随机串> > \\.\pipe\<serviceName>`；服务以 SYSTEM 启动后（cmd 并非合法服务，启动"失败"是预期）SYSTEM 的 cmd 向管道写入，攻击线程 `ImpersonateNamedPipeClient` 模拟其令牌，`DuplicateTokenEx` 后 `CreateProcessWithTokenW` 起 cmd。前提：本地管理员且 UAC 未过滤令牌、有 SeImpersonate；系统版本 ≥ Windows 2000/XP（源码过滤 NT4）。OPSEC：Sigma 规则按 EID 4697 的 `ServiceFileName` 匹配 `cmd` + `/c` + `echo` + `\pipe\`，CobaltStrike 同类实现匹配 `%COMSPEC%` 变体；服务安装行为显眼。
- **技术 2：服务命名管道（Dropper/管理员）**。把 elevator DLL 写到 `%TEMP%\*.dll`，服务参数改为 `rundll32.exe <dll>,a /p:<pipeName>`，由 SYSTEM 的 rundll32 加载 DLL 并连接管道。前提同上。OPSEC：Sigma 匹配 `rundll32` + `.dll,a` + `/p:`；临时目录落 DLL、rundll32 加载未签名 DLL 都是强特征，通常不是首选。
- **技术 3：令牌复制（内存/管理员）**。需要 `SeDebugPrivilege` 且仅 x86：`OpenSCManager(SC_MANAGER_ENUMERATE_SERVICE)` → `EnumServicesStatus` 两段式枚举 → `OpenService/QueryServiceStatusEx` 取 PID → `OpenProcess` 打开 SYSTEM 服务进程 → `VirtualAllocEx/WriteProcessMemory/LoadRemoteLibraryR` 反射式注入 elevator DLL → 注入线程获得 SYSTEM 令牌，`OpenThreadToken`+`DuplicateToken` 后更新 meterpreter 令牌。OPSEC：全程内存无文件落地、暂无对应 Sigma，但反射加载与内存扫描可能被 AV 检出，可擦除 PE 头/DOS 头进一步规避；受 x86 限制。
- **技术 4：RPCSS 句柄窃取**。要求 Windows 8.1/Server 2012 R2（6.3）+：打开 `rpcss` 服务进程（NETWORK SERVICE），用 `NtQueryInformationProcess(ProcessHandleInformation)` 枚举其句柄表，筛选 Token 类型且 `TOKEN_ALL_ACCESS` 的句柄，`DuplicateHandle` 后按 `TokenStatistics.AuthenticationId` 是否等于 SYSTEM LUID、特权数量是否最多挑出最佳令牌，`SetThreadToken` 完成提权。无需落地文件、无外部认证流量，OPSEC 最好；细节见 `[[pentest-privilege-escalation-rpcss-process-handle-token-steal]]`。
- **技术 5：PrintSpoofer 变体**。要求 6.3+ 与 SeImpersonate：`RpcRemoteFindFirstPrinterChangeNotification` 的 `pszLocalMachine` 传 `\\localhost/pipe/<uid>`，spoolsv 校验时把整段当主机名、实际连接时 `/` 规范化为 `\` 并追加 `\pipe\spoolss`，最终连到攻击者注册的 `\\localhost\pipe\<uid>\pipe\spoolss`，`ImpersonateNamedPipeClient` 窃取 SYSTEM 令牌。细节见 `[[pentest-privilege-escalation-printspoofer-unc-path-normalization]]`。OPSEC：ProcMon 中 `spoolsv.exe` 在 1 秒内打开/写入该管道，管道名以 `\pipe\spoolss` 结尾，是很好的检测点。
- **技术 6：EFSRPC（EfsPotato）变体**。要求 6.0+：通过 `EfsRpcOpenFileRaw`/`StubEfsRpcEncryptFileSrv` 让 lsass（SYSTEM）访问 `\\localhost/pipe/<uid>/<uid>` 形式的恶意管道，并用 `RpcBindingSetAuthInfoW` 把认证级别设为 `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` 绕过微软对原 EFSRPC 利用的修复；Vista/2008 只支持 `\pipe\lsarpc`，更高版本可用 `\pipe\efsrpc`（不存在时尝试启动 EFS 服务，等待 START_PENDING/CONTINUE_PENDING）。OPSEC：与打印/EFS 管道相同的 ProcMon 痕迹；微软将此类 RPC 提权视作"预期行为"，文章写作时仍可打 Win10/11/2019。
- **共同本质**：所有技术都是"让高权限进程把令牌交给我们"的不同诱导方式——服务（1/2/3 由 SYSTEM 服务执行我们的载荷）、RPCSS 句柄（4 直接读取）、打印/EFS RPC（5/6 诱 SYSTEM 服务向可控管道认证），最后都落到 `ImpersonateNamedPipeClient` 或 `SetThreadToken` + 令牌复制。

## 触发条件

- 当前会话为本地管理员（技术 1/2/3/5）或 NETWORK SERVICE 等同会话服务账户（技术 4），且拥有 `SeImpersonatePrivilege`/`SeDebugPrivilege` 等所需特权；UAC 未把管理员令牌过滤成受限令牌。
- 系统版本满足各技术要求：技术 1 ≥ 2000/XP、技术 2 同、技术 3 x86、技术 4 ≥ 6.3、技术 5 ≥ 6.3、技术 6 ≥ 6.0。
- 目标未通过 AppLocker/WDAC 阻止 cmd/rundll32/未签名 DLL，也未对命名管道与服务安装做行为拦截。
- 有本地管理员时优先内存型技术（3/4），避免服务安装与临时目录落文件。

## 利用步骤

1. `getuid` 确认当前身份，`getprivs`/`whoami /priv` 确认 `SeImpersonate`、`SeDebug` 与完整性级别（System/High）。
2. 直接 `getsystem` 观察默认 ANY 用哪一技术成功（输出 `got system via technique N`），据此判断当前环境可用面。
3. 指定技术重试：`getsystem -t 1/2/3/4/5/6`；失败时按版本与特权对照上面原理定位原因（如 6.3 以下技术 4/5 直接不支持）。
4. 成功 `getuid` 应返回 `NT AUTHORITY\SYSTEM`；`drop_token` 可回到原用户令牌，便于控制影响。
5. 若被杀软拦截，改用内存型技术 3/4，或把对应逻辑独立写进 shellcode loader，避免 cmd/rundll32 与临时文件特征。
6. 测试完成 `rev2self`/`drop_token` 恢复，清理创建的服务与临时文件（技术 1/2）。

## PoC

```text
meterpreter > getuid
Server username: DESKTOP-ALFUM4F\admin
meterpreter > getsystem
... got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > drop_token
Relinquished token, now running as: NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: DESKTOP-ALFUM4F\admin
```

```text
getsystem -h
  0 : All techniques available
  1 : Named Pipe Impersonation (In Memory/Admin)
  2 : Named Pipe Impersonation (Dropper/Admin)
  3 : Token Duplication (In Memory/Admin)
  4 : Named Pipe Impersonation (RPCSS variant)
  5 : Named Pipe Impersonation (PrintSpooler variant)
  6 : Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)
```

技术 1 的服务参数核心（源码示意）：`cmd.exe /c echo <serviceName> > \\.\pipe\<serviceName>`；技术 2 为 `rundll32.exe <temp>\<name>.dll,a /p:<name>`。

## 变体与关联

- **单独技术卡**：RPCSS 句柄窃取见 `[[pentest-privilege-escalation-rpcss-process-handle-token-steal]]`；PrintSpoofer 见 `[[pentest-privilege-escalation-printspoofer-unc-path-normalization]]`；SeImpersonate+Potato 家族见 `[[pentest-privilege-escalation-sweetpotato-seimpersonate-system]]`、`[[pentest-privilege-escalation-godpotato-useprotseq-hook-pipe]]`、`[[pentest-privilege-escalation-rogue-potato-oxid-resolve-ncacn-np]]`；SeDebug 令牌复制见 `[[pentest-privilege-escalation-windows-system-process-token-impersonation]]`；EFSRPC 经 MSSQL CLR 见 `[[pentest-privilege-escalation-mssql-sharpsqltools-clr-efspotato]]`。
- **自定义实现**：把六种技术拆成独立 shellcode/loader，上线即高权限；或按 OPSEC 替换 cmd/rundll32 为等价过程、擦除 PE 头、避免服务安装。
- **边界**：UAC 过滤令牌、缺少 SeImpersonate/SeDebug、AppLocker 阻止、EDR 拦截管道/服务、系统版本不满足，都会使对应技术失败；技术 4 在 6.3 以下直接返回不支持。

## 检测与防御

- **服务安装检测**：EID 4697（ServiceFileName 含 `cmd`/`/c`/`echo`/`\pipe\` 或 `rundll32`/`.dll,a`/`/p:`）是技术 1/2 的直接规则；监控短命服务与异常 binPath。
- **管道检测**：监控 `spoolsv.exe`/`lsass.exe` 打开或写入可疑命名管道（尤其以 `\pipe\spoolss` 结尾、生命周期 < 1 秒）；对 `\\.\pipe\<随机十六进制>\pipe\*` 模式告警。
- **句柄/令牌检测**：非 SYSTEM 进程以 `PROCESS_ALL_ACCESS` 打开 `svchost -k RPCSS -p`、调用 `NtQueryInformationProcess(ProcessHandleInformation)`、`DuplicateHandle` 复制 Token、`SetThreadToken`，是技术 4 的高价值遥测。
- **防御**：降低服务账户特权（去 SeImpersonate/SeDebug），启用 UAC/LSA 保护与 Credential Guard，AppLocker/WDAC 限制 cmd/rundll32 与未签名 DLL，EDR 监控令牌/句柄异常；及时修补但注意 EFSRPC 类被微软视为预期行为。
