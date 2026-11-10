---
id: code-analysis-reverse-windows-session0-duplicate-token-createprocessasuser
title: Session 0 隔离绕过：服务进程 DuplicateTokenEx 出主令牌后 SetTokenInformation(TokenSessionId=WTSGetActiveConsoleSessionId)，CreateProcessAsUser 在用户桌面会话创建进程
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: session0-token-sessionid-createprocessasuser
tags:
- windows
- session0
- token
- createprocessasuser
- wtsapi
- malware-analysis
- ipc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V463
  verified_at: '2026-11-10T14:56:13+08:00'
  notes: 已对照原文与28/28图核实：图22 与卡内调用链一致（OpenProcessToken 0xF01FF -> DuplicateTokenEx 主令牌 -> WTSGetActiveConsoleSessionId -> SetTokenInformation(TokenSessionId,4) -> userenv CreateEnvironmentBlock -> CreateProcessAsUserA 0x430 + lpDesktop=winsta0\default），服务持久化背景见图17-20（Windows Eventn 服务指向 Videos 下 exe）。KB 中无其他 WTSGetActiveConsoleSessionId/TokenSessionId 卡，winlogon/系统进程令牌卡为窃取提权不同链，需并列。原文未标版本，不设 affected_versions；无 sources 字段；path 合法。dup-scan(11-08)早于建卡。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-session0-duplicate-token-createprocessasuser/
draft: false
kb_aliases:
- Session 0 隔离绕过
- 服务创建用户会话进程
- WTSGetActiveConsoleSessionId
- TokenSessionId
- CreateProcessAsUser winsta0\\default
- 跨会话创建进程
- 远控插件进程间通信
---

## 一句话结论

Windows 服务运行在 Session 0，默认无法与已登录用户的桌面交互；样本在服务/SYSTEM 上下文里 `OpenProcessToken(GetCurrentProcess())` 取自身令牌，`DuplicateTokenEx` 复制成主令牌，`SetTokenInformation(TokenSessionId, WTSGetActiveConsoleSessionId())` 把令牌绑定到活动控制台会话，再经 `userenv.dll!CreateEnvironmentBlock` 建环境块、`CreateProcessAsUserA` 且 `lpDesktop="winsta0\\default"` 启动进程，就把组件放进了用户桌面会话，可与 Session 0 的服务进程跨会话通信（远控的截屏/键盘/代理等插件常用）。

## 原理

- **Session 0 隔离**：Vista 之后服务运行在 Session 0，没有交互式桌面；用户应用在 Session 1+ 的 `winsta0\default` 桌面。服务直接 `CreateProcess`/`ShellExecute` 出来的进程也在 Session 0，用户看不到也无法交互。
- **令牌的会话绑定**：每个访问令牌带 `TokenSessionId`（信息类 12），新进程的会话由令牌决定。用 `SetTokenInformation` 把主令牌的 `TokenSessionId` 改成活动控制台会话号，再用该令牌 `CreateProcessAsUser`，新进程就落在用户会话。
- **具体调用链（样本伪代码）**：
  1. `OpenProcessToken(GetCurrentProcess(), 0xF01FF, &hToken)` 取服务进程令牌（服务通常以 LocalSystem 运行，具备 `SeAssignPrimaryTokenPrivilege`、`SeIncreaseQuotaPrivilege`）。
  2. `DuplicateTokenEx(hToken, 0x2000000, NULL, SecurityIdentification, TokenPrimary, &hNewToken)` 复制出可分配的主令牌。
  3. `WTSGetActiveConsoleSessionId()` 取当前活动控制台会话（无登录用户时返回 0xFFFFFFFF）。
  4. `SetTokenInformation(hNewToken, TokenSessionId, &sessionId, 4)` 把令牌改绑到该会话。
  5. `LoadLibraryA("userenv.dll")` + `GetProcAddress(..., "CreateEnvironmentBlock")`，用新令牌生成用户环境块。
  6. `CreateProcessAsUserA(hNewToken, app, cmd, ..., 0x430, lpEnvironment, NULL, &StartupInfo, &pi)`，其中 `StartupInfo.lpDesktop` 指向 `winsta0\default`，创建标志含 `CREATE_UNICODE_ENVIRONMENT`。
- **为什么可行**：服务的 SYSTEM 令牌权限足够复制并分配主令牌；会话号只是令牌上的一个字段，修改后进程创建即生效；`winsta0\default` 让新进程挂到用户可交互桌面。新进程默认仍是 SYSTEM 身份（令牌来自服务），对“GUI 辅助进程/代理组件”已足够；若要以登录用户身份运行，则改用 `WTSQueryUserToken(sessionId)` 取用户令牌（需要 LocalSystem 的 `SeTcbPrivilege`）。
- **样本用途**：金眼狗系样本在服务持久化后，用这条路径创建用户会话进程，与 Session 0 的服务进程做进程间通信，支撑截屏、键盘、下载/执行等插件功能。
- **边界**：需要活动控制台会话（有人登录）；服务令牌需具备分配主令牌/增加配额特权（LocalSystem 默认有，普通用户服务没有）；`SetTokenInformation(TokenSessionId)` 在部分受限环境/受保护进程策略下可能失败；`lpDesktop` 写错或桌面不存在会导致进程创建成功但无界面。

## 触发条件

- 恶意代码以 Windows 服务或 LocalSystem/SYSTEM 身份运行（或持有 `SeAssignPrimaryTokenPrivilege`、`SeIncreaseQuotaPrivilege`）。
- 目标主机有已登录的交互式用户（`WTSGetActiveConsoleSessionId() != 0xFFFFFFFF`）。
- 需要从 Session 0 向用户会话投放 GUI/交互组件，或与用户会话进程建立跨会话 IPC。
- 未被 EDR 对 `SetTokenInformation(TokenSessionId)`、服务创建用户会话进程的行为拦截。

## 利用步骤

1. 确认当前进程在 Session 0 且有活动控制台会话：`ProcessIdToSessionId(GetCurrentProcessId(), &sid)`、`WTSGetActiveConsoleSessionId()`。
2. 打开自身令牌：`OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)`。
3. 复制主令牌：`DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hNewToken)`。
4. 改绑会话：`SetTokenInformation(hNewToken, TokenSessionId, &sid, sizeof(sid))`。
5. 用 `userenv.dll!CreateEnvironmentBlock(&env, hNewToken, FALSE)` 生成环境块。
6. `CreateProcessAsUserA(hNewToken, helperPath, cmdline, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, env, NULL, &si, &pi)`，`si.lpDesktop = "winsta0\\default"`，`si.cb = sizeof(si)`。
7. 子进程出现在用户桌面会话；通过命名管道/共享内存/Socket 与 Session 0 服务进程通信，执行截屏、键鼠、下载执行等插件功能。
8. 需要以登录用户身份（而非 SYSTEM）运行时，改用 `WTSQueryUserToken(sid, &hUserToken)` 再 `CreateProcessAsUser`，并 `CreateEnvironmentBlock`。

## PoC

```c
#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>

DWORD sid = WTSGetActiveConsoleSessionId();          // 0xFFFFFFFF 表示无登录会话
HANDLE hTok = NULL, hNew = NULL;
OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hTok);
DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hNew);
SetTokenInformation(hNew, TokenSessionId, &sid, sizeof(sid));

LPVOID env = NULL;
typedef BOOL (WINAPI *PFN_CEB)(LPVOID *, HANDLE, BOOL);
PFN_CEB pCEB = (PFN_CEB)GetProcAddress(LoadLibraryA("userenv.dll"), "CreateEnvironmentBlock");
if (pCEB) pCEB(&env, hNew, FALSE);

STARTUPINFOA si = {0};
si.cb = sizeof(si);
si.lpDesktop = (LPSTR)"winsta0\\default";            // 挂到用户交互桌面
PROCESS_INFORMATION pi = {0};
CreateProcessAsUserA(hNew, "C:\\path\\helper.exe", NULL, NULL, NULL, FALSE,
                     CREATE_UNICODE_ENVIRONMENT, env, NULL, &si, &pi);
```

说明：以上为按样本反编译整理的最小示意，未在本机执行；不同系统版本令牌特权与环境块处理可能需调整。

## 变体与关联

- **WTSQueryUserToken 变体**：以 LocalSystem 调用 `WTSQueryUserToken(sessionId, &hToken)` 直接取登录用户令牌，再 `CreateProcessAsUser`，进程身份为普通用户而非 SYSTEM；需要 `SeTcbPrivilege`。
- **CreateProcessWithTokenW 变体**：持有 `SeImpersonatePrivilege`（管理员/服务常见）时可用 `CreateProcessWithTokenW` 等价创建进程，常用于提权后重启自身。
- **服务/令牌相关既有卡**：令牌窃取与模拟见 [[pentest-privilege-escalation-windows-system-process-token-impersonation]]；winlogon 主令牌 + `CreateProcessWithTokenW` 见 [[pentest-privilege-escalation-winlogon-primary-token-createprocesswithtokenw-self-restart]]；UAC 注册表关闭见 [[pentest-privilege-escalation-enablelua-registry-disable-uac]]。
- **样本链关联**：该样本的服务持久化、白加黑加载链与 C2 选择见 [[pentest-c2-apt-q27-signed-photo-loader-s3-manifest-encrypted-shellcode-memory-pe]]、[[pentest-c2-silverfox-qqmusic-ak-txt-xor-decompress-upx-dll-loader]]。
- **检测关联**：跨会话/环境键控类反分析可参考 [[code-analysis-reverse-anti-debug-desktop-artifact-keying-drive-count-shortcut]] 等桌面环境探测卡。

## 检测与防御

- **检测**：服务进程（父进程 `services.exe` 或 Session 0 进程）创建出 Session ≥1、桌面为 `winsta0\default` 的子进程；Sysmon/4688 中出现 SYSTEM 身份却在用户会话运行的 GUI 进程；对 `SetTokenInformation(TokenSessionId)`、`DuplicateTokenEx(TokenPrimary)`、`CreateProcessAsUser` 组合的 API 监控。
- **检测**：同一镜像/路径的进程同时出现在 Session 0 与用户会话，且通过命名管道/共享内存频繁通信；服务 binPath 位于用户可写目录（Videos/AppData/ProgramData）是强可疑信号。
- **防御**：最小化服务账户特权（非必要不授予 `SeAssignPrimaryTokenPrivilege`/`SeIncreaseQuotaPrivilege`/`SeTcbPrivilege`）；WDAC/AppLocker 限制用户目录可执行文件；监控并限制服务创建用户会话进程；EDR 对跨会话进程创建与异常令牌修改告警。
- **注意**：部分合法软件（更新器、输入法、远程协助）也会用类似方式在用户会话启动组件，需结合签名、路径、父子进程与行为链判断。
