---
id: defense-detection-sliver-impersonate-token-owner-mismatch
title: Sliver impersonate 令牌窃取检测：线程模拟令牌 SYSTEM 与进程主令牌所有者不一致
type: scenario
domain: defense
path: defense/detection
technique: sliver-impersonate-token-owner-mismatch-detection
aliases:
- Sliver impersonate 检测
- 令牌窃取检测
- 线程模拟令牌
- ImpersonationToken.User
- CurrentTokenOwner
- SeAssignPrimaryTokenPrivilege
tags:
- defense
- detection
- sliver
- c2
- token-impersonation
- windows
- edr
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:08:12+08:00'
  notes: 已对照原文核对：impersonate 通过 OpenProcessToken/DuplicateTokenEx/ImpersonateLoggedOnUser 挂线程、AdjustTokenPrivileges 启用 SeAssignPrimaryTokenPrivilege/SeIncreaseQuotaPrivilege，检测判据为线程模拟令牌 User（如 SYSTEM）与进程主令牌 OwnerSid 不一致，均与正文一致。未验证点：原文对比图为外链未随文分发，卡片按正文文字描述；检测需 EDR 线程令牌遥测，无现成 PoC，未复跑；affected_versions 已 --clear。
---

## 一句话结论

Sliver 的 `impersonate` 会从目标用户拥有的进程窃取令牌，并用 `ImpersonateLoggedOnUser` 让当前线程以该令牌运行；检测点是**线程的模拟令牌用户（如 `NT AUTHORITY\SYSTEM`）与所在进程主令牌所有者（如普通登录用户）不一致**，这种线程/进程令牌所有权错位与 Mimikatz 的令牌模拟结果相同。

## 原理

- **Windows 令牌模型**：进程持有一个主令牌（primary token）决定其安全上下文；线程可以持有模拟令牌（impersonation token），在访问资源时临时采用另一个用户身份。正常程序也可能使用模拟，但通常发生在服务端代表客户端访问资源的场景，且模拟令牌与进程上下文存在合理关联。
- **Sliver 的做法**：`impersonate` 先枚举目标用户拥有的进程并 `OpenProcessToken` 取得令牌，再 `DuplicateTokenEx` 复制为模拟令牌，用 `ImpersonateLoggedOnUser` 挂到当前线程；随后为命令提示符当前线程启用 `SeAssignPrimaryTokenPrivilege` 与 `SeIncreaseQuotaPrivilege`（`AdjustTokenPrivileges`），使新进程可以携带被窃取的令牌运行。最终效果是：一个由普通用户进程派生/承载的线程或子进程，拥有 `NT AUTHORITY\SYSTEM` 等更高权限的令牌。
- **为什么可检测**：从 EDR/内核令牌遥测看，线程的模拟令牌 `ImpersonationToken.User` 会显示为 `NT AUTHORITY\SYSTEM`，而该线程所属进程的主令牌 `OwnerSid` 仍是普通用户（如 `MSEDGEWIN10\IEUser`）。这种“低权进程里出现高权线程模拟令牌”的不一致在干净主机上很少见，且与后续 `cmd.exe` 子进程、敏感操作时间相关。
- **与其它工具的共性**：Cobalt Strike 的 `steal_token`、Mimikatz 的 `token::impersonate`/`token::elevate`、Potato 家族的 `SeImpersonate` 利用最终都会制造类似的令牌/进程所有者错位，因此该判据可泛化为“令牌操纵”检测，而非只针对 Sliver。

## 触发条件

- 受害主机为 Windows，EDR/内核遥测能够读取线程模拟令牌与进程主令牌所有者（或能读取 ETW 的令牌相关事件）。
- 攻击者已获得 Sliver 会话并执行 `impersonate`，且目标用户/进程存在可窃取的高权令牌。
- 分析者能把令牌事件与进程创建、网络外联、命令执行关联起来。

## 检测步骤

1. 采集进程/线程令牌遥测：进程 PID、进程主令牌 OwnerSid、线程 TID 与模拟令牌 User。
2. 筛选不一致项：
   - 进程中存在线程的 `ImpersonationToken.User` 为 `NT AUTHORITY\SYSTEM`（或域管理员等更高权限）；
   - 同一进程的主令牌所有者是普通用户；
   - 该线程随后创建了 `cmd.exe`/`powershell.exe` 子进程或执行了敏感 API。
3. 关联 `OpenProcessToken`、`DuplicateTokenEx`、`ImpersonateLoggedOnUser`、`AdjustTokenPrivileges` 的 EDR API 事件（若采集）。
4. 检查进程来源：Sliver 植入体进程、其父进程与网络连接；核对 `whoami`/`CurrentTokenOwner` 类侦察行为。
5. 对告警做主客体确认：是否业务服务（IIS/MSSQL）正常的客户端模拟；若是，排除或降低优先级。

## PoC

无现成 PoC（检测依赖 EDR 的线程令牌遥测）。概念性查询：

```text
for each process P:
  proc_owner = owner_sid(P.primary_token)
  for each thread T in P:
    if T.impersonation_token.user != proc_owner and
       T.impersonation_token.user is high-privilege (e.g. NT AUTHORITY\SYSTEM):
       alert(P, T, proc_owner, T.impersonation_token.user)
```

```text
# 关联事件（示例字段）
- 进程创建：cmd.exe/powershell.exe 的父进程为低权用户进程
- 安全日志 4672：分配给新登录的特权（可作旁证）
- 网络：该进程/父进程存在到外部地址的 C2 心跳
```

说明：检测逻辑依据 Sliver `impersonate` 的 API 行为与文章描述整理，未在真实环境复跑。

## 变体与关联

- **变体：Mimikatz/Cobalt Strike**：`token::elevate`、`steal_token` 产生相同的令牌错位，可复用本判据。
- **变体：Potato/PrintSpoofer**：通过 `SeImpersonatePrivilege` 模拟高权服务令牌，检测思路相同但触发 API 不同。
- **关联**：Sliver 的 PowerShell 命令执行检测见 [[defense-detection-sliver-powershell-child-process-cmdline]]；shellcode 注入检测见 [[defense-detection-sliver-execute-shellcode-remote-thread]]；攻击侧令牌窃取手法见 [[pentest-privilege-escalation-windows-system-process-token-impersonation]]。
- **边界**：EDR 不采集线程令牌、模拟发生在同一用户上下文、或攻击者使用内核级手段隐藏令牌时，该判据失效。

## 检测与防御

- **检测**：线程模拟令牌与进程主令牌所有者不一致、低权进程派生高权子进程、令牌操纵 API 序列；与进程创建和网络行为组合告警。
- **防御**：最小权限运行 Web/服务进程；启用 Credential Guard 与 LSA 保护；限制 `SeDebugPrivilege`、`SeImpersonatePrivilege`、`SeAssignPrimaryTokenPrivilege` 的授予；对敏感进程启用 PPL；EDR 阻断可疑令牌复制/模拟。
- **响应**：确认后终止相关进程、轮换被窃取账户凭据、检查同令牌是否已被用于横向移动。
