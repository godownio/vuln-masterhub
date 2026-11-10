---
id: defense-detection-sliver-powershell-child-process-cmdline
title: Sliver 命令 shell 的 PowerShell 子进程检测：固定 -NoExit 与 UTF8 命令行特征
type: scenario
domain: defense
path: defense/detection
technique: sliver-powershell-child-process-detection
tags:
- defense
- detection
- sliver
- c2
- powershell
- process-creation
- sysmon
- cmdline
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:08:11+08:00'
  notes: 已对照原文与图片核对：shell_windows.go 常量为 powershell.exe + -NoExit + -Command + [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8，SysProcAttr 用 priv.CurrentToken 且 HideWindow:true；GetSystemShellPath 优先级（自定义→powershell→cmd）与卡片一致。未验证点：Sysmon/4688 查询与告警为概念配置，未在真实 Sliver 会话复跑；原文未给版本区间，affected_versions 已 --clear。
url: /docs/defense/detection/defense-detection-sliver-powershell-child-process-cmdline/
draft: false
kb_aliases:
- Sliver PowerShell 检测
- Sliver command shell
- -NoExit -Command [Console]::OutputEncoding
- powershell 子进程检测
- Sliver 进程创建遥测
---

## 一句话结论

Sliver 在 Windows 上执行命令 shell 时优先启动 `powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8`，并以当前进程令牌运行、隐藏窗口；在进程创建遥测中同时匹配这条固定命令行、非交互父进程与后续 C2 外联，即可较稳地识别 Sliver 的命令执行阶段。

## 原理

- **源码决定指纹**：Sliver 的 `shell_windows.go` 把 PowerShell 启动参数写成常量：可执行文件 `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`，参数 `-NoExit`、`-Command`、`[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8`。`GetSystemShellPath` 的优先级是：自定义 shell 路径存在则用之，否则 `powershell.exe` 存在则用之，最后回退 `cmd.exe`。
- **启动方式**：`Start` 用 `exec.Command` 启动进程，`SysProcAttr` 指定 `Token: syscall.Token(priv.CurrentToken)` 与 `HideWindow: true`，即用植入体当前令牌运行、不弹窗口。因此从进程树看，PowerShell 的父进程是 Sliver 植入进程，而不是 `explorer.exe`、终端或计划任务；命令行固定且带 `-NoExit`（执行完不退出）与 UTF-8 输出编码设置。
- **为什么这条规则有效**：`-NoExit` 通常用于调试/交互式会话，正常业务脚本很少与 `[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8` 同时出现，且其父进程往往不在正常办公软件链路中。攻击者若手工执行 `powershell -enc ...` 则命令行不同，但 Sliver 自带的 shell 命令会命中该常量。
- **可用遥测**：Sysmon Event ID 1（进程创建，含命令行与父进程）、Windows 安全日志 4688（需开启命令行审计 `ProcessCreationIncludeCmdLine_Enabled`）、EDR 进程事件；PowerShell 4104 脚本块日志可补足命令内容，4103 模块日志可记录管道执行。
- **边界**：攻击者可修改源码/自定义 profile 或上传自带 PowerShell 脚本改变命令行；目标没有 powershell.exe 时回退 cmd.exe；命中该命令行也可能来自合法运维脚本（需结合父进程与网络行为）。

## 触发条件

- 受害主机为 Windows，且具备进程创建审计（Sysmon 1 / 4688 命令行 / EDR）。
- Sliver session 或 beacon 通过自带 `shell` 命令执行了 PowerShell 命令。
- 目标存在 `powershell.exe`（否则走 cmd.exe，需换用其他判据）。
- 分析者能关联主机进程事件与网络外联（C2 目的地址/心跳）。

## 检测步骤

1. 确认进程创建日志包含命令行与父进程字段（Sysmon 1 默认有；4688 需开启命令行审计）。
2. 匹配命令行特征：
   ```text
   Image 以 \powershell.exe 结尾
   CommandLine 同时包含 "-NoExit" 与 "[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8"
   ```
3. 检查父进程：不是 `explorer.exe`、终端、IDE 或已知运维调度器，而是可疑服务/临时目录进程；同时该父进程有到外部地址的长连接或心跳。
4. 关联 PowerShell 4104 脚本块日志，查看被执行的命令（侦察、下载、横向等）。
5. 在 Velociraptor/EDR 中把“异常父进程 + 固定参数 + 隐藏窗口 + C2 外联”组合成告警，降低单指标误报。

## PoC

```xml
<!-- Sysmon 进程创建过滤（概念配置） -->
<Sysmon>
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains all">-NoExit;[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

```powershell
# Windows 事件查询（Sysmon 1）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'powershell\.exe' -and
                 $_.Message -match '-NoExit' -and
                 $_.Message -match 'UTF8Encoding' }
```

说明：检测逻辑依据 Sliver 源码常量与文章描述，未在真实 Sliver 会话中复跑。

## 变体与关联

- **变体：cmd.exe 回退**：目标无 PowerShell 时 Sliver 用 `cmd.exe` 执行，需改为监控植入体派生的 `cmd.exe /c` 与异常父进程。
- **变体：自定义 shell/参数**：攻击者可用 `--shell-path` 或改源码规避固定参数；此时结合 EDR 的进程树异常与网络行为检测。
- **关联**：Sliver 的令牌窃取检测见 [[defense-detection-sliver-impersonate-token-owner-mismatch]]；shellcode 注入检测见 [[defense-detection-sliver-execute-shellcode-remote-thread]]；网络侧见 [[defense-detection-sliver-default-tls-jarm-31337]]。
- **对照**：其他 PowerShell 宿主/LOLBin 的检测见 [[defense-detection-sqlps-lolbin-powershell]]。

## 检测与防御

- **检测**：上述命令行+父进程规则；PowerShell 脚本块日志；进程树中出现植入体进程 → powershell.exe → 横向工具/网络连接的链路。
- **防御**：对服务账户与应用进程启用 AppLocker/WDAC 限制脚本宿主；启用 Constrained Language Mode；不需要 PowerShell 的服务器移除/限制 powershell.exe；EDR 阻断可疑子进程并告警。
- **响应**：确认命中后隔离主机，提取植入体样本与内存，排查 C2 地址、持久化与已执行的命令。
