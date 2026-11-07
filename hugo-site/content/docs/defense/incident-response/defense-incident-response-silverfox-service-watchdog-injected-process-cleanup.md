---
id: defense-incident-response-silverfox-service-watchdog-injected-process-cleanup
title: 银狐服务+看门狗+系统进程注入的清除顺序：先断更与停脚本，再删服务与载荷
type: scenario
domain: defense
path: defense/incident-response
technique: silverfox-service-watchdog-injected-process-cleanup
tags:
- incident-response
- windows
- malware
- silverfox
- service
- watchdog
- process-injection
- cleanup
- defender-exclusion
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:52:22+08:00'
  notes: 已对照原文与截图核对：服务 xr1hh、pBvF/rzrOrYtU 等随机 BAT、PID 10124/10220、注入 sihost→taskhostw、DisplaySessionContainers.log、Defender 排除与隐藏属性均一致；清除顺序为原文处置建议的合理展开；未验证点：未实机处置。
url: /docs/defense/incident-response/defense-incident-response-silverfox-service-watchdog-injected-process-cleanup/
draft: false
kb_aliases:
- 银狐木马清除顺序
- 服务看门狗清理
- sihost 注入进程处置
- xr1hh 服务删除
- DisplaySessionContainers.log 清理
- 银狐应急响应
---

## 一句话结论

这类银狐样本用自动服务、多个 BAT 看门狗和系统进程注入互相兜底：先杀 `sihost.exe` 会触发向 `taskhostw.exe` 转移，先杀载荷进程会被 `sc start` 在约 10 秒内复活。正确顺序是先断 C2 与留内存证据，再停/删看门狗 BAT 与 cmd，随后停/删服务，最后处理注入进程并清理载荷目录、Defender 排除与隐藏文件。

## 原理

- **多层兜底结构**：持久化由三部分组成——自动服务 `xr1hh`（`ImagePath=cmd /c ... start DlCLr.exe`）、`C:\Windows` 下的随机名 BAT 看门狗（每 10 秒 `tasklist` 查 PID，缺失则 `sc start xr1hh`）、以及注入到 `sihost.exe`/`uhssvc.exe`/`taskhostw.exe` 的内存模块。任一层未清除，其他层都会把载荷拉回来。
- **先杀进程会触发复活**：服务与 BAT 的检查周期约 10 秒；结束 `DlCLr.exe` 后，BAT 在下一轮执行 `sc start`，服务再次以 SYSTEM 权限启动载荷。只清进程而不停服务/脚本，现场会表现为“杀不掉”。
- **先杀系统进程会触发转移**：`sihost.exe` 是 Shell Infrastructure Host，`uhssvc.exe` 是 Update Health Service，`taskhostw.exe` 是任务宿主。样本注入这些系统进程后，若被结束，代码会转移到另一个系统进程（现场观察到结束 `sihost` 后注入 `taskhostw`）；直接杀系统关键进程还可能导致桌面/登录异常，且可能被系统保护机制阻止。
- **内存证据优先**：样本常驻内存、落地文件可能自删除或只以注入形式存在；重启会丢失内存中的注入模块、网络连接与配置。因此应先拍内存镜像（见关联取证卡），再动手清除。
- **C2 先断**：样本通过 `sihost.exe` 持续连接 `192.238.192.11:22`（域名 `www.sjdxb120.com`）。不清除网络通道，攻击者可能重新投递或下发指令；处置时应先在边界封禁 IP/域名与异常 SSH 出站。
- **隐藏与排除增加清理遗漏**：载荷目录 `C:\ProgramData\latest-b\`、GUID 配置目录及 `config.ini`/`desktop.ini`/`KKONE` 被设为隐藏+系统属性；Defender 排除了 `C:\ProgramData\latest-b\pstbA\`。只按普通文件浏览会看不到，需用 `attrib` 与 Defender 排除列表核对。
- **键盘/剪贴板日志是数据泄露证据**：`C:\ProgramData\<GUID>\DisplaySessionContainers.log` 记录键盘与剪贴板内容；清理前应保全并评估凭据泄露范围，随后轮换相关账号密码。

## 触发条件

- Windows 主机确认或高度怀疑感染银狐/同类服务+看门狗木马：出现随机名服务、`C:\Windows` 下随机 BAT、系统进程异常 SSH 外联、`ProgramData` 隐藏目录等。
- 已获得管理员权限，能停止/删除服务、结束进程、修改文件属性与 Defender 排除。
- 处置前已尽可能保留现场：进程列表、网络连接、服务配置、BAT 内容、内存镜像/样本哈希。
- 业务允许短时中断或重启；若不能重启，需要更谨慎地按顺序停服务、停脚本、挂起/结束注入进程。

## 利用步骤

1. **隔离与封禁**：在防火墙/边界封禁 `192.238.192.11`、`www.sjdxb120.com` 及异常 SSH 出站，防止清除过程中重新下载或回连；保留现有连接记录。
2. **留证与内存镜像**：记录 `tasklist /v`、`netstat -ano`、`Get-CimInstance Win32_Process`、`sc qc xr1hh`、`reg query` 服务项、`dir /a C:\Windows\*.bat`；用 DumpIt 拍内存镜像并计算哈希；对可疑进程可先挂起。
3. **停看门狗脚本**：用 `Get-CimInstance Win32_Process` 找命令行含 `.bat` 的 `cmd.exe`（现场 PID 10124 运行 `pBvF.bat`、10220 运行 `rzrOrYtU.bat`），记录命令行后结束这些 cmd；删除 `C:\Windows` 下随机名 BAT（如 `pBvF.bat`、`rzrOrYtU.bat`、`aFJz`、`WkzWsvx`），先备份/哈希再删除。
4. **停/删服务**：`sc stop xr1hh`，再 `sc delete xr1hh`；核对 `HKLM\SYSTEM\CurrentControlSet\Services\xr1hh` 的 `ImagePath` 与 `DisplayName`，确认没有第二个随机名服务指向同一载荷目录。
5. **处理注入进程**：在服务与脚本已停的前提下，挂起/结束被注入的 `sihost.exe`、`uhssvc.exe`、`taskhostw.exe` 实例；若担心系统稳定性，可直接重启主机（重启前确保服务已删、BAT 已删、启动项已清）。注意结束 `sihost` 后可能看到 `taskhostw` 接管，需继续排查。
6. **清理载荷与配置**：删除 `C:\ProgramData\latest-b\` 与 GUID 目录前先备份样本/日志；用 `attrib -h -s -r` 去除隐藏/系统/只读属性后再删除；检查 `C:\ProgramData` 下其他随机 GUID 目录、`config.ini`、`desktop.ini`、`KKONE`。
7. **移除 Defender 排除与残留**：`Get-MpPreference` 查看 `ExclusionPath`，用 `Remove-MpPreference -ExclusionPath 'C:\ProgramData\latest-b\pstbA'` 移除；检查 Defender 策略注册表、计划任务、Run 键、启动目录是否有第二层持久化。
8. **验证与恢复**：观察至少数个 10 秒周期，确认没有新 `cmd.exe /c *.bat`、没有 `sc start xr1hh`、没有 `sihost`/`taskhostw` 异常外联、没有进程复活；重启后复查服务、BAT、`ProgramData` 隐藏目录与网络；评估 `DisplaySessionContainers.log` 泄露的账号并轮换凭据。

## PoC

以下为处置命令骨架，仅作防御研究；执行前先留证并评估业务影响：

```powershell
# 现场快照
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match '\.bat' } | Select ProcessId,CommandLine
sc.exe qc xr1hh
reg query "HKLM\SYSTEM\CurrentControlSet\Services\xr1hh"
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath

# 停看门狗与 cmd
Stop-Process -Id 10124,10220 -Force

# 停/删服务
sc.exe stop xr1hh
sc.exe delete xr1hh

# 清隐藏属性后删除载荷目录（先备份）
attrib -h -s -r "C:\ProgramData\latest-b\pstbA\*" /s
Remove-Item -Recurse -Force "C:\ProgramData\latest-b"

# 移除 Defender 排除
Remove-MpPreference -ExclusionPath 'C:\ProgramData\latest-b\pstbA'
```

## 变体与关联

- 变体：服务名/DisplayName/载荷目录随机化；BAT 看门狗改为 PowerShell 脚本或第二个服务；注入目标换成 `svchost.exe`、`explorer.exe`、`dllhost.exe`；C2 从 SSH 22 换成 HTTPS/WebSocket。
- 变体：看门狗不只 `sc start`，还会重新下载载荷或从备份目录复制；清理时必须同时删除备份与下载器。
- 关联：[[pentest-persistence-windows-service-bat-watchdog-resurrection]]（服务+BAT 看门狗原理）、[[pentest-c2-silverfox-inno-dlclr-vmprotect-png-zlib-chain]]（完整加载链）、[[defense-forensics-memory-netscan-malfind-dump-injected-process]]（内存取证）、[[defense-incident-response-linux-c2-watchdog-cleanup-order]]（Linux 同类清除顺序）。

## 检测与防御

- **服务与脚本**：监控 Event ID 7045/7036；筛选 `ImagePath` 含 `cmd /c`、`start ""`、`ProgramData` 的服务；检查 `C:\Windows` 根目录随机名 BAT 与运行它们的 `cmd.exe`；关注 `tasklist`/`findstr`/`sc start` 的组合与约 10 秒周期。
- **进程与网络**：`sihost.exe`、`uhssvc.exe`、`taskhostw.exe` 出现外部 22 端口连接；系统进程内存出现 RWX VAD；进程父 PID 与创建时间矛盾（PPID 欺骗）。
- **文件与配置**：`C:\ProgramData` 下随机 GUID 目录、隐藏+系统属性的 `config.ini`/`desktop.ini`/`KKONE`、`DisplaySessionContainers.log`；Defender `ExclusionPath` 中出现 `ProgramData` 子目录。
- **加固**：限制服务创建与 `C:\Windows` 写入；审计 Defender 排除变更；启用应用白名单与系统进程保护；封禁异常 SSH 出站；定期检查启动项、服务与隐藏目录。
- **处置注意**：不要先杀 `sihost.exe`/`taskhostw.exe` 等系统进程，也不要只结束载荷进程；先断网、留证、停脚本、停服务，再处理注入进程与文件。清理完成后持续观察并轮换可能泄露的凭据。
