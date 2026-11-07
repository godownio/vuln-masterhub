---
id: defense-incident-response-silverfox-nvgpu-nvml-ie-task-cleanup
title: 银狐 nvgpu/nvml 变种应急处置：先删 Microsoft Compatibility Internet Explorer 计划任务，再清 IE 目录伪签名文件与注入进程
type: scenario
domain: defense
path: defense/incident-response
technique: silverfox-nvgpu-nvml-ie-task-cleanup
aliases:
- 银狐 nvgpu 清除
- Microsoft Compatibility Internet Explorer 计划任务
- nvml.dll 白加黑清除
- IE 目录 nvgpu_x64.exe
- 银狐 18.166.2.135 处置
- congihwe.cn 应急
tags:
- incident-response
- windows
- silverfox
- scheduled-task
- dll-sideloading
- process-injection
- ioc
- cleanup
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T13:46:42+08:00'
  notes: 已对照原文全文与37张图核对：IOC（18.166.2.135:5676、congihwe.cn、IE 目录四文件、伪签名、任务 XML、自删除命令）与图12/13/15/17/18/26 一致；处置顺序（先删任务再清文件/进程）与原文处置措施相符。已把‘svchost.exe 注入’改为‘疑似注入/系统进程承载’，避免把原文推断写成事实；其余为基于已观测 IOC 的防御性加固建议。confidence=medium 保留。未验证点：未在真实环境执行处置；nvml.dll 后续注入链未证实；无 CVE/版本、无 sources/source_url。
---

## 一句话结论

确认主机感染银狐 nvgpu/nvml 变种后，处置顺序应是：先隔离主机并在边界封禁 C2 `18.166.2.135:5676` 与域名 `congihwe.cn`，保留任务 XML、文件与网络现场；随后删除 `\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer` 开机计划任务（否则重启会再次拉起 `nvgpu_x64.exe`），再结束 `nvgpu_x64.exe`、承载 `nvml.dll` 的进程，并用 EDR 清理 `svchost.exe` 中的疑似注入模块，最后删除 `C:\Program Files\Internet Explorer` 下的 `nvgpu_x64.exe`、`nvml.dll`、`nvml.bin`、`temp.key`，并复查其他持久化与凭据泄露。

## 原理

- **计划任务是复发根因**：任务 XML 使用 `BootTrigger` 开机触发、`S-1-5-18`（SYSTEM）、`HighestAvailable`，Action 为 `C:\Program Files\Internet Explorer\nvgpu_x64.exe`。只要任务还在，重启后白程序会再次启动并侧加载 `nvml.dll`，表现为“文件删了又回来/网络断了又连上”。
- **白加黑依赖文件同目录共存**：`nvgpu_x64.exe` 静态导入 `nvml.dll`，Windows 按 DLL 搜索顺序优先加载 EXE 同目录的同名 DLL；只删 EXE 或只删 DLL 都不足以终止已加载的恶意模块，需同时清理并结束进程。
- **系统进程承载增加清理难度**：动态日志中 `nvgpu_x64.exe` 由 `svchost.exe` 释放/创建任务，样本可能借助系统进程上下文执行；直接结束系统进程可能影响系统稳定性，优先用 EDR 的模块卸载/注入清理能力，必要时重启并在重启前确保任务已删除。
- **自删除与清理对抗**：原始释放器会执行 `cmd /c timeout 2 & del /f /q "<自身路径>"` 抹掉投递文件，因此不能只依赖“找到原 EXE 并删除”；应以计划任务、IE 目录落地文件、C2 连接和进程模块为主要证据。
- **清理前留证**：样本会读取 `win.ini`、做虚拟机检测并与 C2 通信；先记录任务 XML、文件哈希、签名信息、进程/网络连接和 DNS 缓存，再动手删除，避免破坏溯源与后续情报比对。
- **凭据风险**：银狐类远控常具备键盘记录、浏览器凭据窃取与横向能力；清理后应评估该时间段内登录过的账号、保存过的密码与内网凭据，必要时轮换。

## 触发条件

- 主机出现以下任一痕迹：`C:\Program Files\Internet Explorer` 下存在 `nvgpu_x64.exe`/`nvml.dll`/`nvml.bin`/`temp.key`；存在 `\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer` 计划任务；`svchost.exe` 连接 `18.166.2.135:5676`；DNS 缓存有 `congihwe.cn`。
- 已获得管理员权限，能够删除 SYSTEM 计划任务、结束进程、删除 `Program Files` 下文件。
- 处置前已尽可能保留现场；业务允许短时中断或重启。
- 需要判断是否存在第二套持久化（服务、Run 键、启动目录、其他计划任务、WMI 订阅、注入模块），避免只清一条链。

## 利用步骤

1. **隔离与封禁**：在防火墙/边界封禁 `18.166.2.135:5676` 与 `congihwe.cn`，保留现有连接记录；断开主机网络或限制出站，防止清理过程中重新下载/回连。
2. **现场取证**：记录 `tasklist /v`、`netstat -ano`、`Get-CimInstance Win32_Process`、`schtasks /query /tn ... /xml`、`ipconfig /displaydns`；对 IE 目录四个文件计算 SHA256 并保存签名信息；导出任务 XML 与 Security 4698/任务计划程序 106/200/201 日志；有条件时先做内存镜像。
3. **删除计划任务**：`schtasks /delete /tn "\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer" /f`；删除后确认 `C:\Windows\System32\Tasks\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer` 文件已消失，并检查是否还有同 Action 的其他任务。
4. **结束进程**：结束 `nvgpu_x64.exe`；用 EDR/Process Explorer 查找加载了 IE 目录 `nvml.dll` 的进程并结束；对 `svchost.exe` 中的可疑注入模块，优先使用 EDR 卸载/隔离，避免直接杀系统进程；无法安全清理时安排重启（重启前必须已删任务）。
5. **删除载荷**：先备份/哈希，再删除 `C:\Program Files\Internet Explorer\nvgpu_x64.exe`、`nvml.dll`、`nvml.bin`、`temp.key`；检查同目录及其他系统目录是否还有同名/同签名文件。
6. **排查第二套持久化**：检查服务（`sc query`/注册表 `Services`）、Run/RunOnce、启动目录、其他计划任务、WMI 事件订阅、COM 劫持、`AppInit_DLLs`、`Image File Execution Options`；检查 `C:\Windows\win.ini` 最近访问与自删除命令痕迹。
7. **复查与恢复**：重启后确认任务不存在、IE 目录文件未复活、无 `nvgpu_x64.exe` 进程、无 `18.166.2.135:5676` 连接、DNS 无 `congihwe.cn` 解析；用更新后的 AV/EDR 全盘扫描，检查浏览器扩展与凭据。
8. **凭据与影响评估**：评估该主机上的账号、浏览器保存密码、内网凭据、API Key 是否可能被窃取；必要时轮换密码、吊销会话、通知相关方；持续观察是否有横向移动迹象。

## PoC

以下为防御性处置命令骨架，执行前先留证并评估业务影响：

```powershell
# 1) 现场快照
Get-ScheduledTask -TaskPath '\Microsoft\Windows\WS\' | Format-List TaskName,TaskPath,State
Export-ScheduledTask -TaskName 'Microsoft Compatibility Internet Explorer' -TaskPath '\Microsoft\Windows\WS\' > task.xml
Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'nvgpu|nvml' } | Select ProcessId,Name,CommandLine
Get-NetTCPConnection -RemotePort 5676 | Select LocalAddress,RemoteAddress,State,OwningProcess
ipconfig /displaydns | Select-String 'congihwe'

# 2) 文件哈希与签名
Get-FileHash 'C:\Program Files\Internet Explorer\nvgpu_x64.exe','C:\Program Files\Internet Explorer\nvml.dll','C:\Program Files\Internet Explorer\nvml.bin','C:\Program Files\Internet Explorer\temp.key' -Algorithm SHA256
Get-AuthenticodeSignature 'C:\Program Files\Internet Explorer\nvgpu_x64.exe','C:\Program Files\Internet Explorer\nvml.dll' | Format-List *

# 3) 删除任务（先于结束进程/重启）
schtasks /delete /tn "\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer" /f

# 4) 结束进程（按实际 PID）
Stop-Process -Id <nvgpu_pid> -Force

# 5) 备份后删除载荷
New-Item -ItemType Directory -Path C:\IR\silverfox_backup -Force
Copy-Item 'C:\Program Files\Internet Explorer\nvgpu_x64.exe','C:\Program Files\Internet Explorer\nvml.dll','C:\Program Files\Internet Explorer\nvml.bin','C:\Program Files\Internet Explorer\temp.key' C:\IR\silverfox_backup\
Remove-Item 'C:\Program Files\Internet Explorer\nvgpu_x64.exe','C:\Program Files\Internet Explorer\nvml.dll','C:\Program Files\Internet Explorer\nvml.bin','C:\Program Files\Internet Explorer\temp.key' -Force

# 6) 复查
schtasks /query /tn "\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer"
Get-NetTCPConnection -RemotePort 5676 -ErrorAction SilentlyContinue
```

## 变体与关联

- 变体：任务名/路径可能换成其他 `\Microsoft\Windows\*` 系统路径，或改用服务、Run 键、启动目录持久化；清理时不能只按本卡的任务名搜索，应按 Action 指向的程序与 `S-1-5-18`/`HighestAvailable` 特征排查。
- 变体：宿主可能换成其他 GPU/系统工具白程序（如 `smigpu.exe`），DLL 名也可能是 `libsmi.dll` 等；清理原则相同：任务、白程序、恶意 DLL、加密 `.bin` 一起处理。
- 关联：[[code-analysis-reverse-windows-silverfox-tls-loader-nvgpu-nvml-chain]]（本样本的加载器与投递链分析）、[[pentest-persistence-signed-gpu-masquerade-hidden-scheduled-task-system]]（同类 GPU 白程序 + SYSTEM 计划任务持久化）、[[defense-incident-response-silverfox-service-watchdog-injected-process-cleanup]]（另一银狐变种的服务+看门狗清理顺序）、[[pentest-initial-access-seo-fake-official-software-download]]（IE 目录 nvml/nvgpu 落地痕迹的投递侧）。
- 边界：原文未完成完整动态调试，`nvml.dll` 导出函数与后续注入链的具体行为未逐行证实；本卡依据已观测到的任务、文件、进程与网络行为给出处置顺序，实际环境需结合 EDR 告警与第二套持久化排查调整。

## 检测与防御

- **IOC 检测**：
  - 文件：`C:\Program Files\Internet Explorer\nvgpu_x64.exe`、`nvml.dll`、`nvml.bin`、`temp.key`；`nvgpu_x64.exe` 伪腾讯签名、`nvml.dll` 伪光明食品签名。
  - 计划任务：`\Microsoft\Windows\WS\Microsoft Compatibility Internet Explorer`，Action 指向 IE 目录 `nvgpu_x64.exe`，`S-1-5-18`/`HighestAvailable`/`BootTrigger`。
  - 网络：`18.166.2.135:5676`、域名 `congihwe.cn`；`svchost.exe` 发起 5676 端口外联。
  - 哈希（原文样本）：`ea409b82af0f276a7099ee9d0f688e16afbef8d6189401daf7c7689a06e5706a`、`c5d9fba03c64f0174a2cbd9956f969b34c59d56727c3e05e9edabbb1592d3a12`、`a2c4dd0e5eec6a00e757472278050db6761fc30f1047107113410c61ddecdb30`。
- **行为检测**：TLS 回调在 OEP 前调用 `VirtualProtect`/内存解密；`svchost.exe` 向 `Program Files\Internet Explorer` 写 EXE/DLL；`nvgpu_x64.exe` 加载同目录 `nvml.dll`；创建 `S-1-5-18`/`HighestAvailable` 的开机任务；`cmd /c timeout 2 & del /f /q` 自删除。
- **防御**：不要运行来源不明的“人员名单”类 EXE；限制从 `Program Files\Internet Explorer` 等目录执行非 IE 组件；监控 SYSTEM 计划任务创建（4698）与 Tasks 目录变更；启用 AppLocker/WDAC、签名校验与 EDR 内存扫描；对 IE 目录、`svchost.exe` 异常外联、GPU 相关陌生 DLL 做基线告警。
- **响应**：按本卡顺序清理后持续观察至少一个重启周期；如发现第二套持久化或横向移动迹象，扩大排查范围并轮换凭据。
