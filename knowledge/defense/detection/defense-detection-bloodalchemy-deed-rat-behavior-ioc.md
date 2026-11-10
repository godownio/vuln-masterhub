---
id: defense-detection-bloodalchemy-deed-rat-behavior-ioc
title: BloodAlchemy/Deed RAT 行为与狩猎特征：run_mode 0–6、服务/启动/taskschd 持久化、反沙箱、Early Bird APC 注入与 0x11xx–0x15xx 命令集
type: scenario
domain: defense
path: defense/detection
technique: bloodalchemy-deed-rat-hunting-ioc
aliases:
- BloodAlchemy 检测
- BloodAlchemy IOC
- Deed RAT 狩猎
- ShadowPad 变种检测
- run_mode 行为
- Early Bird APC 注入检测
- C:\ProgramData\Store 狩猎
tags:
- detection
- threat-hunting
- windows
- malware
- bloodalchemy
- deed-rat
- shadowpad
- ioc
- persistence
- process-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:58:48+08:00'
  notes: 已对照原文与20张图核对：run_mode 0-6 行为表、持久化触发条件（run_mode 0/3、非持久路径、配置0x34非0）、persistence_flag 1-4、四个 Test 落地目录与 test.exe/BrLogAPI.dll/DIFX、服务名 Test/Digital Imaging System、Run 键与 ONLOGON（图12-14）、反沙箱 0x1c 开关与进程名/DNS/c:/bin 文件、GetCursorInfo/GetPhysicalCursorPos（图16）、注入 0x54/0x68 开关、目标进程与 VirtualAllocEx/WriteProcessMemory/VirtualProtectEx/QueueUserAPC/ResumeThread（图15）、协议 switch 1-8 与 DNS 配置 0x98/0xB0/0xAC（图17）、命令 ID 0x1101-0x1502（图18）、error.log 与异常处理、mutex、45AB45AB vs 54 45 ED DE（图20/19）均一致。狩猎命令为只读排查未执行。与 Early Bird 通用手法卡、AgentTesla 家族卡等候选无同链，非重复。无 affected_versions（恶意软件无版本区间）、无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。
---

## 一句话结论

BloodAlchemy（Deed RAT/ShadowPad 演化版）的主机狩猎面由一组稳定特征构成：`C:\Windows` 下的 `BrDifxapi.exe`+`BrLogAPI.dll`+`DIFX` 侧加载三件套与计划任务 `\Dell\BrDifxapi`；`C:\ProgramData\Store` 下 15 个字母命名的加密配置；载荷按 `run_mode`（0–6）切换 C2 通信、进程注入、反调试/反沙箱与持久化（服务/启动目录/taskschd COM，目录名 Test），注入用 `QueueUserAPC`（Early Bird）指向 `SearchIndexer.exe`/`wininit.exe`/`taskhost.exe`/`svchost.exe` 等，后门命令 ID 为 `0x11xx`–`0x15xx`。

## 原理

- **run_mode 决定行为**：载荷入口用六个参数调用，第一个参数为运行模式，不同值组合不同能力：0 = C2 通信+后门+创建/注入进程+反调试+反沙箱+持久化；1 = C2 通信+后门；2 = 创建 C2 通信线程；3 = C2+后门+注入+反调试+反沙箱+持久化；4 = 创建指定进程并注入；5 = 创建命名管道；6 = 恶意软件安装。狩猎时不能只按单一行为匹配。
- **持久化**：run_mode 为 0 或 3、可执行路径不在持久化目录、配置 `0x34` 非 0 时触发；`persistence_flag` 1 = 服务+启动目录+taskschd COM，2 = 服务，3 = 启动目录，4 = taskschd COM。落地目录为 `%AUTOPATH%\Test\`、`%LocalAppData%\Programs\Test\`、`%ProgramFiles%\Test\`、`%ProgramFiles(x86)%\Test\`，放入 `test.exe`、`BrLogAPI.dll`、`DIFX`。配置中可见示例：服务名 `Test`、显示名 `Digital Imaging System`、运行键 `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` 值名 `Test`、计划任务名 `ONLOGON`。
- **反沙箱**：run_mode 0、可执行路径非持久化路径、配置 `0x1C` 为 1 时启用，检查进程名（`communicator.exe`、`steam.exe`、`SteamService.exe`、`infium.exe`、`MemCompression.exe`、`sedsvc.exe`）、DNS 解析结果（`www.microsoft.com`、`google.com`）与 `c:/bin/` 下的文件（`filemon.sys`、`filemon.inf`、`mrr.exe`、`mflash.exe`、`sleep.exe`、`fuzzy.dll`），并调用 `GetCursorInfo`/`GetPhysicalCursorPos` 判断交互环境；据此推测用于规避 Trellix 沙箱。
- **进程注入（Early Bird）**：run_mode 0/3 且配置 `0x54`=1 时，把 payload 中的 shellcode 注入 `%windir%\system32\SearchIndexer.exe`、`wininit.exe`、`taskhost.exe`、`svchost.exe`；先 `VirtualAllocEx`、`WriteProcessMemory`、`VirtualProtectEx`，再 `QueueUserAPC(buf, thread, ...)` + `ResumeThread`，即 Early Bird APC 注入。run_mode 0/4 且配置 `0x68`=1 时另创建 `wininit.exe`/`taskeng.exe`/`taskhost.exe`/`svchost.exe` 并注入。
- **通信协议按配置切换**：C2 信息（最多 10 个）解出后提取协议 ID，用 switch 选择 `TCP_MUX_protocol`（1/8）、`HTTP_HTTPS_protocol`（2/3）、`UDP_protocol`（4）、`DNS_protocol`（5，读取配置 0x98/0xB0/0xAC 如 0x16 与 ONLOGON）、`PIPE_SMB_protocol`（6/7），并填充 `create_socket_connect`/`connect_send_recv`/`recv_data`/`wsarecv`/`wsasend` 等函数指针。
- **后门命令**：命令 ID 0x1101 更新配置、0x1102 获取当前配置、0x1201 更新 test.exe、0x1202 更新 BrLogAPI.dll、0x1203 更新 DIFX、0x1204 卸载并终止、0x1205 启动持久化目录下 test.exe、0x1302 把收到的载荷写入注册表值、0x1303 删除注册表值、0x1401/0x1402 获取/更新代理信息、0x1501 收集受害者信息、0x1502 回显，另有未知的 0x1301/0x1304。
- **主机痕迹**：`%ALLUSERSPROFILE%` 下 `error.log` 记录异常处理信息（`Access Exception Address`/`Code` 格式）；mutex 示例 `DFYNBEDKJHGAFSTIJECYUKFDEUJH`；载荷 magic `45AB45AB`（Deed RAT 为 `54 45 ED DE`）。
- **家族背景**：BloodAlchemy 与 Deed RAT 共享自定义载荷头（PE 式结构）、DLL/shellcode 加载流程、入口点后异常处理、插件加载启动函数、插件名/插件信息、配置加密数据偏移结构、持久化目录名与文件名；两者的源头是 ShadowPad。

## 触发条件

- 需要在 Windows 主机/内存/网络中狩猎 ShadowPad 系（BloodAlchemy/Deed RAT）活动。
- 可以发现文件系统、计划任务、服务、注册表运行键、进程注入行为与网络连接中的上述特征。
- 载荷可能按 run_mode 只启用部分能力，因此需要多维度关联而非单点匹配。
- 配置/Kill switch 由攻击者控制，未启用持久化或注入时相应特征缺失。

## 利用步骤

1. **文件与计划任务排查**：查 `C:\Windows` 下 `BrDifxapi.exe`、`BrLogAPI.dll`、无扩展名 `DIFX` 组合；查计划任务 `\Dell\BrDifxapi` 与 `\Test`/`ONLOGON` 相关项。
2. **持久化目录排查**：检查 `%AUTOPATH%\Test\`、`%LocalAppData%\Programs\Test\`、`%ProgramFiles%\Test\`、`%ProgramFiles(x86)%\Test\` 下的 `test.exe`/`BrLogAPI.dll`/`DIFX`；查服务 `Test`/显示名 `Digital Imaging System`、Run 键 `...\CurrentVersion\Run` 值 `Test`。
3. **配置与日志排查**：查 `C:\ProgramData\Store` 下 15 个字母命名的文件；查 `%ALLUSERSPROFILE%\error.log` 中的异常地址记录。
4. **内存扫描**：搜索 magic `45AB45AB`、`54 45 ED DE` 与 `DIFX` 字符串；对可疑进程检查 `QueueUserAPC` 注入迹象（`VirtualAllocEx`+`WriteProcessMemory`+`VirtualProtectEx`+`QueueUserAPC`+`ResumeThread` 调用序列）。
5. **网络关联**：按配置解出的 C2 与协议（TCP_MUX/HTTP(S)/UDP/DNS/PIPE_SMB）检索连接；DNS 协议模式下注意异常 DNS 查询。
6. **处置**：隔离主机、终止恶意进程与注入线程、清理服务/计划任务/运行键/持久化目录，重置被劫持的 VPN/维护账号。

## PoC

狩猎命令示例（只读排查）：

```powershell
# 侧加载三件套与无扩展名文件
Get-ChildItem C:\Windows -Filter 'Br*' -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows -Filter 'DIFX' -ErrorAction SilentlyContinue

# 计划任务与服务
schtasks /query /fo LIST /v | Select-String -Pattern 'Dell\\BrDifxapi|ONLOGON'
sc query Test

# 持久化目录与配置
Get-ChildItem "$env:ProgramData\Store" -ErrorAction SilentlyContinue
Get-ChildItem "$env:ProgramData\Test","$env:LOCALAPPDATA\Programs\Test","$env:ProgramFiles\Test" -ErrorAction SilentlyContinue
```

说明：以上为特征排查命令，不运行样本；实际狩猎需结合 EDR 进程/注入遥测与内存扫描。

## 变体与关联

- **变体（家族版本）**：Deed RAT 使用 `54 45 ED DE` magic、插件 ID 0x20、入口 0x1740；BloodAlchemy 为 `45AB45AB`/0x10/0x698C。ShadowPad 为其前身，狩猎特征可跨家族迁移。
- **变体（持久化组合）**：persistence_flag 1-4 对应服务/启动/taskschd COM 的不同组合；目录名与文件名可被改版替换。
- **变体（通信）**：同一载荷支持 TCP_MUX、HTTP(S)、UDP、DNS、PIPE_SMB 多种协议，网络特征随协议 ID 变化。
- 关联：[[code-analysis-reverse-windows-bloodalchemy-loader-aes-fnv-lznt1]]（加载链与 magic/节表）、[[code-analysis-reverse-windows-bloodalchemy-config-1byte-key-decrypt]]（配置字段解密）、[[pentest-c2-early-bird-apc-injection-debug-process-variant]]（Early Bird APC 注入手法）、[[defense-detection-agenttesla-web-panel-stealer-behavior-ioc]]（同类恶意家族狩猎卡）。
- 边界：run_mode 限制能力、配置在文件中而非内嵌、或攻击者清理痕迹后，单点特征可能不足，需要内存取证与网络侧联合判断。

## 检测与防御

- **检测规则**：EDR 对 `BrDifxapi.exe`/`BrLogAPI.dll`/`DIFX` 文件名、`\Dell\BrDifxapi` 计划任务、服务 `Test`/`Digital Imaging System`、Run 键值 `Test`、Store 下 15 字母文件、`error.log` 异常记录告警；内存 YARA 匹配 `45AB45AB`/`54 45 ED DE`；监控 `QueueUserAPC` 注入与目标进程组合。
- **加固**：安全 DLL 搜索模式、WDAC/AppLocker 限制 `C:\Windows` 与用户目录可执行文件；限制 VPN/维护账号权限并启用强认证；对计划任务、服务、运行键变更审计。
- **响应**：隔离主机、清理持久化（服务/任务/注册表/目录）、轮换被劫持账号与设备凭据；用配置解出的 C2 做网络封禁与同网段排查。
- **防御评估**：定期用本卡特征对终端做回溯狩猎；对 ShadowPad/Deed RAT/BloodAlchemy 共享代码特征做长期跟踪。
