---
id: code-analysis-reverse-anti-debug-critical-process-window-title-av-detection
title: 银狐远控反分析组合：进程关键化防杀、轮询挂起与窗口标题/杀软名单探测
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: critical-process-window-title-av-detection
tags:
- anti-debug
- anti-analysis
- windows
- malware-analysis
- silverfox
- winos
- critical-process
- window-enumeration
- av-detection
- c2
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:00:06+08:00'
  notes: 已对照原文与截图核对：NtSetInformationProcess类29关键进程、GetExitCodeProcess==259+Sleep(300ms)轮询、窗口标题与杀软名单均一致；杀软进程快照比对方式为合理推断，原文未逐行展示
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-critical-process-window-title-av-detection/
draft: false
kb_aliases:
- NtSetInformationProcess ProcessBreakOnTermination
- 进程关键化防杀
- 关键进程蓝屏
- 窗口标题枚举安全工具
- 反杀软进程名单
- 银狐反分析
- Winos 反调试
---

## 一句话结论

远控样本在运行前组合三类对抗：把自身设置为“关键进程”（`NtSetInformationProcess` 的 `ProcessBreakOnTermination=29`，置 1 后结束进程会触发蓝屏）、用一个轮询目标进程退出状态并永久 `Sleep(300ms)` 的循环让分析者以为程序挂起、再通过 `EnumWindows` + `GetWindowTextW` 匹配安全/分析工具的窗口标题，并用内置的大名单检测杀软进程；目的是阻止分析者轻易结束样本、拖延动态分析并识别受控环境。

## 原理

- **关键进程防杀**：`NtSetInformationProcess(ProcessHandle, 29, &value, sizeof(value))` 中信息类 29 是 `ProcessBreakOnTermination`；值置 1 后，内核把该进程标记为 critical。用户态结束关键进程时，内核会调用 `KeBugCheckEx`（`CRITICAL_PROCESS_DIED`，0xEF）直接蓝屏，而不是只杀进程。样本先打开自身令牌，用 `LookupPrivilegeValueW(SE_DEBUG_NAME)` + `AdjustTokenPrivileges` 启用调试特权，再 `OpenProcess(0x1FFFFF, ...)` 取得自身句柄执行设置；没有管理员/调试特权时调用会失败，样本通常忽略失败继续运行。
- **为什么用关键进程而不是普通守护**：普通双进程互拉、服务看门狗都能被一次性清理；关键进程把“杀样本”变成“杀系统”，迫使分析者在虚拟机快照、挂起或内核调试下操作，显著提高处置成本。代价是行为非常显眼：启用 `SeDebugPrivilege`、对自身调用 `NtSetInformationProcess` 类 29，都是 EDR 的高危规则点。
- **轮询挂起循环**：反调试函数打开一个进程句柄（`OpenProcess(0x400, 0, pid)`，0x400 为 `PROCESS_QUERY_INFORMATION`），循环调用 `GetExitCodeProcess`；只要返回 `STILL_ACTIVE`（259）就 `Sleep(0x12C)`（300ms）继续等，形成永不返回的等待。分析者若在调试器里跟随该函数，会一直停在这个循环里，看不到后续逻辑；也可被用作对父进程/守护进程的轮询。
- **窗口标题探测**：`EnumWindows` 遍历顶层窗口，对每个可见窗口用 `GetWindowTextW` 取标题（缓冲区 0x800 字节），再与宽字符串表比较：`流量`、`ApateDNS`、`Malwarebytes`、`TCPEye`、`TaskExplorer`、`CurrPorts`、`Port`、`Metascan`、`Wireshark`、`任务管理器`、`资源监视器`、`网络分析`、`Fiddler`、`火绒`、`Capsa`、`Sniff`、`Process`、`提示符`。命中任一即置标志，后续可能退出、延迟或改变行为。相比只查进程名，窗口标题能覆盖那些进程名被伪装、但界面标题仍是产品名的工具。
- **杀软进程名单**：样本内置一张远大于常见清单的杀软进程/显示名表，覆盖 360、金山毒霸、QQ 电脑管家、火绒、百度杀毒、江民、瑞星、QuickHeal、微软 MSE/Defender、Comodo、DR.WEB、Outpost、安博士 V3、AVG、F-Secure、卡巴斯基、McAfee、NOD32、可牛、趋势、小红伞、Avast、诺顿、熊猫卫士、BitDefender、PSafe、Ad-watch、K7、UnThreat、联想管家等。检测通常用进程快照遍历比对进程名，命中即判定存在安全软件。
- **组合效果**：窗口标题与进程名单负责“发现分析环境”，关键进程负责“不能被轻易终止”，挂起循环负责“拖时间”。三者都不改变载荷的最终行为，但显著增加动态分析、取证和应急清除的难度。

## 触发条件

- 目标为 Windows，样本以可执行文件或注入模块形式运行。
- 关键进程设置需要进程具备 `SeDebugPrivilege`（通常管理员权限）；权限不足时该步失败但不影响后续。
- 样本运行在交互式桌面会话中，`EnumWindows` 能枚举到安全工具窗口；在无桌面/服务会话中窗口探测效果下降。
- 目标进程能调用 `NtSetInformationProcess`、`EnumWindows`、`GetWindowTextW` 等 API，未被 EDR 拦截。
- 分析者尝试用任务管理器/`taskkill` 结束样本，或未在虚拟机快照下操作。

## 利用步骤

（按样本对抗逻辑描述，非本机复现。）

1. **启用调试特权**：`OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &token)`，`LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)`，`AdjustTokenPrivileges` 启用。
2. **设置关键进程**：`GetModuleHandleA("ntdll.dll")` + `GetProcAddress("NtSetInformationProcess")`，`OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId())`，调用 `NtSetInformationProcess(h, 29, &one, 4)`。
3. **进入挂起循环**：打开目标进程句柄，循环 `GetExitCodeProcess`，等于 `STILL_ACTIVE` 时 `Sleep(300ms)`，永不返回。
4. **枚举窗口标题**：`EnumWindows` 回调中对可见窗口 `GetWindowTextW`，与内置安全工具标题表逐项 `wcsstr` 比较。
5. **枚举杀软进程**：用进程快照遍历进程名，与内置杀软名单比对；命中后按样本策略退出或改变行为。
6. **分析绕过**：在虚拟机快照中运行；用调试器 patch `NtSetInformationProcess` 调用或把信息类 29 的调用改成 `ret`；用挂起（suspend）代替结束进程；对 `EnumWindows`/`GetWindowTextW` 下断点或 hook，观察命中项。

## PoC

无公开利用 PoC（仅样本行为分析）。用于识别的 API 序列：

```text
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)
LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)
AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)
NtSetInformationProcess(hSelf, 29 /* ProcessBreakOnTermination */, &one, sizeof(one))
```

```text
EnumWindows(EnumFunc, 0)
EnumFunc: IsWindowVisible -> GetWindowTextW(hwnd, buf, 0x800) -> wcsstr(buf, L"火绒") ...
```

分析时不要直接结束已关键化的样本；先在虚拟机快照/内核调试环境操作，或 patch 掉类 29 调用。

## 变体与关联

- 变体：可改用 `RtlSetProcessIsCritical` 封装、把关键化放到子进程、或改用 `ProcessBreakOnTermination` 的其他信息类组合；窗口探测可换成 `GetForegroundWindow`、UI Automation 或进程命令行扫描；杀软名单可外部化到配置文件/资源段。
- 关联：[[code-analysis-reverse-anti-debug-silverfox-installer-vm-detection]]（银狐安装器反虚拟机三件套）、[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]（通用反沙箱/反调试）、[[defense-incident-response-silverfox-service-watchdog-injected-process-cleanup]]（银狐服务看门狗的实际清除顺序）。
- 后续链：本组合位于 Winos 登录模块/载荷内，投递与加载见 [[pentest-initial-access-signed-msi-huorong-fake-installer-scheduled-task]]、[[pentest-c2-winos-wps-loader-processcount-rc4-custom-decrypt]]。

## 检测与防御

- **关键进程检测**：监控进程启用 `SeDebugPrivilege` 后对自身调用 `NtSetInformationProcess`（信息类 29）；对已标记 critical 的样本不要用常规结束进程，改用挂起、快照或内核调试。
- **窗口探测检测**：`EnumWindows` + `GetWindowTextW` 遍历大量窗口并与安全产品名比较，是可疑行为；可在 EDR 中对“非 UI 进程批量读取窗口标题”告警。
- **名单特征**：内置宽字符串杀软名单（360Safe.exe、HipsTray.exe、msmpeng.exe 等）与安全工具标题表可作为 YARA/内存规则；名单长度和内容可作家族指纹。
- **反分析对抗**：分析环境隐藏或改名安全工具窗口、在服务会话/无桌面环境运行样本，可降低窗口探测命中；对关键进程设置做 API hook 并记录调用。
- **应急响应**：发现关键进程样本时先隔离主机、保留内存镜像，再在维护窗口重启/快照处置；不要直接 `taskkill`，避免蓝屏导致证据丢失。清除后检查计划任务、安装包与同批次载荷。
