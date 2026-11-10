---
id: code-analysis-reverse-anti-debug-debugger-process-window-detect-rename-bypass
title: 针对调试器的反调试：EnumProcesses+GetModuleBaseNameA 或 FindWindowA 检测 OllyDbg 并 TerminateProcess，改名/re-pair 绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: debugger-process-window-detect-rename-bypass
tags:
- windows
- anti-debug
- ollydbg
- process-enumeration
- findwindow
- terminateprocess
- renaming
- re-pair
- reversing
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:55:26+08:00'
  notes: 已对照原文与图23-35核对：EnumProcesses PID 数组、OpenProcess(0x410)、EnumProcessModules 基址 0x400000、GetModuleBaseNameA 取 Ollydbg.exe、大写比较 OLLYDBG.EXE 后 OpenProcess(PROCESS_TERMINATE)+TerminateProcess；第二样本 FindWindowA 类名 OllyDbg+CreateToolhelp32Snapshot/Process32First/Next 比对进程名、命中 ExitProcess；RE-Pair 改名与 WinDowse 查类名（原文示例改名为 Msn21，类名变 Msn21）绕过均一致，PoC 已按图改为 Msn21。与 PEB/NtQuery 反调试卡检测对象与绕过不同，dedup related/new；原文无版本；无 URL/文章 ID/长段摘录；未复跑
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-debugger-process-window-detect-rename-bypass/
draft: false
kb_aliases:
- 检测调试器进程
- OllyDbg 进程检测
- FindWindow 检测 OllyDbg
- 反调试杀调试器
- RE-Pair 绕过
- 改名绕过反调试
- EnumProcesses GetModuleBaseNameA
---

## 一句话结论

一些样本会主动检测“正在调试它的调试器”：一路用 `EnumProcesses → OpenProcess → EnumProcessModules → GetModuleBaseNameA` 枚举进程名并与 `OLLYDBG.EXE` 比较，另一路用 `CreateToolhelp32Snapshot + Process32First/Next` 配合 `FindWindowA`（类名/标题含 `OllyDbg`）查找调试器窗口，命中后对调试器进程 `TerminateProcess`/自身 `ExitProcess`；由于检测只依赖进程名/窗口类名这类可修改的字符串，把 OllyDbg 改名（如 RE-Pair 0.6）或改窗口类名/标题即可绕过。

## 原理

- **检测目标是调试器本身**：与 PEB 标志类反调试不同，这类样本不读自身状态，而是从系统层面找“OllyDbg.exe”这个进程或“OllyDbg”窗口。常见两条实现：
  1. **进程枚举**：`EnumProcesses` 取全部 PID → 逐个 `OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION)` → `EnumProcessModules` 取模块基址 → `GetModuleBaseNameA(hProcess, hModule, buf, 0x104)` 取进程名 → 大写后与 `OLLYDBG.EXE` 比较；命中则 `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` 杀掉调试器。
  2. **窗口 + 快照**：`FindWindowA("OllyDbg", NULL)` 按窗口类名查找（OD 的类名/标题可被检测），存在则 `ExitProcess`；若窗口被改，再用 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32First/Next` 遍历进程名 `OLLYDBG.EXE` 进行第二轮匹配。
- **为什么改名能绕过**：上述比较都是字符串匹配（进程名来自 PE 文件名/映像名，窗口类名来自注册的窗口类）。把 `OLLYDBG.EXE` 改成 `OLLYDBG`（无扩展名）或任意名字后，`GetModuleBaseNameA`/`Process32Next` 返回的名字不再等于硬编码字符串；改窗口标题/类名则让 `FindWindowA` 找不到。样本没有别的身份校验（如 PID 父子关系、调试端口），所以改名即失效。
- **为什么容易分析**：样本通常会把这些函数隐藏（不在导入表/名称窗口），但都在运行时经 `GetProcAddress` 解析；在 `GetProcAddress` 处下断即可看到请求的函数名与返回地址，再逐个下断观察 PID/句柄/进程名比较过程。
- **局限**：改名绕过只对“按名字检测”的样本有效；若样本改用 `NtQueryInformationProcess` 的 DebugPort/DebugObjectHandle、父进程关系、`CheckRemoteDebuggerPresent` 或 PEB 标志，则需要对应的隐藏/补丁手段（ScyllaHide、HideOD 等）。

## 触发条件

- 样本启动后调试器被强制关闭/自身退出，且行为上出现进程枚举或窗口查找。
- 样本把相关 API 动态解析（导入表/名称窗口看不到 EnumProcesses/FindWindowA 等），需要先捕获隐藏函数。
- 分析者使用 OllyDbg 等名字固定的调试器；若样本按类名/标题检测，窗口信息可被修改。

## 利用步骤

1. 载入样本但不运行，在 `GetProcAddress` 下断（`BP GetProcAddress`），运行并记录解析出的函数名与返回地址（方法见 [[code-analysis-dynamic-debugging-getprocaddress-breakpoint-hidden-api]]）。
2. 对可疑 API 在解析地址处下断：`EnumProcesses`、`OpenProcess`、`EnumProcessModules`、`GetModuleBaseNameA` 或 `CreateToolhelp32Snapshot`、`Process32First/Next`、`FindWindowA`、`TerminateProcess`。
3. 继续运行，观察：`EnumProcesses` 返回的 PID 数组（可对数组下内存访问断点）、`OpenProcess` 的 PID 是否为调试器、`EnumProcessModules` 返回的基址、`GetModuleBaseNameA` 缓冲区内容是否为大写的 `OLLYDBG.EXE`，以及比较后的 `TerminateProcess`/`ExitProcess` 分支。
4. 若是 `FindWindowA` 路线，观察传入的类名/标题字符串（如 `OllyDbg`）与命中后的退出分支。
5. 绕过：用 RE-Pair 等工具把调试器主程序改名为不带原字符串的名字（并选择“启动前打补丁/改名”），必要时修改窗口类名/标题；重新运行样本，确认不再触发终止。
6. 若改名后仍被杀，检查是否还有进程父关系/调试端口/PEB 标志类检测，转向对应绕过（隐藏调试器、ScyllaHide/HideOD、内核调试）。

## PoC

无独立代码；关键观察点与绕过操作：

```text
BP GetProcAddress                       ; 先捕获隐藏 API
; 命中 GetProcAddress 后记录:
;   EnumProcesses -> 0x76BC3A76
;   EnumProcessModules -> 0x76BC1EF4
;   GetModuleBaseNameA -> 0x76BC2132
BP <各返回地址>                          ; 逐个下断观察参数/返回
BP OpenProcess / BP TerminateProcess    ; 观察被杀 PID 与终止分支

; 绕过: 用 RE-Pair 0.6 选择 OllyDbg 主程序 -> 改名(原文示例改为 Msn21，窗口类名随之变为 Msn21) -> 启动时打补丁
;       再运行样本，GetModuleBaseNameA 返回的名字不再匹配 OLLYDBG.EXE
```

调试器中看到的比较结果示例：`GetModuleBaseNameA` 返回 `ollydbg.exe`，与样本内硬编码的 `OLLYDBG.EXE` 比较相等后走到 `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess`。

## 变体与关联

- 关联：捕获隐藏 API 的断点技巧见 [[code-analysis-dynamic-debugging-getprocaddress-breakpoint-hidden-api]]；PEB 标志类反调试的识别与补丁见 [[code-analysis-reverse-anti-debug-peb-fields-patch]]。
- 变体：窗口检测可换成枚举所有窗口标题（`EnumWindows`+`GetWindowText`）匹配调试器标题，绕过同样靠改标题/类名。
- 变体：进程检测可换成 `CreateToolhelp32Snapshot` 或 WMI 查询；绕过仍是改进程名，但要注意映像名与磁盘文件名可能分离（需同时改）。
- 关联：恶意样本检测安全软件进程/窗口（360tray、杀软窗口标题）属于同一类“按名字找工具”的反分析，见 [[code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum]] 与 [[code-analysis-reverse-anti-debug-critical-process-window-title-av-detection]]；本卡针对的是调试器本体及改名绕过。
- 边界：改名只对字符串匹配有效；DebugPort/父子进程/PEB 类检测需要 ScyllaHide 等专门插件或内核调试。

## 检测与防御

- 分析侧信号：样本导入极少但运行时大量调用进程/模块枚举与窗口查找；内嵌 `OLLYDBG.EXE`、`OllyDbg` 等字符串（可静态搜索）；命中后调用 `TerminateProcess` 杀死非自身进程。
- 防御/加固（对软件作者）：不要只按进程名/窗口名判断调试器（易绕过），应组合 `NtQueryInformationProcess(DebugPort/DebugObjectHandle)`、`CheckRemoteDebuggerPresent`、PEB 标志与代码完整性校验；对自身进程做防终止保护（谨慎使用）。
- 对分析者：优先用改名/re-pair 绕过名字检测，再按需隐藏 PEB/调试端口；抓不到行为时改内核调试或对目标 API 下断。
