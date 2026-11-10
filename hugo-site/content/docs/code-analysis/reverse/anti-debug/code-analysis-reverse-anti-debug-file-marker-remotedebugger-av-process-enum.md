---
id: code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum
title: 加载器反调试与环境探测：code.jpg 标记文件 + CheckRemoteDebuggerPresent + Toolhelp32 枚举 360tray.exe
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: anti-debug-file-marker-remotedebugger-av-process-enum
tags:
- windows
- anti-debug
- anti-sandbox
- checkremotedebuggerpresent
- toolhelp32
- 360tray
- malware-loader
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V280
  verified_at: '2026-11-08T02:28:30+08:00'
  notes: 已对照原文与 img10/12/15 核对：code.jpg 不存在才进入检查、Sleep 0xC8、CheckRemoteDebuggerPresent、命中后 Sleep 0x3A98 再 ExitProcess、Toolhelp32 枚举 360tray.exe 均符；未执行
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum/
draft: false
kb_aliases:
- code.jpg 反调试
- CheckRemoteDebuggerPresent 检测
- Toolhelp32 枚举 360tray.exe
- 安全软件进程探测
- 环境标记文件
- 反沙箱检查
---

## 一句话结论

载荷在进入主逻辑前先检查 `C:\Users\Public\Downloads\code.jpg` 是否存在：只有该文件不存在时才 `Sleep(0xC8)` 并调用 `CheckRemoteDebuggerPresent(GetCurrentProcess(), &pbDebuggerPresent)`，若检测到调试器则 `Sleep(0x3A98)`（约 15 秒）后 `ExitProcess(0)`。随后用 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` + `Process32First/Next` 遍历进程，比较 `360tray.exe`，用于识别 360 安全软件环境。这套组合是低成本的环境/调试探测，不直接产生危害，但决定后续载荷是否继续执行。

## 原理

- **标记文件反向判断**：`GetFileAttributesA("C:\\Users\\Public\\Downloads\\code.jpg") == -1` 表示文件不存在。正常受害机通常没有这个文件，因此会进入反调试检查；若该文件已存在（例如分析机预置、重复运行或沙箱标记），则跳过 `CheckRemoteDebuggerPresent`。这是样本特有的“环境标记”逻辑，可被分析者用来让样本走非反调试路径。
- **远程调试器检测**：`CheckRemoteDebuggerPresent(GetCurrentProcess(), &pbDebuggerPresent)` 查询当前进程是否被调试（包括从其他进程附加的调试器），比仅用 `IsDebuggerPresent` 更广。命中后先 `Sleep(0x3A98)`（15000ms 量级）延迟退出，干扰分析者断点/抓行为。
- **进程枚举**：`CreateToolhelp32Snapshot(2 /*TH32CS_SNAPPROCESS*/, 0)` 创建进程快照，`Process32First`/`Process32Next` 遍历 `PROCESSENTRY32.szExeFile`，与 `360tray.exe` 比较。360tray 是 360 安全卫士的托盘进程，样本据此判断是否存在 360 环境，可影响后续免杀/防火墙策略。
- **为什么这样组合**：三项检查成本低、实现简单，且分别覆盖“分析标记”“调试器”“安全软件”三类环境；即使某一项被绕过，其他项仍可能触发。它们不依赖高权限，适合在载荷早期执行。
- **边界**：`CheckRemoteDebuggerPresent` 只能检测调试器，不能检测沙箱/虚拟机；进程名比较可被改名或伪造；标记文件逻辑是样本特例，不可当作通用反调试规则。

## 触发条件

- Windows 主机，载荷已解密并在内存中执行（通常由下载器/白加黑宿主拉起）。
- `C:\Users\Public\Downloads\code.jpg` 不存在（典型受害机）；若存在则跳过调试器检查。
- 若当前进程被调试器附加，且 `CheckRemoteDebuggerPresent` 返回真，则延迟后退出。
- 进程可创建 Toolhelp 快照并枚举进程（普通用户通常可做）；`360tray.exe` 存在时会命中环境判断。

## 利用步骤

1. 载荷入口先调用 `GetFileAttributesA("C:\\Users\\Public\\Downloads\\code.jpg")`。
2. 若返回 `-1`（不存在），`Sleep(0xC8)` 后调用 `CheckRemoteDebuggerPresent`。
3. 若 `pbDebuggerPresent` 非 0，`Sleep(0x3A98)` 后 `ExitProcess(0)`，不执行后续恶意逻辑。
4. 若未被调试，调用 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`。
5. `Process32First/Next` 遍历进程名，比较 `360tray.exe`，记录/分支处理 360 环境。
6. 继续执行防火墙规则、UAC 修改、文件落盘与白加黑链。

## PoC

```c
#include <windows.h>
#include <tlhelp32.h>

static BOOL has_360tray(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    BOOL found = FALSE;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "360tray.exe") == 0) { found = TRUE; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

void anti_analysis(void) {
    if (GetFileAttributesA("C:\\Users\\Public\\Downloads\\code.jpg") == INVALID_FILE_ATTRIBUTES) {
        Sleep(0xC8);
        BOOL dbg = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
        if (dbg) {
            Sleep(0x3A98);
            ExitProcess(0);
        }
    }
    BOOL av = has_360tray();   // 命中 360 环境时走不同分支
    (void)av;
}
```

## 变体与关联

- [[code-analysis-reverse-anti-debug-sandbox-environment-checks]]：覆盖时间加速、桌面文件数、用户名/主机名敏感词、`NtQueryInformationProcess` 的 `DebugPort`/`DebugFlags` 等低成本检查；本卡是“标记文件 + 远程调试器 + 特定 AV 进程”组合，检测项不同。
- [[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]：VM 注册表、虚拟化进程、MAC OUI、CPU/内存、父进程等指纹；本卡不包含 VM 指纹。
- 变体：`IsDebuggerPresent`、`NtQueryInformationProcess(ProcessDebugPort)`、`OutputDebugString` 异常、`GetTickCount` 时间差、遍历窗口标题/进程名识别分析工具与安全软件（360、火绒、IDA、Process Monitor 等）。

## 检测与防御

- API/行为：进程读取 `C:\Users\Public\Downloads\code.jpg`（少见路径）；调用 `CheckRemoteDebuggerPresent`；短时间内创建 Toolhelp 进程快照并枚举 `360tray.exe`；命中调试器后长时间 `Sleep` 再退出。
- 分析侧：预置 `code.jpg` 可让样本跳过该反调试分支；调试时 Hook/拦截 `CheckRemoteDebuggerPresent` 返回 0，或在其调用前修改返回值；对 `Sleep` 做加速/跳过。
- 防御：EDR 监控 `CheckRemoteDebuggerPresent`、Toolhelp 快照与异常 `Sleep/ExitProcess` 组合；沙箱应模拟真实用户环境并隐藏调试器；安全软件可对自身进程名被枚举做告警。
- 注意：这些检查本身不是漏洞，只是载荷的生存策略；绕过时应在授权分析环境中进行。
