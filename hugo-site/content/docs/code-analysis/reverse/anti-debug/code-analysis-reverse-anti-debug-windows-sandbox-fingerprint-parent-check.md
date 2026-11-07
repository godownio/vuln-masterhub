---
id: code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check
title: Windows 免杀沙箱指纹组合检测：注册表/VM 进程/MAC OUI/资源/uptime/用户名/调试器与 explorer 父进程校验
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: windows-sandbox-vm-fingerprint-composite-parent-gate
tags:
- anti-debug
- anti-sandbox
- evasion
- windows
- vm-detection
- sandbox-evasion
- parent-process
- malware
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V177
  verified_at: '2026-11-06T17:22:02+08:00'
  notes: 已对照原文及 12 张图核对；C 代码未编译执行
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check/
draft: false
kb_aliases:
- 沙箱检测
- 虚拟机检测
- 反沙箱组合
- 父进程校验
- explorer.exe 父进程检查
- MAC OUI 检测
- VM 注册表检测
- uptime 检测
---

## 一句话结论

Windows loader 可以在执行恶意逻辑前跑一组低成本环境指纹：VM 注册表关键词、虚拟化进程名、MAC OUI、CPU 核数/内存、系统 uptime、用户名敏感词、调试器 API 以及父进程是否为 `explorer.exe`；任意一项命中就直接退出，使沙箱/虚拟机/调试器看不到后续行为，从而绕过动态分析。

## 原理

- **注册表痕迹**：`HKLM\HARDWARE\DEVICETREE\SYSTEM`、`HKLM\HARDWARE\DESCRIPTION\System`、`HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` 中常出现 `VMware`、`VirtualBox`、`QEMU`、`Xen` 等字符串；递归枚举值/子键名并转小写匹配即可。示例中在 `Disk\Enum` 的值数据里命中 `SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S...`。
- **虚拟化进程**：枚举 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`，匹配 `vboxservice`、`vboxtray`、`vmwaretray`、`vmwareuser`、`vmacthlp`、`vmsrvc`、`vmusrvc`、`prl_cc`、`prl_tools`（去 `.exe` 后小写比较）。
- **MAC OUI**：`GetAdaptersAddresses` 枚举网卡，检查前 3 字节是否属于 VMware（`00:05:69`、`00:0C:29`、`00:1C:14`、`00:50:56`）、VirtualBox（`08:00:27`、`0A:00:27`）、Parallels（`00:1C:42`）、Hyper-V（`00:03:FF`）。示例虚拟机中多个适配器均为 `00:0C:29:...`。
- **资源特征**：`GetSystemInfo().dwNumberOfProcessors < 2` 或 `GlobalMemoryStatusEx().ullTotalPhys < 2GB` 判为疑似低配沙箱；示例虚拟机为 1 核 / 2047MB，本机为 16 核 / 16092MB。
- **uptime 特征**：`GetTickCount64()` 取得系统运行秒数，`<120s` 说明是刚启动的分析环境；真实用户机通常已运行数小时/数天（示例 78551 秒）。
- **用户名/主机名敏感词**：`GetUserNameA`（或 `GetComputerNameA`）后转小写，匹配 `sandbox`、`malware`、`analy`、`virus`、`test` 等分析环境常用词。
- **调试器检测**：`IsDebuggerPresent()` 查 PEB `BeingDebugged`；`CheckRemoteDebuggerPresent(GetCurrentProcess(), &b)` 查远程调试；`NtQueryInformationProcess(..., ProcessDebugPort=7, ...)` 返回非 0 调试端口即被调试。三者组合比单一 API 更难被一次性 hook 绕过。
- **父进程校验**：`CreateToolhelp32Snapshot` 找到自身 PID 的 `th32ParentProcessID`，再按 PID 查父进程名；双击运行的正常样本父进程通常是 `explorer.exe`，而沙箱批量分析常由 `python.exe`/`analyzer.exe`/`cmd.exe`/`powershell.exe` 启动。父进程不是 `explorer.exe` 就直接退出（示例从 PowerShell 启动时父进程为 `powershell.exe`，程序判定后退出）。
- **为什么有效**：这些信号在真实用户主机上大多不成立，而在云沙箱/虚拟机中是默认配置；检查本身只是查询 API/注册表，不产生明显的恶意行为，因此动态分析平台在样本退出前拿不到载荷行为。代价是检查越多误报越高，真实用户也可能因主机名/资源/启动方式命中而无法运行。

## 触发条件

- Windows 目标，loader 能在解密/分配/外联/注入等敏感动作之前执行环境检查。
- 分析环境使用 VMware/VirtualBox/QEMU/Hyper-V 等虚拟机，或资源受限、刚启动、用户名规整的沙箱。
- 样本由脚本/分析器/命令行批量拉起，父进程不是 `explorer.exe`。
- 攻击者接受误报（正常用户被拦截）与漏报（高配沙箱伪装）的取舍。

## 利用步骤

1. 在入口点最先执行检查，任何命中立即 `ExitProcess(0)` 或转入无害行为；不要先分配 RWX、解密 payload 或发起网络请求，避免留下行为特征。
2. 注册表检查：打开上述三个键，枚举值名/值数据/子键名，小写后匹配 `vmware|virtual|vbox|qemu|xen`。
3. 进程检查：进程快照遍历，匹配虚拟化工具进程名（去 `.exe`、转小写）。
4. 网卡检查：`GetAdaptersAddresses` 遍历，匹配虚拟化 OUI 前缀。
5. 资源检查：CPU 核数 <2 或物理内存 <2GB 即判可疑。
6. uptime 检查：`GetTickCount64()/1000 < 120` 判可疑。
7. 用户名/主机名检查：匹配 `sandbox|malware|analy|virus|test`。
8. 调试器检查：`IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess(ProcessDebugPort)` 任一命中即退出。
9. 父进程检查：取自身父 PID 与父进程名，不是 `explorer.exe` 即退出；通过后再解密/注入/外联。
10. 可把检查拆成多个函数并做少量无害延迟/交叉验证，降低“入口即大量环境查询”这一行为特征的显著性。

## PoC

注册表关键词检查（节选）：

```c
static const char *kw[] = {"vmware", "virtual", "vbox", "qemu", "xen"};

int contains_virt(const char *s) {
    char buf[512]; strncpy(buf, s, sizeof(buf)-1); buf[sizeof(buf)-1] = 0;
    for (char *p = buf; *p; p++) *p = (char)tolower((unsigned char)*p);
    for (int i = 0; i < 5; i++) if (strstr(buf, kw[i])) return 1;
    return 0;
}
/* 对 HKLM\HARDWARE\DEVICETREE\SYSTEM、
   HKLM\HARDWARE\DESCRIPTION\System、
   HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
   枚举 RegEnumValueW/RegEnumKeyExW，宽字符转 UTF-8 后匹配 */
```

MAC OUI 与父进程检查（节选）：

```c
static const unsigned char ouis[][3] = {
    {0x00,0x05,0x69},{0x00,0x0C,0x29},{0x00,0x1C,0x14},{0x00,0x50,0x56},
    {0x08,0x00,0x27},{0x0A,0x00,0x27},{0x00,0x1C,0x42},{0x00,0x03,0xFF}
};

DWORD parent_pid(void) {
    DWORD me = GetCurrentProcessId(), ppid = 0;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    if (Process32First(s, &pe)) do {
        if (pe.th32ProcessID == me) { ppid = pe.th32ParentProcessID; break; }
    } while (Process32Next(s, &pe));
    CloseHandle(s);
    return ppid;
}
/* 再用同样的快照按 ppid 取 szExeFile，_stricmp 与 "explorer.exe" 比较；
   不等则 ExitProcess(0) */
```

资源、uptime、调试器检查：

```c
SYSTEM_INFO si; GetSystemInfo(&si);
MEMORYSTATUSEX ms = { .dwLength = sizeof(ms) }; GlobalMemoryStatusEx(&ms);
if (si.dwNumberOfProcessors < 2 || ms.ullTotalPhys < 2ULL*1024*1024*1024)
    ExitProcess(0);                       /* 低配沙箱 */
if (GetTickCount64() / 1000 < 120)
    ExitProcess(0);                       /* 刚启动 */
if (IsDebuggerPresent()) ExitProcess(0);
BOOL remote = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
if (remote) ExitProcess(0);
```

## 变体与关联

- **信号变体**：桌面文件数、最近打开文档、系统语言/区域、磁盘容量/型号、BIOS/主板字符串、`vmGuestLib`/WMI 热区、屏幕分辨率、截屏像素统计等；本库已有 [[code-analysis-reverse-anti-debug-silverfox-installer-vm-detection]]、[[code-analysis-reverse-anti-debug-visual-environmental-keying-screenshot]]。
- **时序变体**：不在入口立即检查，而是延迟/多信号投票/分阶段触发，见 [[code-analysis-reverse-anti-debug-delayed-conditional-trigger]]。
- **调试器变体**：`NtQueryInformationProcess` 的 `ProcessDebugFlags`、`NtQueryInformationThread` 的 `ThreadHideFromDebugger`、硬件断点寄存器、异常处理行为；见 [[code-analysis-reverse-anti-debug-sandbox-environment-checks]]。
- **父进程绕过**：如果仅靠父进程名判断，攻击者可用 `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` 伪造 `explorer.exe` 父进程，见 [[pentest-c2-windows-ppid-spoof-suspended-host-injection]]。
- **平台变体**：Linux 用 `/proc/uptime`、`/proc/stat`、`/proc/meminfo`、`/proc/self/status` 的 `TracerPid`、`LD_PRELOAD` 等，见 [[code-analysis-reverse-anti-debug-linux-sandbox-environment-probes]]。

## 检测与防御

- **沙箱侧反制**：模拟真实主机特征——较长 uptime、≥2 核/≥2GB 内存、常见用户名/主机名、干净但非空的桌面、真实网卡 OUI；从 `explorer.exe` 启动样本或修正父进程链；隐藏调试器或使用内核调试。
- **行为检测**：监控样本启动后短时间内集中调用 `RegOpenKeyEx` 读虚拟化键、`CreateToolhelp32Snapshot` 枚举进程、`GetAdaptersAddresses`、`GlobalMemoryStatusEx`、`GetTickCount64`、`IsDebuggerPresent`/`NtQueryInformationProcess`、读取自身父进程，随后立即退出的组合模式。
- **EDR/沙箱增强**：对“入口即退出”的样本延长观察、多轮执行、在不同环境重复投放；对父进程为脚本/分析器的样本不直接判定恶意，而是结合 API 调用序列。
- **防御**：限制未知样本执行；对注册表/进程/网卡枚举做审计；把环境查询告警与后续无行为关联分析；真实用户机上避免使用 `sandbox/test/malware` 类主机名并保持资源充足可降低误报。
