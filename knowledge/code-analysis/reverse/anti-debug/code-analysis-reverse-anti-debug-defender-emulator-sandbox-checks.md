---
id: code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks
title: Defender 模拟器与沙箱综合环境检测：\myapp.exe 进程名、Mpclient 导出 hash、无效句柄返回值与 1GB 堆分配
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: defender-emulator-sandbox-environment-checks
aliases:
- Defender 模拟器检测
- Mpclient 函数 hash 检测
- NtIsProcessInJob 无效句柄检测
- NtCompressKey 无效句柄检测
- 1GB 堆分配反沙箱
- VirtualAllocExNuma 物理内存检测
- SxIn.dll 360 沙箱检测
- 银狐环境检测
tags:
- anti-debug
- anti-sandbox
- anti-emulator
- defender
- mpclient
- ntdll
- windows
- malware-analysis
- silverfox
- defense-evasion
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V288
  verified_at: '2026-11-08T05:16:38+08:00'
  notes: 已对照全文与39图核对：图08 sub_99A5依次bypassETW/bypassAMSI/checkExeName/checkMpHash/vdllCheck/vdllCheck2；图11-12 \myapp.exe与C:\myapp.exe/C:\Windows\iexplore.exe；图13 ror哈希0x70CE7692/0x04CE4554/0x7A99CFAE→0xC0000462；图14 NtIsProcessInJob==293、图15 NtCompressKey>=0；图16 CLASS_E_CLASSNOTAVAILABLE；图17 HeapAlloc 1GB+100000000次循环；图18 VirtualAllocExNuma+SxIn.dll；图19 dwNumberOfProcessors>=2；图20 主机名互斥体0xB7；图21 runas/TokenElevation；图22-23 c:\xxxx.ini；图24 GetTickCount64(300ms)>100；图25 rdtsc差<0xA。已修正两处：0xC0000462的NTSTATUS名实为STATUS_NEEDS_REMEDIATION（ntstatus.h 0xC0350015才是STATUS_HV_INVALID_VP_STATE）；堆循环为100000000（1亿）而非1000万。dedup仅自身及银狐反VM等related；dup-scan相关pair均related。未复跑。
---

## 一句话结论

银狐样本在解密出后续 shellcode 后先执行一整套环境指纹检测：用 `\myapp.exe` 识别 Defender 二进制模拟器进程名；遍历 `ntdll` 导出表并用自定义 `ror` 哈希匹配 3 个 `Mpclient` 模拟函数（命中即返回 `0xC0000462`）；用无效句柄调用 `NtIsProcessInJob`/`NtCompressKey` 并比对模拟器预定返回值；再用 1GB 堆分配、`VirtualAllocExNuma` + `SxIn.dll`（360 沙箱）、CPU 核数、主机名互斥体、`runas` 提权循环、`c:\xxxx.ini`（Gh0st 标记）与 `GetTickCount64`/`rdtsc` 计时差综合判断是否处于分析环境，命中则退出或死循环。

## 原理

- **Defender 二进制模拟器**：微软为首次扫描提供模拟执行环境，会伪造进程名、模块和 API 返回值。样本针对这些“破绽”做反向检测：
  - `checkExeName` 读取模块文件名，模拟器下会得到 `\myapp.exe`（不是真实进程名）；代码还对比 `C:\Windows\iexplore.exe` 与 `C:\myapp.exe` 两种预期。
  - `checkMpHash` 通过 `LdrGetDllHandleEx`/`RtlImageDirectoryEntryToData` 手工遍历 `ntdll` 导出表，对每个导出名计算自定义 `ror` 哈希，与 `0x70CE7692`、`0x04CE4554`、`0x7A99CFAE` 三个 `Mpclient` 模拟函数哈希比较；任一命中返回 `0xC0000462`（`STATUS_NEEDS_REMEDIATION`；原文未命名，此为样本返回码，勿与 `STATUS_HV_INVALID_VP_STATE`=0xC0350015 混淆），上层据此退出。
  - 用无效句柄调用内核函数，判断返回值是否为模拟器预设值：`NtIsProcessInJob(-1, ...) == 293`；`NtCompressKey(0xFFFFF1234) >= 0`。真实系统对无效句柄返回错误码，模拟器往往返回“成功/固定值”，从而暴露。
- **资源与硬件指纹**：
  - `HeapAlloc(GetProcessHeap(), 8, 1000000000)` 申请 1GB 并跑 1 亿次（100000000）循环，资源受限沙箱会失败或超时；
  - `VirtualAllocExNuma` 要求多物理 CPU，失败则判定环境异常；随后 `GetModuleHandleA("SxIn.dll")` 探测 360 沙箱注入的分析 DLL；
  - `GetSystemInfo` 判断 `dwNumberOfProcessors >= 2`，单核沙箱直接退出；
  - `GetComputerNameW` + `CreateMutexW(hostname)`，`GetLastError()==0xB7`（`ERROR_ALREADY_EXISTS`）说明同名互斥体已存在（重复运行/分析环境）。
- **人为环境与既有感染标记**：
  - `ShellExecuteExA` 以 `runas` 动词启动自身并要求 `TokenElevation`，若当前不是管理员则无限弹 UAC，诱导用户提权；
  - 检查 `c:\xxxx.ini` 是否存在：该文件是 Gh0st 后门落地标记，已存在说明机器可能已被同家族感染，样本可选择跳过或走不同分支；
  - `GetTickCount64` 在 `Sleep(300ms)` 前后的差值 > 100、`rdtsc` 两次差值 < 0xA 等判断时间是否被加速/虚拟化。
- **为什么组合这么多检查**：单一检查容易误判或被分析者 patch；组合覆盖模拟器、沙箱、虚拟机、调试与已有感染五种状态，任一命中即可让样本不进入恶意分支，提高自动化分析成本。

## 触发条件

- 样本已解密并进入环境检测阶段（通常在 ETW/AMSI 补丁之后）；
- 运行环境为 Defender 模拟器、沙箱、虚拟机或单核/资源受限环境；
- 分析者未 patch 对应 API 返回值或未预置 `c:\xxxx.ini` 等标记。

## 利用步骤

1. 解密后续 shellcode 后，先调用 `checkExeName`，比对模块名是否为 `\myapp.exe`/`C:\Windows\iexplore.exe`。
2. 调用 `checkMpHash`：枚举 `ntdll` 导出，计算 `ror` 哈希，命中 3 个 `Mpclient` 哈希则返回 `0xC0000462`。
3. 用无效句柄调用 `NtIsProcessInJob`、`NtCompressKey`，按预设返回值判断模拟器。
4. 执行 `HeapAlloc(1GB)` + 1 亿次（100000000）循环、`VirtualAllocExNuma`、`GetModuleHandle("SxIn.dll")`、`GetSystemInfo`、主机名互斥体等资源/硬件检查。
5. 检查 `c:\xxxx.ini`；尝试 `runas` 提权并进入 UAC 循环；用 `GetTickCount64`/`rdtsc` 检测时间加速。
6. 全部通过后才下载后续载荷并执行；任一命中则 `ExitProcess`、返回错误码或死循环。

## PoC

原文逆向得到的伪代码（仅用于检测/研究，未执行）：

```c
// 1) 进程名检测
if (!_stricmp(moduleName, "\\myapp.exe")) ExitProcess(0);

// 2) ntdll 导出 hash 检测
for (i = 0; i < exportCount; i++) {
    h = rorApiHash(exportName[i]);
    if (h == 0x70CE7692 || h == 0x04CE4554 || h == 0x7A99CFAE)
        return 0xC0000462;   // STATUS_NEEDS_REMEDIATION
}

// 3) 无效句柄返回值检测
if (NtIsProcessInJob((HANDLE)-1, NULL) == 293) ExitProcess(0);
if (NtCompressKey((HANDLE)0xFFFFF1234) >= 0) ExitProcess(0);

// 4) 资源/硬件检测
if (!HeapAlloc(GetProcessHeap(), 8, 1000000000)) ExitProcess(0);
if (VirtualAllocExNuma(GetCurrentProcess(), 0, 0x1000, 0x3000, 0x40, 0)) ExitProcess(0);
if (GetModuleHandleA("SxIn.dll")) ExitProcess(0);
if (GetSystemInfo()->dwNumberOfProcessors < 2) ExitProcess(0);

// 5) 时间加速检测
first = GetTickCount64();
Sleep(300);
if ((GetTickCount64() - first) > 100) ExitProcess(0);
```

## 变体与关联

- **变体**：检查项可按版本裁剪/组合；哈希算法和常量可替换成其他模拟器 API；`\myapp.exe` 是 Defender 模拟器的固定破绽，其他沙箱可能有不同进程名。
- **变体**：把 1GB `HeapAlloc` 换成大页/连续内存申请、超大文件写入或长循环，用于触发沙箱超时。
- **关联**：[[code-analysis-reverse-anti-debug-silverfox-installer-vm-detection]]（银狐安装器 vmGuestLib/WMI 热区/磁盘容量三件套）、[[code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum]]（code.jpg 标记 + CheckRemoteDebuggerPresent + 360tray 枚举）、[[pentest-c2-silverfox-two-stage-shellcode-loader]]（本检测所在的加载器）、[[pentest-c2-silverfox-av-kill-window-message-byovd-truesight]]（通过检测后的杀软对抗）。

## 检测与防御

- **模拟器/沙箱侧**：Defender 模拟器应随机化伪进程名与 API 返回值，避免固定 `\myapp.exe` 与固定 `Mpclient` 导出集合；沙箱应提供多核、足量内存与真实 `NtIsProcessInJob`/`NtCompressKey` 错误码。
- **静态特征**：搜索 `myapp.exe`、`SxIn.dll`、`c:\xxxx.ini`、`NtIsProcessInJob`/`NtCompressKey` 动态解析、`0xC0000462` 返回码、`ror` 哈希循环常量；对 1GB `HeapAlloc` 常量与 1 亿次循环做 YARA 匹配。
- **行为监控**：进程在短时间内大量分配内存、调用 `VirtualAllocExNuma`、枚举自身模块名、创建以主机名为名的互斥体、反复弹 UAC，可作为可疑行为链告警。
- **分析对抗**：在 IDA/x64dbg 中 patch `checkExeName`/`checkMpHash`/无效句柄检查的返回值，或在沙箱预置 `c:\xxxx.ini`、提供 ≥2 核与足够内存，绕过检测进入恶意分支。
- **防御**：启用 Defender 篡改保护与云保护；对高权限进程创建、UAC 提权与互斥体创建做基线；EDR 监控 `VirtualAllocExNuma` 与异常大额堆分配。
