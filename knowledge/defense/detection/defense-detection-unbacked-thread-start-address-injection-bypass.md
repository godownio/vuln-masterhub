---
id: defense-detection-unbacked-thread-start-address-injection-bypass
title: 线程 Win32StartAddress 落在非 MEM_IMAGE 可执行页即判注入：Get-InjectedThread 判据及其五类绕过
type: scenario
domain: defense
path: defense/detection
technique: thread-start-address-memory-type-injection-detection
aliases:
- Get-InjectedThread
- Get-InjectedThreadEx
- unbacked 线程检测
- 线程起始地址检测
- MEM_IMAGE 判据
- 注入线程检测
tags:
- windows
- detection
- edr
- process-injection
- thread-injection
- virtualqueryex
- unbacked
- memory-forensics
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:34:52+08:00'
  notes: 已对照原文核对：NtQueryInformationThread 参数 9=ThreadQuerySetWin32StartAddress、VirtualQueryEx 取 MEMORY_BASIC_INFORMATION、判据 State==MEM_COMMIT 且 Type!=MEM_IMAGE、K32QueryWorkingSetEx 的 Shared/private_image、GetCfgBitsForAddress+InSystemImageRange 的 cfg_invalid、NT_TIB64 栈基址与 UnwindCode 展开码计算均与正文代码块一致；五类绕过（LoadLibrary DLL、SetThreadContext、jmp rcx、_beginthreadex、inline hook）与正文列举一致。本次核对未读取图片，仅依据正文；正文中 ReactOS 实现、Win7/Win11 _beginthreadex 差异、CFG 位图 x86/x64 差异、栈回溯示意仅在图中，卡内相应描述按正文文字表述写，未核对图内细节，故 confidence 保持 medium
---

## 一句话结论

loader+shellcode、远程线程注入这类手法最终都会让线程的 `Win32StartAddress` 落在一块「已提交（MEM_COMMIT）但不是镜像映射（Type != MEM_IMAGE）」的可执行内存上；用 `NtQueryInformationThread(..., ThreadQuerySetWin32StartAddress=9)` 取起始地址、再用 `VirtualQueryEx` 读 `MEMORY_BASIC_INFORMATION` 判定内存类型，就能把私有页上起跑的线程全部筛出来——于是绕过检测的核心就变成「让起始地址回到某个 MEM_IMAGE 范围内」。

## 原理

- **Windows 内存区只有三类**：`MEM_IMAGE`（PE 镜像映射）、`MEM_MAPPED`（文件/共享映射）、`MEM_PRIVATE`（`VirtualAlloc` 等私有分配）。正常可执行代码都来自某个映射到磁盘的镜像，所以正常线程的起始地址必然指向 `MEM_IMAGE`。
- **为什么注入必然暴露**：`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` 的 shellcode 在私有页上执行，`NtQueryInformationThread` 返回的起始地址就落在这块 `MEM_PRIVATE` 区域；同理反射加载（sRDI）、APC 注入起的线程也都如此。判据只需两个字段：`State == MEM_COMMIT` 且 `Type != MEM_IMAGE`。
- **为什么只看起始地址就够用**：起始地址是线程创建时内核写入 `ETHREAD.Win32StartAddress` 的字段，用户态无法直接伪造（只能通过改变「实际跳转去的代码在哪个页」间接改变判定结果）；这也是该检测比扫描整个进程 RWX 页更廉价、误报更低的原因。
- **绕过的统一思路**：不要「新起一个跑在私有页上的线程」，而要「让线程起始地址指向某个合法镜像内的指令，再从那里跳到 shellcode」。所有绕过手法都在这个约束下做文章：把 shellcode 作为 DLL 落地（起始地址就是 `LoadLibrary` 内的镜像代码）、把挂起线程的入口点写成镜像地址后再改 `RIP`、把镜像里一条 `jmp rcx`（\xff\xe1）当入口、或借 `_beginthreadex` 的 `threadstartex` 中转。
- **检测侧的补强**：正因为起始地址可以被「中转」，后续工具增加了三个与起始地址无关的判据（见下节），把「起点在镜像内但实际执行在私有页」的情况重新拉回视野。

## 触发条件

- 防守方能在用户态枚举目标进程线程（`OpenProcess(PROCESS_QUERY_INFORMATION|VM_READ)`），并有权限调用 `NtQueryInformationThread` 与 `VirtualQueryEx`。
- 目标 Windows 为 x64/x86 常规用户态进程；受保护进程（PPL）、跨会话进程可能取不到句柄。
- 攻击者使用「私有可执行页起跑」的加载方式（VirtualAlloc+memcpy、反射加载、APC/远程线程）；若改用模块踩踏、TxF/Phantom Hollowing、DLL 侧加载等让代码进入镜像页的手法，单靠本判据会漏。

## 利用步骤

1. 枚举进程内全部线程（`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` 或 `NtGetNextThread`），对每个线程 `OpenThread(THREAD_QUERY_INFORMATION)`。
2. 用 `NtQueryInformationThread(hThread, 9 /*ThreadQuerySetWin32StartAddress*/, &buf, sizeof(PVOID), NULL)` 取起始地址。ReactOS 及 WRK 中该分支读的就是 `ETHREAD.Win32StartAddress`。
3. 用 `VirtualQueryEx(hProcess, BaseAddress, &mbi, sizeof(mbi))` 取该地址所属区域，读出 `State`/`Type`/`Protect`/`AllocationProtect`/`RegionSize`。
4. 判定：`State == MEM_COMMIT && Type != MEM_IMAGE` → 标记「可疑注入线程」。为降低误报，再叠加「`Protect` 含执行权限」「区域无文件背书」。
5. 对命中的线程做进程归属、模块归属与网络/子进程行为关联，避免把 JIT（.NET/Java/浏览器）划出的私有可执行页误判。

## PoC

```powershell
# 取得线程起始地址（NtQueryInformationThread 的 ThreadQuerySetWin32StartAddress = 9）
$buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
$ok  = $Ntdll::NtQueryInformationThread($hThread, 9, $buf, [IntPtr]::Size, [IntPtr]::Zero)
$startAddress = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf)

# 查该地址的内存区属性，判据：已提交 且 不是镜像映射
$mbi = VirtualQueryEx -ProcessHandle $hProcess -BaseAddress $startAddress
if ($mbi.State -eq 'MEM_COMMIT' -and $mbi.Type -ne 'MEM_IMAGE') {
    "suspicious injected thread: start=$startAddress type=$($mbi.Type) prot=$($mbi.Protect)"
}
```

```c
// 关键字段：MEMORY_BASIC_INFORMATION.Type 的取值来自内核页表/控制区类型，
// 攻击者无法通过用户态 API 把私有页「改标」成 MEM_IMAGE，只能改代码落点。
```

## 变体与关联

- **基于 DLL 的绕过（起始地址天然合法）**：`OpenProcess → VirtualAllocEx → WriteProcessMemory(写 DLL 路径) → GetProcAddress(LoadLibraryA) → CreateRemoteThread`；线程从 `LoadLibrary` 的镜像代码起跑，加载后再由 `DllMain` 执行 payload，起始地址是 `MEM_IMAGE`，本判据失效。
- **SetThreadContext 绕过**：`CreateRemoteThread` 创建一个 `CREATE_SUSPENDED` 线程、入口点写成镜像内地址（如 `LoadLibrary`），再 `SetThreadContext` 把 `RIP/Rcx` 改成 shellcode 地址后 `ResumeThread`。起始地址字段仍是镜像地址，但实际执行流在私有页——需要栈回溯类检测（见关联卡）。
- **jmp rcx 绕过**：在已映射镜像里搜 `\xff\xe1`（`jmp rcx`）作为线程入口，把 shellcode 地址通过 `lpParameter`（rcx）传入；起始地址指向镜像中的这条跳板指令。
- **`_beginthreadex` 绕过**：在内部起本地线程（经 msvcrt 的 `threadstartex` 中转）执行传入的函数指针；Win11 上线程起点是 `threadstartex`（镜像内），shellcode 地址作为参数传递，从而绕过；Win7 上 `_beginthreadex` 直接把函数地址交给 `CreateThread`，起不到绕过作用——版本差异必须验证。
- **inline hook 绕过**：改一个正常函数的入口（patch 成跳 shellcode），线程仍从镜像函数起跑。
- **检测侧补强（Get-InjectedThreadEx 思路）**：① `private_image`——用 `K32QueryWorkingSetEx` 查该页的 `VirtualAttributes.Shared`，inline hook 触发写时复制后页变私有（`Shared == false`），并对 `ntdll` 页做豁免以减少 EDR 自身 hook 的误报；② `cfg_invalid`——起始地址在系统镜像范围内、16 字节对齐、且 CFG 位图对应两位为 `00`（该范围无有效跳转目标）时判为 `jmp rcx` 跳板；③ `stack_pivot`/返回地址遍历——见关联卡。
- 关联：`[[defense-detection-pte-walk-kdmapper-unbacked-executable-pages]]`（内核态「可执行但不在模块内」的对应思路）、`[[defense-detection-etw-stack-unbacked-wininet-winhttp-beacon-process-url]]`（用 ETW 栈上的 unbacked 帧定位 beacon，不依赖线程起始地址）、`[[defense-detection-nmi-stack-scan-unbacked-kernel-rootkit]]`。
- 边界：JIT/JVM/.NET 动态代码、加壳程序、部分合法插件也会在私有可执行页上起线程；只按 `Type != MEM_IMAGE` 一条告警误报偏高。攻击者若把代码放进镜像页（模块踩踏、DLL 侧载、Phantom Hollowing），或干脆 patch 掉检测脚本依赖的 API（`NtQueryInformationThread`/`VirtualQueryEx`），本判据失效。

## 检测与防御

- 检测：对全进程线程做「起始地址 → VirtualQueryEx」扫描并落库（周期性或触发式）；把「非 MEM_IMAGE 起始地址 + 可执行权限 + 无模块归属」作为高分特征；同时记录 `Protect` 从 RW 变 RX 的历史（`VirtualProtect`/`NtProtectVirtualMemory` 调用）。
- 防御：开启 CFG/CIG 与 Arbitrary Code Guard 阻碍私有页执行；启用内核回调/PPL 级 EDR 防止检测逻辑被 patch；对 `OpenProcess` 句柄获取、跨进程 `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` 建立行为链告警（即便起始地址合法也能在「写入 + 执行」环节发现）；对 DLL 加载做签名与路径校验，阻断侧载与未签名 DLL 注入。
