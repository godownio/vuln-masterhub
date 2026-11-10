---
id: defense-detection-edr-fake-dll-guard-page-veh
title: EDR 假 DLL + 保护页 + VEH 检测机制：PEB 加载顺序被替换为手动映射 ntdll/kernel32，页面保护挂钩劫持原生 API
type: scenario
domain: defense
path: defense/detection
technique: edr-fake-dll-guard-page-veh-detection
tags:
- defense
- edr
- fake-dll
- guard-page
- veh
- peb
- page-guard-hook
- windows-internals
- detection-mechanism
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:59:11+08:00'
  notes: 已对照原文与图01-20核对：假 ntdll/kernel32 模块（1.97MB/756KB、无描述、PE Viewer 报找不到对象）、InLoadOrderModuleList 顺序 cmd→假ntdll→假kernel32→真ntdll→真kernel32→kernelbase→hooking DLL(第7)、RX+G 保护页(图02)、CrossProcessFlags=4(图14)、AddVectoredExceptionHandler/RemoveVectoredExceptionHandler 导入(图10)、RtlAddVectoredExceptionHandler 调用栈来自 hooking DLL(图17)、cmp eax,80000001h 多处比较与 NtAllocateVirtualMemory/NtProtectVirtualMemory 关联(图12/18)均一致；原文对 VEH 触发后处置仍为假设，卡内已注明。未复跑。
url: /docs/defense/detection/defense-detection-edr-fake-dll-guard-page-veh/
draft: false
kb_aliases:
- Fake DLL
- 假 DLL 检测
- 保护页挂钩
- Page Guard Hook
- VEH EDR
- PEB InLoadOrderModuleList 篡改
- STATUS_GUARD_PAGE_VIOLATION
- CrossProcessFlags VEH
---

## 一句话结论

某 EDR 采用了一种非传统检测机制：进程初始化时把 `ntdll.dll`/`kernel32.dll` 的手动映射副本以 leetspeak 名称（如 `nt?ll`、`kern??dll`）插入 PEB 的 `InLoadOrderModuleList` 第 2/3 位，真实 DLL 被挤到第 4/5 位；假 DLL 的 RX 内存页带 `PAGE_GUARD`，任何通过 `DllBase`（+0x30）PEB 遍历访问假 `ntdll` 的代码都会触发 `STATUS_GUARD_PAGE_VIOLATION`（`0x80000001`），由 EDR 挂钩 DLL 注册的 VEH 接管；挂钩 DLL 中对约 25 个原生 API 比较异常码 `0x80000001`，形成“页面保护挂钩”。

## 原理

- **Fake DLL 的形态**：Process Hacker 中 `cmd.exe` 的模块列表出现两组 `ntdll.dll`/`kernel32.dll`：一组是真实系统 DLL，另一组是 leetspeak 拼写（如 `nt?ll.dll`、`kern??dll`），大小与原始 DLL 完全相同（约 1.97 MB/756 KB）、没有模块描述；PE Viewer 无法加载它们，报“找不到对象名称”，磁盘上也找不到对应文件。它们是原 DLL 的手动映射副本，只是改了名字。
- **PEB 加载顺序被改写**：用 WinDbg `!peb` 和 `dt nt!_PEB_LDR_DATA`/`dt nt!_LDR_DATA_TABLE_ENTRY` 可以看到 `InLoadOrderModuleList` 顺序为：`cmd.exe` → 假 `ntdll`（DllBase 在低地址私有区）→ 假 `kernel32` → 真 `ntdll` → 真 `kernel32` → `kernelbase.dll` → EDR 的 hooking DLL（第 7 个）。未安装该 EDR 的主机上，第 2/3 位就是真实 `ntdll`/`kernel32`，没有假 DLL。
- **保护页**：假 DLL 所在内存是 `Private: Commit`、保护属性 `RX +G`（读-执行 + guard）。访问带 `PAGE_GUARD` 的页会触发 `STATUS_GUARD_PAGE_VIOLATION`（`0x80000001`）异常，系统会把该页的 guard 标志清除并调用异常处理器；EDR 可以在处理器里恢复 guard 继续监控，这就是 page-guard hook。
- **VEH 接管**：EDR 的 x64 hooking DLL 从 `kernel32.dll` 导入 `AddVectoredExceptionHandler`/`RemoveVectoredExceptionHandler`；在 `notepad.exe`/`cmd.exe` 中，`PEB.CrossProcessFlags`（PEB+0x50）为 4（`ProcessUsingVEH` 位），未装 EDR 的进程为 0。x64dbg 在 `RtlAddVectoredExceptionHandler` 下断，调用栈返回地址落在 EDR hooking DLL 的内存范围，证明 VEH 由 EDR 注册。
- **异常码比较**：在 hooking DLL 中搜索 `cmp eax, 80000001h`（小端字节 `3D 01 00 00 80`）可找到多处比较；反汇编显示比较后分支：不等于 `0x80000001` 走普通路径，等于则进入 EDR 的处理函数。IDA 中还看到与 `NtAllocateVirtualMemory`、`NtWriteVirtualMemory`、`NtProtectVirtualMemory` 等约 25 个原生 API 名称相关的比较逻辑，说明 EDR 只对选定的关键 API 做异常码校验，以控制性能开销。
- **攻击面为什么被触发**：大量 shellcode/加载器通过 PEB 遍历 + `DllBase`（`LDR_DATA_TABLE_ENTRY + 0x30`）取 `ntdll` 基址，再解析导出表/系统服务号；在这种 EDR 上 `DllBase` 指向假 `ntdll`，读取/执行即触发保护页异常，EDR 的 VEH 获得控制权并可能终止进程。这是把“PEB 遍历”本身变成检测点的设计。
- **边界**：直接使用 `GetModuleHandleA("ntdll.dll")`、`LoadLibrary` 等 API 会返回真实 DLL（绕过假 DLL），但这些 API 常被内联挂钩；VEH 触发后的具体行为（直接杀进程还是交给 hook DLL 判定）原文未能确定。

## 触发条件

- 目标安装并启用了采用该机制的 EDR（原文未点名厂商），其用户模式 hooking DLL 在进程初始化时修改 PEB、映射假 DLL 并注册 VEH。
- 进程正常初始化（EDR 在进程启动早期注入/加载 hooking DLL）；受保护进程（PPL 等）或 EDR 未覆盖的进程可能不生效。
- 恶意代码/加载器使用 PEB 遍历 + `DllBase` 偏移 `0x30` 定位 `ntdll`，并读取/执行假 DLL 内存。
- 仅用于授权安全研究与防御分析。

## 利用步骤

1. 用 Process Hacker 查看目标进程 Modules：寻找重复的 `ntdll.dll`/`kernel32.dll`、leetspeak 名称、无描述、大小与系统 DLL 相同、PE Viewer 无法加载的模块。
2. 用 WinDbg 附加进程，`!peb` 查看 `Ldr`；`dt nt!_PEB_LDR_DATA <Ldr>` 取 `InLoadOrderModuleList` 地址；逐个 `dt nt!_LDR_DATA_TABLE_ENTRY <entry>` 查看 `DllBase`、`FullDllName`、`BaseDllName`，确认假 DLL 位于第 2/3 位、真实 DLL 第 4/5 位。
3. 用 Process Hacker Memory 页查看假 DLL 区域：`Private: Commit`、`RX +G`，确认 guard page。
4. 在 x64dbg 中对 `RtlAddVectoredExceptionHandler` 下断，查看调用栈是否来自 EDR hooking DLL；用 `dt nt!_PEB` 查看 `CrossProcessFlags` 是否为 4（VEH 在用）。
5. 在 hooking DLL 内存中搜索字节模式 `3D 01 00 00 80`（`cmp eax,80000001h`），反汇编确认异常码分支与相关原生 API 名称。
6. 用最小 C 程序验证：设置 `PAGE_GUARD` + `AddVectoredExceptionHandler`，访问保护页观察 `STATUS_GUARD_PAGE_VIOLATION` 与 VEH 调用（仅授权环境）。

## PoC

保护页 + VEH 的最小验证代码（原文示例的简化，未执行）：

```c
LONG CALLBACK GuardPageExceptionHandler(PEXCEPTION_POINTERS p) {
    if (p->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        // 记录/分析访问；可恢复 guard page 继续监控
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID mem = VirtualAlloc(NULL, si.dwPageSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD old;
    VirtualProtect(mem, si.dwPageSize, PAGE_GUARD | PAGE_READWRITE, &old);
    PVOID h = AddVectoredExceptionHandler(1, GuardPageExceptionHandler);
    // 访问 mem 会触发 STATUS_GUARD_PAGE_VIOLATION (0x80000001)
    (void)h;
    return 0;
}
```

## 变体与关联

- **规避方法**：[[pentest-c2-real-ntdll-base-originalbase-name-compare-fake-dll-bypass]]（用 `OriginalBase`/名称比对绕开假 DLL，取真实 `ntdll` 基址）。
- **常规 EDR 机制**：内联 API 挂钩、IAT 挂钩、AMSI、ETW、内核回调；本卡是用户态 PEB + 保护页 + VEH 的组合，较少见。
- **相关技术**：[[code-analysis-reverse-anti-debug-veh-custom-exception-debugger-detection-hijack]]（VEH 反调试/反反调试）、[[pentest-c2-page-guard-rwx-allocation-memory-scanner-evasion]]（攻击侧利用保护页隐藏 RWX 内存）、[[pentest-c2-veh-sleep-hook-on-demand-executable-evasion]]（VEH + Sleep Hook 按需可执行）。
- **边界**：EDR 未启用该机制、进程未被 hooking DLL 覆盖、攻击者改用 `GetModuleHandleA`/`LoadLibrary`（但可能被内联挂钩）时检测可能失效；原文对 VEH 触发后的处置逻辑仍是黑盒。

## 检测与防御

- **EDR 侧设计**：把假 DLL 映射为 RX + guard page，并在 VEH 中校验异常码与 API；只对约 25 个关键原生 API 做比较以平衡性能；注意保护假 DLL 不被 `GetModuleHandle` 等 API 暴露真实基址（或对这些 API 做挂钩）。
- **蓝队检测**：进程模块列表出现同名/近似名重复、无文件后备、无描述的 DLL；`PAGE_GUARD` 的 RX 私有内存；`CrossProcessFlags` 显示 VEH 在用；hooking DLL 中的 `cmp eax,80000001` 特征；异常的 `RtlAddVectoredExceptionHandler` 调用来源。
- **攻击面监测**：监控通过 PEB 遍历访问 `ntdll` 的可疑进程（保护页异常高频触发）；结合直接系统调用/SSN 解析行为做关联。
- **说明**：本卡是防御方 EDR 机制分析，severity 记为 medium；仅用于授权安全研究与产品评估。
