---
id: code-analysis-reverse-windows-shutdown-window-payload-drop
title: 关机窗口投放载荷：轮询 SM_SHUTTINGDOWN 才落地恶意 DLL，配合内存持有与重启前回写
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: shutdown-window-payload-drop
tags:
- windows
- evasion
- persistence
- sm-shuttingdown
- dll
- guptiminer
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V444
  verified_at: '2026-11-09T23:12:47+08:00'
  notes: 已对照原文核对：Stage 0.9 while(!GetSystemMetrics(SM_SHUTTINGDOWN)) Sleep(0x64) 后才 drop_ati()、Puppeteer 将 updll3.dll3 读入内存并删盘、关机前回写 CreateFileA/WriteFile、WinDefend Start=4，均与原文及图 14/30 一致；『崩溃/断电则不回写』与『作者后来删除该技巧』的表述与原文相符。原文的『删除/释放』指 drop(落盘)，卡片按投放解读正确。无组件版本。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-shutdown-window-payload-drop/
draft: false
kb_aliases:
- SM_SHUTTINGDOWN 投放
- 关机时释放载荷
- 内存持有 DLL 关机回写
- 关机窗口反杀软
- GuptiMiner 关机投放
---

## 一句话结论

恶意软件在正常运行时故意不把最终载荷写盘，只在轮询到系统进入关机流程（`GetSystemMetrics(SM_SHUTTINGDOWN) != 0`）时才释放恶意 DLL/PE；此时其他应用正在关闭、杀软扫描与用户交互窗口都最小。Puppeteer 阶段还把 DLL 常驻内存、从磁盘删除，仅在每次关机前 100 毫秒检查窗口内回写，实现“磁盘上几乎不存在”的持久化。

## 原理

- Windows 关机时 `GetSystemMetrics(SM_SHUTTINGDOWN)` 返回非 0；恶意软件可用 `while (!GetSystemMetrics(SM_SHUTTINGDOWN)) Sleep(...)` 等待该状态，把敏感文件操作推迟到关机阶段。
- 关机阶段大量进程/服务正在停止，AV/EDR 的实时扫描与用户可见性下降，落盘行为更容易漏检；重启后恶意 DLL 已就位，可由白加黑宿主或计划任务加载。
- GuptiMiner Stage 0.9 的 `main` 先释放干净宿主文件、创建计划任务/WMI 订阅、禁用 Defender，然后进入 `SM_SHUTTINGDOWN` 等待循环，只有关机开始且干净文件全部删除成功时才落地最终 `atiadlxx.dll`。
- Puppeteer 变体更极端：把 `updll3.dll3` 读入内存后从磁盘删除，每 100ms 轮询关机状态；检测到关机才把内容写回磁盘，保证下次启动时文件存在。
- 代价是可靠性：若系统崩溃、断电或异常重启，内存中的 DLL 来不及回写，持久化即失效——原文指出作者后来删除了该技巧，用稳定性换隐蔽性。
- 同阶段还会把 Windows Defender 服务 `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend` 的 `Start` 改为 4（Disabled），为落盘与后续行为清障。

## 触发条件

- Windows 目标，恶意进程具备管理员/SYSTEM 权限（可写服务注册表与程序目录）；
- 恶意软件常驻内存运行（注入进程或服务），能持续轮询关机状态；
- 目标正常关机（开始菜单/关机命令）才会触发投放；强制断电/崩溃不会触发；
- 已有可用的持久化宿主（计划任务、WMI 订阅、白加黑目标目录）在下次启动时加载投放的 DLL。

## 利用步骤

1. 运行期只释放干净宿主文件与持久化配置（计划任务/WMI），不落地最终恶意 DLL。
2. 将最终 DLL 内容保存在内存或加密资源中，删除磁盘上的临时副本。
3. 循环 `GetSystemMetrics(SM_SHUTTINGDOWN)`（可每 100ms 一次），未关机则休眠。
4. 检测到关机后，将 DLL 写入目标目录（如 `C:\ProgramData\Microsoft\Crypto\Escan\updll3.dll3`）。
5. 系统重启后由计划任务/宿主加载该 DLL，继续恶意链。
6. 可选：修改 `WinDefend` 的 `Start=4` 关闭 Defender，减少落盘与执行阻力。

## PoC

最小骨架（伪代码，依据原文反编译逻辑归纳）：

```c
// 关机前保持载荷仅在内存
while (1) {
    if (GetSystemMetrics(SM_SHUTTINGDOWN) != 0) {
        // 关机已开始，写回恶意 DLL
        HANDLE f = CreateFileA(TARGET_DLL, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(f, dll_content, dll_size, &written, NULL);
            CloseHandle(f);
        }
        break;
    }
    Sleep(100); // 或 Sleep(0x64)
}
```

原文 Stage 0.9 的对应等待循环为 `while (!GetSystemMetrics(SM_SHUTTINGDOWN)) Sleep(0x64);`，随后才调用 `drop_ati()` 释放最终 DLL；Puppeteer 的 `updll3.dll3` 回写使用同样的关机检测 + `CreateFileA/WriteFile`。

## 变体与关联

- 变体：把“关机投放”改为“登录/解锁/空闲时投放”，触发条件换成对应系统指标。
- 变体：不写盘，直接把 DLL 注入常驻进程或注册为服务 DLL，彻底无文件（但重启后需另一持久化点）。
- 关联：WMI/计划任务条件部署见 [[pentest-persistence-wmi-event-time-window-clean-binary-sideload]]；根证书信任见 [[code-analysis-reverse-windows-self-signed-root-ca-trusted-store]]；注册表载荷存储见 [[pentest-persistence-registry-encrypted-payload-storage]]。
- 关联：Defender 服务禁用属于常见 AV 篡改手法，既有反分析/持久化卡有同类记录。

## 检测与防御

- 监控关机时段（事件 1074/6006 前后）出现的文件创建，尤其是 ProgramData/Program Files 下厂商目录、非签名 DLL 的写入；建立关机窗口文件写入基线。
- 监控 `WinDefend` 服务 `Start` 值从 2/3 改为 4 的注册表变更（事件 4657 或注册表审计）。
- 检查计划任务/WMI 订阅指向的目录中 DLL 的签名与哈希；对“磁盘上文件经常不存在、关机前后才出现”的持久化点做重点排查。
- 分析侧：不要只观察启动后短时间内的行为，应执行正常关机/重启流程并监控关机阶段落盘，或直接模拟 `SM_SHUTTINGDOWN` 环境触发投放逻辑。
