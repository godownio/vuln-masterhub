---
id: code-analysis-dynamic-debugging-memory-breakpoint-virtualprotectex-page-protection
title: 内存断点：VirtualProtectEx 改页保护（PAGE_NOACCESS/PAGE_EXECUTE_READ）实现页级读写执行监视
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: memory-breakpoint-virtualprotectex-page-protection
tags:
- reverse-engineering
- debugging
- breakpoint
- virtualprotectex
- page-protection
- pte
- windows
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V353
  verified_at: '2026-11-09T00:49:13+08:00'
  notes: 已对照原文与37张截图核对；原理/步骤与原文一致，仅保留调试器通用机制补充；未在本机复现调试过程
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-memory-breakpoint-virtualprotectex-page-protection/
draft: false
kb_aliases:
- 内存断点原理
- VirtualProtectEx 断点
- 页属性断点
- 内存访问断点
- 内存写入断点
- PTE 断点
- OllyDbg 内存断点
---

## 一句话结论

内存断点不修改机器码，而是调试器跨进程调用 `VirtualProtectEx`，把目标地址所在页的保护属性改成 `PAGE_NOACCESS` 或 `PAGE_EXECUTE_READ` 等；程序读取、写入或执行该页时触发访问违规异常（`0xC0000005`），调试器捕获异常后暂停。断点粒度是页（通常 4KB），同一页内任意访问都会命中。

## 原理

- **改的是页表属性，不是指令**：`VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, &lpflOldProtect)` 通过进程句柄修改目标进程某段内存所在页的保护属性，落到 PTE 层面。
  - `PAGE_NOACCESS`：`PTE.P=1`，禁止任何访问，读写执行都触发异常；
  - `PAGE_EXECUTE_READ`：`PTE.P=1`、`PTE.R/W=0`，可读可执行但不可写，用于监视写入。
- **异常路径**：访问受保护页时 CPU 产生页错误，内核转换为 `STATUS_ACCESS_VIOLATION`（`0xC0000005`），调试器在异常分发中判断故障地址是否落在自己设置的监视页，命中则暂停程序并展示现场。
- **页粒度带来误报**：同一 4KB 页内的无关变量/指令访问也会触发，需要结合异常地址、当前指令和访问类型筛选；OllyDbg 同一时刻只允许一个内存断点，重新调试后断点会失效，需重新设置。
- **对代码段下断**：在内存窗口选中 CODE 段设置“内存访问断点”，该段每条指令执行都会中断，可用来确认某段代码是否被执行或定位首次执行点，但中断非常频繁。
- **隐蔽性**：因为不写入 `0xCC`，代码段 CRC/首字节扫描类反调试发现不了它；但页属性异常（`VirtualQuery` 可见）本身就是痕迹。
- **为什么仍叫“断点”**：调试器把页保护当作触发器，用异常替代指令替换，达到“任何访问该区域时停下”的效果，且不需要逐字节改代码。

## 触发条件

- 目标为 Windows 用户态进程，调试器有权限修改其内存页属性（跨进程句柄）。
- 已定位要监视的数据地址或代码段。
- 目标自身不会恢复/检测页保护变化，且分析者可接受页级误报。
- OllyDbg 场景下同一时刻只保留一个内存断点，需要分批分析。

## 利用步骤

1. 打开数据窗口，选中要监视的变量/缓冲区地址，右键“断点 → 内存访问/内存写入”。
2. 或者打开内存窗口，选中 CODE 段等区段，右键“设置内存访问断点/设置内存写入断点”，整段监视。
3. 运行程序；发生访问时断下，检查寄存器、栈、指令与内存，确认是谁在读/写该区域。
4. 分析完成后继续运行，调试器会恢复页属性；重新调试时需重新设置断点。
5. 在数据窗口命中时，可结合调用堆栈回溯到写该变量的函数。

## PoC

无 PoC（调试器操作技巧）；其等价实现是在调试器内部对目标进程调用 `VirtualProtectEx(hProcess, pageBase, 0x1000, PAGE_NOACCESS, &oldProtect)`，再在异常分发中等待 `0xC0000005`。

## 变体与关联

- **PAGE_GUARD 一次性异常**：页保护的一种变体，首次访问触发后自动清除，适合做一次性 hook/监控。
- **VEH 只读页动态补丁**：进程内注册异常处理，把关键页设为只读，写入时篡改数据后恢复。
- **硬件断点**：可精确到 1/2/4/8 字节且最多 4 个，没有页级误报，与内存断点互补。
- **调试器内部机制**：调试器通过 `DebugActiveProcess`、`WaitForDebugEvent`/`ContinueDebugEvent` 接收并分发这类异常。

## 检测与防御

- **检测**：`VirtualQuery`/`VirtualQueryEx` 检查代码段或数据页是否出现 `PAGE_NOACCESS`/`PAGE_GUARD` 等异常保护；检测调试器进程/调试端口；对关键页定期恢复属性。
- **对抗**：程序可在访问前自行改回属性，或把校验放在不会被整页监视的独立页；分析者一侧则改用硬件断点避免整页噪音，或先恢复页属性再操纵数据。
- 内存断点不会在代码中留下 `0xCC`，因此基于字节扫描的反调试对其无效，需要页属性/调试器层面的检测。
