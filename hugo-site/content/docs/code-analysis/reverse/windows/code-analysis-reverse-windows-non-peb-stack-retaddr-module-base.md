---
id: code-analysis-reverse-windows-non-peb-stack-retaddr-module-base
title: 非 PEB 获取 ntdll/kernel32 基址：线程启动栈回溯定位 RtlUserThreadStart/BaseThreadInitThunk 返回地址，按页回扫 MZ/PE 头推导模块基址
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: stack-retaddr-page-walk-module-base
tags:
- reverse
- windows
- shellcode
- peb
- stack-walk
- api-resolution
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-28
  verified_at: '2026-11-08T15:20:08+08:00'
  notes: 已对照原文核对：图24-27/30-35 证实栈回溯取 RtlUserThreadStart/BaseThreadInitThunk 返回地址（16 字节对齐、8 结尾），图45-46 证实 MZ 需 word 比较与 0xC0000005 边界问题，图37-44/53-58 证实 win10/11/Server2012/2016 exe 与 shellcode 双形态实测，win7 失效原因（7767385d 低于阈值+ffff00001f80 假阳性）与卡一致；PoC 为核心代码摘要与原文一致
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-non-peb-stack-retaddr-module-base/
draft: false
kb_aliases:
- 非 PEB 获取模块基址
- 栈回溯找返回地址
- BaseThreadInitThunk 返回地址
- shellcode 无 PEB 解析 API
---

## 一句话结论

x64 用户线程启动链固定经过 `ntdll!RtlUserThreadStart` → `kernel32!BaseThreadInitThunk`（再经 XFG thunk 进用户入口），这两次 call 在栈上留下指向 ntdll/kernel32 代码段的返回地址；shellcode 只需读 TEB+0x8 的 StackBase，从栈底向上按 16 字节步长扫描出两个 >0x7ff000000000 的返回地址，把地址按 0x1000 对齐后向低地址按页回扫 MZ/PE 签名即得模块基址，再解析导出表按 hash 找 API——全程不触碰 PEB，绕开针对 PEB 遍历（Ldr 模块链表）的检测与摘链防御。已在 win10/win11/Server 2012/2016 的 exe 与 shellcode 两种形态实测通过（作者用 minGW 编译；VS2022 编译版在 win10 上 kernel32 基址获取失败），win7 因返回地址数值低于 0x7ff000000000 且栈上存在 ffff00001f80 等假阳性值而失效。

## 原理

- 线程启动链：所有 64 位用户线程（主/子线程）最终由 `RtlUserThreadStart` 调用 `Kernel32ThreadInitThunkFunction`（即 BaseThreadInitThunk），后者经 `__guard_xfg_dispatch_icall` / `BaseThreadInitXfgThunk` 进入用户入口——每次 call 都把返回地址压栈，且都发生在线程初始化最早阶段，因此这些返回地址紧邻栈底（StackBase 高地址一侧）。
- 位置判定：x64 调用约定要求 call 前 RSP 16 字节对齐，压入的返回地址必落在以 8 结尾的栈单元，相邻返回地址相差 16 的倍数，故按 16 字节步长扫描即可；共享库加载在 0x7ff000000000 以上，大于该阈值的栈值即可视为返回地址候选（win7 上该阈值失效：返回地址形如 0x7767385d，且栈上出现 0xffff00001f80 假阳性）。
- 基址推导：函数代码位于 .text 节，模块基址在更低的地址；PE 映像按内存页（0x1000）对齐加载，故先把返回地址与 0xFFFFFFFFFFFF1000 相与，再按 0x1000 步长向低地址扫描，命中「word 签名 0x5A4D + e_lfanew 合理 + PE\0\0 签名」即模块基址。注意 MZ 签名必须按 word（2 字节）比较：用 4 字节读到的是 0x00905A4D，与 0x5A4D 比较永不匹配，还会因回扫越过模块范围触发 0xC0000005（边界值 7ff000000000 检查在 MZ 匹配错误时不生效）。
- API 解析：常规 PE 导出表三数组（AddressOfNames/AddressOfNameOrdinals/AddressOfFunctions）遍历，配合 ROR13+ADD 的函数名 hash 匹配；因模块基址已知，hash 无需再叠加模块名 hash。

## 触发条件

- x64 进程（win10/win11/Server 2012+ 实测有效，win7 失效）；
- 主线程或 CreateThread 子线程内均可执行（两者启动链相同）；
- 目标环境对 PEB 遍历有检测/摘链（本技术的适用动机），常规环境无此需求。

## 利用步骤

1. `GetRetaddressFromStack`：`NtCurrentTeb()`（或 `__readgsqword(0x8)` / `mov rdx,gs:[0x8]`）取 StackBase，指针 = StackBase-8，循环读栈值，收集两个非零且 >0x7ff000000000 的值，先取到的为 ntdll 返回地址（栈深处），后取到的为 kernel32 返回地址（浅处，先 pop 出的 r12=BaseThreadInitThunk 返回地址）。
2. `GetImageBaseByRetaddress`：返回地址 &= 0xFFFFFFFFFFFF1000，循环 `addr -= 0x1000`，检验 e_magic==0x5A4D 且 e_lfanew ∈ [0x40,1024) 且 NT 签名 == 0x00004550，命中返回基址。
3. `GetApiAddressByName/ByHash`：解析导出表三数组，按名字/hash 匹配目标函数，返回 `基址 + AddressOfFunctions[ordinal]`。
4. 实测路径：VS2022 编译在 win11 通过、win10 失败（kernel32 基址获取环节）；minGW/clion 编译在 win10/11/Server 2012/2016 均通过；MASM shellcode（pe2shc 转 bin、runshc64 加载）在 win10/11 通过；仅用 ntdll 基址也可完成多数功能，kernel32 失败时可退化为 ntdll-only。

## PoC

```c
ULONG_PTR ulstackBase = *(ULONG_PTR*)((PBYTE)NtCurrentTeb() + 0x8);
ULONG_PTR* p = (ULONG_PTR*)(ulstackBase - 8);
while (!ulNtdll || !ulKernel32) { /* 收集两个 >0x7ff000000000 的非零栈值 */ }
ulNtdll &= 0xFFFFFFFFFFFF1000;   // 再按 0x1000 步长向低地址扫 MZ/PE
```

## 变体与关联

- 同类非 PEB 手法：SEH/TEB 周边结构推导、内存暴力扫描全 7ff 段（低效）、及原文参考的「扫线程栈找 API 返回地址」驱动开发思路；
- 与经典 PEB 遍历（`gs:[0x60]` → Ldr → InMemoryOrderModuleList）相比：不依赖 PEB 可绕过 PEB 摘链/伪造防御，但适用性更窄（win7 不支持、依赖线程启动链稳定）；
- 反射 DLL 注入中的自定位（call $+5 pop）与本文同属「运行时定位」思想。

## 检测与防御

- EDR 可对「从 StackBase 向上扫描 + 跨页回扫 PE 头」的访问模式做启发式检测（短时间大量跨模块读）；
- 对线程启动链关键 API（BaseThreadInitThunk/XFG thunk）所在页面设置页保护告警异常访问；
- 收敛用户态可写的自定位面：检测无 IAT 依赖且直接解析导出表的模块（内存完整性/HVCI 可提高门槛）。
