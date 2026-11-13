---
id: code-analysis-reverse-windows-arm64-dkom-activeprocesslinks-hide-process
title: Windows on ARM64 DKOM 隐藏进程：EPROCESS ActiveProcessLinks 偏移 0x400 双向摘链，ImageFileName 0x560 比对
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: arm64-dkom-activeprocesslinks-hide-process
tags:
- reverse
- windows
- arm64
- rootkit
- dkom
- eprocess
- kernel
- hide-process
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T13:57:13+08:00'
  notes: 已对照原文核对：EPROCESS ARM64偏移 ActiveProcessLinks=0x400、Flink/Blink=0x400/0x408、ImageFileName=0x560、UniqueProcessId=0x3f8 与原文WinDbg输出一致；HideProcess遍历与RemoveEntryList摘链逻辑与原文代码一致；与取证卡(pslist/psscan)为攻防两侧不同方向；原文未标注Windows构建号（研究环境Win11 on ARM64、调试模式）；无受影响版本区间；PoC未编译运行
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-arm64-dkom-activeprocesslinks-hide-process/
draft: false
kb_aliases:
- ARM64 DKOM
- 隐藏进程
- ActiveProcessLinks 摘链
- RemoveEntryList
- EPROCESS 偏移
- Windows on ARM Rootkit
- HideProcess
---

## 一句话结论

DKOM 隐藏进程不修改任何代码，而是把目标进程的 `EPROCESS.ActiveProcessLinks` 从系统进程双向链表中摘除：在 Windows on ARM64 上该字段位于 `EPROCESS+0x400`（`Flink`/`Blink` 在 +0x400/+0x408），进程映像名在 `+0x560`；驱动从当前进程的链表项开始遍历，按 `ImageFileName` 找到目标后用 `RemoveEntryList` 做 `Blink->Flink=Flink` / `Flink->Blink=Blink` 摘链。进程仍存活并可运行，但任务管理器/`pslist` 等走 `ActiveProcessLinks` 的枚举看不到它；用 `psscan`/`PspCidTable` 等直接扫描 `EPROCESS`/句柄表的方式仍能发现。

## 原理

- **EPROCESS 与进程链表**：Windows 把所有活动进程通过内嵌的 `LIST_ENTRY ActiveProcessLinks` 挂在以 `PsActiveProcessHead` 为头的双向循环链表上。遍历方式：取当前进程 `PsGetCurrentProcess()` 的 `ActiveProcessLinks` 地址（`EPROCESS + offset`），沿 `Flink` 前进直到绕回起点；每次用 `(entry - offset)` 还原 `EPROCESS`，再用 `ImageFileName` 比对进程名。这正是 `PsGetNextProcess`/任务管理器枚举的实现基础。
- **ARM64 偏移与 x86 不同**：原文在 Windows 11 on ARM64 上 `dt nt!_EPROCESS` 得到：`ProcessLock 0x3f0`、`UniqueProcessId 0x3f8`、`ActiveProcessLinks 0x400`、`RundownProtect 0x410`、`ImageFileName 0x560`。`LIST_ENTRY` 为 `Flink +0x0`、`Blink +0x8`，所以 `ActiveOffsetPre=0x400`（Flink）、`ActiveOffsetNext=0x408`（Blink）、`ImageName=0x560`。这些偏移随 Windows 版本/架构变化，必须按目标构建核对，不能照搬 x86 的 0xb8。
- **摘链（DKOM）**：`RemoveEntryList(entry)` 执行：
  ```text
  entry->Blink->Flink = entry->Flink;
  entry->Flink->Blink = entry->Blink;
  ```
  即让前后节点互相指向，跳过目标项。目标进程对象本身不被释放、句柄表/线程/内存都还在，因此进程继续运行，只是从“活动进程链表”这个视图消失。
- **代码要点**：原文 `HideProcess` 从 `PsGetCurrentProcess()` 的 `ActiveProcessLinks` 出发，循环 `Flink` 遍历（到 `PrevListEntry==CurrListEntry` 停止），每步用 `(ULONG_PTR)CurrListEntry - ActiveOffsetPre` 还原 `EPROCESS`，`ImageFileName` 与目标名比较，命中且 `MmIsAddressValid` 后 `RemoveEntryList` 并退出。
- **为什么有效/局限**：任务管理器、`pslist`、`ZwQuerySystemInformation(SystemProcessInformation)` 等依赖 `ActiveProcessLinks` 的枚举会漏掉该进程；但 `psscan` 类内存扫描（直接搜 `EPROCESS` 池标签/结构）、`PspCidTable`+`ExEnumHandleTable`、内核回调/EDR 仍可发现“链表外”的进程。DKOM 还可能留下链表完整性/计数异常，是交叉视图检测的经典目标。
- **平台限制**：需要 Ring0 驱动；PatchGuard 会定期检查部分内核结构（原文提示约 15–30 分钟内可能蓝屏），研究环境需关闭 PatchGuard/DSE/Secure Boot；HVCI 等也可能影响。

## 触发条件

- Windows on ARM64（或任意 Windows，偏移按版本重算）且已能执行 Ring0 驱动；调试/研究环境关闭 PatchGuard、驱动签名强制与 Secure Boot，或具备绕过。
- 目标 `EPROCESS` 布局已知（`ActiveProcessLinks`、`ImageFileName` 偏移），进程名可获取。
- 目标进程处于活动进程链表中且对象地址有效；驱动可读写内核内存。

## 利用步骤

1. 在目标构建上用 `dt nt!_EPROCESS` 确认 `ActiveProcessLinks`、`ImageFileName`、`UniqueProcessId` 偏移（原文 ARM64：0x400/0x560）。
2. 驱动中从 `PsGetCurrentProcess()` 加 `ActiveOffsetPre` 取当前进程链表项，沿 `Flink` 遍历（`NextListEntry = CurrListEntry->Flink`）。
3. 每步用 `(CurrListEntry - ActiveOffsetPre)` 还原 `EPROCESS`，读 `+ImageName` 与目标进程名比较；注意 `ImageFileName` 是 15 字节短名（无路径、可能截断）。
4. 命中后用 `MmIsAddressValid` 校验链表项，`RemoveEntryList(CurrListEntry)` 摘链并 `break`。
5. 用任务管理器/`pslist` 验证目标消失但进程仍能响应（如网络/文件句柄仍工作）；用 `psscan`/直接 `EPROCESS` 扫描验证仍能找到（交叉视图）。
6. 恢复：把目标进程的 `ActiveProcessLinks` 重新插回链表（`InsertHeadList`/`InsertTailList` 或恢复 Flink/Blink），否则退出/清理时可能异常。

## PoC

原文 `HideProcess` 核心代码（未在本机编译运行）：

```c
ULONG_PTR ActiveOffsetPre = 0x400;   // ARM64: EPROCESS.ActiveProcessLinks.Flink
ULONG_PTR ActiveOffsetNext = 0x408;  // Blink
ULONG_PTR ImageName = 0x560;         // ARM64: EPROCESS.ImageFileName

VOID HideProcess(char* ProcessName)
{
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    PLIST_ENTRY CurrListEntry = (PLIST_ENTRY)((PUCHAR)CurrentProcess + ActiveOffsetPre);
    PLIST_ENTRY PrevListEntry = CurrListEntry->Blink;
    PLIST_ENTRY NextListEntry = NULL;

    while (CurrListEntry != PrevListEntry) {
        NextListEntry = CurrListEntry->Flink;
        char* currImageFileName = (char*)(((ULONG_PTR)CurrListEntry - ActiveOffsetPre) + ImageName);
        DbgPrint("Iterating %s\r\n", currImageFileName);
        if (strcmp(currImageFileName, ProcessName) == 0) {
            if (MmIsAddressValid(CurrListEntry))
                RemoveEntryList(CurrListEntry);   // Blink->Flink=Flink; Flink->Blink=Blink
            break;
        }
        CurrListEntry = NextListEntry;
    }
}
```

偏移核对（原文 WinDbg ARM64）：

```text
0: kd> dt nt!_EPROCESS
+0x3f0 ProcessLock
+0x3f8 UniqueProcessId
+0x400 ActiveProcessLinks : _LIST_ENTRY
+0x410 RundownProtect
+0x560 ImageFileName : [15] UChar
```

## 变体与关联

- **进程枚举与交叉视图**：[[code-analysis-reverse-windows-kernel-process-enumerate-four-ways]] 给出 `PsGetNextProcess`、手走 `ActiveProcessLinks`、`PspCidTable` 等四种枚举方式，并指出“③ 与 ④ 结果不一致说明有进程被 DKOM 摘链”；本卡是摘链侧的实现与 ARM64 偏移。
- **取证检测**：[[defense-forensics-pslist-psscan-hidden-terminated-process-diff]]（pslist/psscan 双视角发现隐藏进程）、[[binary-pwn-kernel-windows-shellcode-token-steal-eprocess]]（遍历 `ActiveProcessLinks` 窃取 System Token，同一结构的不同用途）。
- **同文其它 rootkit 技术**：[[code-analysis-reverse-windows-arm64-ssdt-compactoffset-trampoline-hook]]、[[code-analysis-reverse-windows-arm64-kisystemservice-global-syscall-hook]]（SSDT/全局 syscall hook）、[[code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service]]（隐藏注册表服务项）。
- **变体**：也可摘除线程链表（隐藏线程）、修改 `UniqueProcessId`/父进程、或同时伪造 `ImageFileName`；DKOM 的目标不限于进程。恢复链表时需注意 IRQL 与并发（链表操作应在受保护/合适 IRQL 下进行）。

## 检测与防御

- **交叉视图检测**：对比 `pslist`（走 `ActiveProcessLinks`）与 `psscan`/`EPROCESS` 内存扫描、`PspCidTable`+`ExEnumHandleTable` 枚举结果；出现“psscan 有、pslist 无”的进程即疑似摘链隐藏（还要排除已退出进程）。
- **链表完整性**：校验 `ActiveProcessLinks` 双向一致性（`entry->Flink->Blink == entry`）、链表长度与 `PsActiveProcessHead` 计数/句柄表总数是否匹配；异常 IRQL/驱动对 `EPROCESS+0x400` 附近的写操作。
- **缓解**：PatchGuard/KPP、HVCI、DSE、Secure Boot、易受攻击驱动阻止列表；限制未签名驱动；EDR 内核回调/ETW 监控进程创建与退出，不依赖单一链表视图。
- **响应**：内存取证用交叉视图定位隐藏进程，提取其 `EPROCESS`/句柄/线程；调试环境可手动重新插链或重启清理。
