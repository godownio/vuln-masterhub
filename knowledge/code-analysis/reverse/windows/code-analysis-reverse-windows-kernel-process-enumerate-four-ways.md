---
id: code-analysis-reverse-windows-kernel-process-enumerate-four-ways
title: 内核态按名字找进程的四种方式：暴力 PID 枚举、未导出 PsGetNextProcess 特征码定位、手走 ActiveProcessLinks、PspCidTable + ExEnumHandleTable
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-kernel-process-enumeration-by-name-four-methods
aliases:
- 内核遍历进程
- PsLookupProcessByProcessId 暴力枚举
- PsGetNextProcess 特征码定位
- ActiveProcessLinks 手动遍历
- PspCidTable 句柄表枚举
- ExEnumHandleTable TypeIndex
- PsGetProcessImageFileName
- EPROCESS 按名查找
tags:
- windows
- kernel-driver
- eprocess
- process-enumeration
- activeprocesslinks
- pspcidtable
- handle-table
- signature-scan
- rootkit
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:26:35+08:00'
  notes: 已对照原文核对；本次核对未读取图片；四条实现逐条比对一致：PsLookupProcessByProcessId 从 8 步进 4 到 100000 + PsGetProcessImageFileName；IoCreateStreamFileObjectLite 起 0x1000 内扫 00 00 66 FF 8E 86、命中减 22 得 PsGetNextProcess；ActiveProcessLinks 偏移 0x0b8 手走 Flink；PsLookupThreadByThreadId+0x1e+2 取址、*PsProcessType 相关两步解引用后 ExEnumHandleTable、回调里 (Value & 0xfffffff8)-0x18 得 OBJECT_HEADER、TypeIndex==7、比 ImageFileName 均与正文一致。已指出原文 GetProcessByName2 先推进再比对导致返回值错位，复核成立。未验证点：未加载运行驱动；卡内 PoC 里 PspCidTable 的解引用写成 t = *(PULONG)(...) 再 *(PULONG)*(PULONG)t，比原文多一层间接，仅释意偏差且卡内已提示按版本核对间接层级；原文无版本区间，未设 affected_versions。
---

## 一句话结论

内核驱动里「按进程名拿 `PEPROCESS`」有四条递进的路子：① 用导出函数 `PsLookupProcessByProcessId` 从 8 开始按 4 递增暴力枚举 PID，再用 `PsGetProcessImageFileName` 比名字（最笨但只用导出符号）；② `PsGetNextProcess` 未导出，可在导出函数 `IoCreateStreamFileObjectLite` 附近扫特征码 `00 00 66 FF 8E 86`、命中处减 22 字节即得函数入口，随后按「取下一个进程」的语义链式走；③ 手动从 `PsGetCurrentProcess()` 加 `ActiveProcessLinks` 偏移（示例 0xb8）取 `Flink` 双向链遍历，正是 `PsGetNextProcess` 的实现；④ 从 `PsLookupThreadByThreadId + 0x1e + 2` 处解引用取出 `PspCidTable`，再用 `ExEnumHandleTable` 回调逐个判断 `OBJECT_HEADER.TypeIndex == 7`（进程对象）并比对 `ImageFileName`。四条路对应四种约束：能不能用未导出符号、要不要依赖版本偏移、是否需要遍历全系统的句柄表。

## 原理

- **为什么都归结到 `EPROCESS`**：内核 API 几乎都以 `PEPROCESS` 为入参，而用户态只知道 PID/进程名；把「名字 → PEPROCESS」这一步做掉，后续 `KeStackAttachProcess`、读写进程内存、取 `Token` 等才有落点。
- **① 暴力枚举的成立前提**：`PsLookupProcessByProcessId` 是导出函数、按 PID 取对象并**返回带引用的对象**（必须 `ObDereferenceObject`），因此可以无脑扫 PID 空间。代价是每次都要走一遍 `PspCidTable` 查找，PID 上限 100000、步进 4 意味着 ~2.5 万次调用，只适合一次性使用；且必须记得对未命中的对象解引用，否则泄漏引用导致进程退不掉。
- **② 特征码定位未导出函数的可行性**：`ntoskrnl` 的导出表只暴露一部分符号，`PsGetNextProcess` 没有导出，但它的机器码在相邻导出函数附近固定出现；原文用 `IoCreateStreamFileObjectLite` 起扫 0x1000 字节、匹配 `00 00 66 FF 8E 86`（`mov word ptr [rsi+...]` 类指令的字节），命中位置减去 22 就是函数序言。这种做法依赖「内核版本 + 编译选项相同」，一旦打过补丁或换 build 就会失效，因此必须做「命中失败就回退到方案③」的兜底。
- **③ 手走链表为什么等价于 ②**：`EPROCESS` 内嵌 `LIST_ENTRY ActiveProcessLinks`（示例偏移 0xb8，随 Windows 版本变化），所有活动进程挂在以 `PsActiveProcessHead` 为头的双向循环链上。以当前进程的该项为起点、`Flink` 前进、直到绕回起点，每步用 `(ULONG_PTR)entry - offsetof(ActiveProcessLinks)` 还原 `EPROCESS`——这就是 `PsGetNextProcess` 的实现，唯一缺点是偏移要按版本适配。
- **④ 句柄表枚举的另一条正交路径**：`PspCidTable` 是内核维护的「CID（PID/TID）→ 对象」全局句柄表，`PsLookupProcessByProcessId`/`PsLookupThreadByThreadId` 都查它。原文用「`PsLookupThreadByThreadId` 指令里 `lea` 出来的 `PspCidTable` 地址」反推表指针（`+0x1e+2` 是那条 `mov rcx, [rip+disp]` 的操作数偏移），再对其调 `ExEnumHandleTable`；回调里 `HandleTableEntry->Value & ~7` 得到对象体地址、减 0x18 得 `OBJECT_HEADER`，`TypeIndex == 7` 即进程对象（进程/线程类型索引在不同版本可能不同，需实测），最后比对 `ImageFileName`。
- **四种方式的选择逻辑**：只求能跑、不管性能 → ①；能接受版本绑定、要通用遍历 → ②③；已有地址泄漏/要拿到「系统里所有进程对象（含非 ActiveProcessLinks 链上的）」→ ④；被杀软 hook 掉 `PsLookupProcessByProcessId` 时，④ 往往还能绕过（它直接读表）。
- **反过来的攻防含义**：这四种被 rootkit 用来枚举/定位目标进程（例如找 AV 进程做 patch），也被 EDR 用来验证「链表是否被摘链隐藏」——若 ③ 与 ④ 得到的结果不一致，说明有进程从 `ActiveProcessLinks` 上被摘下（DKOM 隐藏）。

## 触发条件

- 能加载/运行内核代码（自写驱动、测试签名、BYOVD、或内核调试环境）。
- 目标内核为 Windows（`EPROCESS` 布局、`ActiveProcessLinks` 偏移、`PspCidTable` 指令模式随版本变化，需按版本核对）。
- 需要按进程名/路径定位目标，且已有进程名（`ImageFileName` 只有 15 字节、截断且大小写不敏感）。
- 方案②需目标 build 与特征码匹配；方案④需 `ExEnumHandleTable` 在当前版本可用（未导出但存在）。

## 利用步骤

1. 声明未文档化函数原型：`NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS)`，以及 `ExEnumHandleTable`、`PsGetNextProcess` 的 typedef。
2. 选定策略。先试 ① 做基线（`for (i = 8; i <= 100000; i += 4)`，命中 `_stricmp(name, target) == 0` 就返回；未命中务必 `ObDereferenceObject`）。
3. 若要做通用遍历，实现 `FuzzFunc(start, len, sig, sigLen)` 特征扫描：在 `IoCreateStreamFileObjectLite` 起 0x1000 字节内找 6 字节签名，命中地址减 22 得 `PsGetNextProcess`，赋给函数指针。
4. 用 `PsGetCurrentProcess()` 作起点循环调用 `PsGetNextProcess`，直到绕回起点；每次取 `PsGetProcessImageFileName` 比对。注意原文示例里「先推进再比对」的写法会把返回值错位，正确应为「先比对当前，再推进」。
5. 或者绕过符号：`(PLIST_ENTRY)((ULONG_PTR)PsGetCurrentProcess() + 0x0b8)` 取 `ActiveProcessLinks`，`Flink` 遍历，`(PEPROCESS)((ULONG_PTR)entry - 0x0b8)` 还原对象。
6. 若要拿全量对象或绕过被 hook 的 API：从 `PsLookupThreadByThreadId` 反解 `PspCidTable`，`ExEnumHandleTable(table, Callback, targetName, NULL)`；回调里 `objHead = (OBJECT_HEADER*)((entry->Value & ~7) - 0x18)`，`objHead->TypeIndex == 7` 时取 `(PEPROCESS)(objHead + 1)` 比 `ImageFileName`。
7. 验证：与 `PsGetProcessId`、用户态进程列表交叉比对，确认没有漏项/错位；测完释放所有引用（`ObDereferenceObject`）。

## PoC

```c
NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);

/* ① 暴力 PID 枚举（注意解引用） */
PEPROCESS by_pid(PUCHAR name) {
    PEPROCESS p = NULL;
    for (ULONG i = 8; i <= 100000; i += 4) {
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)i, &p))) {
            if (_stricmp(PsGetProcessImageFileName(p), name) == 0) return p; /* 返回带引用 */
            ObDereferenceObject(p);
        }
    }
    return NULL;
}

/* ② 特征码定位未导出的 PsGetNextProcess */
typedef PEPROCESS (NTAPI *pPsGetNextProcess)(PEPROCESS);
UCHAR sig[] = { 0x00, 0x00, 0x66, 0xFF, 0x8E, 0x86 };
PVOID hit = FuzzFunc((PUCHAR)IoCreateStreamFileObjectLite, 0x1000, sig, 6);
pPsGetNextProcess next = (pPsGetNextProcess)((PUCHAR)hit - 22);

/* ③ 手动 ActiveProcessLinks（偏移按版本改） */
PLIST_ENTRY start = (PLIST_ENTRY)((ULONG_PTR)PsGetCurrentProcess() + 0x0b8);
for (PLIST_ENTRY e = start->Flink; e != start; e = e->Flink) {
    PEPROCESS p = (PEPROCESS)((ULONG_PTR)e - 0x0b8);
    DbgPrint("%s\n", PsGetProcessImageFileName(p));
}

/* ④ PspCidTable + ExEnumHandleTable */
PULONG t = *(PULONG)((PUCHAR)PsLookupThreadByThreadId + 0x1e + 2);
PULONG table = *(PULONG)*(PULONG)t;   /* 原文写法，按版本核对间接层级 */
ExEnumHandleTable(table, callback_check_typeindex_and_name, targetName, NULL);
```

原文四种方式各自给出了完整可编译片段并在调试环境验证输出（`DbgPrint` 打出目标 `EPROCESS`）。

## 变体与关联

- **偏移自动化**：`ActiveProcessLinks` 偏移可用 `ActiveProcessLinks` 特征扫描或 PDB 符号（`dt nt!_EPROCESS`）动态获取，避免硬编码 0xb8；`PspCidTable` 也可直接按符号名在 `ntoskrnl` 导出表之外的 PDB 中查。
- **用户态等价物**：`NtQuerySystemInformation(SystemHandleInformation)` 拿到 System 进程句柄 + 偏移，可在用户态泄漏 `EPROCESS` 并通过 `ActiveProcessLinks` 遍历，见 [[pentest-privilege-escalation-system-handle-info-eprocess-leak-active-process-links]]。
- **隐藏与反隐藏**：rootkit 从 `ActiveProcessLinks` 摘链（DKOM）即可让 ②③ 看不到，但 ④ 仍能枚举到，因此「两路结果取差集」是发现隐藏进程的经典做法。
- **关联**：[[code-analysis-reverse-windows-process-notify-callback-analysis]]（进程创建回调数组，另一个观察点）、[[code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service]]（同类 DKOM 隐藏手法）。

## 检测与防御

- **检测**：驱动中出现对 `IoCreateStreamFileObjectLite` 附近代码段的字节扫描（特征码搜索是典型 rootkit/驱动行为）；`ExEnumHandleTable` 被非系统模块调用；同一驱动短时间内对 PID 空间做大规模 `PsLookupProcessByProcessId`（暴力枚举特征）；`PsGetProcessImageFileName` 高频调用。
- **防御**：开启 HVCI/内核代码完整性（阻止运行期改内核代码与特征扫描后 patch）、驱动签名强制与 ELAM；用 PPL 保护关键安全进程；监控驱动加载。
- **可见性**：部署基于 ETW/内核回调的进程创建监控，与 `ActiveProcessLinks` 遍历结果做周期性对账，发现「链上缺失」即告警。
- **边界**：这四条都是合法内核编程手段，攻防双方都在用；判定恶意要看「谁在调用 + 调用后做了什么」，不能只看 API 本身。
