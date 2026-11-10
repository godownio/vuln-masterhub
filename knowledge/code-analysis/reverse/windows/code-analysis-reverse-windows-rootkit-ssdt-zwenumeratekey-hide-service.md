---
id: code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service
title: Rootkit SSDT Hook ZwEnumerateKey 隐藏服务注册表项：清 CR0.WP 改只读页 + 调原函数后忽略大小写跳过自身子键 + 关机通知恢复
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: rootkit-ssdt-hook-zwenumeratekey-service-hide
aliases:
- SSDT hook
- ZwEnumerateKey 钩子
- 隐藏服务注册表项
- CR0 WP 清位
- HKLM Services 隐藏
- Festi 注册表隐藏
- IoRegisterShutdownNotification 恢复
tags:
- reverse
- windows
- kernel
- rootkit
- ssdt
- registry
- hook
- malware-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:37:30+08:00'
  notes: 已对照原文 content.md 与 33 张图片逐项核对（Festi 样本分析）；六卡分别对应文件系统过滤隐藏/SSDT 注册表隐藏/直发 IRP 通信/.cdata XOR API 名/DR 寄存器反调试/日期种子 DGA，各自技术原子独立、判为原子粒度合格；与 dup-scan 中同文 related pair 并列保留（机制与触发不同）；未动态运行驱动/样本。
---

## 一句话结论

rootkit 通过 SSDT 把 `ZwEnumerateKey` 的地址改成自己的 `NewZwEnumerateKey`：钩子先调原函数取子键信息，按 `KeyInformationClass`（KeyNodeInformation/KeyNameInformation）解析子键名，再用不区分大小写的 `FindToString` 与自身驱动服务名比较，命中就递归调用 `ZwEnumerateKey(..., Index+1, ...)` 跳过该条目；写 SSDT 前用 `KeRaiseIrql(2)` 提 IRQL、`_disable()` 关中断、清 `CR0` 第 16 位（WP）写保护，写完恢复。这样枚举 `HKLM\SYSTEM\CurrentControlSet\Services` 的软件看不到恶意服务项。

## 原理

- **SSDT 与系统调用**：SSDT（System Service Descriptor Table）保存内核系统服务函数地址，用户态 `Nt*`/`Zw*` 调用经索引进入 SSDT。把 `ZwEnumerateKey` 对应表项改成钩子地址，所有注册表子键枚举都会经过钩子。
- **写只读页的常规手法**：SSDT 通常位于只读内存，需先 `__readcr0()` 读取 CR0，`__writecr0(v & 0xFFFFEFFF)` 清除 WP（Write Protect，bit 16），再写表项；为防止中断/其他 CPU 并发，还 `KeGetCurrentIrql()` < 2 时 `KfRaiseIrql(2)`、`_disable()` 关中断。文章 `EnablePatching(2)` 即做这些，写完 `DisablePatching(2)` 恢复。
- **钩子逻辑**：`NewZwEnumerateKey` 调 `OldZwEnumerateKey`，根据 `KeyInformationClass`：
  - `KeyNodeInformation`：`KeyInformation + 12` 是名称起始，`v8 = *(DWORD*)(KeyInformation + 5)` 是名称长度；
  - `KeyNameInformation`：`KeyInformation + 2`、长度 `*KeyInformation`；
  - 其他：`KeyInformation + 8`、长度 `*(DWORD*)(KeyInformation + 3)`。
  然后用 `FindToString(name, len, ownServiceName)` 做不区分大小写匹配（注册表名大小写不敏感），命中则 `return ZwEnumerateKey(KeyHandle, Index + 1, ...)` 跳过该项，否则返回原结果。
- **为什么能隐藏**：上层软件（任务管理器、驱动枚举工具、安全软件）若用 `ZwEnumerateKey` 列服务子键，拿到的是被钩子过滤后的列表；直接查具体键（`ZwOpenKey`+`ZwQueryValueKey`）仍可能发现，因此 rootkit 还需配合文件隐藏/直接查询阻断。
- **关机恢复**：`SetToRestoreRegistry` 创建设备并 `IoRegisterShutdownNotification`，在关机通知处理程序里检查恶意驱动/服务键是否存在，若被删除则重新写入，保证重启后持久化。
- **局限**：PatchGuard/KPP 会检测 SSDT 修改；HVCI/内核完整性会阻止清 WP；现代 EDR 用直接系统调用/内核回调可绕过被钩子的 `ZwEnumerateKey`。

## 触发条件

- 驱动已加载到 Ring0，且目标系统未启用 PatchGuard/HVCI/KPP 对 SSDT 的强保护（或 rootkit 有绕过）。
- 需要隐藏 `HKLM\SYSTEM\CurrentControlSet\Services\<driver>` 等服务注册表项，避免安全软件/用户发现驱动存在。
- 驱动能在关机通知中重新写入注册表（有 SYSTEM 权限）。
- 分析场景：样本出现 `ZwEnumerateKey`、`CR0`/`KeRaiseIrql`、`IoRegisterShutdownNotification` 等特征。

## 利用步骤

1. 静态定位 `SetHookOnZwEnumerateKey`：看到 `EnablePatching(2)`、`HookRoutine(ZwEnumerateKey, &NewZwEnumerateKey, OldZwEnumerateKey)`、`DisablePatching(2)`。
2. 分析 `EnablePatching`：确认 IRQL 提升、`_disable()`、`__readcr0/__writecr0` 清 bit16；记录恢复流程。
3. 分析 `NewZwEnumerateKey`：确定 `KeyInformationClass` 分支、名称偏移/长度、`FindToString` 匹配的字符串（自身服务名）。
4. 动态验证：加载样本后，用 regedit/PowerShell `Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services` 与直接 `ZwOpenKey` 查询对比；缺失项即被隐藏。
5. 绕过/取证：用内核调试器或直接系统调用（不经过 SSDT hook 的路径）枚举；检查 SSDT 表项是否指向驱动模块外；用 Volatility/rekall 等离线内存分析。
6. 清理：恢复 SSDT 原地址/卸载驱动，删除服务键并检查关机通知回调。

## PoC

无漏洞利用 PoC；以下为按文章逻辑重写的伪代码（未编译/加载）：

```c
typedef NTSTATUS (*PFN_ZwEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

PVOID OldZwEnumerateKey;
UNICODE_STRING OwnService;   // 例：\Registry\Machine\SYSTEM\CurrentControlSet\Services\festi

char EnablePatching(char flags) {
    if (flags & 1) { if (KeGetCurrentIrql() < 2) KeRaiseIrql(2, &OldIrql); }
    if (flags & 4) _disable();
    if (flags & 2) { ULONG cr0 = __readcr0(); __writecr0(cr0 & 0xFFFFEFFF); } // clear WP
    return 1;
}

NTSTATUS NewZwEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS Class,
                           PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS st = ((PFN_ZwEnumerateKey)OldZwEnumerateKey)(KeyHandle, Index, Class,
                                                          KeyInformation, Length, ResultLength);
    if (!NT_SUCCESS(st) || !KeyInformation) return st;

    PVOID name; ULONG nameLen;
    if (Class == KeyNodeInformation)      { name = (PBYTE)KeyInformation + 12; nameLen = *(DWORD*)((PBYTE)KeyInformation + 5); }
    else if (Class == KeyNameInformation) { name = (PBYTE)KeyInformation + 2;  nameLen = *(DWORD*)KeyInformation; }
    else                                   { name = (PBYTE)KeyInformation + 8;  nameLen = *(DWORD*)((PBYTE)KeyInformation + 3); }

    if (FindToString(name, nameLen >> 1, OwnService.Buffer))   // case-insensitive
        return ((PFN_ZwEnumerateKey)OldZwEnumerateKey)(KeyHandle, Index + 1, Class,
                                                       KeyInformation, Length, ResultLength);
    return st;
}
```

## 变体与关联

- 变体：也可 hook `ZwQueryKey`/`ZwOpenKey` 阻断按名查询；或直接修改注册表 hive 内存/使用 `CmRegisterCallback` 过滤。
- 变体：不恢复 SSDT（更隐蔽但更易被 PatchGuard 检测）；或用 inline hook（改函数头跳转）避开 SSDT 表项校验。
- 变体：关机恢复可换成服务/驱动定时写入、注册表事务、WMI 事件订阅等持久化方式。
- 关联：[[code-analysis-reverse-windows-rootkit-fs-filter-attach-hide-file]]（同一样本的文件隐藏）、[[code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook]]（MSR/LSTAR 级 syscall hook）、[[pentest-persistence-windows-easy-file-locker-xlkfs-driver-hide]]（驱动级隐藏）。

## 检测与防御

- 检测：比较 `ZwEnumerateKey` 与直接系统调用/离线 hive 解析结果；检查 SSDT 表项是否指向非 ntoskrnl 地址/未知驱动；监控 CR0 写、`KeRaiseIrql(2)`+`_disable` 组合；PatchGuard/HVCI 告警。
- 防御：启用 HVCI/KDP/PatchGuard；驱动签名与加载白名单；EDR 使用直接系统调用/内核回调；对服务键做完整性基线比对；限制管理员权限与 BYOVD。
- 说明：本文是 rootkit SSDT/注册表隐藏机制分析，severity 记为 medium；仅用于授权的恶意样本分析与防御研究。
