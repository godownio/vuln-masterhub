---
id: code-analysis-reverse-windows-rootkit-fs-filter-attach-hide-file
title: Rootkit 文件系统过滤驱动隐藏自身：IoCreateFile(\SystemRoot) → IoGetRelatedDeviceObject → IoCreateDevice + IoAttachDeviceToDeviceStack，在 IRP 栈中过滤自身文件名
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: rootkit-filesystem-filter-driver-self-hide
aliases:
- 文件系统过滤驱动 rootkit
- IoAttachDeviceToDeviceStack 隐藏文件
- SystemRoot 设备栈挂载
- IRP FileName 过滤
- Festi 文件隐藏
- 驱动自身文件隐藏
tags:
- reverse
- windows
- kernel
- rootkit
- filesystem-filter
- irp
- malware-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:37:24+08:00'
  notes: 已对照原文 content.md 与 33 张图片逐项核对（Festi 样本分析）；六卡分别对应文件系统过滤隐藏/SSDT 注册表隐藏/直发 IRP 通信/.cdata XOR API 名/DR 寄存器反调试/日期种子 DGA，各自技术原子独立、判为原子粒度合格；与 dup-scan 中同文 related pair 并列保留（机制与触发不同）；未动态运行驱动/样本。
---

## 一句话结论

内核 rootkit 通过 `IoCreateFile("\SystemRoot")` 打开系统根目录、`ObReferenceObjectByHandle` 取 `FILE_OBJECT`、`IoGetRelatedDeviceObject` 取对应文件系统 `DEVICE_OBJECT`，再用 `IoCreateDevice` 创建自己的设备并 `IoAttachDeviceToDeviceStack` 附加到该设备栈顶部；此后所有文件系统 IRP 都先经过恶意设备，它在 dispatch 中取 `CurrentStackLocation->FileObject->FileName` 与自身驱动文件名/路径做不区分大小写匹配，命中就返回 `STATUS_ACCESS_DENIED`（0xC0000022），从而让驱动文件在资源管理器/枚举 API 中“消失”。

## 原理

- **文件系统设备栈与过滤驱动**：Windows I/O 管理器把 IRP 从驱动栈顶层向下传递；过滤驱动通过 `IoAttachDeviceToDeviceStack(newDevice, targetDevice)` 把自己插到目标设备（这里是 `\SystemRoot` 对应的卷/文件系统设备）之上，之后发往该设备的 IRP 都会先到过滤驱动，返回数据也会经过它。
- **挂载步骤**（文章 `SetHookOnSystemRoot`）：
  1. `RtlInitUnicodeString(&DestinationString, L"\\SystemRoot")`，填 `OBJECT_ATTRIBUTES`；
  2. `IoCreateFile` 打开 `\SystemRoot` 得到句柄；
  3. `ObReferenceObjectByHandle` 由句柄取 `FILE_OBJECT`；
  4. `IoGetRelatedDeviceObject(FileObject)` 取该文件对象对应的 `DEVICE_OBJECT`；
  5. `ObfReferenceObject` 增加引用；
  6. `IoCreateDevice(DriverObject, 0xC, 0, target->DeviceType, target->Characteristics, 0, &DeviceObject)` 创建同类型设备；
  7. 初始化设备扩展，`IoAttachDeviceToDeviceStack(DeviceObject, TargetDevice)` 附加到栈顶。
- **IRP 过滤**：恶意驱动把 `DriverObject->MajorFunction[0..0x1B]` 批量替换为统一 dispatch（`sub_12D06`），在 dispatch 中检查 `CurrentStackLocation->MajorFunction`、`FileObject->FileName`、`Parameters.Read.Key` 等；若文件名匹配自身驱动名（`FindToString` 不区分大小写，因为注册表/文件名比较），返回 0xC0000022 让调用方认为“拒绝访问/不存在”，从而隐藏文件。文章还看到 `KeStackAttachProcess`/`KeUnstackDetachProcess` 附加到目标进程上下文做内存块字符串清理，进一步抹除痕迹。
- **为什么有效**：用户态文件枚举最终走 IRP/文件系统；过滤驱动位于文件系统之上，可以在枚举/查询路径中剔除自身条目。安全产品若只在用户态枚举，看到的是被过滤后的视图。
- **局限**：直接读磁盘/卷（raw volume）、离线分析、内核态交叉视图（比较文件系统设备栈与磁盘内容）、PatchGuard/驱动完整性检查可以发现异常过滤驱动；驱动必须正确转发其他 IRP，否则系统不稳定。

## 触发条件

- 攻击者已能加载内核驱动（BYOVD、漏洞提权、签名驱动滥用等），驱动运行在 Ring0。
- 目标文件系统设备可通过 `\SystemRoot` 访问，驱动可创建同类型设备并附加（需要相应权限/签名策略允许）。
- rootkit 需要隐藏自身驱动文件、配置文件或其他落地文件，且用户态枚举是主要发现途径。
- 分析场景：样本含 `IoAttachDeviceToDeviceStack`、`IoCreateFile(\SystemRoot)`、`ObReferenceDeviceObject` 等导入/字符串，或驱动栈中出现未知过滤设备。

## 利用步骤

1. 静态定位 `DriverEntry`/初始化函数中的 `IoCreateFile`、`ObReferenceObjectByHandle`、`IoGetRelatedDeviceObject`、`IoCreateDevice`、`IoAttachDeviceToDeviceStack` 调用链（文章 `SetHookOnSystemRoot`）。
2. 确认目标设备：`RtlInitUnicodeString` 的字符串（如 `\SystemRoot`）与 `DeviceType/Characteristics` 来源；确认新设备附加到哪个栈。
3. 分析 dispatch：找到 `MajorFunction` 批量替换、`CurrentStackLocation->FileObject->FileName` 读取、`FindToString` 比较的字符串（自身驱动名/路径）与返回状态（0xC0000022）。
4. 动态验证：加载样本后，用 WinObj/DeviceTree 查看设备栈是否多出未知过滤设备；对比 `dir`/`FindFirstFile` 与 raw volume 解析结果，确认为文件隐藏。
5. 绕过/取证：用内核调试器/驱动枚举列出过滤设备，直接读卷/离线挂载取证；或卸载/禁用可疑驱动后重新枚举。
6. 清理：记录设备对象/驱动对象地址与驱动路径，提取样本做哈希/签名。

## PoC

无漏洞利用 PoC；以下为按文章逻辑重写的挂载骨架（仅用于理解，未编译/加载）：

```c
NTSTATUS AttachToSystemRoot(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT *OutDevice) {
    UNICODE_STRING name; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb;
    HANDLE h; PFILE_OBJECT fileObj; PDEVICE_OBJECT target, dev;

    RtlInitUnicodeString(&name, L"\\SystemRoot");
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(IoCreateFile(&h, FILE_READ_ATTRIBUTES, &oa, &iosb, NULL,
                                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                                 FILE_DIRECTORY_FILE, NULL, 0))) return STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(ObReferenceObjectByHandle(h, FILE_READ_ATTRIBUTES, NULL, KernelMode,
                                              (PVOID*)&fileObj, NULL))) return STATUS_UNSUCCESSFUL;

    target = IoGetRelatedDeviceObject(fileObj);
    ObfReferenceObject(target);
    if (!NT_SUCCESS(IoCreateDevice(DriverObject, 0xC, NULL, target->DeviceType,
                                   target->Characteristics, FALSE, &dev))) return STATUS_UNSUCCESSFUL;

    /* 初始化设备扩展，附加到文件系统设备栈顶 */
    if (!IoAttachDeviceToDeviceStack(dev, target)) { IoDeleteDevice(dev); return STATUS_UNSUCCESSFUL; }
    *OutDevice = dev;
    return STATUS_SUCCESS;
}
```

## 变体与关联

- 变体：可附加到 `\FileSystem\Ntfs`/`\FileSystem\Fastfat` 或卷设备（`\Device\HarddiskVolumeX`），按目标文件所在卷选择；也可用 minifilter（`FltRegisterFilter`）实现更正规的过滤。
- 变体：隐藏对象不限于驱动文件，还可隐藏配置文件、日志、插件文件；匹配字符串可做成哈希/模糊匹配，避免明文。
- 变体：除返回 0xC0000022 外，还可伪造目录项/修改 `FileInformation` 长度，让枚举结果“跳过”自身。
- 关联：[[pentest-persistence-windows-easy-file-locker-xlkfs-driver-hide]]（合法文件锁驱动隐藏文件）、[[code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook]]（内核 syscall hook）、[[code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service]]（同一样本的注册表隐藏）。

## 检测与防御

- 检测：枚举驱动对象/设备栈（WinObj、DeviceTree、`!devstack`），对比文件系统栈中是否有未知过滤设备；对比用户态枚举与 raw volume/离线解析结果；检查驱动导入 `IoAttachDeviceToDeviceStack`、`IoCreateFile(\SystemRoot)` 等可疑组合；用 PatchGuard/驱动完整性/签名策略阻止未知驱动加载。
- 防御：启用 HVCI/驱动签名强制、KDP/内核数据保护；限制管理员权限与 BYOVD 攻击面；EDR 监控设备对象创建/附加与驱动加载；对关键文件用独立于操作系统的完整性校验。
- 说明：本文是 rootkit 文件隐藏机制分析，severity 记为 medium；仅用于授权的恶意样本分析与防御研究。
