---
id: code-analysis-reverse-windows-rootkit-direct-irp-tcp-udp-bypass-monitor
title: Rootkit 绕过网络监控：手工 ObCreateObject 构造 FILE_OBJECT 并直接向 \Device\Tcp/\Device\Udp 发 IRP_MJ_CREATE，避开 ZwCreateFile Hook
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: rootkit-direct-irp-tcp-udp-create-bypass
aliases:
- 直发 IRP_MJ_CREATE
- 手工 FILE_OBJECT
- ObCreateObject IoFileObjectType
- ObInsertObject
- IofCallDriver tcpip
- \Device\Tcp 隐藏通信
- Festi 通信保护
tags:
- reverse
- windows
- kernel
- rootkit
- irp
- tcpip
- stealth
- malware-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:37:36+08:00'
  notes: 已对照原文 content.md 与 33 张图片逐项核对（Festi 样本分析）；六卡分别对应文件系统过滤隐藏/SSDT 注册表隐藏/直发 IRP 通信/.cdata XOR API 名/DR 寄存器反调试/日期种子 DGA，各自技术原子独立、判为原子粒度合格；与 dup-scan 中同文 related pair 并列保留（机制与触发不同）；未动态运行驱动/样本。
---

## 一句话结论

安全软件常用两种方式监控网络：hook `ZwCreateFile` 拦截打开设备的尝试，或把自己的过滤设备附加到 `\Device\Tcp`/`\Device\Udp`。Festi 两者都绕开：它用 `ObCreateObject(IoFileObjectType)` 手工创建 `FILE_OBJECT`、初始化安全属性后 `ObInsertObject` 插入对象表，自己构造 `IRP_MJ_CREATE`（主功能号设为 `IRP_MJ_CREATE`），再通过 `ObReferenceObjectByName("\\Driver\\Tcpip")` + 遍历 `DriverObject->DeviceObject` 找到 `\Device\Tcp`/`\Device\Udp` 的 `DEVICE_OBJECT`，最后 `IofCallDriver` 直接把 IRP 发给 tcpip.sys，从而不经过 `ZwCreateFile` 和文件系统/网络过滤钩子。

## 原理

- **正常路径**：用户态/内核态打开网络设备通常走 `ZwCreateFile("\\Device\\Tcp", ...)`，安全产品 hook 该 API 或在其下层设备栈挂过滤驱动即可看到请求。
- **手工构造对象**：`ObCreateObject(Type, ObjectType=IoFileObjectType, ...)` 创建 `FILE_OBJECT`；初始化 `FileName`、`RelatedFileObject`、`Flags`、`DeviceObject` 等字段；`ObInsertObject` 把它插入对象管理器/文件对象列表；这样对象管理器认为这是合法文件对象，但创建过程没有走 `ZwCreateFile` 的路径。
- **自建 IRP**：`IoAllocateIrp(DeviceObject->StackSize, FALSE)` 分配 IRP，填 `IRP_MJ_CREATE` 主功能、`Tail.Overlay.CurrentStackLocation` 参数（`FileObject`、`DeviceObject`、`SecurityContext` 等），设置完成例程/事件，然后 `IofCallDriver(DeviceObject, Irp)` 直接投递给目标设备驱动（tcpip.sys）。
- **找设备对象**：`RtlInitUnicodeString(&name, L"\\Driver\\Tcpip")`（或 `\\Driver\\tdx`），`ObReferenceObjectByName(..., IoDriverObjectType, ...)` 取驱动对象；遍历 `DriverObject->DeviceObject` 链表，用 `ObQueryNameString` 取每个设备名，`RtlCompareUnicodeString` 与 `\Device\Tcp`/`\Device\Udp` 比较，命中后 `ObfReferenceObject` 保存指针。
- **为什么能绕过**：`ZwCreateFile` hook 看不到手工 IRP；附加到 `\Device\Tcp` 的过滤驱动位于设备栈上，但 `IofCallDriver` 直接调用目标设备对象的驱动，不经过附加在其上的过滤设备（取决于实现/栈位置；文章称安全设备不会注意到）。这使得 rootkit 的 C&C 通信更难被网络监控发现。
- **局限**：内核回调（`ObRegisterCallbacks`、WFP 过滤、ETW/网络栈回调）仍可观察到连接/IRP；手工构造对象若字段不完整可能导致崩溃/蓝屏；现代 Windows 对象/IRP 结构偏移随版本变化。

## 触发条件

- rootkit 已获得 Ring0 执行权限，需要与 C&C 通信但不想触发 `ZwCreateFile` hook 或设备过滤驱动。
- 目标系统允许内核代码调用 `ObCreateObject`/`ObInsertObject`/`IofCallDriver` 等未导出/导出内核 API（需解析地址）。
- 目标网络栈为 `\Device\Tcp`/`\Device\Udp`（tcpip.sys/tdx），设备对象名/驱动名与系统版本匹配。
- 分析场景：样本出现 `ObCreateObject`、`IoFileObjectType`、`IofCallDriver`、`\Device\Tcp` 字符串等特征。

## 利用步骤

1. 静态定位 `ObCreateObject`/`ObInsertObject`/`IofCallDriver` 调用链，确认 `ObjectType` 为 `IoFileObjectType`，`IRP` 主功能为 `IRP_MJ_CREATE`。
2. 分析 `FILE_OBJECT` 字段初始化（`FileName`/`RelatedFileObject`/`DeviceObject`/`Flags`/`SecurityContext`），记录与系统版本相关的偏移。
3. 定位设备对象查找：`ObReferenceObjectByName("\\Driver\\Tcpip")`、遍历 `DriverObject->DeviceObject`、`ObQueryNameString` 比较 `\Device\Tcp`/`\Device\Udp`。
4. 动态验证：在 `IofCallDriver`/`tcpip!TcpCreate` 下断，观察 IRP 是否绕过 `ZwCreateFile` 与网络过滤驱动；用网络监控对比是否能看到连接。
5. 防御/取证：用 WFP/ETW/内核回调在更底层抓包；检查未知 `FILE_OBJECT`/IRP 来源；对比 `ZwCreateFile` 与网络栈实际连接。

## PoC

无漏洞利用 PoC；以下为按文章逻辑重写的流程伪代码（未编译/加载）：

```c
// 1) 取 \Device\Tcp / \Device\Udp 的 DEVICE_OBJECT
UNICODE_STRING drvName; PDRIVER_OBJECT tcpipDrv; PDEVICE_OBJECT dev = NULL, tmp;
RtlInitUnicodeString(&drvName, L"\\Driver\\Tcpip");
ObReferenceObjectByName(&drvName, OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType,
                        KernelMode, NULL, (PVOID*)&tcpipDrv);
for (tmp = tcpipDrv->DeviceObject; tmp; tmp = tmp->NextDevice) {
    OBJECT_NAME_INFORMATION info; ULONG ret;
    if (NT_SUCCESS(ObQueryNameString(tmp, &info, sizeof(info), &ret)) &&
        RtlEqualUnicodeString(&info.Name, &tcpName, TRUE)) { dev = tmp; break; }
}

// 2) 手工创建 FILE_OBJECT
PFILE_OBJECT fileObj;
ObCreateObject(KernelMode, IoFileObjectType, NULL, KernelMode, NULL, sizeof(FILE_OBJECT), 0, 0, (PVOID*)&fileObj);
// 初始化 FileName/RelatedFileObject/DeviceObject/Flags/SecurityContext ...
ObInsertObject(fileObj, NULL, 0, 0, NULL);

// 3) 构造 IRP_MJ_CREATE 并直接投递
PIRP irp = IoAllocateIrp(dev->StackSize, FALSE);
PIO_STACK_LOCATION sp = IoGetNextIrpStackLocation(irp);
sp->MajorFunction = IRP_MJ_CREATE;
sp->FileObject = fileObj;
sp->DeviceObject = dev;
// 初始化 Parameters.Create.* 与完成例程/事件
IofCallDriver(dev, irp);
```

## 变体与关联

- 变体：也可用 `NtCreateFile` 直接系统调用（不经过用户态 hook）或 `ZwOpenFile` 的底层路径；但手工 IRP 更彻底地绕过文件对象创建钩子。
- 变体：目标设备可换成 `\Device\Tcp6`/`\Device\RawIp`/AFD 等；驱动名 `\Driver\tdx` 用于某些系统。
- 变体：用 `IoBuildDeviceIoControlRequest`/`IoBuildSynchronousFsdRequest` 构造 IRP，或直接调用 `tcpip!TcpCreate` 等内部函数。
- 关联：[[code-analysis-reverse-windows-rootkit-fs-filter-attach-hide-file]]（同一样本的文件系统过滤）、[[code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook]]（syscall hook）、[[code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service]]（注册表隐藏）。

## 检测与防御

- 检测：WFP/ETW/网络内核回调在更底层监控连接；检查 `ObCreateObject(IoFileObjectType)` + `IofCallDriver` 的可疑调用；对比 `ZwCreateFile` 审计与网络实际连接；内核完整性/驱动行为监控。
- 防御：启用 HVCI/KDP、驱动签名与加载白名单；EDR 使用内核回调/ETW 而非仅用户态 API hook；对 IRP 创建/设备对象访问做审计；限制管理员权限与 BYOVD。
- 说明：本文是 rootkit 直接 IRP 通信绕过网络监控的机制分析，severity 记为 medium；仅用于授权的恶意样本分析与防御研究。
