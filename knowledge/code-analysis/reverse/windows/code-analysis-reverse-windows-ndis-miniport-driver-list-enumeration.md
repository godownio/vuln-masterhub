---
id: code-analysis-reverse-windows-ndis-miniport-driver-list-enumeration
title: 内核枚举 NDIS 小端口驱动：遍历 ndisMiniDriverList 链表 dump _NDIS_M_DRIVER_BLOCK 与 MiniportDriverCharacteristics 回调地址
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: ndis-miniport-driver-list-enumeration
aliases:
- ndisMiniDriverList
- _NDIS_M_DRIVER_BLOCK 遍历
- MiniportDriverCharacteristics
- NdisMRegisterMiniportDriver
- '!ndiskd.miniport'
- '!ndiskd.minidriver'
- 网卡驱动枚举
- NDIS hook 排查
tags:
- windows
- kernel-driver
- ndis
- driver-enumeration
- linked-list
- anti-hook
- rootkit
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V431
  verified_at: '2026-11-09T18:39:21+08:00'
  notes: 已对照原文全文（1521 行，含 Windbg dt/_NDIS_MINIPORT_BLOCK 转储、!ndiskd 输出、内核代码与测试输出）核对：NdisMRegisterMiniportDriver→ndisInternalRegisterMiniportDriver 分配 _NDIS_M_DRIVER_BLOCK 并头插 ndisMiniDriverList（KSPIN_LOCK ndisMiniDriverListLock）属实；_NDIS_M_DRIVER_BLOCK 偏移（NextDriver 0x008/DriverObject 0x028/ServiceRegPath 0x030/MiniportDriverCharacteristics 0x070/ServiceName 0x1e8/ImageName 0x368）与 dt 输出一致；Header.Size>0x088 读 DirectOid、>0x098 读 SynchronousOid 与原文代码一致；BthPan 6.30 与 e1i68x64 6.50 两实例、!ndiskd.miniport/minidriver/netadapter 交叉验证（个数/地址/名称一致）如实。路径 code-analysis/reverse/windows 合法，无文章 ID/URL/长段摘录；单一内核枚举技术，颗粒度合适。原文无 affected_versions（仅目标调试环境），未设置版本。未验证点：未在本机加载驱动执行 PoC；偏移仅对原文示例 build 成立。
---

## 一句话结论

内核中枚举网卡小端口驱动的落点是 `ndis!ndisMiniDriverList` 全局链表：定位这个未导出全局（符号/PDB、按 build 硬编码地址，或用 `NdisMRegisterMiniportDriver` 返回的 `_NDIS_M_DRIVER_BLOCK` 作为入口）后，按 `NextDriver` 遍历，即可读出每个驱动的 `ServiceRegPath`、`ImageName`、`DriverObject` 以及 `MiniportDriverCharacteristics` 里的 `OidRequestHandler`、`SendNetBufferListsHandler` 等回调地址，用于 NDIS hook/rootkit 排查或网络栈驱动研究。

## 原理

- **注册即入链**：`NdisMRegisterMiniportDriver` 直接调用 `ndisInternalRegisterMiniportDriver`，后者分配一个 `_NDIS_M_DRIVER_BLOCK`，把指针通过最后一个参数返回给驱动，同时把该结构头插进全局链表 `ndisMiniDriverList`（受 `KSPIN_LOCK ndisMiniDriverListLock` 保护）：`MiniportDriver->NextDriver = ndisMiniDriverList; ndisMiniDriverList = MiniportDriver;`。
- **结构字段（示例 build 偏移）**：`_NDIS_M_DRIVER_BLOCK` 的 `+0x008 NextDriver`、`+0x028 DriverObject`、`+0x030 ServiceRegPath`（`\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\<服务名>`）、`+0x070 MiniportDriverCharacteristics`、`+0x1e8 ServiceName`、`+0x368 ImageName`。`MiniportDriverCharacteristics` 里既有 `Major/MinorNdisVersion`、`Major/MinorDriverVersion`、`Flags`，也有一整套回调：`SetOptionsHandler`、`InitializeHandlerEx`、`HaltHandlerEx`、`UnloadHandler`、`PauseHandler`、`RestartHandler`、`OidRequestHandler`、`SendNetBufferListsHandler`、`ReturnNetBufferListsHandler`、`CancelSendHandler`、`CheckForHangHandlerEx`、`ResetHandlerEx`、`DevicePnPEventNotifyHandler`、`ShutdownHandlerEx`、`CancelOidRequestHandler`，更高版本还追加 `DirectOidRequestHandler`/`CancelDirectOidRequestHandler` 与 `SynchronousOidRequestHandler`。
- **按适配器继续展开**：每个驱动块的 `MiniportQueue` 指向 `_NDIS_MINIPORT_BLOCK` 队列，块内 `NextMiniport`、`MiniportName`、`pAdapterInstanceName`、`PhysicalMediumType`、`MiniportMediaType`、`IfIndex`、`NetLuid` 等描述具体网卡；实例名如 Bluetooth PAN 或 Intel 82574L。
- **版本门控读取**：新字段是否存在由 `MiniportDriverCharacteristics.Header.Size` 决定（示例：大于 0x088 才读 `DirectOidRequestHandler`，大于 0x098 才读 `SynchronousOidRequestHandler`），也可按 `MajorNdisVersion/MinorNdisVersion` 判断；超出实际结构大小的读取会错位。
- **内核代码遍历必须加锁**：链表会被驱动注册/卸载并发修改，遍历前需 `KeAcquireSpinLockRaiseToDpc(ndisMiniDriverListLock)`，遍历完 `KeReleaseSpinLock`；不加锁可能读到正在释放的节点导致蓝屏。
- **地址来源与版本绑定**：`ndisMiniDriverList`、`ndisMiniDriverListLock` 未导出，地址随 Windows build 与 KASLR 变化；可用 PDB 符号在线解析、按 build 硬编码（调试时由 `x ndis!ndisMiniDriverList`/`dq` 得到），或自己也注册一个 miniport 取得块指针后沿 `NextDriver` 向下遍历（只能看到链的一部分）。
- **为什么可用于 AntiHook/rootkit 排查**：NDIS 驱动通过回调地址被协议栈调用，若某个 `OidRequestHandler`/`SendNetBufferListsHandler` 指向自身映像范围之外（或与同 build 基线不同），说明回调被第三方驱动改写/挂钩；把枚举结果与 `ImageName` 对应模块的基址+大小比对，即可筛出可疑 hook，也能用于发现隐藏的过滤驱动。
- **调试器交叉验证**：WinDbg 的 `!ndiskd.miniport` 列出所有 miniport（驱动块地址、NetAdapter 地址、名称），`!ndiskd.minidriver <addr>` 显示驱动映像/注册表路径/引用计数，`!ndiskd.netadapter <addr>` 显示媒体类型、设备实例、绑定协议（TCPIP/TCPIP6/RSPNDR/LLTDIO 等）与过滤器（WFP/QoS），可与自写遍历结果对照个数、地址、名称。

## 触发条件

- 能在内核态运行代码（自写驱动/测试签名、BYOVD、或内核调试环境），或能用 WinDbg 附加目标内核；
- 有目标 build 的符号/PDB，或接受按 build 硬编码 `ndisMiniDriverList(Lock)` 地址；
- 目标是研究/排查 NDIS 小端口驱动、回调 hook 或网络过滤栈行为；
- 遍历时能正确加锁并按 `Header.Size`/版本门控读取字段，否则可能错位或蓝屏。

## 利用步骤

1. WinDbg 中先确认符号与链表：`x ndis!ndisMiniDriverList`、`dt poi(ndis!ndisMiniDriverList) _NDIS_M_DRIVER_BLOCK`，沿 `NextDriver` 走到 `(null)` 即链表尾。
2. 用 `!ndiskd.miniport` 获取驱动块与 NetAdapter 地址清单，再用 `!ndiskd.minidriver <块地址>`、`!ndiskd.netadapter <适配器地址>` 查看映像、服务路径、绑定与过滤器，作为基线。
3. 在内核代码中声明 `PKSPIN_LOCK ndisMiniDriverListLock` 与 `PNDIS_M_DRIVER_BLOCK ndisMiniDriverList`，按目标 build 填入符号地址（或实现 PDB/特征码解析）。
4. `KeAcquireSpinLockRaiseToDpc` 加锁后 `for (d = ndisMiniDriverList; d; d = d->NextDriver)` 遍历，按 `Header.Size` 门控打印 `MiniportDriverCharacteristics` 各回调地址、`ServiceName`、`ImageName`、`ServiceRegPath`。
5. 释放锁，把结果输出到应用层；与驱动模块基址范围比对，标记指向映像外的回调（潜在 NDIS hook），或与同 build 基线做差异。
6. 交叉验证：自写枚举的个数/地址应与 `!ndiskd.miniport` 一致。

## PoC

内核遍历骨架（地址需按目标 build 由符号/PDB 填入）：

```c
PKSPIN_LOCK ndisMiniDriverListLock;
PNDIS_M_DRIVER_BLOCK ndisMiniDriverList;

void DumpMiniDriverInfo(void) {
    if (!ndisMiniDriverListLock || !ndisMiniDriverList) return;

    KIRQL irql = KeAcquireSpinLockRaiseToDpc(ndisMiniDriverListLock);
    for (PNDIS_M_DRIVER_BLOCK d = ndisMiniDriverList; d; d = d->NextDriver) {
        DbgPrint("Ndis %d.%d Driver %d.%d Image %wZ Service %wZ\n",
                 d->MiniportDriverCharacteristics.MajorNdisVersion,
                 d->MiniportDriverCharacteristics.MinorNdisVersion,
                 d->MiniportDriverCharacteristics.MajorDriverVersion,
                 d->MiniportDriverCharacteristics.MinorDriverVersion,
                 &d->ImageName, &d->ServiceName);
        DbgPrint("  OidRequestHandler=%p SendNetBufferListsHandler=%p\n",
                 d->MiniportDriverCharacteristics.OidRequestHandler,
                 d->MiniportDriverCharacteristics.SendNetBufferListsHandler);

        if (d->MiniportDriverCharacteristics.Header.Size > 0x088) {
            DbgPrint("  DirectOidRequestHandler=%p\n",
                     d->MiniportDriverCharacteristics.DirectOidRequestHandler);
        }
        if (d->MiniportDriverCharacteristics.Header.Size > 0x098) {
            DbgPrint("  SynchronousOidRequestHandler=%p\n",
                     d->MiniportDriverCharacteristics.SynchronousOidRequestHandler);
        }
    }
    KeReleaseSpinLock(ndisMiniDriverListLock, irql);
}
```

WinDbg 验证命令：

```text
x ndis!ndisMiniDriverList
dt poi(ndis!ndisMiniDriverList) _NDIS_M_DRIVER_BLOCK
!ndiskd.miniport
!ndiskd.minidriver <驱动块地址>
!ndiskd.netadapter <NetAdapter 地址>
```

原文在调试环境验证输出与 `!ndiskd.miniport` 的个数、地址、名称一致；PoC 未在本机加载驱动执行。

## 变体与关联

- 变体：链表头定位可换成 PDB 符号解析、特征码扫描 `ndis.sys` 中引用 `ndisMiniDriverList` 的指令、或先注册一个 dummy miniport 取得块指针再沿 `NextDriver` 遍历。
- 变体：只关心适配器时可从驱动块 `MiniportQueue` 进入 `_NDIS_MINIPORT_BLOCK`，读取 `MiniportName`、`pAdapterInstanceName`、`PhysicalMediumType`、`IfIndex`、`NetLuid` 等。
- 变体：AntiHook 侧可把每个回调地址与 `DriverObject->DriverStart/DriverSize` 或 `ImageName` 模块范围比对；同 build 基线差异比对可减少误报。
- 关联：[[code-analysis-reverse-windows-kernel-process-enumerate-four-ways]]（同类内核链表/未导出符号枚举思路）、[[code-analysis-reverse-windows-cm-callback-list-enum-unregister]]、[[code-analysis-reverse-windows-ex-callback-object-enum]]（内核回调数组枚举）、[[code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook]]（hook 检测的另一观察点）。
- 边界：`_NDIS_M_DRIVER_BLOCK`/`_NDIS_MINIPORT_BLOCK` 是未文档化内部结构，偏移随 build 变化；KASLR 使地址每次启动不同；遍历不加锁或结构版本门控错误可能蓝屏；这些能力攻防两用，判定恶意需结合调用者与后续行为。

## 检测与防御

- 检测：非安全产品驱动在运行期读取 `ndis.sys` 全局/扫描其特征码、批量 dump NDIS 回调地址，属可疑内核行为；结合驱动加载日志（服务安装 7045、驱动签名、BYOVD 黑名单）排查。
- 防御：启用驱动签名强制/ELAM/HVCI 与内核代码完整性，阻止未签名/易受攻击驱动加载；对关键回调做基线与范围校验，发现指向映像外的地址即告警。
- 可见性：用 `!ndiskd` 与自建基线定期对账；结合 `LoadImageNotify`/内核回调监控驱动装载，避免只看单个 API。
- 边界：合法 EDR/防火墙也会枚举 NDIS 回调，单凭“读取链表”不能定性，需结合模块签名、加载路径与后续行为。
