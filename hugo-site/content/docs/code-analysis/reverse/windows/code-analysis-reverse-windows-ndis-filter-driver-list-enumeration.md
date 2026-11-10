---
id: code-analysis-reverse-windows-ndis-filter-driver-list-enumeration
title: 内核枚举 NDIS 轻量级网络过滤驱动（LWF）：遍历 ndisFilterDriverList dump _NDIS_FILTER_DRIVER_BLOCK 与 DefaultFilterCharacteristics 处理函数
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: ndis-filter-driver-list-enumeration
tags:
- windows
- kernel-driver
- ndis
- filter-driver
- lwf
- driver-enumeration
- linked-list
- anti-hook
- anti-rootkit
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T16:35:06+08:00'
  notes: 已对照原文13692核对：链表头插流程、结构偏移、5个LWF实例与!ndiskd.filter/filterdriver一致；force理由成立（ndisFilterDriverList/_NDIS_FILTER_DRIVER_BLOCK/NdisFRegisterFilterDriver 与前作ndisMiniDriverList小端口枚举不同链不同结构）；PoC为按原文事实改写骨架未加载验证
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-ndis-filter-driver-list-enumeration/
draft: false
kb_aliases:
- ndisFilterDriverList
- _NDIS_FILTER_DRIVER_BLOCK 遍历
- NdisFRegisterFilterDriver
- NDIS LWF 枚举
- 轻量级网络过滤驱动
- '!ndiskd.filter'
- '!ndiskd.filterdriver'
- 网络过滤驱动枚举
- NDIS filter driver 排查
---

## 一句话结论

注册为 LWF 的网络过滤驱动都会在 `NdisFRegisterFilterDriver` 内部被挂进 `ndis!ndisFilterDriverList` 全局链表（受 `ndisFilterDriverListLock` 自旋锁保护）：定位这个未导出全局（或直接使用自己注册过滤驱动时返回的 `_NDIS_FILTER_DRIVER_BLOCK *`），按 `+0x008 NextFilterDriver` 遍历，即可读出每个过滤驱动的 `ImageName`、`ServiceName`、`FriendlyName/UniqueName` 以及 `DefaultFilterCharacteristics` 中的 `AttachHandler`、`SendNetBufferListsHandler`、`ReceiveNetBufferListsHandler`、`OidRequestHandler` 等回调地址，等价于用编程方式复现 `!ndiskd.filter` / `!ndiskd.filterdriver` 的输出。

## 原理

- **注册即入链**：IDA 分析 `NdisFRegisterFilterDriver` 的流程为：分配一块 `_NDIS_FILTER_DRIVER_BLOCK`；把块地址写入调用者传入的最后一个输出参数；把该结构头插进全局链表 `ndisFilterDriverList`，插入时持有自旋锁 `ndisFilterDriverListLock`（`FilterDriver->NextFilterDriver = ndisFilterDriverList; ndisFilterDriverList = FilterDriver;` 后释放）。因此链表节点即过滤驱动注册块，`NextFilterDriver` 就是遍历指针。
- **为什么能枚举到别人**：所有通过 `NdisFRegisterFilterDriver` 注册的 LWF（系统自带如 `pacer.sys`、`vwififlt.sys`、`wfplwfs.sys`，以及第三方防火墙/VPN 过滤驱动）都进入同一链表；不依赖驱动是否导出接口，也不依赖服务是否可停止。这正是"别人注册了过滤驱动、又卸载不掉时，如何看清并让它不起作用"的知识前提。
- **结构布局（示例 build 的 WinDbg `dt` 偏移）**：`_NDIS_FILTER_DRIVER_BLOCK` 的 `+0x008 NextFilterDriver`、`+0x010 DriverObject`、`+0x018 FilterQueue`（指向 `_NDIS_FILTER_BLOCK`，即绑定到具体小端口的过滤模块队列）、`+0x020 FilterDriverContext`、`+0x028 Lock`、`+0x030 Flags`、`+0x038 DeviceList`、`+0x048 Ref`、`+0x060 DefaultFilterCharacteristics`、`+0x150 Bind`、`+0x158 ImageName`（`_UNICODE_STRING`，如 `pacer.sys`）。
- **回调全集**：`+0x060` 处的 `_NDIS_FILTER_DRIVER_CHARACTERISTICS` 由调用者在注册时提供，包含 `Header`（Size/Type/Revision）、`Major/MinorNdisVersion`、`Major/MinorDriverVersion`、`Flags`、`FriendlyName`、`UniqueName`（GUID 字符串）、`ServiceName`，以及 `SetOptionsHandler`、`SetFilterModuleOptionsHandler`、`AttachHandler`、`DetachHandler`、`RestartHandler`、`PauseHandler`、`SendNetBufferListsHandler`、`SendNetBufferListsCompleteHandler`、`CancelSendNetBufferListsHandler`、`ReceiveNetBufferListsHandler`、`ReturnNetBufferListsHandler`、`OidRequestHandler`、`OidRequestCompleteHandler`、`CancelOidRequestHandler`、`DevicePnPEventNotifyHandler`、`NetPnPEventHandler`、`StatusHandler`、`DirectOidRequestHandler`、`DirectOidRequestCompleteHandler`、`CancelDirectOidRequestHandler`、`SynchronousOidRequestHandler`、`SynchronousOidRequestCompleteHandler`。数据面收发包、OID 请求与 PnP 事件都经这些指针调用，因此枚举它们就能掌握网络过滤栈的全部可插桩点。
- **三种入口（按可靠性）**：① 自己安装一个 LWF，用 `NdisFRegisterFilterDriver` 返回的块指针沿 `NextFilterDriver` 向下遍历——无需解析未导出符号，但头插语义下只能看到比自己更早注册的部分链；② 定位 `ndis.sys` 中未导出的 `ndisFilterDriverList` 全局（PDB 符号、按 build 硬编码调试得到的地址，或特征码扫描），可看到完整链表，但地址随 build 与 KASLR 变化；③ 若存在导出 API 最佳，原文未找到。
- **必须加锁**：驱动注册/卸载会并发修改链表，遍历前 `KeAcquireSpinLockRaiseToDpc(ndisFilterDriverListLock)`，结束后 `KeReleaseSpinLock`；不加锁可能读到正在释放的节点而蓝屏。这与 miniport 链表的遍历纪律一致。
- **版本门控**：`_NDIS_FILTER_DRIVER_CHARACTERISTICS` 的 `Header.Size` 随 NDIS 版本增长（DirectOid/SynchronousOid 等后加字段）；读取可选回调前应比较 `Header.Size`（或用 `Major/MinorNdisVersion`）判断字段是否存在，否则越界读会错位。
- **调试器交叉验证**：WinDbg 中 `!ndiskd.filter` 按链表顺序列出每个过滤驱动块地址、FriendlyName，以及已绑定小端口的 Filter/ Miniport 实例；`!ndiskd.filterdriver <块地址>` 显示 Ndis API 版本、驱动版本、DriverObject、Driver image、Bind flags（如 Optional/Modifying 或 Mandatory/Modifying/UnbindOnAttach）与全部 handler 地址。原文自写枚举结果与这两条命令在个数、地址、FriendlyName 上完全一致，说明遍历方法正确。
- **攻防两用**：对攻击/对抗方，枚举可识别"卸不掉"的第三方过滤驱动并进一步针对其回调（如使其暂停/失效）；对防御方，把每个 handler 地址与该驱动 `ImageName` 对应模块基址+大小比对，或与同 build 基线做差异，可发现回调被改写/挂钩的 NDIS rootkit。

## 触发条件

- 能在内核态运行代码（自写驱动/测试签名、BYOVD、内核调试环境），或可用 WinDbg 附加目标内核；
- 有目标 build 的符号/PDB，或接受按 build 硬编码 `ndisFilterDriverList(Lock)` 地址；
- 目标是 LWF（`NdisFRegisterFilterDriver` 注册）而非 TDI 过滤或 WFP callout（它们分别走设备链与 WFP 枚举）；
- 正确加锁并按 `Header.Size`/版本门控读取字段，否则可能错位或蓝屏。

## 利用步骤

1. WinDbg 确认符号与链表：`x ndis!ndisFilterDriverList`、`dq poi(ndis!ndisFilterDriverList) L1`、`dt poi(ndis!ndisFilterDriverList) _NDIS_FILTER_DRIVER_BLOCK`，沿 `NextFilterDriver` 走到 `(null)`。
2. 对每个块 `dt <块地址>+0x060 _NDIS_FILTER_DRIVER_CHARACTERISTICS`，记录 FriendlyName/UniqueName/ServiceName 与全部 handler 地址；`+0x158` 处读 `ImageName`。
3. 用 `!ndiskd.filter` 与 `!ndiskd.filterdriver <块地址>` 取基线，与自写遍历结果对照个数、地址、名称。
4. 内核代码中声明 `PKSPIN_LOCK ndisFilterDriverListLock` 与 `PNDIS_FILTER_DRIVER_BLOCK ndisFilterDriverList`，按目标 build 填入符号地址（或实现 PDB/特征码解析）；加锁后 `for (f = ndisFilterDriverList; f; f = f->NextFilterDriver)` 遍历。
5. 按 `Header.Size` 门控打印 `DefaultFilterCharacteristics` 各回调；对每个回调地址与 `ImageName` 模块范围比对，标记指向映像外的地址（潜在 NDIS hook），或与同 build 基线做差异。
6. 需要定位具体网卡上的过滤实例时，从块内 `+0x018 FilterQueue` 进入 `_NDIS_FILTER_BLOCK` 队列展开，与 `!ndiskd.filter` 的 Filter/Miniport 对应关系核对。

## PoC

内核遍历骨架（地址需按目标 build 由符号/PDB 填入；原文未提供本卡片对应的完整可编译工程）：

```c
PKSPIN_LOCK ndisFilterDriverListLock;
PNDIS_FILTER_DRIVER_BLOCK ndisFilterDriverList;

void DumpFilterDrivers(void) {
    if (!ndisFilterDriverListLock || !ndisFilterDriverList) return;

    KIRQL irql = KeAcquireSpinLockRaiseToDpc(ndisFilterDriverListLock);
    for (PNDIS_FILTER_DRIVER_BLOCK f = ndisFilterDriverList; f; f = f->NextFilterDriver) {
        PNDIS_FILTER_DRIVER_CHARACTERISTICS c = &f->DefaultFilterCharacteristics;
        DbgPrint("Filter %wZ unique=%wZ svc=%wZ image=%wZ\n",
                 &c->FriendlyName, &c->UniqueName, &c->ServiceName, &f->ImageName);
        DbgPrint("  Attach=%p Detach=%p Send=%p Recv=%p Oid=%p\n",
                 c->AttachHandler, c->DetachHandler,
                 c->SendNetBufferListsHandler, c->ReceiveNetBufferListsHandler,
                 c->OidRequestHandler);
        if (c->Header.Size > 0x088) {
            DbgPrint("  DirectOid=%p\n", c->DirectOidRequestHandler);
        }
    }
    KeReleaseSpinLock(ndisFilterDriverListLock, irql);
}
```

WinDbg 验证命令：

```text
x ndis!ndisFilterDriverList
dq poi(ndis!ndisFilterDriverList) L1
dt poi(ndis!ndisFilterDriverList) _NDIS_FILTER_DRIVER_BLOCK
dt <块地址>+0x060 _NDIS_FILTER_DRIVER_CHARACTERISTICS
!ndiskd.filter
!ndiskd.filterdriver <块地址>
```

原文在调试环境验证：链表遍历到的 5 个过滤驱动（QoS Packet Scheduler 挂在 Intel 82574L 网卡、Virtual WiFi Filter Driver、WFP vSwitch Layers LWF、WFP Native MAC Layer LWF 与 WFP 802.3 MAC Layer LWF 挂在同一网卡）与 `!ndiskd.filter` 的个数、地址、FriendlyName 一致；PoC 未在本机加载驱动执行。

## 变体与关联

- 变体（入口）：自己注册 LWF 取返回块指针沿 `NextFilterDriver` 遍历（实现最简单，只覆盖部分链）；解析 `ndisFilterDriverList` 未导出符号；特征码扫描 `ndis.sys` 中引用该全局的指令；若能找到导出的枚举 API 则最优。
- 变体（展开层）：从驱动块 `FilterQueue`（`+0x018`）进入 `_NDIS_FILTER_BLOCK` 队列，枚举某过滤驱动绑定到各小端口的实例，对应 `!ndiskd.filter` 中的 Filter/Miniport 行。
- 变体（AntiHook）：把 handler 地址与 `ImageName` 模块范围或 `DriverObject->DriverStart/DriverSize` 比对，或与同 build 干净基线做差异，筛出被改写/挂钩的回调；WFP/TDI 过滤的枚举走各自独立路径（设备链/WFP callout 枚举）。
- 关联：[[code-analysis-reverse-windows-ndis-miniport-driver-list-enumeration]]（同一系列的前作，遍历 `ndisMiniDriverList`/`_NDIS_M_DRIVER_BLOCK` 枚举小端口驱动，方法论相同但全局、结构、注册 API 不同）、[[code-analysis-reverse-windows-kernel-process-enumerate-four-ways]]（内核未导出符号/链表枚举思路）、[[code-analysis-reverse-windows-cm-callback-list-enum-unregister]]、[[code-analysis-reverse-windows-ex-callback-object-enum]]（内核回调枚举）、[[code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook]]（hook 的另一观察点）。
- 边界：`_NDIS_FILTER_DRIVER_BLOCK`/`_NDIS_FILTER_DRIVER_CHARACTERISTICS` 是未文档化内部结构，偏移随 build 变化；KASLR 使全局地址每次启动不同；遍历不加锁或版本门控错误可能蓝屏；这些能力攻防两用，判定恶意需结合调用者与后续行为。
- 注意：原文"编码实现"小节贴出的示例代码实际操作的是 miniport 链表（`ndisMiniDriverList`/`PNDIS_M_DRIVER_BLOCK`），与其测试输出展示的过滤驱动字段（FriendlyName/UniqueName/ServiceName）不一致，应视为系列文章的残留片段；本卡只采用原文经 WinDbg 验证的过滤驱动链表事实。

## 检测与防御

- 检测：非安全产品驱动在运行期读取 `ndis.sys` 全局、扫描其特征码、批量 dump NDIS 过滤驱动回调地址，属可疑内核行为；结合驱动加载日志（服务安装 7045、驱动签名状态、BYOVD 黑名单）排查。
- 防御：启用驱动签名强制/ELAM/HVCI 与内核代码完整性，阻止未签名/易受攻击驱动加载；对过滤驱动回调做基线与模块范围校验，发现指向映像外的地址即告警。
- 可见性：用 `!ndiskd.filter`/`!ndiskd.filterdriver` 与自建基线定期对账（个数、地址、FriendlyName、handler 指针）；结合 `LoadImageNotify`/内核回调监控驱动装载，避免只看单个 API。
- 边界：合法 EDR/防火墙/VPN 也会注册并枚举 LWF，单凭"读取链表"不能定性，需结合模块签名、加载路径与后续行为。
