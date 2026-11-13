---
id: code-analysis-reverse-windows-ndis-protocol-driver-list-enumeration
title: 内核枚举 NDIS 协议驱动：遍历 ndisProtocolList 链表 dump _NDIS_PROTOCOL_BLOCK 与协议回调地址
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: ndis-protocol-driver-list-enumeration
aliases:
- ndisProtocolList
- _NDIS_PROTOCOL_BLOCK 遍历
- NdisRegisterProtocolDriver
- 协议驱动枚举
- '!ndiskd.protocol'
- NDIS 协议驱动排查
- 网络协议驱动链表
tags:
- windows
- kernel-driver
- ndis
- protocol-driver
- driver-enumeration
- linked-list
- anti-hook
- rootkit
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V604
  verified_at: '2026-11-12T18:35:17+08:00'
  notes: 已通读全文（本篇0图，images为空）核对：IDA 部分明确 NdisRegisterProtocolDriver 分配 _NDIS_PROTOCOL_BLOCK 后经 ndisRegisterProtocolDriverCommon 在 ndisProtocolListLock 下头插 ndisProtocolList；WinDbg 转储 NextProtocol=+0x010、Name=+0x048、BindAdapterHandlerEx=+0x060、ReceiveNetBufferListsHandler=+0x0b0、SendNetBufferListsCompleteHandler=+0x0b8、OidRequestCompleteHandler=+0x140、BindDeviceName=+0x1b0、RootDeviceName=+0x1b8、ImageName=+0x328 与卡片逐项一致；!ndiskd.protocol 与自写驱动 DbgPrint 输出个数/地址/名称一致（WANARPV6/WANARP/RSPNDR/MSLLDP/LLTDIO/RDMANDK/TCPIP6TUNNEL/TCPIPTUNNEL/TCPIP6/TCPIP）。修正一处：原文 MinorNdisVersion 只有 0x55(6.85)/0x1e(6.30)/0x28(6.40)，卡内“6.55 混合的 Windows 10 环境”为笔误且原文未提 Windows 版本，已改为 NDIS 6.85/6.30/6.40 并去掉 Windows 10 断言。affected_versions 留空正确：NDIS 版本是目标环境而非受影响组件版本。dedup：报告判 miniport 卡 likely_duplicate/append_scenario，核对结论后确认注册 API(NdisRegisterProtocolDriver vs NdisMRegisterMiniportDriver)、全局链(ndisProtocolList vs ndisMiniDriverList)、结构(_NDIS_PROTOCOL_BLOCK vs _NDIS_M_DRIVER_BLOCK)、回调集合与调试命令(!ndiskd.protocol vs !ndiskd.miniport)均不同，且库内已有同粒度
    filter/miniport 两卡，保留本卡成立。未验证点：无内核调试环境，未复跑 WinDbg/驱动。
---

## 一句话结论

所有通过 `NdisRegisterProtocolDriver` 注册的网络协议驱动都会被头插进 `ndis!ndisProtocolList` 全局链表（受 `ndisProtocolListLock` 自旋锁保护）；定位这个未导出全局（或使用自己注册协议驱动时返回的 `_NDIS_PROTOCOL_BLOCK *`），按 `NextProtocol` 遍历，即可读出每个协议驱动的 `Name`、`ImageName`、`BindDeviceName`/`RootDeviceName` 以及 `BindAdapterHandlerEx`、`ReceiveNetBufferListsHandler`、`SendNetBufferListsCompleteHandler`、`OidRequestCompleteHandler` 等回调地址，等价于用编程方式复现 `!ndiskd.protocol`。

## 原理

- **注册即入链**：IDA 分析 `NdisRegisterProtocolDriver` 可见：先分配一个 `_NDIS_PROTOCOL_BLOCK`，调用 `ndisRegisterProtocolDriverCommon`，后者在 `KeAcquireSpinLockRaiseToDpc(&ndisProtocolListLock)` 保护下执行 `ProtocolBlock->NextProtocol = ndisProtocolList; ndisProtocolList = ProtocolBlock;`，最后把块指针写入调用者提供的最后一个参数。链表节点即协议驱动注册块，`NextProtocol` 就是遍历指针。
- **为什么能枚举到别人**：系统自带协议（TCPIP、TCPIP6、TCPIPTUNNEL、TCPIP6TUNNEL、WANARP、WANARPV6、RSPNDR、MSLLDP、LLTDIO、RDMANDK 等）与第三方协议驱动都进入同一链表；不依赖驱动是否导出接口或服务是否可停止。协议驱动在链路层收发数据，早期 Windows 的 WFP 未必能拦截，因此枚举它们对 rootkit/恶意协议驱动排查与网络栈研究都有价值。
- **结构布局（示例 build 的 WinDbg `dt` 偏移）**：`_NDIS_PROTOCOL_BLOCK` 的 `+0x010 NextProtocol`、`+0x018 OpenQueue`（指向 `_NDIS_OPEN_BLOCK`，即绑定到具体小端口的打开实例队列）、`+0x048 Name`（`_UNICODE_STRING`，如 `TCPIP`）、`+0x058 IsIPv4`、`+0x059 IsIPv6`、`+0x060 BindAdapterHandlerEx`、`+0x068 UnbindAdapterHandlerEx`、`+0x070 OpenAdapterCompleteHandlerEx`、`+0x078 CloseAdapterCompleteHandlerEx`、`+0x080 PnPEventHandler`/`NetPnPEventHandler`、`+0x088 UnloadHandler`、`+0x090 UninstallHandler`、`+0x098 RequestCompleteHandler`、`+0x0a0 StatusHandlerEx`/`StatusHandler`、`+0x0a8 StatusCompleteHandler`、`+0x0b0 ReceiveNetBufferListsHandler`、`+0x0b8 SendNetBufferListsCompleteHandler`、`+0x140 OidRequestCompleteHandler`、`+0x1b0 BindDeviceName`、`+0x1b8 RootDeviceName`、`+0x328 ImageName`（如 `tcpip.sys`）。
- **三种入口（按可靠性）**：① 自己安装一个协议驱动，用 `NdisRegisterProtocolDriver` 返回的块指针沿 `NextProtocol` 向下遍历——无需解析未导出符号，但头插语义下只能看到比自己更早注册的部分链；② 定位 `ndis.sys` 中未导出的 `ndisProtocolList`/`ndisProtocolListLock`（PDB 符号、按 build 硬编码调试得到的地址，或特征码扫描），可看到完整链表，但地址随 build 与 KASLR 变化；③ 若存在导出的枚举 API 最佳，原文未找到。
- **必须加锁**：驱动注册/卸载会并发修改链表，遍历前 `KeAcquireSpinLockRaiseToDpc(ndisProtocolListLock)`，结束后 `KeReleaseSpinLock`；不加锁可能读到正在释放的节点而蓝屏。
- **版本门控**：`_NDIS_PROTOCOL_BLOCK` 的字段随 NDIS 版本变化（示例环境混有 NDIS 6.85/6.30/6.40，对应 `MinorNdisVersion` 的 0x55/0x1e/0x28），跨 build 读取前应以符号/`dt` 确认偏移，不能直接套用；回调可选字段是否存在也可参考 `MajorNdisVersion/MinorNdisVersion`。
- **调试器交叉验证**：WinDbg 中 `!ndiskd.protocol` 不带参数按链表顺序列出协议块地址与名称；`!ndiskd.protocol <块地址>` 显示 Ndis API 版本、驱动版本、引用计数、驱动映像、绑定的小端口与全部 handler 地址。原文自写驱动的输出与这两条命令在个数、地址、名称上完全一致。
- **攻防两用**：对攻击/对抗方，枚举可识别“卸不掉”的第三方协议驱动并针对其回调；对防御方，把每个 handler 地址与该驱动 `ImageName` 对应模块基址+大小比对，或与同 build 基线做差异，可发现回调被改写/挂钩的 NDIS rootkit；也能发现隐藏的协议驱动。

## 触发条件

- 能在内核态运行代码（自写驱动/测试签名、BYOVD、内核调试环境），或可用 WinDbg 附加目标内核。
- 有目标 build 的符号/PDB，或接受按 build 硬编码 `ndisProtocolList(Lock)` 地址。
- 目标是研究/排查 NDIS 协议驱动、回调 hook 或链路层网络行为。
- 遍历时能正确加锁并按实际 build 的结构偏移读取字段，否则可能错位或蓝屏。

## 利用步骤

1. 用 IDA 分析 `ndis!NdisRegisterProtocolDriver`/`ndisRegisterProtocolDriverCommon`，确认链表头插流程与锁变量。
2. WinDbg 定位未导出全局：`x ndis!ndisProtocolList`、`dq poi(ndis!ndisProtocolList) L1`，用 `dt` 转储 `_NDIS_PROTOCOL_BLOCK`，记录 `NextProtocol` 偏移与回调字段。
3. 沿 `NextProtocol` 逐节点 `dt`，直到 `NextProtocol` 为 null（结束标志）；同时用 `!ndiskd.protocol` 交叉验证名称与地址。
4. 编写内核驱动：把 `ndisProtocolList` 与 `ndisProtocolListLock` 地址按目标 build 填入，或自己注册协议驱动取得块指针；加锁遍历并打印 `Name`、`ImageName`、`BindDeviceName`、`RootDeviceName` 与各 handler。
5. 将每个 handler 地址与对应 `ImageName` 模块基址+大小比对，筛出映像外/基线异常的回调；结合 `OpenQueue` 展开绑定的小端口实例。
6. 授权环境中只做只读枚举，不修改链表或回调；测试驱动注意签名与 PatchGuard。

## PoC

WinDbg 手工遍历：

```text
0: kd> x ndis!ndisProtocolList
0: kd> dq poi(ndis!ndisProtocolList) L1
0: kd> dt poi(ndis!ndisProtocolList) _NDIS_PROTOCOL_BLOCK
0: kd> dt <NextProtocol 地址> _NDIS_PROTOCOL_BLOCK
...
0: kd> !ndiskd.protocol
0: kd> !ndiskd.protocol <块地址>
```

内核驱动遍历骨架：

```c
KIRQL Irql = KeAcquireSpinLockRaiseToDpc(ndisProtocolListLock);
for (_NDIS_PROTOCOL_BLOCK *Tmp = ndisProtocolList; Tmp; Tmp = Tmp->NextProtocol) {
    DbgPrint("Name:%wZ ImageName:%wZ\n", Tmp->Name, Tmp->ImageName);
    DbgPrint("BindAdapterHandlerEx:%p Receive:%p SendComplete:%p\n",
             Tmp->BindAdapterHandlerEx, Tmp->ReceiveNetBufferListsHandler,
             Tmp->SendNetBufferListsCompleteHandler);
}
KeReleaseSpinLock(ndisProtocolListLock, Irql);
```

## 变体与关联

- **变体（链表）**：`ndisFilterDriverList`（LWF 过滤驱动）、`ndisMiniDriverList`（小端口驱动）、`ndisProtocolList`（协议驱动）三条注册链；同一套“定位未导出全局+加锁遍历+按版本门控读回调”的方法可复用到其它 NDIS 结构。
- **变体（入口）**：自己注册驱动后沿链表向下（只能看部分）、PDB/符号定位、按 build 硬编码、特征码扫描。
- **变体（后利用）**：展开 `OpenQueue`/`_NDIS_OPEN_BLOCK` 与 `BindingAdapter`，把协议驱动与具体网卡/小端口关联；或把 handler 与系统基线比对找 hook。
- **关联**：[[code-analysis-reverse-windows-ndis-filter-driver-list-enumeration]]（LWF 过滤驱动枚举）、[[code-analysis-reverse-windows-ndis-miniport-driver-list-enumeration]]（小端口驱动枚举）。
- **边界**：没有符号/正确偏移时无法解析字段；KASLR 使硬编码地址失效；PatchGuard/KMCS 可能阻止内核代码；只读枚举不改链表，不构成利用链本身。

## 检测与防御

- **防御视角**：对 NDIS 回调与 `ImageName` 模块范围做基线比对，发现映像外 handler；监控协议驱动注册（`NdisRegisterProtocolDriver`）与未知驱动加载；启用驱动签名、HVCI/KMCS。
- **攻击视角**：该枚举本身可识别第三方协议驱动/EDR 网络组件，进一步针对其回调做对抗；授权测试中仅做只读枚举。
- **检测**：调试器附加/内核驱动加载；对 `ndisProtocolList` 内存的读取；异常驱动查询 NDIS 内部结构。
