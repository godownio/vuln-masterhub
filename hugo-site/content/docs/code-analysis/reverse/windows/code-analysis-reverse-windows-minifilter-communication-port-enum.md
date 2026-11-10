---
id: code-analysis-reverse-windows-minifilter-communication-port-enum
title: 遍历 fltmgr!_FLT_FILTER.ConnectionList 枚举 MiniFilter CommunicationPort：回调、Cookie、对象名与安全描述符
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: minifilter-communication-port-enumeration
tags:
- windows
- kernel
- minifilter
- fltmgr
- driver
- enumeration
- windbg
- rootkit
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V433
  verified_at: '2026-11-09T20:14:39+08:00'
  notes: 已对照全文核对（原文无图片）：FltCreateCommunicationPort 伪码的 MaxConnections/OBJ_KERNEL_HANDLE 校验、ObCreateObject、VerifierExtension 的 VERIFIER_COOKIE 与 Fltpv* 包装回调、ConnectionList.mLock 下 +2 计数插入、ObInsertObject；WinDbg 的 _FLT_SERVER_PORT_OBJECT 字段偏移 0x10/0x18/0x20/0x28/0x30/0x38/0x3c/0x40、_FLT_FILTER.ConnectionList +0x208、_FLT_MUTEX_LIST_HEAD mList +0x38/mCount +0x48、BindFltPort 单节点 mCount=2、WdFilter 端口名/SDDL(0x1f0001)/回调/Cookie/MaxConnections 输出均一致；原文“编码实现 略”，卡标注无 PoC 属实。未验证点：驱动侧实现与 FltEnumerateFilters 取 _FLT_FILTER 列表为合理补全，偏移需按目标 Windows 版本复核。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-minifilter-communication-port-enum/
draft: false
kb_aliases:
- MiniFilter CommunicationPort 枚举
- FLT_SERVER_PORT_OBJECT
- ConnectionList 遍历
- 遍历 minifilter 端口
- FltCreateCommunicationPort 逆向
- FilterConnectionPort 对象
---

## 一句话结论

MiniFilter 的 CommunicationPort（ServerPort）是挂在内核对象上的 `_FLT_SERVER_PORT_OBJECT`，`FltCreateCommunicationPort` 创建后把它插入 `_FLT_FILTER.ConnectionList`；遍历每个 filter 的这条链表即可枚举全部端口，并对每个对象取名字（`ObQueryNameString`）、安全描述符（`ObGetObjectSecurity`）、Connect/Disconnect/Message 回调、Cookie 与 MaxConnections/NumberOfConnections，用于驱动攻击面梳理或反 rootkit/AV 分析。

## 原理

- **FltCreateCommunicationPort 的内部行为**（反编译结论）：校验 `MaxConnections > 0` 且对象属性含 `OBJ_KERNEL_HANDLE` 后，`FltObjectReference(Filter)`，用 `ObCreateObject(FltGlobals.FltpServerPortObjectType, sizeof(_FLT_SERVER_PORT_OBJECT))` 创建对象，填 `Filter`、`MaxConnections`；随后在 `Filter->ConnectionList.mLock`（FAST_MUTEX）保护下把对象的 `FilterLink` 插入 `ConnectionList.mList`，最后 `ObInsertObject(..., FLT_PORT_ALL_ACCESS, ...)` 插入对象命名空间（通常在根目录 `\` 下）。
- **VerifierExtension 分支**：若 filter 有验证器扩展，驱动传入的 `ServerPortCookie` 和三个回调会被搬进一个 `VERIFIER_COOKIE` 结构，对象 `Cookie` 指向该结构，回调字段则换成 fltmgr 的 `FltpvConnectionNotify`/`FltpvDisconnectNotify`/`FltpvMessageNotify` 包装函数；否则 `Cookie` 就是原始 `ServerPortCookie`，回调就是驱动注册的函数。枚举时看到 `Cookie` 指向内核池小结构、回调落在 fltmgr 而非驱动模块，即可判断该端口处于验证器模式。
- **枚举面**：`_FLT_FILTER.ConnectionList` 是 `_FLT_MUTEX_LIST_HEAD`，`mList` 偏移 +0x38、`mCount` 偏移 +0x48（Win10/11 x64 实测，`ConnectionList` 在 `_FLT_FILTER` 内偏移 0x208）。`mList` 是循环双向链表，每个节点就是 `_FLT_SERVER_PORT_OBJECT.FilterLink`（偏移 0）；遍历 Flink 即可得到每个端口对象。示例中 bindflt 的链表只有一个节点（`mCount=2`，FAST_MUTEX 的计数语义含锁位，不等于节点数）。
- **端口对象字段**（x64 实测）：`FilterLink` 0x0、`ConnectNotify` 0x10、`DisconnectNotify` 0x18、`MessageNotify` 0x20、`Filter` 0x28、`Cookie` 0x30、`Flags` 0x38、`NumberOfConnections` 0x3c、`MaxConnections` 0x40；由 `Filter` 指针可回读 `_FLT_FILTER` 的 `Name`、`DefaultAltitude`、`DriverObject` 等。
- **名字与权限**：`FltCreateCommunicationPort` 的 `ObjectAttributes->ObjectName` 让端口对象拥有名字（如 `\MicrosoftMalwareProtectionPortWD`、`\BindFltPort`），用 `ObQueryNameString` 可由对象地址取回；用 `ObGetObjectSecurity` + `ObReleaseObjectSecurity` 取安全描述符，再 `ConvertSecurityDescriptorToStringSecurityDescriptor` 转 SDDL，能直接看出哪些 SID 被允许以 `0x1f0001` 权限连接端口（示例中 WD 端口只允许两个特定服务 SID）。
- **并发安全**：遍历链表必须持有 `mLock`（FAST_MUTEX），否则与端口创建/删除并发会破坏遍历（这也是实现层面的稳定性要求，而非攻击步骤）。

## 触发条件

- 内核态代码（驱动）能访问 fltmgr 的 filter 列表/`_FLT_FILTER` 结构，或能进行 Windbg 内核调试。
- 已知目标 Windows 版本的结构偏移（跨版本可能变化，需重新核对）。
- 需要读取对象名/安全描述符时，对象需仍在命名空间且调用者具备相应权限（内核态通常满足）。

## 利用步骤

1. Windbg 定位：`!fltkd.filters` 列出所有 `_FLT_FILTER`；`dt _FLT_FILTER <addr>` 查看 `ConnectionList`（示例 +0x208）；`dt _FLT_MUTEX_LIST_HEAD <addr+0x208>` 读 `mList`/`mCount`；对 `mList.Flink` 指向的地址 `dt _FLT_SERVER_PORT_OBJECT` 验证字段；`!object <对象地址>` 查看类型与名字。
2. 驱动实现：从 fltmgr 全局 filter 列表（或 `FltEnumerateFilters`）拿到每个 `_FLT_FILTER`，获取 `ConnectionList.mLock`，按 `mList` 的 Flink/Blink 遍历，每个节点减去 `FilterLink` 偏移 0 得到 `_FLT_SERVER_PORT_OBJECT`。
3. 对每个端口对象：`ObQueryNameString` 取名字；`ObGetObjectSecurity`/`ConvertSecurityDescriptorToStringSecurityDescriptor` 取 SDDL；读三个回调地址、Cookie、MaxConnections、NumberOfConnections，并用 `Filter` 指针取 filter 名与驱动对象。
4. 通过回调地址反查所属驱动模块与全路径（示例中可把 WdFilter 的回调都归到 `WdFilter.sys`），形成“filter → 端口 → 回调 → 驱动文件”的映射。
5. 若目标是反 rootkit/AV 分析，可将结果与 `\` 命名空间中的端口对象列表交叉验证，找出未在 filter 链表中登记的隐藏端口或权限过宽的端口。

## PoC

无 PoC（原文仅给出 Windbg 验证与实现要点，未提供完整代码）。关键验证命令：

```text
!fltkd.filters
dt _FLT_FILTER <filter_addr>
dt _FLT_MUTEX_LIST_HEAD <filter_addr+0x208>
dt <mList.Flink> _FLT_SERVER_PORT_OBJECT
!object <port_object_addr>
```

## 变体与关联

- 关联 [[code-analysis-reverse-windows-cm-callback-list-enum-unregister]]：同样通过遍历内核全局/结构内链表枚举受保护对象并取出 Cookie/回调，只是对象从注册表回调换成 MiniFilter 通信端口。
- 关联 [[code-analysis-reverse-windows-rootkit-fs-filter-attach-hide-file]]：MiniFilter/文件过滤驱动方向的 rootkit 分析；本卡提供端口侧的枚举视角。
- 变体：直接从对象命名空间 `\` 枚举 `FilterConnectionPort` 类型对象（名字如 `Safe360Port`、`WcifsPort`），再用对象地址 `dt _FLT_SERVER_PORT_OBJECT` 反查所属 filter；对象名/安全描述符对判断“哪个端口允许低权限进程连接”尤其有用。
- 边界：`_FLT_FILTER`/`_FLT_SERVER_PORT_OBJECT` 偏移随 Windows 版本变化；VerifierExtension 模式下 Cookie 是 `VERIFIER_COOKIE` 而非原始 ServerPortCookie；遍历不加锁会与端口生命周期竞争。原文顺带提出对 CommunicationPort 做 fuzz 的思路，但未展开验证，不构成完整利用场景。

## 检测与防御

- 防御（端口侧）：为 CommunicationPort 设置最小化安全描述符，只允许必要服务 SID 连接；限制 `MaxConnections`；对端口消息回调做严格输入校验。
- 防御（驱动加载）：启用 WDAC/驱动黑名单与 HVCI，阻止未知内核模块加载——本技术本身需要内核代码执行或内核调试。
- 检测：监控内核模块对 fltmgr 结构（`_FLT_FILTER`、ConnectionList）的读取与 `ObQueryNameString`/`ObGetObjectSecurity` 调用组合；用基线对比端口列表，发现新增/隐藏的 FilterConnectionPort 或回调指向未知模块的端口。
