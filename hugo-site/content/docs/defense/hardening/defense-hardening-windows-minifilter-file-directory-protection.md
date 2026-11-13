---
id: defense-hardening-windows-minifilter-file-directory-protection
title: MiniFilter 文件/目录保护驱动：IRP_MJ_CREATE + IRP_MJ_SET_INFORMATION 预回调按 PID/路径/属性拒绝访问与删改
type: scenario
domain: defense
path: defense/hardening
technique: minifilter-file-directory-protection
tags:
- windows
- kernel-driver
- minifilter
- file-protection
- access-control
- anti-tamper
- hardening
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V571
  verified_at: '2026-11-12T09:34:21+08:00'
  notes: 已对照原文与5张图核对（图03 FLT_OPERATION_REGISTRATION、图05 预操作回调签名等）。卡片与原文文件/目录保护节逐点一致：注册 IRP_MJ_CREATE 与 IRP_MJ_SET_INFORMATION 共用预回调、按 Data->Iopb->MajorFunction 区分；PsGetCurrentProcessId 取 PID；FltGetFileNameInformation(FLT_FILE_NAME_NORMALIZED|QUERY_DEFAULT) 取完整路径；SetFileInformation.FileInformationClass 区分 FileRenameInformation/FileNameInformation/FileDispositionInformation；Create.Options>>24 识别 FILE_CREATE/FILE_OPEN_IF/FILE_OVERWRITE_IF 与 FILE_DELETE_ON_CLOSE；命中置 STATUS_ACCESS_DENIED+Information=0 返回 FLT_PREOP_COMPLETE，未命中 FLT_PREOP_SUCCESS_NO_CALLBACK。卡内 FltParseFileNameInformation、进程名白名单、硬链接别名绕过等为合理补充知识；最小化 PoC 如实标注无完整可编译驱动与运行验证。冗余检查：与同篇文件隐藏卡（DIRECTORY_CONTROL 摘链）目标与IRP不同，与 process-ob-callback/registry-callback 资源不同；dedup 候选均 related 非同链，dup-scan 无本卡 pair。未执行原文代码。
url: /docs/defense/hardening/defense-hardening-windows-minifilter-file-directory-protection/
draft: false
kb_aliases:
- 文件过滤驱动保护文件
- IRP_MJ_CREATE 拦截文件打开
- IRP_MJ_SET_INFORMATION 阻止删除重命名
- minifilter 防篡改
- FLT_PREOP_COMPLETE STATUS_ACCESS_DENIED
---

## 一句话结论

MiniFilter 驱动注册 `IRP_MJ_CREATE` 与 `IRP_MJ_SET_INFORMATION` 的预操作回调，在文件/目录被打开、重命名、删除之前，按访问者 PID、`FltGetFileNameInformation` 解析出的完整路径、以及请求的处置方式（`FILE_CREATE`/`FILE_OPEN_IF`/`FILE_OVERWRITE_IF`、`FILE_DELETE_ON_CLOSE`、`FileRenameInformation`/`FileDispositionInformation`）匹配保护规则，命中即置 `STATUS_ACCESS_DENIED` 并返回 `FLT_PREOP_COMPLETE`，从而阻止受保护文件被打开、改写、重命名或删除。

## 原理

- **请求入口**：用户态 `CreateFile`/`OpenFile` 最终发 `IRP_MJ_CREATE`；删除走 `IRP_MJ_SET_INFORMATION` 且 `FileInformationClass=FileDispositionInformation`，重命名走同一主功能号且 `FileInformationClass=FileRenameInformation`。这些 IRP 在到达文件系统驱动前会先经过 MiniFilter 的预操作回调。
- **短路 IRP**：预回调在文件系统处理请求之前运行；把 `Data->IoStatus.Status` 置为 `STATUS_ACCESS_DENIED`、`Information=0` 并返回 `FLT_PREOP_COMPLETE`，等于直接以失败完成该 IRP，不再向下层转发——这是与「后回调改结果」不同的强制拦截点。放行则返回 `FLT_PREOP_SUCCESS_NO_CALLBACK`。
- **判定要素**：
  - 访问者：`PsGetCurrentProcessId()` 取当前发起进程 PID（IRP 在发起者上下文同步下发），可按 PID/进程名白名单或黑名单判断。
  - 路径：`FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pNameInfo)` 获取规范化完整路径，再用 `FltParseFileNameInformation` 拆出卷/目录/文件名，与保护路径列表比较。
  - 意图：`Data->Iopb->Parameters.Create.Options` 高 8 位为处置方式，`FILE_CREATE`(2)/`FILE_OPEN_IF`(3)/`FILE_OVERWRITE_IF`(5) 表示会创建/覆盖；`FILE_DELETE_ON_CLOSE` 需单独判断。`IRP_MJ_SET_INFORMATION` 则看 `Parameters.SetFileInformation.FileInformationClass` 细分删除（`FileDispositionInformation`）/重命名（`FileRenameInformation`）/改名信息（`FileNameInformation`）。
- **为什么成立**：预回调是 Filter Manager 强制调用链的一环，用户态所有走 I/O 管理器的文件操作都无法跳过它；只要规则覆盖了所有「会改变文件」的主功能号与信息类，普通进程拿不到句柄也发不出删除/重命名请求。
- **边界**：只挂 `IRP_MJ_CREATE` 不全面——已打开句柄的删除/重命名由 `IRP_MJ_SET_INFORMATION` 承载，必须同时注册；按完整路径比较可被硬链接/符号链接别名绕过（新别名路径不在名单内）；raw volume 读写、内核态直接构造 IRP、离线修改磁盘不受该驱动约束。

## 触发条件

- 已能加载内核驱动（测试签名模式、签名驱动部署），驱动成功注册 MiniFilter 实例。
- 保护路径/进程规则已配置并经用户态（如通信端口或注册表）下发。
- 目标场景：保护配置文件、启动项、备份、许可文件等不被恶意进程或误操作打开/删改。

## 利用步骤

1. 在 `FLT_OPERATION_REGISTRATION` 数组中注册 `IRP_MJ_CREATE` 与 `IRP_MJ_SET_INFORMATION`，两者可共用同一个预回调（示例中均为 `FsFilter1PreOperation`），在回调内用 `Data->Iopb->MajorFunction` 区分。
2. `IRP_MJ_SET_INFORMATION` 分支读取 `Data->Iopb->Parameters.SetFileInformation.FileInformationClass`，对 `FileRenameInformation`/`FileNameInformation`/`FileDispositionInformation` 分别识别重命名、改名、删除意图。
3. 取 `PsGetCurrentProcessId()` 与 `FltGetFileNameInformation(...FLT_FILE_NAME_NORMALIZED...)` 得到的完整路径，做规则匹配。
4. `IRP_MJ_CREATE` 分支解析 `Parameters.Create.Options` 高 8 位处置方式，识别 `FILE_CREATE`/`FILE_OPEN_IF`/`FILE_OVERWRITE_IF` 与 `FILE_DELETE_ON_CLOSE`，判断是否写/删意图。
5. 命中规则：`Data->IoStatus.Status = STATUS_ACCESS_DENIED; Data->IoStatus.Information = 0; return FLT_PREOP_COMPLETE;`；未命中返回 `FLT_PREOP_SUCCESS_NO_CALLBACK` 放行。

最小化 PoC：无完整可编译驱动与运行验证；原文只有过程性代码片段（回调注册、PID/路径/属性判定、`FLT_PREOP_COMPLETE` 拒绝）。

## 变体与关联

- 商用驱动 Easy File Locker/xlkfs 用同类过滤层实现「不可见、不可写、不可删」三态开关，停止服务后恢复。
- 按路径字符串比较的保护可被硬链接绕过：`CreateHardlink` 建立新别名路径不请求目标写权限，写入别名即改原文件（已有卡记录）。
- 与 `ObRegisterCallbacks` 进程/线程句柄保护、`RegistryCallback` 注册表键保护共同构成驱动层防护体系：分别覆盖进程、注册表、文件三类资源。
- 同一 MiniFilter 还可挂 `IRP_MJ_DIRECTORY_CONTROL` 做目录枚举隐藏（见 MiniFilter 文件隐藏卡），形成「隐藏 + 拒绝访问」组合。

## 检测与防御

- 若作为防护方：规则要覆盖 `IRP_MJ_CREATE` 与 `IRP_MJ_SET_INFORMATION` 全部相关信息类，并对 `FILE_DELETE_ON_CLOSE`、硬链接/符号链接别名路径做规范化处理（如 `FltGetFileNameInformation` 取 normalized + 目标 `FileObject` 对应路径一并比对）。
- 若评估此类驱动：`fltmc filters`/`fltmc instances` 查看注册的 minifilter 与 altitude；检查驱动签名、服务安装记录（7045/System 日志）与用户态通信端口。
- 防御绕过面：限制内核驱动加载（驱动签名强制、HVCI），监控 minifilter 注册与保护规则通信端口的异常连接；对受保护文件做离线/带外校验。
