---
id: code-analysis-reverse-windows-minifilter-directory-control-file-hide
title: MiniFilter 目录查询回调摘除 FILE_BOTH_DIR_INFORMATION 链表项隐藏文件：IRP_MJ_DIRECTORY_CONTROL 后处理改缓冲区
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: minifilter-directory-control-file-hide
aliases:
- MiniFilter 文件隐藏
- IRP_MJ_DIRECTORY_CONTROL 隐藏文件
- FILE_BOTH_DIR_INFORMATION 摘链
- 微过滤器目录枚举过滤
- minifilter 隐藏自身文件
tags:
- windows
- kernel
- minifilter
- rootkit
- file-hiding
- irp
- evasion
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V571
  verified_at: '2026-11-12T09:34:18+08:00'
  notes: 已对照原文与5张图核对（01筛选器管理器概念、02 Filter Manager I/O栈与altitude、03 FLT_OPERATION_REGISTRATION数组/Pre/Post回调、04 SKIP_CACHED_IO/PAGING_IO/NON_DASD_IO、05 PFLT_PRE_OPERATION_CALLBACK签名）。卡片技术点与原文文件隐藏节一致：注册 IRP_MJ_DIRECTORY_CONTROL，判断 IRP_MN_QUERY_DIRECTORY+FileBothDirectoryInformation+Length>0，MdlAddress 非空用 MmGetSystemAddressForMdl（原文示例，注释推荐 Safe 版），否则用 DirectoryBuffer，遍历 FILE_BOTH_DIR_INFORMATION 按 FileName/长度命中并修正前驱 NextEntryOffset 摘链，不能靠 STATUS_ACCESS_DENIED 隐藏。说明：原文文字称前回调且注册结构第三域(FsFilterAntsDrPostFileHide)为 PreOperation，但回调内检查 Data->IoStatus.Status 并直接改输出缓冲区属 post 语义；卡内标题取“后处理改缓冲区”的正确机制、正文步骤1已注明原文示例挂前回调，无实质性错误。最小化 PoC 如实标注原文仅给摘链片段、无完整可编译驱动。dedup 候选 rootkit-fs-filter-attach-hide-file 为传统设备栈 IoAttachDeviceToDeviceStack 机制、minifilter-communication-port-enum 为端口枚举，均非同链；dup-scan 无本卡 pair。未执行原文代码。
---

## 一句话结论

加载一个 MiniFilter（微过滤器）驱动，注册 `IRP_MJ_DIRECTORY_CONTROL` 的预/后操作回调，在目录枚举缓冲区里遍历 `FILE_BOTH_DIR_INFORMATION` 单向链表，把目标文件条目从链表中摘除并修正前一项的 `NextEntryOffset`，即可让 `FindFirstFile`/资源管理器等常规目录枚举看不到该文件，而文件仍真实存在于磁盘上。

## 原理

- **枚举路径**：用户态目录枚举（`FindFirstFile`/`FindNextFile`、`dir`）最终走 `NtQueryDirectoryFile` → `IRP_MJ_DIRECTORY_CONTROL`（MinorFunction=`IRP_MN_QUERY_DIRECTORY`）。文件系统驱动在调用方提供的缓冲区中填充 `FILE_BOTH_DIR_INFORMATION` 结构链表：每项含 `FileName`、`FileNameLength`、`NextEntryOffset`，最后一项 `NextEntryOffset` 为 0，用户态解析这条链表得到目录列表。
- **MiniFilter 介入点**：MiniFilter 向 Filter Manager 注册 `FLT_REGISTRATION`，其中 `FLT_OPERATION_REGISTRATION` 数组按 `MajorFunction` 挂 pre/post 回调；Filter Manager 按 altitude 顺序调用这些回调，再把 IRP 转发到下层文件系统。`IRP_MJ_DIRECTORY_CONTROL` 的 post 回调在文件系统完成请求后、结果返回用户态前被调用，因此此时修改输出缓冲区会影响用户态看到的枚举结果。
- **缓冲区获取**：`Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress` 非空（直接 I/O）时用 `MmGetSystemAddressForMdlSafe`（文章示例用 `MmGetSystemAddressForMdl(NormalPagePriority)`，微软推荐 Safe 版本）映射；否则直接用 `Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer` 指向的缓冲区。
- **摘链**：遍历 `FILE_BOTH_DIR_INFORMATION`，用 `FileName`/`FileNameLength` 匹配目标名；命中项若不是最后一项且前面有项，把前一项 `NextEntryOffset` 改为「前一项起始地址 → 命中项下一项起始地址」的字节偏移；命中项是最后一项则把前一项 `NextEntryOffset` 置 0；若命中项就是首项，直接让后续代码以第二项为链表头（文章示例以 `pPreFileInfo` 维护前驱）。
- **为什么成立**：用户态枚举只解析驱动/文件系统写入缓冲区的这条链表，不会回到磁盘重新校验；只要在数据拷贝回用户态之前裁剪链表，用户态看到的就是被过滤后的视图。注意 `IRP_MJ_DIRECTORY_CONTROL` 不能靠返回 `STATUS_ACCESS_DENIED` 隐藏（那会让整个枚举失败），必须改数据。
- **边界**：基于 NTFS MFT/raw volume 的磁盘解析不经过文件系统 IRP，能看到真实条目；`IRP_MJ_QUERY_INFORMATION` 等按句柄查询名字的路径未处理时，已知句柄仍可确认文件；驱动栈/回调枚举与离线分析可发现非预期 minifilter。

## 触发条件

- 攻击者能加载内核驱动（BYOVD、驱动签名滥用、提权漏洞等），驱动运行在 Ring0。
- 驱动注册 `IRP_MJ_DIRECTORY_CONTROL` 回调，并对 `IRP_MN_QUERY_DIRECTORY` + `FileBothDirectoryInformation` 请求做处理；通常同时注册 `IRP_MJ_CREATE` 拒绝按名打开，形成「看不见也打不开」。
- 目标是通过常规目录枚举隐藏落地文件/目录（样本、配置、工具），而非对抗磁盘取证。

## 利用步骤

1. `FltRegisterFilter` 注册 `FLT_REGISTRATION`，在 `FLT_OPERATION_REGISTRATION` 数组中为 `IRP_MJ_DIRECTORY_CONTROL` 挂 pre 或 post 回调（文章示例挂前回调，名为文件隐藏处理）。
2. 回调中判断：`Data->Iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL`、`MinorFunction == IRP_MN_QUERY_DIRECTORY`、`QueryDirectory.FileInformationClass == FileBothDirectoryInformation`、`QueryDirectory.Length > 0` 且 `NT_SUCCESS(Data->IoStatus.Status)`。
3. 取缓冲区：`MdlAddress != NULL` 时 `MmGetSystemAddressForMdlSafe(MdlAddress, NormalPagePriority)`，否则用 `QueryDirectory.DirectoryBuffer`；为空直接返回继续处理。
4. 遍历链表：对每项取 `FileName`/长度与隐藏文件名比较（可用 `wcslen`/按长度匹配），命中则按上节规则修正前驱 `NextEntryOffset` 摘除该节点，继续遍历剩余节点。
5. 正常返回 `FLT_POSTOP_FINISHED_PROCESSING`（post）或 `FLT_PREOP_SUCCESS_NO_CALLBACK`（pre 放行给下层）。

最小化 PoC：文章只给出摘链核心片段（缓冲区获取 + `FILE_BOTH_DIR_INFORMATION` 遍历与 `NextEntryOffset` 修正），未提供完整可编译驱动及运行验证，故无完整 PoC。

## 变体与关联

- 传统文件系统过滤驱动用 `IoCreateFile("\SystemRoot")` + `IoGetRelatedDeviceObject` + `IoCreateDevice` + `IoAttachDeviceToDeviceStack` 挂设备栈，在 dispatch 中按 `FileObject->FileName` 过滤 IRP——同一目标、不同挂载机制（无 Filter Manager、需自行处理全部 IRP 转发）。
- 同一 MiniFilter 还可挂 `IRP_MJ_CREATE`：命中目标路径时返回 `STATUS_ACCESS_DENIED`（`Data->IoStatus.Status = STATUS_ACCESS_DENIED; return FLT_PREOP_COMPLETE;`），使隐藏文件无法被按名打开。
- `IRP_MJ_SET_INFORMATION` 的 `FileDispositionInformation`（删除）/`FileRenameInformation`（重命名）同样可拦截，防止隐藏文件被删改。
- 只摘 `FileBothDirectoryInformation` 时，`FileNamesInformation`/`FileIdBothDirectoryInformation` 等其它信息类枚举可能仍暴露条目，完整实现需覆盖多个信息类。

## 检测与防御

- `fltmc filters`/`fltmc instances`、驱动对象与设备栈枚举，发现未知 minifilter 及其 altitude 与签名状态；对比正常基线。
- Raw volume/NTFS MFT 解析或离线取证，与用户态枚举结果做交叉视图比对（差异即为隐藏条目）。
- 内核回调注册枚举（Filter Manager 的已注册过滤器列表）、`PsLoadedModuleList` 与驱动加载日志（7045/Service 安装、Sysmon 6/7 驱动加载事件）。
- 启用驱动签名强制与 HVCI/内核完整性策略，限制未签名/不受信驱动加载；EDR 监控 minifilter 注册与 `FltRegisterFilter` 行为。
