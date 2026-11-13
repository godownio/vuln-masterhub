---
id: defense-hardening-windows-minifilter-acquire-section-block-image-load
title: MiniFilter 拦截 DLL/EXE 镜像加载：IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION 预回调按 PAGE_EXECUTE + PID/路径拒绝，FltReadFile 做 PE 校验
type: scenario
domain: defense
path: defense/hardening
technique: minifilter-acquire-section-block-image-load
aliases:
- minifilter 阻止 DLL 加载
- IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION 拦截
- 驱动层模块加载拦截
- 反作弊 DLL 拦截
- PageProtection PAGE_EXECUTE 过滤
tags:
- windows
- kernel-driver
- minifilter
- module-load
- dll-injection
- anti-cheat
- hardening
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V571
  verified_at: '2026-11-12T09:34:24+08:00'
  notes: 已对照原文与5张图核对。卡片与原文进程/模块拦截节一致：注册 IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION（示例 FsFilterAntsDrvPreExe）、按 PsGetCurrentProcessId+FltGetFileNameInformation 的 PID/路径规则、PageProtection==PAGE_EXECUTE 判断可执行映射、Data->IoStatus.Status 置 STATUS_ACCESS_DENIED（或 STATUS_INSUFFICIENT_RESOURCES 弹资源错误）+FLT_PREOP_COMPLETE 拒绝、FltReadFile 读 FileObject 做 PE(DOS/NT头)校验以区分该 IRP 混入的非模块调用。说明：原文片段写作 if(PageProtection==PAGE_EXECUTE){return FLT_PREOP_SUCCESS_NO_CALLBACK;} 与拦截意图相反，应理解为仅对非 PAGE_EXECUTE 放行；卡内按“只处理可执行映射请求”表述，符合该拦截点的正确用法。卡内反射式/手动映射、Herpaderping 绕过与 PsSetLoadImageNotifyRoutine 只能通知不能阻止为合理边界补充（后者已有 verified 卡）。dedup 候选 load-image-notify、ntdll-remap 均 related 非同链；dup-scan 无本卡 pair。未执行原文代码。
---

## 一句话结论

MiniFilter 驱动注册 `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` 的预操作回调，按发起进程 PID、`FltGetFileNameInformation` 取到的模块路径和 `Parameters.AcquireForSectionSynchronization.PageProtection == PAGE_EXECUTE` 判断「可执行镜像加载」请求，命中规则即返回 `STATUS_ACCESS_DENIED`（或 `STATUS_INSUFFICIENT_RESOURCES` 弹资源错误）并 `FLT_PREOP_COMPLETE`，使目标 EXE/DLL 无法被映射加载；由于该 IRP 对很多非加载调用也会触发，实践中再用 `FltReadFile` 读取文件头做 PE 校验区分真正的模块文件。

## 原理

- **镜像加载路径**：`LoadLibrary`/`LdrLoadDll` → `NtCreateSection(SEC_IMAGE)` → 映射并获取节同步。加载器对已落地文件以「执行」为目的获取节时，I/O 管理器会下发 `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`，其参数 `PageProtection` 表明请求的保护属性；请求 `PAGE_EXECUTE` 即为可执行映射。
- **拦截点**：MiniFilter 的预回调在 IRP 到达文件系统前运行，可检查 `Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection`：等于 `PAGE_EXECUTE` 时按 `PsGetCurrentProcessId()`（发起映射的进程）与 `FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pNameInfo)` 的完整路径匹配规则。
- **拒绝方式**：`Data->IoStatus.Status = STATUS_ACCESS_DENIED; Data->IoStatus.Information = 0; return FLT_PREOP_COMPLETE;` 使 `LoadLibrary` 直接失败；改用 `STATUS_INSUFFICIENT_RESOURCES` 则加载器弹出「资源不足」类错误窗口。
- **PE 校验的必要性**：`IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` 并不只服务镜像加载，很多其它按节访问文件的调用也会进入该回调；若不加区分地拦截会误伤正常文件读取。做法是用 `FltReadFile` 从 `FileObject` 读取文件头，解析 DOS/NT 头确认确是 EXE/DLL（并可按导入表/签名进一步细分），只拦有效模块。
- **为什么有效**：Windows 的镜像映射必须经过节获取同步这一文件系统入口，MiniFilter 停在这里即可让加载失败；`IRP_MJ_CREATE` 拦截（打开即失败）更粗暴但会影响所有读文件操作，而本路径只针对可执行映射，粒度更细。
- **边界**：手动映射/反射式加载（自己 `NtCreateSection` 非镜像节 + `NtMapViewOfSection` 后重定位、修导入）不经过「镜像加载」语义的节获取，可绕过；先加载后覆盖文件的 Process Herpaderping 类手法也能规避基于路径/内容的首检；已有进程句柄/内核态操作不受用户态规则约束。

## 触发条件

- 已能加载内核驱动并注册 MiniFilter（测试签名或签名驱动部署）。
- 驱动注册 `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` 回调，并配置要阻止的进程/模块路径规则。
- 场景：反作弊阻止外挂 DLL、EDR 阻止未授权模块、终端管控限制特定 EXE/DLL 运行。

## 利用步骤

1. 在 `FLT_OPERATION_REGISTRATION` 数组中注册 `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`，挂预回调（示例 `FsFilterAntsDrvPreExe`）。
2. 回调中取 `PsGetCurrentProcessId()` 与 `FltGetFileNameInformation(...)` 的模块完整路径，与规则列表比对。
3. 判断 `Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == PAGE_EXECUTE`，只处理可执行映射请求。
4. 因该 IRP 会混入大量非模块请求，用 `FltReadFile` 读取 `FileObject` 头部，解析 PE（DOS 头 `MZ`、NT 头 `PE\0\0`、Characteristics 中 DLL 位）确认为有效 EXE/DLL。
5. 命中规则：置 `STATUS_ACCESS_DENIED`（或 `STATUS_INSUFFICIENT_RESOURCES`）并返回 `FLT_PREOP_COMPLETE`；否则 `FLT_PREOP_SUCCESS_NO_CALLBACK` 放行。

最小化 PoC：无完整可编译驱动及运行验证；原文给出回调注册、PID/路径/`PageProtection` 判定与拒绝状态设置的片段。

## 变体与关联

- 更粗粒度的替代：在 `IRP_MJ_CREATE` 预回调按路径直接拒绝打开，模块根本读不到文件；副作用是影响一切读取场景。
- `PsSetLoadImageNotifyRoutine` 只能在镜像加载后通知，不能阻止加载，适合监控不适合拦截。
- 常见绕过（库中已有相关卡）：反射式/手动映射（不做 SEC_IMAGE 镜像加载）、Process Herpaderping（先建节再覆盖文件）、DLL 侧加载与白加黑（借合法宿主加载）。
- 与文件/目录保护卡（`IRP_MJ_CREATE`/`IRP_MJ_SET_INFORMATION` 防删改）、进程保护卡（`ObRegisterCallbacks`）同属驱动层强制防护，可按资源类型组合部署。

## 检测与防御

- 管理面：`fltmc filters`/`fltmc instances` 查看未知 minifilter 及其 altitude，核对驱动签名与安装记录（7045/System 日志）。
- 绕过面评估：用反射式加载/手动映射验证规则是否只覆盖 SEC_IMAGE 路径；检查规则对 PID 继承、改名拷贝、硬链接别名的处理。
- 作为防御方：规则需结合 PE 有效性校验（否则误伤大量文件读取）并只处理 `PAGE_EXECUTE`；对签名/哈希做白名单，避免仅按文件名/路径判断被改名绕过。
- 通用加固：驱动签名强制、HVCI，限制未受信驱动加载以防攻击者用同类驱动实施反向拦截。
