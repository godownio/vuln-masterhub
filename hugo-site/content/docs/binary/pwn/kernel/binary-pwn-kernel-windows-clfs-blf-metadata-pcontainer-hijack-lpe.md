---
id: binary-pwn-kernel-windows-clfs-blf-metadata-pcontainer-hijack-lpe
title: Windows CLFS 驱动 BLF 元数据漏洞族：篡改 SignaturesOffset/cbSymbolZone/控制记录索引与校验和，改写 CLFS_CONTAINER_CONTEXT.pContainer 虚表指针提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-clfs-blf-metadata-pcontainer-hijack-lpe
tags:
- windows
- kernel
- clfs
- clfs-sys
- blf
- driver
- lpe
- function-pointer-hijack
- out-of-bounds-write
- metadata-corruption
- cve-2022-24521
- cve-2022-37969
- cve-2023-23376
- cve-2023-28252
cve:
- CVE-2022-24521
- CVE-2022-37969
- CVE-2023-23376
- CVE-2023-28252
severity: high
confidence: low
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V616
  verified_at: '2026-11-12T20:55:12+08:00'
  notes: 已通读原文并逐张核对 17 张图：CVE-2022-24521/37969、CVE-2023-23376/28252 四个编号均原文明确；pContainer 虚调用偏移 +0x8/+0x18、CClfsContainer vtable、AllocSymbol cbSymbolZone、OpenImage/ExtendMetadataBlock/FlushControlRecord/WriteMetadataBlock 与 28252 校验和为 0 的链条均与截图一致；CVE-2022-30220 仅崩溃未纳入正确。原文无完整 exp，卡片已标注无 PoC 且 confidence low。dedup new，候选非同链，dup-scan 无 pair。未设 affected_versions（原文无版本区间）。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-windows-clfs-blf-metadata-pcontainer-hijack-lpe/
draft: false
kb_aliases:
- CLFS 提权
- clfs.sys 漏洞
- BLF 文件伪造
- CVE-2022-24521 CLFS
- CVE-2022-37969
- CVE-2023-23376
- CVE-2023-28252
- pContainer 虚表劫持
- SignaturesOffset 覆盖指针
---

## 一句话结论

Windows CLFS（Common Log File System）驱动在解析用户可构造的 BLF 基础日志文件时，对元数据头（`CLFS_LOG_BLOCK_HEADER.SignaturesOffset`、`CLFS_BASE_RECORD_HEADER.cbSymbolZone`、`CLFS_CONTROL_RECORD` 的块索引与校验和）缺乏严格边界校验，攻击者可让扇区签名写入区与 `CLFS_CONTAINER_CONTEXT.pContainer` 指针重叠、或用 `memset` 越界写破坏该指针，再借助 `RemoveContainer`/`FlushImage`/`CheckSecureAccess` 等路径对 pContainer 的虚函数调用（vtable 偏移 +0x8/+0x18 等）劫持内核执行流，实现本地提权；CVE-2022-24521、CVE-2022-37969、CVE-2023-23376、CVE-2023-28252 均为该攻击面上的实例。

## 原理

- **CLFS 与 BLF**：CLFS 是内核日志子系统，用户态通过 `CreateLogFile(logFileName, ...)` 创建/打开日志，并在本地生成同名 `.blf` 基础日志文件；BLF 中的元数据块（Base Record、Control Record、容器上下文等）以 0x200 字节扇区为单位持久化，驱动在加载/写入时解析其中大量偏移与指针字段。
- **编码会写签名**：日志块以 `CLFS_LOG_BLOCK_HEADER` 开头，含 `RecordOffsets[16]`、`SignaturesOffset`、`Checksum`（CRC32，`CCrc32::ComputeCrc32`）等字段。块编码/解码由 `ClfsEncodeBlock`/`ClfsDecodeBlock` 完成，编码时按扇区把每 0x200 字节的后两字节签名写入 `SignaturesOffset` 指向的数组。由于 `SignaturesOffset` 来自文件、可被攻击者修改，若让它与 `CLFS_CONTAINER_CONTEXT.pContainer` 字段所在偏移相交，编码写入就会覆盖这个内核指针，而不触发对 pContainer 的置零保护。
- **pContainer 是虚表调用载体**：`CLFS_CONTAINER_CONTEXT.pContainer` 指向内核 `CClfsContainer` 对象，其首字段是 vtable 指针（`*this = &CClfsContainer::vtable`），释放/移除路径以 `(*(void(**)(...))(*(QWORD*)pContainer + 0x8))(pContainer)`、`+0x18` 等偏移调用虚函数。`CClfsBaseFilePersisted::RemoveContainer` 会调用 `FlushImage`，后者经 `WriteMetadataBlock` → `ClfsEncodeBlock`/`ClfsDecodeBlock` 后再次取 `pContainer` 调用其函数指针；CVE-2022-24521 正是先令 `cidQueue == -1` 时 pContainer 被置 0、再进入 RemoveContainer/FlushImage 的路径，用签名覆盖把 pContainer 改成攻击者构造的地址，从而 RIP 控制（任意内核函数调用）。
- **cbSymbolZone 缺边界校验（CVE-2022-37969）**：`CClfsBaseFilePersisted::AllocSymbol` 直接用 BLF 文件里 `CLFS_BASE_RECORD_HEADER.cbSymbolZone` 的值计算新增容器应跳过的空间；其唯一校验是与 `SignaturesOffset` 比较，而后者同属可构造字段，可被布置为绕过值。校验通过后 `memset` 在日志符号区越界写入，落点可对准 `CLFS_CONTAINER_CONTEXT` 的偏移字段，把 `CClfsContainer` 指针破坏为攻击者可控地址（例如用户态可申请内存），再被后续容器操作使用。
- **控制记录索引与校验和逻辑缺陷（CVE-2023-23376/CVE-2023-28252）**：`CClfsBaseFilePersisted::OpenImage` 会检查 `CLFS_CONTROL_RECORD` 的 `iExtendBlock`/`iFlushBlock` 小于 6，但 `ExtendMetadataBlock` 实际使用时并不重新校验；攻击者可先通过检查、再修改控制记录/索引让函数把越界指针当作块指针使用。28252 进一步利用 `WriteMetadataBlock` 直接调 `WriteSector`：`ClfsEncodeBlock` 先把校验和置 0，内部检测到异常返回错误码后不再更新校验和，于是元数据块校验和保持 0，恰好绕过 `OpenImage` 的校验；随后 `CreateLogFile` 调 `CClfsBaseFilePersisted::CheckSecureAccess` 遍历容器取 pContainer 并调用虚函数，构造的容器偏移使其指向用户空间伪造的虚函数布局即完成任意函数执行。23376 则通过让 `CLFS_CONTROL_RECORD->DumpCount` 递增，使编码过程把改动数据写入并覆盖 `CLFS_LOG_BLOCK_HEADER->RecordOffsets[0]`，最终执行被修改过的控制记录。

## 触发条件

- 目标为存在相应未修复 CLFS 漏洞的 Windows 版本，攻击者具有本地普通用户权限（本地提权场景）；
- 攻击者可创建/操纵日志文件（`CreateLogFile`、`AddLogContainer` 等 CLFS 用户态 API），并能在磁盘上布置构造好的 `.blf` 文件（可利用 `CClfsBaseFilePersisted` 加载路径或用户态映射伪造文件内容）；
- 能触发驱动重新加载/写入元数据的路径（打开日志、容器操作、`CreateLogFile` 的 `CheckSecureAccess` 遍历等）；
- 原文为漏洞族机制梳理，未给出完整利用工程与版本偏移，实际利用需按目标 build 校准结构偏移与池/用户态地址布局。

## 利用步骤

1. 用 CLFS API（`CreateLogFile`/`AddLogContainer` 等）创建日志，生成合法 BLF 并观察其元数据块结构，确认 Base Record、Control Record、容器上下文在块内的偏移。
2. 按目标 CVE 选择篡改点：让 `SignaturesOffset` 与 `CLFS_CONTAINER_CONTEXT.pContainer` 重叠（24521）；或把 `cbSymbolZone` 布置成能通过 `SignaturesOffset` 比较的异常值，使 `AllocSymbol` 的 `memset` 越界落到 pContainer 字段（37969）；或构造 `CLFS_CONTROL_RECORD` 的 `eExtendState`/`iExtendBlock`/`iFlushBlock`/`DumpCount` 与校验和一致的状态，驱动 `ExtendMetadataBlock`/`WriteMetadataBlock` 使用越界块索引或写入 `RecordOffsets`（23376/28252）。
3. 让驱动重新执行 `OpenImage`/`ReadImage`/`RemoveContainer`/`FlushImage`/`CheckSecureAccess` 等加载与写入路径，使编码写入或越界 memset 覆盖 pContainer，或使被构造的控制记录/偏移生效。
4. 在用户态布置伪造的 `CClfsContainer` 虚表（可申请内存并放入函数指针布局），使 pContainer 指向该内存；内核在 RemoveContainer/FlushImage/CheckSecureAccess 中按 vtable 偏移（+0x8、+0x18 等）调用函数指针，完成任意内核函数调用/执行流劫持。
5. 提权收尾（公开利用常见做法，原文未展开）：以内核执行能力替换当前进程 token 或关闭相关保护，取得 SYSTEM。

## PoC

无完整 PoC（原文为 CLFS 漏洞族综述与补丁 diff 分析，未附可运行的 exp 或结构偏移表）。原文验证到的最小事实是：`ClfsEncodeBlock` 会把扇区签名写入 `SignaturesOffset` 指向区域，`AllocSymbol` 以 `cbSymbolZone` 计算 `memset` 目标；据此可构造相交布局覆盖 pContainer。复现需结合目标版本的 CLFS 结构偏移与触发序列。

## 变体与关联

- CVE-2022-24521：`cidQueue == -1` → pContainer 置 0 → `RemoveContainer`/`FlushImage`，`SignaturesOffset` 相交覆盖 pContainer，vtable 调用劫持。
- CVE-2022-37969：`AllocSymbol` 使用未充分校验的 `cbSymbolZone`，`memset` 越界写坏容器上下文的 pContainer 指针，指向用户可控内存。
- CVE-2023-23376：`OpenImage` 检查与 `ExtendMetadataBlock` 使用之间存在索引校验缺口，配合 `DumpCount` 递增覆盖 `RecordOffsets[0]`，执行被修改的控制记录。
- CVE-2023-28252：`ClfsEncodeBlock` 错误路径不更新校验和 → 校验和为 0 绕过 `OpenImage` 校验 → `WriteMetadataBlock` 越界访问 MetaBlockControlShadow → `CheckSecureAccess` 遍历容器调用伪造 pContainer 虚函数。CVE-2022-30220（ReadImage 中 cBlocks 与实际大小不一致导致零大小池分配、未初始化块头在编码时崩溃）原文只分析到崩溃，未打通提权链，未纳入本卡。
- 关联：[[binary-pwn-kernel-windows-segment-heap-ghost-chunk-pipe-attribute-lpe]]（同为池破坏类 LPE，其中引用了 CVE-2022-24521 的 Segment Heap 利用手法，与本卡 CLFS 解析链不同）、[[binary-pwn-kernel-windows-driver-mdl-doublefree-ws2p-arbitrary-decrement-previousmode]]（Windows 驱动对象劫持思路）。

## 检测与防御

- 审计/研究视角：CLFS 系列问题高度集中在 BLF 元数据头的偏移、索引、校验和字段；用补丁 diff 对照 `CClfsBaseFilePersisted::LoadContainerQ/RemoveContainer/FlushImage/AllocSymbol/OpenImage/ReadImage/ExtendMetadataBlock/WriteMetadataBlock` 可快速定位同类未校验点。静态分析结果需按目标 build 校准结构布局后再尝试复现。
- 开发/厂商视角：对 `SignaturesOffset`、`cbSymbolZone`、`cBlocks`、`iExtendBlock`、`iFlushBlock` 等文件字段做严格边界与一致性校验；编码前对 pContainer 等敏感字段做完整性保护；校验和失败不得继续使用未校验的元数据块。
- 检测：监控异常 `CreateLogFile`/CLFS 日志容器操作与可疑 `.blf` 文件投放；及时安装对应 CVE 的补丁（这些漏洞多数已被在野利用）。
