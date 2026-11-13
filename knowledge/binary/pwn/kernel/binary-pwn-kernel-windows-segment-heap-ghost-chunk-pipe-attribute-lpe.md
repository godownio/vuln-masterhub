---
id: binary-pwn-kernel-windows-segment-heap-ghost-chunk-pipe-attribute-lpe
title: Windows 10 Segment Heap 池溢出：POOL_HEADER 的 CacheAligned/PreviousSize 造 ghost chunk 并借伪造 PipeAttribute 任意读提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-segment-heap-ghost-chunk-pool-overflow-lpe
aliases:
- Scoop the Windows 10 pool
- ghost chunk 幽灵块
- POOL_HEADER 攻击
- PreviousSize 任意释放
- PoolType CacheAligned
- BlockSize 扩溢
- Segment Heap 池溢出
- CVE-2022-24521 利用手法
tags:
- windows
- kernel
- pwn
- pool-overflow
- segment-heap
- pool-header
- ghost-chunk
- pipe-attribute
- token-stealing
- lpe
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V580
  verified_at: '2026-11-12T12:31:47+08:00'
  notes: 已对照 content.md 全文与全部 32 图逐项核对：Segment Heap 后端路由(图06)、_SEGMENT_HEAP/_HEAP_SEG_CONTEXT(图07-10)、POOL_HEADER 19H1 语义与 ProcessBilled 编码、CacheAligned 双 header(图21-23)、PreviousSize 任意释放与 ghost chunk(图24)、PipeAttribute/NtFsControlFile 0x11003C 任意读、CVE-2022-24521 归属均与原文一致。原文为综述且无完整 PoC/偏移，卡片 PoC 节已如实标注无完整 PoC、confidence low。已修正一句话结论中'内核池改用 Segment Heap'为'内核空间引入、与 NT Heap 并存、按大小路由'。dedup 复核与 cng 池溢出、pipe-attribute-KASLR、io-ring、WNF 等卡均非同链；affected_versions 原文未给出(仅 OS 19H1+ 环境说明)，保持为空。未验证点：未实际编译/运行任何内核利用代码。
---

## 一句话结论

Windows 10 19H1 起内核空间引入 Segment Heap（与既有 NT Heap 并存，池分配按大小路由到 LFH/VS/Segment/Large 后端）后，池溢出漏洞可覆盖相邻块的 `POOL_HEADER`：清掉 `PoolType` 的 `PoolQuota` 位可绕过 `ProcessBilled` 配额检查，置上 `CacheAligned` 位后释放路径会按攻击者可控的 `PreviousSize` 去定位并释放"前一个块"（一个字节 × 0x10，最多可向前 0xFF0 的任意 0x10 对齐地址），把 `PreviousSize` 设为漏洞块大小或利用它把释放重定向到漏洞块内部伪造的 `POOL_HEADER`，即可在合法块中间造出与相邻块共享内存的 ghost chunk；再配合命名管道属性对象与用户态伪造的 `PipeAttribute` 获得内核任意读，泄露内核基址后替换 EPROCESS token 提权到 SYSTEM（公开研究中 CVE-2022-24521 即采用该手法）。

## 原理

- **Segment Heap 的分配路由**：内核按申请大小选后端——`<=0x200` 走 LFH（`RtlHpLfhContextAllocate`），`<=0x20000` 走 VS（`RtlHpVsContextAllocateInternal`），更大走段分配（`RtlHpSegAlloc`/`RtlHpLargeAlloc`）。各后端上下文（`_HEAP_SEG_CONTEXT`/`_HEAP_VS_CONTEXT`/`_HEAP_LFH_CONTEXT`）挂在 `_SEGMENT_HEAP` 下，堆喷时只有同尺寸块才会落到同一后端/bucket。
- **19H1 之后 POOL_HEADER 的字段语义**：`PreviousSize`/`PoolIndex` 正常分配时不再使用（保持 0），`BlockSize` 只在块被放入动态快表（Dynamic Lookaside，0x200~0xF80 的释放块）时使用，`PoolType`/`PoolTag` 语义不变，`ProcessBilled` 仍跟踪分配进程，且自 Win8 起以 `chunk_addr ^ ExpPoolQuotaCookie ^ KPROCESS` 编码，释放时校验解码结果是否为合法 `_KPROCESS`。
- **PoolQuota 位**：若块 `PoolType` 含 `PoolQuota(0x8)`，释放时会解引用 `ProcessBilled`；溢出时把该位清掉即可避免因伪造指针触发检查/蓝屏，代价是不再走配额释放路径。
- **BlockSize 扩溢（小溢变大溢）**：`BlockSize` 是"大小/0x10"的一个字节。溢出块释放后若尺寸落在动态快表区间，会按 `BlockSize` 入表；把 `BlockSize` 改大（>0x200）就能让一个几字节的溢出在后续分配/释放时表现出 0xFD0 量级的可控区域，把受限溢出放大成更大的池溢出。
- **PreviousSize 任意释放**：`PreviousSize` 也是"大小/0x10"的一个字节。Segment Heap 下部分对 `CacheAligned` 的检查缺失，溢出设置下一块的 `PoolType.CacheAligned` 位后，释放该块时释放器会用受控 `PreviousSize` 找到"原块"并释放它：一个字节 × 0x10，最多可释放当前块之前 0xFF*0x10=0xFF0 内任意 0x10 对齐地址。把 `PreviousSize` 设为漏洞块大小，可在 UAF 情形下形成池溢出。
- **ghost chunk（幽灵块）**：在上述任意释放能力上，不释放漏洞块之前的地址，而是在漏洞块内部伪造一个假 `POOL_HEADER`，用 `PoolType` 攻击把释放重定向到该伪造头，于是释放器在合法块中间创建了一个"假块"。该假块与合法块共享同一段内存，后续对合法块的读写即等价于改写假块（及其覆盖的下一个对象），从而把池溢出升级为对象级伪造/任意读原语。
- **从 ghost chunk 到任意读**：公开利用（Scoop the Windows 10 pool / CVE-2022-24521）让 ghost chunk 与某个命名管道属性块重叠：`NtFsControlFile(..., 0x11003C, ...)` 创建的 `PipeAttribute`（分页池，键值对链表）位于重叠区时，对合法块的写入即修改 `PipeAttribute` 的字段；把其 `AttributeValue` 指针指向用户态伪造的 `PipeAttribute`，再触发属性读取，内核会按伪造的 `AttributeValue`/`AttributeValueSize` 读任意内核地址，得到任意读原语。
- **收尾提权**：任意读泄露 `EPROCESS`/内核基址（或直接找 system 进程），再用漏洞提供的写原语替换当前进程 `EPROCESS.Token` 为 system token，完成 SYSTEM 提权。`_EX_FAST_REF` 的低 4 位是引用计数，token 指针需 `& ~0xf` 对齐。
- **堆喷与布局**：LFH 每次从最多 32 块的 bitmap 组里随机选空块，需在漏洞块前后各喷 >32 个同尺寸块对抗随机化；VS 需先喷上千块清空 `FreeChunkTree` 大于目标尺寸的块，迫使分配器开新子段，再释放约 1/3 制造空洞；快表重平衡需要时间，实践中分两批喷并间隔 1~2 秒。
- **为什么成立**：Segment Heap 把多个池后端合一后，`POOL_HEADER` 的部分字段从"仅供调试/统计"变成释放路径仍会读取的输入；而 `CacheAligned` 对齐块的第二个 header、`PreviousSize`/`BlockSize` 的单字节编码与动态快表的存在，共同给了溢出数据影响释放行为的能力。

## 触发条件

- 目标为 Windows 10 19H1 及之后（引入内核 Segment Heap）或行为相近的 Windows 11；不同 build 的 POOL_HEADER/上下文偏移需重新确认。
- 存在能溢出/写入相邻池块 `POOL_HEADER` 的漏洞（堆溢出、越界写等），且能控制写入内容与部分长度。
- 能控制同尺寸对象的分配与释放（堆喷），把漏洞块放进 LFH 或 VS 后端并构造相邻关系；VS 块最小约 0x210。
- 能以普通用户身份创建命名管道并调用 `NtFsControlFile`（FSCTL 0x11003C）创建 `PipeAttribute`。
- 目标未启用使伪造 header 失效的缓解（如更严格的对齐/元数据校验、HVCI 下的池保护），且攻击者有足够内存与分页文件支撑大规模喷射。

## 利用步骤

1. 用 `dt nt!_SEGMENT_HEAP`/`_HEAP_SEG_CONTEXT`/`_HEAP_VS_CONTEXT`/`_HEAP_LFH_CONTEXT` 与 `_POOL_HEADER` 在目标 build 上确认字段偏移；按申请大小确定目标后端（LFH/VS/段）。
2. 用同尺寸对象做堆喷：LFH 在漏洞块前后各喷超过 32 个块对抗 bitmap 随机化；VS 先大量分配清空 `FreeChunkTree` 大块、开新子段，再释放约 1/3 形成可控空洞，分两批喷并等待快表重平衡。
3. 触发漏洞把数据写入相邻块的 `POOL_HEADER`：清 `PoolType.PoolQuota` 位，按需改大 `BlockSize`（放大溢出面），并设置 `PoolType.CacheAligned` 位、把 `PreviousSize` 指向目标释放位置。
4. 触发相邻块释放，让释放器按受控 `PreviousSize` 释放漏洞块内部伪造的 `POOL_HEADER`，生成 ghost chunk（与合法块/相邻对象共享内存）。
5. 让 ghost chunk 与命名管道 `PipeAttribute` 重叠：对合法块的写入即改写 `PipeAttribute` 字段；把 `AttributeValue` 指向用户态伪造的 `PipeAttribute`，通过 `NtFsControlFile` 属性读取实现任意内核地址读。
6. 用任意读泄露内核基址/定位 `EPROCESS`（也可结合其它泄露原语），再用漏洞的写能力把 system 进程 token 写入当前进程 `EPROCESS.Token`（`_EX_FAST_REF` 低 4 位清零），完成提权。
7. 全程注意恢复被改写的 `PipeAttribute`/池头原始值，避免退出时蓝屏。

## PoC

无完整 PoC（原文为综述，未附 Scoop the Windows 10 pool 的 exp 代码；该手法在 CVE-2022-24521 等公开利用中被采用）。

关键结构/布局（示意，偏移随 build 变化）：

```c
struct POOL_HEADER {      // Windows 10 19H1+ 语义
    char  PreviousSize;   // 正常分配为 0；释放时若 CacheAligned 置位则被用作"前块大小/0x10"
    char  PoolIndex;      // 未使用
    char  BlockSize;      // 大小/0x10；块入动态快表时使用
    char  PoolType;       // 含 PoolQuota(0x8)、CacheAligned(0x4) 等位
    int   PoolTag;
    void *ProcessBilled;  // chunk_addr ^ ExpPoolQuotaCookie ^ KPROCESS
};
```

```c
// 伪造 PipeAttribute（用户态），内核按 AttributeValue/AttributeValueSize 读取
struct PipeAttribute {
    LIST_ENTRY list;
    char      *AttributeName;
    uint64_t   AttributeValueSize;   // 任意读长度
    char      *AttributeValue;       // 指向任意内核地址
    char       data[0];
};
// NtFsControlFile(hPipe, NULL, NULL, NULL, &status, 0x11003C,
//                 input, input_size, output, output_size);
```

## 变体与关联

- 变体：ghost chunk 的用途不限于 PipeAttribute，任何可被"合法块写入"影响其字段、且自身有指针可被内核解引用的池对象（I/O Ring 预注册缓冲区数组、WNF 状态数据、注册表键值等）都可作为升级对象。
- 关联：[[binary-pwn-kernel-windows-pipe-attribute-np-ccb-kaslr-leak]]（PipeAttribute 结构与 `_NP_CCB`/FileObject/DriverObject 泄露链）、[[binary-pwn-kernel-windows-io-ring-pipe-arbitrary-rw]]（另一种任意读写原语，常与该手法互换使用）、[[binary-pwn-kernel-windows-wnf-paged-pool-spray-hole-digging]]（分页池喷射/挖洞布局）、[[binary-pwn-kernel-cve-2025-21333-vkrnlintvsp-dacl-truncation-pool-overflow]]（同一时代池溢出 + WNF/I/O Ring 完整链）。
- 变体：不造 ghost chunk 时，把 `PreviousSize` 设为漏洞块大小可直接制造 UAF/池溢出；只改 `BlockSize` 则可把受限溢出放大到 0xFD0 量级。
- 边界：Windows 版本/build 变化会改变 POOL_HEADER 语义、后端路由与快表行为；HVCI/池加密/更严格的元数据校验会让伪造 header 失效；大规模喷射对内存/分页文件要求高；原文为技术综述，未给出可复现的完整参数与偏移。

## 检测与防御

- 检测：进程短时间内大量创建命名管道/属性、I/O Ring、WNF 等池对象；池块 `POOL_HEADER` 中出现异常的 `CacheAligned` 位、非零 `PreviousSize`、超常 `BlockSize`；`PoolTag` 与块来源不一致；`PipeAttribute.AttributeValue` 指向用户态地址；随后出现异常内核内存读取与 token 替换。
- 防御：及时安装 Windows 补丁；启用 HVCI、内核池硬化/池元数据校验与对齐检查恢复；限制普通用户批量创建命名管道属性等分页池分配；对 `NtFsControlFile` 属性接口做配额与指针合法性校验；用 ETW/EDR 监控异常池布局与 token 替换行为。
