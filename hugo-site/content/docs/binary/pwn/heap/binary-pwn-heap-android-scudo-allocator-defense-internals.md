---
id: binary-pwn-heap-android-scudo-allocator-defense-internals
title: Android Scudo 分配器防御机制与利用面（前置知识）：Block 头/CRC16 校验、Android 关闭 quarantine 的 UAF 复用、double-free 重分配绕过与 TransferBatch 洗牌边界
type: scenario
domain: binary
path: binary/pwn/heap
technique: android-scudo-allocator-defense-internals
tags:
- pwn
- heap
- android
- scudo
- allocator
- uaf
- double-free
- mitigation
- internals
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V670
  verified_at: '2026-11-13T10:19:10+08:00'
  notes: 已对照原文与 img01（Region/保护页/随机 offset 布局）、img02 首帧（heapview 工具）核对 Block 头/16 位校验和/Region 配置/TransferBatch 洗牌/quarantine=0 复用/double-free 与溢出结论；原文无完整 exploit，卡片按前置知识定位、无夸大，confidence medium 如实；未在 Android 目标上实测。
url: /docs/binary/pwn/heap/binary-pwn-heap-android-scudo-allocator-defense-internals/
draft: false
kb_aliases:
- Scudo 分配器
- Android Scudo
- Scudo 防御机制
- TSDRegistryShared
- TransferBatch 洗牌
- SizeClassAllocator64
- Scudo quarantine
---

## 一句话结论

Android 11+ 默认分配器 Scudo 用"0x10 字节 Block 头 + CRC32 截断校验 + State 位 + 可选 quarantine + TransferBatch 洗牌"来缓解堆漏洞；但在 Android 配置下 `quarantine_size_kb=0`（隔离关闭），释放的块会被立即复用，UAF 依然可打；直接 double free 会被 State 位拦截，而"free → 重新分配重建头 → 再 free"的经典利用形态能通过全部检查；块洗牌只在每 4 个 TransferBatch 内进行，填满前 4 批后下一批仍可得到连续分配——这些是编写 Android 堆利用时的关键前置知识。

## 原理

- **整体结构**（文章基于 Android 13 arm64、AOSP external/scudo commit 93fc3ad0，`standalone/` 目录）：Scudo 分主/辅两个分配器——主分配器 `SizeClassAllocator64` 管理 ≤0x10010 字节的分配，辅助分配器 `MapAllocator` 管理更大分配；每个线程组有本地缓存 `TSDRegistryShared`（Android 最多 8 个 TSD，默认 2 个）。
- **Block 与 ClassId**：`malloc(n)` 实际需要 `n + 0x10` 字节，前 0x10 是 Block 头、后接用户数据；按大小分入 class（Android 64 位 Classes 从 0x20、0x30 … 到 0x10010），同 class 的块属于同一 Region（Region 0 存空闲块链表 TransferBatch）。头部字段（按位）：`ClassId:8、State:2、OriginOrWasZeroed:2、SizeOrUnusedBytes:20、Offset:16、Checksum:16`；Checksum 是 CRC32 截断为 16 位（`Crc ^ (Crc >> 16)`），在 free 时校验头部是否被改写。
- **Region 布局**：`NumClasses * 2^RegionSizeLog`（Android RegionSizeLog=28、33 个 class 含 Region 0，总虚拟分配约 0x210000000 字节）；每个 Region 初始 0x40000 字节、两端保护页，Region 之间随机 offset；分配用尽时上移保护页并扩容。小块线性溢出若超过 0x40000 会撞保护页直接终止。
- **分配路径**：`malloc → combined.h allocate`：主/辅分流 → `TSD->getCache().allocate(ClassId)`，本地缓存空则 `refill` 从 TransferBatch 复制一批；TransferBatch 也空则 `populateFreeListAndPopBatch` 生成 `MaxNumBatches=4`（Android）批，每批大小由 `MaxCached = max(1, min(13, (1<<13)/BlockSize))` 决定；块在写入 TransferBatch 前按 `compactPtrGroup` 分组的 `shuffle` 洗牌。
- **释放路径**：`deallocate` 先校验指针对齐、读取并校验头部 checksum、`State == Allocated`、Origin 类型匹配（`DeallocTypeMismatch` 选项）、`DeleteSize` 匹配（`DeleteSizeMismatch` 选项），然后 `quarantineOrDeallocateChunk`：quarantine 关闭或块过大或 ClassId==0 时直接把 State 置 `Available` 并归还 TSD 缓存（缓存满则 drain 一半回 TransferBatch）；辅助分配器每个分配由 mmap 支撑、有保护页、无隔离。
- **利用面一：UAF**。Android 的 `quarantine_size_kb` 默认 0（`flags.inc`），quarantine 被禁用，free 后块立即回到缓存/TransferBatch；文章实测 `malloc(0x200) → free → malloc(0x200)` 返回同一地址（辅助分配器 `malloc(0x20000)` 同样如此），因此 UAF 的"释放后仍可访问"原语在 Android Scudo 下依然成立，不存在延迟复用屏障。
- **利用面二：double free**。直接的二次 free 会被头部 `State` 位识别并终止（Scudo 对"同一块连续两次 free"防护有效）；但利用者的典型形态是 `free(p) → 重新 malloc 拿回 p 并写入 → 再 free(p)`，第二次 free 时头部已被重建，所有检查全部通过——Scudo 对这种"中间重分配的 double free"不提供保护。
- **利用面三：块洗牌边界**。洗牌只发生在 4 个 TransferBatch 的生成过程中，且只在 `compactPtrGroup` 同组内 shuffle；攻击者可以先把前 4 个 TransferBatch 全部分配/保留，再申请下一组 4 个批，从而让后续分配重新呈现"连续/可预测"的布局，绕过"连续分配非连续"的对抗设计。
- **利用面四：堆溢出**。小溢出会覆盖下一个 Block 头，free 该块时 checksum/State 校验失败导致进程终止；利用者要么精细重建一个合法头（含正确 ClassId/Size/Checksum），要么在溢出后不再释放被污染块、只利用已有写入；此路径可行但依赖具体漏洞与分配控制。
- **为什么是"前置知识"**：文章没有给出完整 exploit，只给出防护评估与可利用性判断；它是构造 Android 堆利用（UAF/溢出/double-free）时选择堆风水与绕过点的依据。

## 触发条件

- 目标为 Android 11+（Scudo 为默认分配器；文章实测 Android 13 / Pixel 7 / arm64），进程 maps 中出现 `[anon:scudo:primary]`。
- 已存在一个堆漏洞原语（UAF、堆溢出、double free 或可控的非法释放），且攻击者能控制分配/释放时机与大小。
- 使用 AndroidConfig（RegionSizeLog 28、MaxNumBatches 4、quarantine 0 等）；不同 OS/架构/config 下偏移与行为会变化，需要按目标重核。
- 若目标启用 MTE 或自定义 quarantine，需重新评估复用与越界检测的边界。

## 利用步骤

（本卡为防护评估/前置知识，下列为利用开发时的评估步骤，不是完整 exploit）

1. 判定分配器与配置：检查 `/proc/<pid>/maps` 的 `anon:scudo:primary`、确认 Android 版本与 Scudo 配置，估算目标 class 的 BlockSize 与 MaxCached。
2. 评估 UAF 复用：按目标大小 `malloc → free → malloc` 观察是否返回同一地址（Android 下预期是），确认可以直接用新对象占位释放块。
3. 评估 double free：若只能触发连续两次 free，`State` 位会拦截；把第二次 free 之前插入一次同尺寸分配并重建头部（正常写入），即可通过检查。
4. 评估随机化：先占满 4 个 TransferBatch，再观察下一组分配是否连续；利用 `MaxCached` 与 class 大小计算需要预留/释放的块数。
5. 评估溢出：小溢出覆盖相邻 Block 头后避免 free 被污染块；若必须 free，按头部格式重建 ClassId/State/Size/Checksum。
6. 结合具体漏洞选择目标（函数指针、对象字段、长度字段等）并设计堆风水；注意辅助分配器路径的保护页与 mmap 对齐。

## PoC

```text
# 文章观察 1：Block 头（malloc(0x22) 后 dump 返回指针 - 0x10）
0xb40000772459dcc0  03 21 02 00 00 00 28 6c 00 00 00 00 00 00 00 00
# ClassId=3, State=1(Allocated), SizeOrUnusedBytes=0x22, Checksum=0x286c

# 文章观察 2：Android 下 quarantine 关闭，free 后立即复用（主分配器）
[Pixel 7::myprogram] -> a = malloc(0x200)      => 0xb4000076d4447000
[Pixel 7::myprogram] -> free(ptr(a))
[Pixel 7::myprogram] -> a = malloc(0x200)      => 0xb4000076d4447000

# 辅助分配器同样复用
[Pixel 7::myprogram] -> a = malloc(0x20000)    => 0xb4000076d4447000
[Pixel 7::myprogram] -> free(ptr(a))
[Pixel 7::myprogram] -> a = malloc(0x20000)    => 0xb4000076d4447000
```

## 变体与关联

- 变体：启用 quarantine 或 MTE 的目标会改变 UAF/溢出结论；不同 RegionSizeLog/Class 表/`MaxNumBatches` 影响洗牌与堆风水计算。
- 关联：[[binary-pwn-heap-jemalloc-free-anywhere-in-chunk-whole-chunk-free-overlap]]（另一非 glibc 分配器的利用思路对照）、[[binary-pwn-heap-uaf-function-pointer-hijack]]、[[binary-pwn-heap-fastbin-fd-fake-chunk-bss-arbitrary-alloc]]、[[binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc]]（glibc 堆利用对照）。
- 边界：文章只做防护评估、未给出完整 Android 漏洞利用；实际利用还取决于目标进程的分配到原语、JNI/Renderer 沙箱与 SELinux 限制。

## 检测与防御

- 检测（防御方）：检测 `[anon:scudo:primary]` 异常布局与堆喷；对 UAF/double-free 类漏洞，依赖 Scudo 头部校验/State 位产生的 abort（SIGABRT、scudo 报告）作为崩溃信号。
- 加固：在支持设备启用 MTE（memory tagging）与更严格的 Scudo 配置（减小 MaxCached、开启 quarantine、增大 Region 随机化）；及时给 libc/系统组件打补丁，减少 UAF/溢出原语。
- 注意：quarantine 关闭是性能取舍，Android 的默认配置使 UAF 仍可复用；不能把"启用 Scudo"当作 UAF 缓解。
