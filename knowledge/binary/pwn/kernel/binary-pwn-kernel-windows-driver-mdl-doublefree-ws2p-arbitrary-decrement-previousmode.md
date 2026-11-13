---
id: binary-pwn-kernel-windows-driver-mdl-doublefree-ws2p-arbitrary-decrement-previousmode
title: Windows 第三方驱动 MDL double free → Ws2P 对象 UAF 与任意递减改 KTHREAD.PreviousMode 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-driver-mdl-doublefree-ws2p-arbitrary-decrement-previousmode
aliases:
- SYSTEM 驱动提权
- MDL double free
- Ws2P UAF
- ws2ifsl 任意递减
- PreviousMode 读写原语
- Windows 驱动 UAF 提权
tags:
- windows
- kernel
- driver
- double-free
- mdl
- uaf
- pool-spray
- ws2ifsl
- previousmode
- lpe
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:58:46+08:00'
  notes: 已对照原文核对：第三方驱动双重释放 MDL、NpFr/IoSb 堆喷占位 Ws2P(ws2ifsl)、关闭 handle 任意递减改 PreviousMode、64 位 IOCTL_ALLOCATE32 截断蓝屏坑与原文一致；原文仅策略无 exp 细节，confidence low 合理
---

## 一句话结论

Windows 第三方驱动通过 DeviceIoControl 提供“申请内存并映射到用户态/释放映射/释放内存”功能，两个释放路径都没有把指针置空，连续释放两次即对 NonPagedPool 上的 MDL 造成 double free；把该 MDL 槽位用 NpFr/IoSb 等对象占位、转换成对 Ws2P（ws2ifsl）对象的 UAF，再在关闭 ws2ifsl handle 时获得任意递减，将当前线程 `_KTHREAD.PreviousMode` 从 UserMode 改为 KernelMode，即可让 Nt* 系列 API 跳过用户态地址校验，构造内核任意读写并窃取 SYSTEM token。

## 原理

- **原始缺陷**：驱动的 IOCTL 分配函数把 MDL 映射到用户态并保存指针，释放函数释放映射/内存后不把指针清空；同一指针再释放一次触发 double free，对象为 NonPagedPool 上的 MDL。
- **从 double free 到 UAF**：第一次释放后立刻用可控对象占位同一 pool 槽位，第二次释放会把该对象当成 MDL 再次释放，使其成为悬空对象；后续再对该槽位分配/使用即为 UAF。
- **占位对象选择**：原文使用 NpFr（named pipe，`NpFr*` pool tag）与 IoSb（`IopVerifierExAllocatePoolWithQuota`，`IoSb*`）做堆喷，目标是让被释放的槽位被 Ws2P（`ws2ifsl.sys` 对象）占据；Nu1L 的另一解使用 CLFS 对象，说明可选对象不唯一。
- **任意递减**：Ws2P 对象在关闭对应 ws2ifsl handle 时会执行清理逻辑，其中包含对某字段的递减；通过 UAF 控制该对象的字段/指针，可使递减作用到攻击者选择的地址，得到一个 arbitrary decrement 原语。
- **PreviousMode**：`_KTHREAD.PreviousMode` 为 1 表示系统调用来自用户态，内核在执行 `NtReadVirtualMemory`/`NtWriteVirtualMemory` 等 API 时会校验目标地址是否在用户空间；把它改成 0（KernelMode）后，这些 API 不再做用户态地址检查，从用户态即可读写内核地址。
- **提权收尾**：用内核任意读定位当前进程/线程的 token 与 `_KTHREAD`，再用任意写把 token 替换为 SYSTEM token（或直接改 PreviousMode 后用 API 操作），完成本地提权。
- **64 位调用 32 位 IOCTL 的坑**：`IOCTL_ALLOCATE32` 路径中 `ULONG MappedBuffer = (ULONG)MmMapLockedPagesSpecifyCache(...)` 把 64 位内核地址截断成 32 位，64 位用户态进程拿到的是非法地址，访问即蓝屏；预期用 32 位程序触发该 IOCTL。

## 触发条件

- 目标安装存在 double free 缺陷的第三方驱动，且普通用户可打开设备并发送对应 IOCTL。
- 目标 Windows 版本允许 Medium Integrity 读取内核地址且 PreviousMode 方法可用（原文提示 Windows 11 Build 22621 仍可）。
- 攻击者能在进程内做 pool spray（命名管道、verifier 分配、CLFS 等）并控制对象布局。
- 需要 32 位进程调用 32 位分配 IOCTL，避免地址截断导致蓝屏。

## 利用步骤

1. 打开驱动设备，调用 allocate IOCTL 获得 MDL 映射的用户态地址。
2. 调用 free 释放，再用另一个 free 路径（或同一路径）二次释放同一 MDL，制造 double free。
3. 在两次释放之间/之后用 NpFr（大量命名管道）与 IoSb 对象堆喷，目标是让 Ws2P 对象落到被释放的 pool 槽位。
4. 关闭/重新打开 ws2ifsl handle，触发 Ws2P 清理路径中的递减；通过 UAF 布局让递减落在 `_KTHREAD.PreviousMode`（或先伪造指针链指向该字段）。
5. 确认 PreviousMode 变为 0 后，用 NtReadVirtualMemory/NtWriteVirtualMemory 对内核地址读写。
6. 遍历当前进程 EPROCESS/Token，找到 SYSTEM token 并写入自身进程 token 指针；或直接修改 token 权限位，完成提权。
7. 若使用 64 位进程，注意 IOCTL_ALLOCATE32 的 integer truncation 会导致蓝屏，应改用 32 位进程。

## PoC

无完整 PoC（原文未给出 exp 细节，作者 exploit 以外部压缩包提供）。关键 IOCTL 定义：

```c
#define IOCTL_ALLOCATE32 \
    CTL_CODE( SIOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS )

ULONG MappedBuffer = (ULONG)MmMapLockedPagesSpecifyCache(
    Mdl, UserMode, MmNonCached, NULL, FALSE, NormalPagePriority); // 32 位地址，64 位进程会截断
```

## 变体与关联

- 变体：占位对象可用 CLFS（Nu1L 解法）、named pipe、verifier 分配等，核心是“让 UAF 槽位被能触发可控递减/写的对象占据”。
- 变体：得到任意递减后可改 PreviousMode、token 引用计数或 ACL，按目标版本选择稳定路径。
- 关联：Windows PreviousMode 改写提权的其他案例见 [[pentest-privilege-escalation-appid-sys-cve-2024-21338-previousmode-system-token]]；Windows 内核 double free 利用的通用堆风水见 [[binary-pwn-kernel-cve-2024-1086-nft-verdict-double-free-dirty-pagetable-modprobe]]。
- 边界：原文只描述策略与对象选择，未给出偏移、pool tag 细节、完整 ROP/利用代码；换 Windows 版本需重新标定 `_KTHREAD` 偏移与对象布局。

## 检测与防御

- 修复：驱动在释放后把指针置空，使用引用计数/句柄对象管理 MDL 生命周期；对 IOCTL 的分配/释放做状态校验，禁止重复释放。
- 加固：开启内核池隔离（segment heap/pool partitioning）、SMEP/SMAP/KVA shadow；限制普通用户对第三方驱动设备的访问。
- 检测：驱动设备被频繁打开/关闭；同一 MDL 地址重复释放；异常命名管道/CLFS 对象暴增；线程 PreviousMode 被修改或 Nt* API 对内核地址的异常访问。
