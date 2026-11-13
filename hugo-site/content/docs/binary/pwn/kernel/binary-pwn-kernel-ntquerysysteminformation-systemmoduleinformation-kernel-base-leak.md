---
id: binary-pwn-kernel-ntquerysysteminformation-systemmoduleinformation-kernel-base-leak
title: NtQuerySystemInformation 的 SystemModuleInformation（0xB）类：用户态枚举内核模块并泄露 ntoskrnl.exe 基址
type: scenario
domain: binary
path: binary/pwn/kernel
technique: ntquerysysteminformation-systemmoduleinformation-kernel-base-leak
tags:
- windows
- kernel
- pwn
- kaslr
- info-leak
- ntquerysysteminformation
- systemmoduleinformation
- userland
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:35:42+08:00'
  notes: 已对照原文《从零探索现代windows内核栈溢出-以HEVD练习为例（下）》及全部 50 张截图核对：0xB=SystemModuleInformation、SYSTEM_MODULE_INFORMATION 布局、两次调用取长度、strstr 匹配 ntoskrnl.exe、示例基址 0xfffff8065b400000/0xfffff80245800000 均一致；PoC 为原文 ulGetKernelBase 的等价改写。未在本机复跑，偏移/gadget 需按目标 build 校正。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-ntquerysysteminformation-systemmoduleinformation-kernel-base-leak/
draft: false
kb_aliases:
- SystemModuleInformation
- NtQuerySystemInformation 0xB
- SYSTEM_MODULE_INFORMATION
- ntoskrnl 基址泄露
- Windows KASLR 绕过
- EnumDeviceDrivers 替代
---

## 一句话结论

以信息类 `0xB`（`SystemModuleInformation`）调用 `NtQuerySystemInformation`，内核会把已加载模块的 `SYSTEM_MODULE_INFORMATION` 数组（含每个模块的 `ImageBaseAddress`、`ImageSize` 和完整路径名）复制到调用者的用户态缓冲区，普通用户即可直接读出 `ntoskrnl.exe` 的加载基址，从而绕过 KASLR 计算 gadget 与内核函数地址。

## 原理

- **信息类 0xB**：`NtQuerySystemInformation` 的 `SYSTEM_INFORMATION_CLASS` 枚举中，`SystemModuleInformation = 0xB` 表示「已加载内核模块列表」。该枚举与返回结构没有完整公开文档，但结构稳定：`SYSTEM_MODULE_INFORMATION { ULONG ModulesCount; SYSTEM_MODULE Modules[1]; }`，每个 `SYSTEM_MODULE` 含 `ImageBaseAddress`（PVOID）、`ImageSize`、`Flags`、`Id`、`NameOffset`、`Name[MAXIMUM_FILENAME_LENGTH]` 等字段。
- **为什么能拿到真实基址**：KASLR 只随机化镜像加载位置，并不隐藏「模块列表」这一元数据；该接口本意是给诊断/安全工具枚举驱动，普通用户态调用即可，内核按真实虚拟地址填充 `ImageBaseAddress`，随后整体复制回用户缓冲区。
- **两次调用模式**：先以 `SystemInformation(NULL, 0)` 探测所需长度（返回 `STATUS_INFO_LENGTH_MISMATCH` 并写出 `ReturnLength`），按长度分配缓冲区后再次查询，遍历 `ModulesCount` 项。
- **名称匹配**：`Name` 是形如 `\SystemRoot\system32\ntoskrnl.exe` 的完整路径，用 `strstr(name, "ntoskrnl.exe")` 之类的子串匹配即可选中内核主镜像；同时也能枚举 `win32kbase.sys`、`ndis.sys` 等驱动的基址。
- **用途**：得到基址后，`运行时地址 = ImageBaseAddress + RVA`。RVA 可通过离线分析同一版本 ntoskrnl.exe（PDB、ROPgadget、IDA）获得，例如 ROP gadget、`ExAllocatePoolWithTag`、`RtlCopyMemory`、`PsInitialSystemProcess` 等；这是内核 Exploit 中成本最低的 KASLR 绕过之一。
- **与其它泄露方式的区别**：不依赖任意读/内存破坏原语，也不是漏洞；在只有普通用户权限、尚无内核原语时就能完成，是后续栈溢出/池溢出利用的前置步骤。

## 触发条件

- 目标为 Windows；调用进程能通过 `GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation")` 取到函数并发起系统调用（普通用户即可）。
- 需要解码 `SYSTEM_MODULE_INFORMATION`/`SYSTEM_MODULE` 的布局；不同 Windows 版本的字段宽度（32/64 位）与名称长度上限不同。
- 后续利用所需的 RVA 与目标 build 匹配；若只知道模块基址而不知道偏移，仍无法定位具体函数/gadget。
- 部分受管控环境可能通过 EDR/策略记录或限制该查询，案例未涉及此类限制。

## 利用步骤

1. 从 ntdll 导入 `NtQuerySystemInformation`（`SystemModuleInformation` 常量取 `0xB`）。
2. 以 `(0xB, NULL, 0, &len)` 调用，取得所需缓冲区长度。
3. 分配 `len` 字节（`GlobalAlloc(GMEM_ZEROINIT, len)`/`HeapAlloc`），再以 `(0xB, buf, len, &len)` 查询。
4. 把 `buf` 解释为 `SYSTEM_MODULE_INFORMATION`，遍历 `Modules[i]`，对 `Modules[i].Name` 做 `strstr` 匹配 `ntoskrnl.exe`。
5. 命中后返回 `Modules[i].ImageBaseAddress`；示例环境中得到 `0xfffff8065b400000`、`0xfffff80245800000` 等随启动变化的基址。
6. 用 `base + RVA` 计算 gadget/函数地址，交给后续 ROP 或 shellcode 使用（例如栈溢出卡中的 `pop rcx`、`mov cr4, rcx`）。

## PoC

```c
unsigned long long ulGetKernelBase(const char *module_name) {
    HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return 0;

    ULONG len = 0;
    NtQuerySystemInformation(0xB /* SystemModuleInformation */, NULL, 0, &len);

    PSYSTEM_MODULE_INFORMATION info =
        (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
    if (!info) return 0;

    NTSTATUS st = NtQuerySystemInformation(0xB, info, len, &len);
    if (st != 0) return 0;

    for (unsigned i = 0; i < info->ModulesCount; i++) {
        char *name = (char *)info->Modules[i].Name;
        if (strstr(name, module_name))
            return (unsigned long long)info->Modules[i].ImageBaseAddress;
    }
    return 0;
}
```

`SYSTEM_MODULE`/`SYSTEM_MODULE_INFORMATION` 需按目标位宽自行定义（64 位下 `PVOID` 为 8 字节，`Name` 为按字节的路径数组）。案例在 Windows 10 19045.2006 上返回 `ntoskrnl.exe` 基址并用于后续 ROP；未在本机复跑。

## 变体与关联

- 关联：[[binary-pwn-kernel-windows-driver-stack-overflow-ioctl-ret-hijack]]（同系列 HEVD 栈溢出，用本卡泄露的基址计算 gadget）。
- 关联：[[binary-pwn-kernel-windows-kvas-nonpaged-pool-executable-shellcode-rop]]（同一基址用于解析 `ExAllocatePoolWithTag`/`RtlCopyMemory` 的地址）。
- 变体：`EnumDeviceDrivers` 返回 `lpImageBase` 数组，第一项通常是 ntoskrnl；或 `LoadLibrary("ntoskrnl.exe")` 映射用户态副本后用 `GetProcAddress` 求 RVA，再与内核基址相加（BYOVD 场景常用）。
- 变体：`SystemHandleInformation` 等其它信息类可泄露内核对象地址（EPROCESS 等），与本卡的模块基址泄露互补。
- 变体：若已有任意内核读，可沿 `DriverObject->MajorFunction` 等对象链恢复基址（如命名管道 Attribute 链），不依赖本接口。
- 边界：只泄露模块基址，不提供任意读写；RVA 与目标 build 不一致会跳到错误地址导致 BSOD；内核模块列表还可能包含第三方驱动，适合做 BYOVD 目标筛选。

## 检测与防御

- 该接口本身是 Windows 正常诊断能力，单次调用难以判定恶意；可监控短时间大量 `NtQuerySystemInformation(0xB)` 调用、与随后的驱动访问/溢出入侵行为组合。
- 内核侧缓解：启用 HVCI、内核 CFG、KVA Shadow、SMEP/SMAP，降低拿到基址后的可执行原语；KASLR 不是保密边界，不能依赖其单独阻止利用。
- 缩减攻击面：限制普通用户加载/访问可被利用的第三方驱动；对设备对象做 ACL 与审计。
- 检测重点放在后续行为：对已知漏洞驱动的超长 IOCTL、内核崩溃、令牌替换、异常内核池分配等。
