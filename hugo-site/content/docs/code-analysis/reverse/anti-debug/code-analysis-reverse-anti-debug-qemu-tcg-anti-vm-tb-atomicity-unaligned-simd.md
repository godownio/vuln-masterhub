---
id: code-analysis-reverse-anti-debug-qemu-tcg-anti-vm-tb-atomicity-unaligned-simd
title: QEMU TCG 反 VM 检测：TB 原子性竞态与未对齐 SIMD 异常差异（附 Windows API/CPUID/SIDT 检查与绕过）
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: qemu-tcg-anti-vm-tb-atomicity-unaligned-simd
tags:
- anti-debug
- anti-vm
- anti-sandbox
- windows
- qemu
- tcg
- cpuid
- sidt
- malware-analysis
- reverse-engineering
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:16+08:00'
  notes: 已对照原文与 img/02.png（QEMU TCG 日志 mov r7,#1 -> mov_i32 tmp3,$0x1; mov_i32 r7,tmp3）核对：GetPwrCapabilities ThermalControl、磁盘阈值、CPUID Hypervisor、SIDT Red Pill、TCG TB 竞态、未对齐 movntps 与 MinHook/patch 绕过均取自原文。原文未给实测结果，代码有内联汇编/逻辑问题；未编译运行。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-qemu-tcg-anti-vm-tb-atomicity-unaligned-simd/
draft: false
kb_aliases:
- 反虚拟机
- Anti-VM
- QEMU TCG 检测
- TB 原子性检测
- movntps 未对齐检测
- Red Pill
- SIDT 反虚拟机
- CPUID Hypervisor 位
- GetPwrCapabilities ThermalControl
---

## 一句话结论

恶意样本可在执行恶意逻辑前用一组“物理机 vs 虚拟机”差异做环境判定：`GetPwrCapabilities` 的 `ThermalControl`、磁盘总/剩余容量阈值、CPUID 的 Hypervisor 位与 `0x40000000` 叶子 ID、SIDT 读取的 IDT 地址字节（Red Pill），以及更针对 QEMU 的 TCG 特性——翻译块（TB）内不响应中断的竞态窗口、未对齐 `movntps` 被透明处理而不触发异常；分析者可通过调整 VM 配置、MinHook/Detours 挂钩检测 API、或在调试器中 patch 检测指令来绕过。

## 原理

- **热控制检测**：`GetPwrCapabilities` 返回 `SYSTEM_POWER_CAPABILITIES`，其中 `ThermalControl` 表示系统是否支持热区管理。物理机通常为 TRUE；虚拟机硬件是仿真的、真实散热由宿主处理，常见为 FALSE。样本据此判定 VM。
- **磁盘容量检测**：`GetDiskFreeSpaceExA` 取总容量/剩余容量。分析用虚拟机常配置 20–60GB 磁盘，物理桌面机普遍 ≥256GB；样本以 `总容量 < 20GB` 或 `剩余 < 10GB` 等阈值判定 VM。该特征是启发式，容易误判也容易通过扩容绕过。
- **CPUID 检测**：`eax=1` 时 `ecx[31]` 是 Hypervisor 存在位；`eax=0x40000000` 返回 12 字节 Hypervisor ID（如 `Microsoft Hv`、`KVMKVMKVM`、`TCGTCGTCGTCG`、`VBoxVBoxVBox`）。这是最稳定的检测之一，除非 hypervisor 主动隐藏。
- **SIDT/Red Pill**：`sidt` 读取 IDTR 的 IDT 基址。经典 Red Pill 认为物理机 IDT 地址高位字节为 `0xFF`，VM 的 IDT 位于不同区域；样本取基址第 3 字节判断。该方法依赖具体 OS/虚拟化实现，现代环境不一定可靠。
- **QEMU TCG 的 TB 原子性**：TCG 把客户机指令翻译成宿主指令块（TB），TB 之间才检查中断/调度；样本开两个线程反复执行 `lock++ → nop 循环 → lock--`，物理 CPU 可在任意指令间被抢占，可能观察到 `lock ≥ 2`；若 TB 执行期间不被外部事件打断，则很难出现中间态，样本据此推断 QEMU。该差异是概率性的，且 `nop` 循环/函数调用本身会跨 TB，实际窗口取决于 TB 边界与宿主调度，不能视为确定性检测。
- **QEMU 未对齐 SIMD**：`movntps` 要求 16 字节对齐，物理机访问未对齐地址会触发访问违规异常；部分 QEMU/TCG 配置会透明处理未对齐访问而不抛异常。样本注册 vectored exception handler，执行未对齐 `movntps`：抛异常判物理机，不抛判 QEMU。该行为依赖 QEMU 版本、宿主架构与 TCG 实现，并非所有 QEMU 都如此。
- **绕过思路**：三类——改 VM 配置接近物理机（内存/磁盘/网卡/CPU 虚拟化标志）、用 MinHook/Detours 挂钩检测 API 并篡改返回结构、在 x64dbg/IDA 中 patch 检测指令或条件跳转（如把 `cpuid` 替换 NOP、反转 SIDT 判断、把 `movntps` 换成其他指令）。

## 触发条件

- 目标样本在恶意逻辑前执行环境检查，且分析运行在 VMware/VirtualBox/QEMU 等虚拟或仿真环境。
- 样本使用上述 API/指令中的一种或多种组合；单一启发式检查可能被高仿真实例自然绕过。
- 分析者具备调试/插桩能力（x64dbg、IDA、Frida、MinHook、API Monitor），或可修改 VM 配置。
- QEMU TCG 专项检查仅在纯 TCG（无 KVM 加速）或特定 TCG 配置下成立；KVM/Hyper-V 硬件加速会改变时序与异常行为。

## 利用步骤

1. 在 VM 中运行样本，记录退出/崩溃/诱饵行为；与物理机对比，若仅在 VM 中出现异常分支，优先怀疑反 VM。
2. 静态定位检测点：搜索 `GetPwrCapabilities`、`GetDiskFreeSpaceEx`、`cpuid`（`0F A2`）、`sidt`（`0F 01 /1`）、`movntps`（`0F 2B`）及异常处理注册（`AddVectoredExceptionHandler`）。
3. 动态验证：在 API/指令处下断，观察返回值与分支；对 CPUID 记录 `eax=0/1/0x40000000` 的寄存器值；对 SIDT 记录 IDT 基址；对 TCG 检测观察共享变量是否出现 `≥2`。
4. 选择绕过：
   - **配置层**：增大内存/磁盘（如 ≥16GB/≥512GB）、使用物理机同款网卡型号、启用/隐藏虚拟化扩展；对 QEMU 可调整 `-cpu` 模型与 TCG 参数，但无法完全消除 TCG 时序差异。
   - **API 层**：MinHook 挂钩 `GetPwrCapabilities` 强制 `ThermalControl=TRUE`；挂钩 `GetDiskFreeSpaceExA` 返回大容量；挂钩 WMI/`LoadLibraryA` 等同类检查。
   - **指令层**：patch `cpuid` 为 NOP 或把 `bt ecx,31` 改为清零；反转 SIDT 字节比较；把未对齐 `movntps` 替换为 `rdtsc` 或其他会触发异常的指令。
5. 逐项验证：多项检查常以 `&&` 组合，需全部满足；每次 patch/hook 后重跑，确认进入恶意分支。

## PoC

原文给出的最小检测代码（节选，未实测，存在编译/逻辑问题，仅示意）：

```c
/* 1. 热控制：VM 常见 ThermalControl=FALSE */
SYSTEM_POWER_CAPABILITIES caps;
if (GetPwrCapabilities(&caps) && !caps.ThermalControl) puts("VM");

/* 2. 磁盘容量阈值 */
GetDiskFreeSpaceExA("C:\\", &c_free, &c_total, &c_total_free);
if (c_total.QuadPart < 20ULL*1024*1024*1024) puts("VM");

/* 3. CPUID Hypervisor ID */
__asm__ volatile("movl $0x40000000, %%eax; cpuid"
                 : "=b"(ebx), "=c"(ecx), "=d"(edx) : : "%eax");
/* 拼接 ebx/ecx/edx 为 12 字节字符串，匹配 "TCGTCGTCGTCG"/"VBoxVBoxVBox" 等 */

/* 4. SIDT / Red Pill */
struct { uint64_t base; } __attribute__((packed)) idtr;
__asm__("sidt %0" : "=m"(idtr));
if (((idtr.base >> 16) & 0xFF) != 0xFF) puts("VM");

/* 5. QEMU TCG：两线程 lock++ / nop / lock--，若 lock 始终 <2 判 QEMU */
/* 6. QEMU 未对齐 movntps：注册 VEH，执行 movntps 到 rsp+1；不抛异常判 QEMU */
```

MinHook 绕过 `GetPwrCapabilities`：

```c
BOOL WINAPI HookedGetPwrCapabilities(PSYSTEM_POWER_CAPABILITIES p) {
    BOOL r = TrueGetPwrCapabilities(p);
    if (r) p->ThermalControl = TRUE;   // 伪装物理机
    return r;
}
```

## 变体与关联

- VMware/VirtualBox 检测更常见的是 `vmGuestLib.dll`、WMI 热区、MAC OUI、VM 进程/服务名、注册表键等；参见 [[code-analysis-reverse-anti-debug-silverfox-installer-vm-detection]] 与 [[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]。
- CPUID Hypervisor 位/ID 可用 `GetSystemFirmwareTable`、WMI、驱动查询等替代；部分样本还会检查 `rdtsc` 时序、`in` 指令、I/O 端口。
- QEMU 专项还可检测 TCG 的指令翻译差异（如 `self-modifying code`、`rdtsc` 频率、未实现指令），但都依赖 QEMU 版本与配置。
- 绕过与反绕过是持续对抗：分析环境应尽量使用硬件虚拟化 + 隐藏 hypervisor 特征（KVM 的 `kvm=off`、Hyper-V  enlightenments、QEMU 的 `-cpu host,hv_*`），并配合 API hook 与指令 patch。
- 关联 [[code-analysis-reverse-anti-debug-sandbox-environment-checks]]、[[code-analysis-reverse-anti-debug-linux-sandbox-environment-probes]]（通用反沙箱检查）。

## 检测与防御

- 对恶意样本分析：建立“检测点清单”（API、CPUID 叶子、SIDT、异常注册、时序循环），逐项 hook/patch 并记录返回值；不要只 patch 一处。
- 对沙箱/分析平台：减少可被观测的 VM 指纹（隐藏 hypervisor CPUID、关闭 VM 特有设备、模拟热区/磁盘容量、使用硬件加速降低 TCG 时序差异），但对强对抗样本无法保证完全隐身。
- 对防御方/EDR：监控样本对 `GetPwrCapabilities`、`GetDiskFreeSpaceEx`、`cpuid`/`sidt`、`AddVectoredExceptionHandler` 的异常组合调用，以及短时间内的多线程自增竞态循环；这些是反分析行为的强特征。
- 注意局限：本文的 QEMU TCG 检测代码未在原文中给出实测结果，TB 原子性与未对齐 `movntps` 行为随 QEMU 版本/宿主变化，不能作为确定性判据；相关检测思路应以低置信度看待。
