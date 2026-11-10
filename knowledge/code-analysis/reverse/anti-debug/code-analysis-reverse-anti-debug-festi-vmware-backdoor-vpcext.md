---
id: code-analysis-reverse-anti-debug-festi-vmware-backdoor-vpcext
title: Festi 驱动反虚拟机：VMware 后门 I/O 端口 0x5658（'VX'/'VMXh'）探测 + Virtual PC vpcext 指令 SEH 检测
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: vmware-backdoor-io-port-vpcext-seh-antivm
aliases:
- VMware 后门检测
- in eax, dx 0x5658
- VMXh
- vpcext 指令
- Virtual PC 检测
- f_anti_vm_check
- Festi 反虚拟机
tags:
- reverse
- anti-debug
- anti-vm
- vmware
- virtual-pc
- vpcext
- seh
- kernel-driver
- festi
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V323
  verified_at: '2026-11-08T15:42:32+08:00'
  notes: 已对照 content.md 与 img/13-16 核对：img13 反汇编 mov ecx,0Ah/mov edx,'VX'/in eax,dx/cmp ebx,'VMXh'，img14 __try 内 mov cl,1/push 5F23h/pop ebx/vpcext 7,0Bh 与 __except 返回 0，img15 f_anti_vm_check 任一命中返回 1，img09 DriverEntry 将返回值存 DriverObject_3 并仅在为 0 时调用 sub_21F75，均与卡一致。原子性：两个探针同属一个 f_anti_vm_check 反虚拟机函数与同一触发链，判为原子合格。未验证点：未动态运行驱动；原文只给 32 位 Festi 驱动片段，无受影响版本。dedup 候选 QEMU TCG/Silverfox/Defender emulator 检测等均非同链。
---

## 一句话结论

Festi 驱动的 `f_anti_vm_check()` 用两条与虚拟化实现强相关的探测识别分析环境：向 VMware 后门 I/O 端口 `0x5658`（`DX='VX'`）执行 `in eax, dx`，若 `EBX` 返回 `'VMXh'` 则判定运行在 VMware 中；在 SEH 保护的 `__try` 中执行 Virtual PC 专属的 `vpcext` 指令，若指令执行成功而不触发异常，则判定存在 Virtual PC 管理程序。任一命中返回 1，`DriverEntry` 随后跳过恶意初始化。

## 原理

- **VMware 后门 I/O 端口**：VMware 工作站/ESXi 在 hypervisor 中实现了后门通道，魔术端口为 `0x5658`（ASCII `VX`）。驱动内联汇编为 `mov ecx, 0Ah; mov edx, 'VX'; in eax, dx; cmp ebx, 'VMXh'`：在 VMware 上执行 `IN` 时由 hypervisor 拦截，`EBX` 被填入魔术值 `'VMXh'`；在物理机或其他 hypervisor 上会得到不同结果或触发异常。由于是特权指令，放在内核驱动中执行。
- **Virtual PC 的 `vpcext` 指令**：`vpcext` 是 Microsoft Virtual PC 专有指令，真实 CPU 上执行会触发非法指令异常（#UD）。代码把 `ebx` 设为 `0x5F23`、`cl=1`，在 `__try` 中执行 `vpcext 7, 0Bh`；如果 Virtual PC 管理程序存在，指令被识别并正常执行，不会进入异常处理器；如果不存在，`__except` 返回 0。`f_anti_vm_check()` 里两个探测分别包在 `sub_18FD0()`（VMware）和 `sub_1901D()`（VPC）中，命中任一即返回 1。
- **为什么用 SEH**：两条探测都可能触发异常——VMware 后门端口在非 VMware 环境下的行为未定义、`vpcext` 在真实 CPU 上是非法指令。用结构化异常处理包住探测，可以把“异常”当作“不是目标虚拟化环境”的正常分支，避免驱动崩溃。
- **检测结果如何使用**：`DriverEntry` 把 `f_anti_vm_check()` 的返回值存入 `DriverObject_3`，后续 `if (!DriverObject_3) sub_21F75(...)`——只有在未检测到虚拟机时才执行某段初始化；这与样本规避沙箱/自动分析的目的一致。
- **绕过思路**：在非 VMware 的 hypervisor（如 KVM/QEMU）中分析，或使用隐藏 VMware 后门/`vpcext` 的沙箱；也可以直接 patch `f_anti_vm_check` 的返回值或异常过滤器。

## 触发条件

- 样本为 32 位 Windows 内核驱动，在 `DriverEntry` 中调用反虚拟机检查；原文样本为 Festi。
- 分析环境为 VMware 或 Virtual PC 时会被识别；物理机/其他虚拟化平台可能不命中。
- 仅用于授权恶意样本分析，不运行驱动。

## 利用步骤

1. 在 `DriverEntry` 中定位 `f_anti_vm_check()` 调用及其返回值的使用（原文为 `DriverObject_3`）。
2. 进入 `sub_18FD0()`，确认 `mov edx, 'VX'`、`in eax, dx`、`cmp ebx, 'VMXh'` 的 VMware 后门探测。
3. 进入 `sub_1901D()`，确认 `__try` 中的 `vpcext 7, 0Bh` 与 `__except` 返回 0 的 Virtual PC 探测。
4. 动态分析时选择不暴露这些特征的 hypervisor；或 patch 两个子函数使其恒返回 0；或在异常处理器/`IN` 指令处下断确认命中路径。
5. 记录检测点作为 IOC：`0x5658`、`'VMXh'`、`0x5F23`、`vpcext` 字节序列，用于同族样本快速识别。

## PoC

原文反汇编对应的最小形态（伪代码，未执行）：

```c
// VMware 后门探测（sub_18FD0）
__try {
    // mov ecx, 0Ah; mov edx, 'VX'; in eax, dx
    if (/* ebx == 'VMXh' */) return 1;   // 运行在 VMware
    return 0;
} __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

// Virtual PC 探测（sub_1901D）
__try {
    // mov cl, 1; push 5F23h; pop ebx; vpcext 7, 0Bh
    return 1;                            // 指令未异常 -> Virtual PC
} __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

// f_anti_vm_check
if (sub_18FD0() || sub_1901D()) return 1;  // 命中任一虚拟机
return 0;
```

## 变体与关联

- 变体：改用 `cpuid` 叶 `0x40000000` 读取 hypervisor 厂商串、检查 `CPUID.1:ECX[31]` hypervisor present 位、`rdmsr` 读 VMware 特定 MSR、时间差/指令计数等；`vpcext` 也可换 `in`/`out` 到其他虚拟化端口。
- 关联：[[code-analysis-reverse-anti-debug-qemu-tcg-anti-vm-tb-atomicity-unaligned-simd]]（QEMU TCG 反 VM 探测）、[[code-analysis-reverse-anti-debug-silverfox-installer-vm-detection]]、[[code-analysis-reverse-anti-debug-silverfox-vmtools-mac-mouse-checks]]、[[code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks]]（其他虚拟机/沙箱检测手法）。
- 边界：非 VMware/Virtual PC 的分析环境不会被这两条探测命中；反之，若沙箱隐藏了后门端口或拦截了 `vpcext`，返回值会被伪造，检测失效。

## 检测与防御

- **样本检测**：YARA/字节特征匹配 `0x5658`、`'VMXh'`、`vpcext` opcode 与包含 `__try/__except` 的探测函数；在 IDA 中搜索 `in` 指令与 `0x5F23` 常量。
- **分析环境加固**：使用不实现 VMware 后门的 hypervisor、隐藏 hypervisor 厂商串、拦截 `IN 0x5658` 与 `vpcext`；或在驱动加载前 patch 反 VM 检查。
- **防御**：这类检查本身是恶意软件反分析行为；生产环境应依靠 EDR/内核完整性监控而不是调试器常驻；发现驱动包含此类探测时按可疑样本处置。
- **说明**：本卡是恶意样本的反分析技术分析，severity 记为 low；仅用于授权样本分析。
