---
id: code-analysis-reverse-anti-debug-cpuid-hypervisor-bit-intel-model-gate
title: CPUID 反虚拟机：leaf 1 ECX 符号判 hypervisor 位 + GenuineIntel 型号白名单设置全局门控
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: cpuid-hypervisor-bit-intel-model-vm-gate
aliases:
- CPUID 反 VM
- hypervisor 位检测
- ECX 符号判断
- GenuineIntel 校验
- IsPhysicalMachine
- Intel 型号白名单
tags:
- anti-vm
- anti-debug
- cpuid
- hypervisor
- windows
- evasion
- malware
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V435
  verified_at: '2026-11-09T20:14:31+08:00'
  notes: 已对照原文与图12/15核对：IsPhysicalMachine 用 EAX=1;cpuid;result=_ECX>=0 判 hypervisor 位（ECX bit31）；图15 IsProcessorFeaturePresent(PF_XMMI64)、leaf0 EBX/EDX/ECX 分别与 'uneG'/'Ieni'/'letn' 异或判 GenuineIntel、leaf1 EAX 掩码后与型号表比对后 global_CPU_type|=1u，均与卡一致。核对中已将卡内误写的型号示例 0x206F0 按图15修正为 0x20660/0x20670，并补 0x30650/0x30660/0x30670；未实测。与 qemu-tcg 卡（仅顺带提及 CPUID hypervisor 位，主体为 TCG 竞态/SIMD）不同链，不重复；dup-scan.json 早于建卡且无本篇 pair。
---

## 一句话结论

样本用内联汇编执行 `CPUID`：leaf 1 返回的 `ECX` 最高位是 hypervisor 存在位，按有符号整数读时若在虚拟机中则为负，于是 `result = _ECX >= 0` 就被当作“物理机”；同时用 leaf 0 的厂商串（GenuineIntel）与 leaf 1 的 family/model 白名单设置全局 CPU 类型标志，供后续逻辑（如是否执行脱钩/走真实流程）门控。

## 原理

- **hypervisor 位**：CPUID leaf 1 的 ECX bit 31 表示“运行在 hypervisor 下”。把它当作有符号 int 读取时，bit31=1 即负数；代码写 `result = _ECX >= 0`，在物理机上为真、在多数虚拟机中为假。样本在 `DllEntryPoint` 与后续函数中重复调用该判断，并用全局变量影响后续行为。
- **厂商/型号校验**：先 `IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE)`；再 CPUID leaf 0 取 EBX/EDX/ECX 并与 `'uneG'`/`'Ieni'`/`'letn'` 异或，判断是否为 `GenuineIntel`；leaf 1 的 EAX 得到 family/model/stepping，与一组 Intel 型号值（如 0x106C0、0x20660/0x20670、0x30650/0x30660/0x30670 等）比对，命中则 `global_CPU_type |= 1`。
- **门控方式**：该全局标志决定后续是否执行 ntdll 脱钩等敏感逻辑；若判断为 VM/非目标 CPU，就走“膨胀代码/无意义分支”或跳过真实行为——既降低沙箱中的暴露，又增加分析难度。
- **为什么要两层**：仅 hypervisor 位可被虚拟机配置隐藏；再加上厂商串与具体型号，可进一步识别 QEMU/KVM/部分云主机，并限定只在攻击者预期的 Intel 硬件上运行。
- 限制：CPUID 结果可被 hypervisor 伪造（隐藏 hypervisor 位、伪装厂商/型号），并非可靠的安全边界。

## 触发条件

- 样本在初始化/入口执行 CPUID 检查，并以结果决定后续行为。
- 分析环境为常见虚拟机/沙箱，hypervisor 位未隐藏或 CPU 型号不在白名单。
- 内联汇编可直接执行（用户态即可，无需驱动）。

## 利用步骤

1. 入口先执行 `_EAX=1; cpuid;` 读 ECX，按有符号比较 `>=0` 判断物理机，结果写入全局变量。
2. 执行 `_EAX=0; cpuid` 取厂商串，与 GenuineIntel 异或比对；再 `_EAX=1` 取 family/model，与硬编码型号表比对。
3. 依据结果设置 `global_CPU_type` / `global_is_not_VM_flag` 等全局标志。
4. 后续敏感逻辑（解密、脱钩、注入）读取这些标志；条件不满足则走无用分支或退出。

## PoC

无 PoC（原文为样本行为分析）。核心形态：

```c
int IsPhysicalMachine(void) {
    int ecx;
    __asm { mov eax, 1; cpuid; mov ecx, ecx }   // leaf 1: ECX bit31 = hypervisor
    return ecx >= 0;                            // VM 中为负 -> false
}
```

## 变体与关联

- 关联 [[code-analysis-reverse-anti-debug-qemu-tcg-anti-vm-tb-atomicity-unaligned-simd]]：QEMU TCG 下结合 CPUID/SIDT 等差异的检测与绕过。
- 关联 [[code-analysis-reverse-anti-debug-festi-vmware-backdoor-vpcext]]：VMware 后门 I/O 端口检测，另一类 VM 指纹。
- 关联 [[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]：注册表/进程/MAC 等组合指纹；本卡是 CPU 指令级指纹。
- 变体：CPUID leaf 0x40000000 读 hypervisor 厂商串；检查 TSC/APIC/ACPI 表；用 `rdtsc` 时序差异识别 VM。
- 边界：hypervisor 可关闭 hypervisor 位、伪装 GenuineIntel 与型号；裸机分析不受影响，但需注意样本只对特定 Intel 型号运行。

## 检测与防御

- 分析侧：在沙箱中隐藏 hypervisor 位、伪装厂商串与常见 Intel 型号；或 hook/跳过 CPUID 相关判断与全局标志。
- 检测：样本入口出现 CPUID 后紧接全局标志赋值、并以该标志门控解密/注入，是典型 anti-VM 结构。
- 防御：沙箱/仿真器应覆盖 CPUID 伪装的多种组合；威胁狩猎可将“CPUID + 硬编码型号表 + 条件分支”作为样本指纹。
