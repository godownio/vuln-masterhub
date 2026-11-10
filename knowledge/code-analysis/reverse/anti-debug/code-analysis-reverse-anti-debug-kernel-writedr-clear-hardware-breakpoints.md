---
id: code-analysis-reverse-anti-debug-kernel-writedr-clear-hardware-breakpoints
title: 内核驱动定时对 DR0–DR3 写 0 清除硬件断点：__writedr(0..3,0) 抵消调试器断点
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: kernel-writedr-clear-hardware-breakpoints
aliases:
- __writedr 清零
- DR0 DR3 调试寄存器
- 硬件断点清除
- 内核反调试
- Festi 反调试
- ProtoHandler 反调试
tags:
- reverse
- anti-debug
- windows
- kernel
- hardware-breakpoint
- dr-register
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:37:47+08:00'
  notes: 已对照原文 content.md 与 33 张图片逐项核对（Festi 样本分析）；六卡分别对应文件系统过滤隐藏/SSDT 注册表隐藏/直发 IRP 通信/.cdata XOR API 名/DR 寄存器反调试/日期种子 DGA，各自技术原子独立、判为原子粒度合格；与 dup-scan 中同文 related pair 并列保留（机制与触发不同）；未动态运行驱动/样本。
---

## 一句话结论

Festi 在协议处理例程 `ProtoHandler` 开头连续执行 `__writedr(0,0)`、`__writedr(1,0)`、`__writedr(2,0)`、`__writedr(3,0)`，把调试地址寄存器 DR0–DR3 全部清零；调试器设置的硬件断点地址被抹掉后不再触发，从而在不调用常见 `IsDebuggerPresent`/`NtQueryInformationProcess` 的情况下干扰内核/用户态调试。

## 原理

- **硬件断点依赖 DR 寄存器**：x86/x64 调试寄存器 DR0–DR3 保存 4 个硬件断点地址，DR7 保存启用位/类型/长度，DR6 保存命中状态。调试器（WinDbg/OllyDbg/x64dbg/内核调试器）设置硬件断点时写这些寄存器。
- **内核可直接写 DR**：驱动通过 `__writedr(reg, value)` 内建函数（或内联 `mov drN, reg`）在 Ring0 写调试寄存器；不需要用户态 API。Festi 在每次协议处理/定时循环中清零 DR0–DR3，使硬件断点失效。
- **为什么有效**：硬件断点不修改代码字节，常被用于对抗 `0xCC` 检测/自校验；清零 DR 后断点消失，调试者会看到程序“跳过”断点或断点不触发。它也不产生明显的 API 调用（如 `NtSetInformationThread`），较隐蔽。
- **局限**：只清 DR0–DR3，不清 DR7 的启用位（若调试器重新写 DR7/DR0-3 可恢复）；软件断点（`0xCC`）、内存断点、单步/异常调试仍可用；若驱动频繁写 DR，调试器可检测到 DR 值被外部修改；在启用 HVCI/虚拟化调试时行为可能不同。
- **文章位置**：`ProtoHandler` 先写 4 个 DR 再调 `ProtoHandler01` 处理 C&C 协议，说明反调试与通信处理绑定，可能周期性执行。

## 触发条件

- 目标为内核驱动/内核模块，具备 Ring0 权限，能执行 `__writedr`/`mov drN` 指令。
- 样本在关键路径/定时循环中调用清零逻辑；分析者使用硬件断点调试该驱动或相关用户态进程。
- 调试环境未使用虚拟化/硬件调试绕过（如 HyperDbg、VMware GDB stub）或未监控 DR 写。
- 仅用于授权恶意样本分析/反调试研究。

## 利用步骤

1. 静态定位 `ProtoHandler`/初始化循环中的 `__writedr`/`mov dr0-dr3` 指令；记录调用频率与所在线程。
2. 动态验证：在调试器中设置硬件断点（如 `ba e 1 <addr>`），运行样本，观察断点是否被清除/不触发；用 `r dr0,dr1,dr2,dr3` 查看值变为 0。
3. 绕过：改用软件断点/内存断点/单步；或使用虚拟机监控器/HyperDbg 在 Ring-1 层调试，避免依赖客户机 DR；也可在每次断点前重新写 DR（脚本化）。
4. 检测：在调试器中监控 `mov drN` 指令/`__writedr` 调用，或在驱动加载后定期检查 DR 值变化。
5. 分析反调试逻辑与通信/持久化路径的关系，确认清零只是干扰还是有条件触发。

## PoC

```c
// 文章 ProtoHandler 的反调试片段（重写示意）
char ProtoHandler(int a1) {
    __writedr(0, 0);   // DR0 = 0
    __writedr(1, 0);   // DR1 = 0
    __writedr(2, 0);   // DR2 = 0
    __writedr(3, 0);   // DR3 = 0
    return ProtoHandler01(a1);
}
```

```text
# 调试器侧观察
0: kd> r dr0,dr1,dr2,dr3
dr0=0000000000000000 dr1=0000000000000000 dr2=0000000000000000 dr3=0000000000000000
# 原硬件断点地址被清零，断点不再命中
```

## 变体与关联

- 变体：同时清 DR6/DR7（`__writedr(6,0)`/`__writedr(7,0)`）更彻底；或随机化清零时机、只在检测到调试器时清。
- 变体：用户态也可通过 `NtSetContextThread`/`SetThreadContext` 清 DR；内核态还可 hook `NtGetContextThread`/`NtSetContextThread` 隐藏 DR。
- 变体：与 `IsDebuggerPresent`、PEB 检查、`NtQueryInformationProcess`、时间检测组合，形成多层反调试。
- 关联：[[code-analysis-reverse-anti-debug-exception-timing-checksum-bypass]]（SEH/INT2D/RDTSC 等动态反调试）、[[pentest-c2-hardware-breakpoint-dr7-rf-setup]]（硬件断点安装原语，作为对抗面）、[[pentest-c2-hardware-breakpoint-veh-amsi-etw-bypass]]（硬件断点+VEH 绕过）。

## 检测与防御

- 检测：调试器/内核监控 `mov drN` 写操作；在驱动加载后对比 DR 值基线；用虚拟化层（HyperDbg/Intel VT-x）在客户机外设置断点；检查驱动是否导入/内联 `__writedr`。
- 防御：分析环境使用硬件虚拟化调试/内存断点/软件断点组合；对关键函数做代码完整性校验；在 VM 中快照/回滚，减少反调试影响。
- 说明：本文是内核 rootkit 反调试机制分析，severity 记为 low；仅用于授权样本分析与防御研究。
