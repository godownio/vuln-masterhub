---
id: code-analysis-dynamic-debugging-hardware-breakpoint-dr6-single-step-source
title: 硬件断点命中判别：DR6 的 B0–B3 区分硬件断点单步异常与 EFLAGS.TF 单步
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: hardware-breakpoint-dr6-single-step-source
tags:
- reverse-engineering
- debugging
- hardware-breakpoint
- dr6
- dr7
- single-step
- windows
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V353
  verified_at: '2026-11-09T00:49:17+08:00'
  notes: 已对照原文与37张截图核对；原理/步骤与原文一致，仅保留调试器通用机制补充；未在本机复现调试过程
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-hardware-breakpoint-dr6-single-step-source/
draft: false
kb_aliases:
- DR6 B0-B3
- 硬件断点单步异常
- STATUS_SINGLE_STEP 来源
- TF 单步区分
- 调试寄存器 DR6
- 硬件断点 4 个限制
- 线程 Context 硬件断点
---

## 一句话结论

硬件断点把线性地址写入调试寄存器 Dr0–Dr3（最多 4 个），由 Dr7 控制使能、类型和长度；命中时和 `EFLAGS.TF` 单步一样都产生 `STATUS_SINGLE_STEP` 异常，单看异常码无法区分，必须读 Dr6 的 B0–B3：某一位为 1 表示对应硬件断点触发，B0–B3 全 0 才是 TF 单步。

## 原理

- **调试寄存器布局**：x86 有 8 个调试寄存器 Dr0–Dr7，Dr4/Dr5 保留；只有 Dr0–Dr3 存放线性地址，所以同时最多 4 个硬件断点。
- **Dr7 控制**：`L0/G0`–`L3/G3` 分别控制 4 个槽的局部/全局使能；`LENx` 指定监视长度（`00`=1 字节、`01`=2 字节、`11`=4 字节，64 位下 `10`=8 字节）；`R/Wx` 指定类型（`00`=执行、`01`=写入、`11`=读写访问）。
- **Dr6 状态**：硬件断点命中后，Dr6 的 `B0`–`B3` 对应位置 1，指明是哪个槽触发；`EFLAGS.TF` 置位导致的单步异常同样走 `STATUS_SINGLE_STEP`，但此时 `B0`–`B3` 全为 0。因此 Dr6 的作用就是区分“硬件断点单步”与“TF 单步”两种来源。
- **按线程隔离**：硬件断点保存在线程 CONTEXT 的调试寄存器中，`SetThreadContext` 只影响指定线程，其他线程不会继承；多线程程序若要覆盖全部线程，需要逐个线程写入上下文。
- **不写代码**：`0xCC` 会被代码段 CRC/字节扫描发现，硬件断点只在寄存器中记录地址，不留下代码字节痕迹，且可断在被优化代码的任意地址；代价是槽位仅 4 个、长度和对齐受限。
- **三种类型**：执行断点（R/W=`00`）在指令执行前停下；写入断点（`01`）在写指定地址后触发；访问断点（`11`）在读写该地址时触发，可用于追踪“谁改了某个变量”。

## 触发条件

- 目标为 Windows 用户态线程，分析者能对其调用 `GetThreadContext`/`SetThreadContext`（调试器、注入 DLL 或进程内 VEH 场景）。
- 目标地址已知（代码或数据），且对应槽位空闲。
- 需要区分单步异常来源，或因目标有代码字节自校验而不能使用 CC 断点。

## 利用步骤

1. 调用 `GetThreadContext` 获取目标线程 CONTEXT（`CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS`）。
2. 把目标线性地址写入空闲的 Dr0–Dr3；按监视类型/长度设置 Dr7 对应槽的 `L/G`、`R/W`、`LEN` 位。
3. `SetThreadContext` 写回使断点生效；若目标有多个线程且需全覆盖，逐线程重复。
4. 异常处理中获得 `STATUS_SINGLE_STEP`（`0x80000004`）时读取 Dr6：`(Dr6 & 0xF)` 的哪一位为 1 就是哪个槽命中；为 0 则说明是 TF 单步。
5. 处理完成后清除 Dr6 状态、恢复 Dr7 对应位；对执行断点置 `EFLAGS.RF`（bit16）避免同一条指令立即重复断下。

## PoC

无独立 PoC；核心判别逻辑（基于 Windows CONTEXT 接口的标准用法）：

```c
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &ctx);
ctx.Dr0 = (DWORD_PTR)target;          // 槽 0 写入监视地址
ctx.Dr7 |= 1;                          // L0=1 使能
ctx.Dr7 &= ~(0xFu << 16);             // RW0=00 执行, LEN0=00 1 字节
SetThreadContext(hThread, &ctx);

// STATUS_SINGLE_STEP 处理：
// (ExceptionInfo->ContextRecord->Dr6 & 0xF) == 0x1  -> Dr0 硬件断点命中
// (ExceptionInfo->ContextRecord->Dr6 & 0xF) == 0    -> EFLAGS.TF 单步（非硬件断点）
```

## 变体与关联

- **硬件执行断点安装原语**：焦点在 Dr7 位域拼装、挂起线程下发 CONTEXT 与 RF 防重复，可作为本卡的底层安装步骤。
- **内核定时清 Dr0–DR3**：反调试驱动周期性把调试寄存器写 0，直接抵消硬件断点。
- **硬件断点 + VEH hook**：在异常处理中改 CONTEXT 寄存器或跳转流程，把硬件断点用作无痕 hook/绕过。
- **TF 单步反调试**：样本用 `EFLAGS.TF` + SEH 制造单步异常差异，检测时同样要依赖 Dr6 区分来源。
- **软件断点/内存断点**：前者改代码字节，后者改页属性，三者可互为替代。

## 检测与防御

- **检测**：读取线程 CONTEXT 的 Dr0–Dr3 是否非零、Dr7 使能位是否被置位；检查 Dr6 状态；对调试寄存器变化做交叉校验。
- **反制**：内核驱动定时清零 Dr0–Dr3（见关联卡），或在关键路径用 `GetThreadContext` 自检；EDR 也常用硬件断点监视敏感 API，因此同样的 Dr 检测逻辑对攻防双方通用。
- **分析者注意事项**：硬件断点是线程级的，目标换线程后断点不生效；4 个槽位有限，需要规划执行/写入/访问断点的分配。
