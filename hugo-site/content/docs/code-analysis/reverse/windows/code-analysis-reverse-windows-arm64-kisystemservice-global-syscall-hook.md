---
id: code-analysis-reverse-windows-arm64-kisystemservice-global-syscall-hook
title: ARM64 全局系统调用 Hook：patch KiSystemService 前 12 字节跳 Code Cave（ADRP/ADD/BR trampoline + 回跳原函数第 4 条指令）
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: arm64-kisystemservice-global-syscall-hook
tags:
- reverse
- windows
- arm64
- rootkit
- kernel
- syscall-hook
- trampoline
- code-cave
- mdl
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T13:57:11+08:00'
  notes: 已对照原文与6图核对（图06 Original/Hooked/Hook Code Cave布局与adrp/add/br回跳）；12字节3指令覆盖、Cave先执行复制字节再恶意代码再trampoline回原函数+12字节的布局已修正一句话结论中的顺序表述；与x64 LSTAR MSR hook机制不同；原文调试模式关闭PatchGuard/DSE/SecureBoot且未展示运行结果，confidence=medium如实；无受影响版本区间；PoC未编译运行
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-arm64-kisystemservice-global-syscall-hook/
draft: false
kb_aliases:
- ARM64 Global Syscall Hook
- KiSystemService Hook
- Windows on ARM64 rootkit
- ADRP ADD BR trampoline
- Code Cave hook
- 全局 syscall hook
- KiPreprocessHardwareError code cave
---

## 一句话结论

全局 syscall hook 只打一个补丁：把 `KiSystemService` 入口前 12 字节（ARM64 三条指令）复制到内核 Code Cave，再用 `adrp/add/br` trampoline 覆盖原入口跳进 Cave；Cave 中先执行被复制的 12 字节，再执行恶意逻辑，最后用 trampoline 跳回原函数第 4 条指令（原入口 +12 字节），于是所有系统调用（而不只是某个 SSDT 表项）都会先经过 hook。这是 ARM64 版的“MSR/全局入口 hook”，同样受 PatchGuard/HVCI 与写只读内存的限制。

## 原理

- **单点入口**：ARM64 用户态 `SVC` 陷入 EL1 后，`VBAR_EL1 → KiArm64ExceptionVectors → KiUserExceptionHandler(+0x400) → KiSystemServiceException → KiSystemService`，所有 syscall 都汇聚到 `KiSystemService`，再按 syscall 号查 `KiServiceTable`。因此 patch `KiSystemService` 本身即可拦截全部系统调用，无需逐项改 SSDT。
- **12 字节覆盖 = 3 条指令**：ARM64 指令定长 4 字节，`adrp xip0, #page`（4B）+ `add xip0, xip0, #imm12`（4B）+ `br xip0`（4B）正好 12 字节；原文把原函数前 12 字节备份到 Code Cave，然后用这 3 条指令覆盖入口跳到 Cave。
- **Cave 中的布局**：先执行被复制出来的原 12 字节（等价于执行原函数前 3 条指令），再执行 hook 恶意代码，最后用 trampoline 跳到原函数第 4 条指令（`KiSystemService + 12`）继续正常分派流程。这样原函数的寄存器/栈状态与正常进入一致，避免破坏调用约定。
- **trampoline 的必要性**：ARM64 没有可携带 64 位绝对地址的 `jmp`；`adrp` 以页为单位计算 PC 相对地址（约 ±4GB 范围），`add` 补低 12 位，`br` 跳到寄存器。原文图示的 trampoline 形如：
  ```asm
  adrp xip0, <target & ~0xfff>
  add  xip0, xip0, #<target & 0xfff>
  br   xip0
  ```
  例：`adrp xip0, BOOTVID!VidSolidColorFill+0x80 (fffff8016bd93000)` / `add xip0, xip0, #0x214` / `br xip0` → 跳到 `0xfffff8016bd93214`。
- **Code Cave 与写保护**：与 ARM64 SSDT hook 相同，需要在已加载内核模块中找“两个 NOP（0xd503201f）+ 全 0”的可执行空洞（也可用其他可写可执行区域）；写 `KiSystemService` 只读代码页时要绕过写保护——ARM64 上 CR0.WP 手法无效，使用 MDL（`IoAllocateMdl` + `MmBuildMdlForNonPagedPool` + `MmMapLockedPagesSpecifyCache`）临时映射为可写再 `RtlCopyMemory`（`SuperCopyMemory`），并提升 IRQL 降低并发风险。
- **与 SSDT hook 的区别**：SSDT hook 改 `KiServiceTable` 表项（CompactOffset），只影响被改的 syscall；全局 hook 改公共入口，所有 syscall 都过 hook，隐蔽性和影响面更大，但对原函数前 12 字节的备份/恢复要求更严格（漏恢复或指令边界错误会直接蓝屏）。
- **限制**：PatchGuard/KPP 会检测代码段修改（原文约 15–30 分钟内触发）；HVCI 阻止写可执行内核页；调试环境需关闭 PatchGuard/DSE/Secure Boot（原文免责声明）。不同 Windows 版本的 `KiSystemService` 入口指令与可达 Cave 范围需重新分析。

## 触发条件

- Windows 11 on ARM64，Ring0 驱动可执行；调试/研究环境关闭 PatchGuard、驱动签名与 Secure Boot，或具备相应绕过。
- 能定位 `KiSystemService` 及其入口指令（符号/特征码），并找到 adrp 可达、可写可执行的 Code Cave。
- 能写只读代码页（MDL 手法）且可承受完整性检测窗口。
- 对系统稳定性有容忍度（原文声明方法可能使系统不稳定/易崩溃）。

## 利用步骤

1. 定位 `nt!KiSystemService`（符号或特征码），反汇编前几条指令，记录前 12 字节（3 条指令）以便备份/恢复。
2. 在已加载模块中搜索 Code Cave（两个 NOP + 0，或可用的可执行空洞），确认在 adrp ±4GB 可达范围内。
3. 在 Cave 中布局：`[原 12 字节] + [恶意 hook 代码] + [trampoline 跳回 KiSystemService+12]`。
4. 用 `SuperCopyMemory`/MDL 把入口前 12 字节改写为 `adrp/add/br` 跳到 Cave 的 trampoline（或直接写入等价 3 条指令）。
5. 触发任意系统调用，验证执行流进入 Cave、恶意逻辑生效、再正常返回原分派流程。
6. 卸载时恢复原 12 字节并清理 Cave；注意 PatchGuard 检测与系统稳定性。

## PoC

原文给出的 trampoline 与 hook 布局（未在本机编译运行）：

```asm
; 通用 ARM64 trampoline：跳转到 64 位绝对地址
adrp xip0, <Absolute Address & 0xfffffffffffff000>
add  xip0, xip0, #<Absolute Address & 0x0fff>
br   xip0

; 示例
adrp xip0, BOOTVID!VidSolidColorFill+0x80 (fffff801`6bd93000)
add  xip0, xip0, #0x214
br   xip0                       ; -> 0xfffff8016bd93214
```

Hook 布局（原文图 6）：

```text
Original Function:            Hooked Function:                Hook (Code Cave):
  pacibsp                       adrp xip0, Caves...             pacibsp
  stp x19,x20,[sp,#-0x10]!      add  xip0, xip0, #...           stp x19,x20,[sp,#-0x10]!
  stp fp,lr,[sp,#-0x10]!        br   xip0   ; -> Cave          stp fp,lr,[sp,#-0x10]!
  mov fp,sp                     mov  fp,sp                      ... Malicious code ...
  ...                           ...                             adrp xip0, nt!KiPreprocessHardwareError+0xa8
                                                                add  xip0, xip0, #0xff4
                                                                br   xip0   ; 跳回原函数第 4 条指令
```

写只读代码页使用原文 `SuperCopyMemory`（MDL 映射后 `RtlCopyMemory`，见 [[code-analysis-reverse-windows-arm64-ssdt-compactoffset-trampoline-hook]] 卡内代码）。

## 变体与关联

- **x86 对应技术**：[[code-analysis-reverse-windows-kisystemcall64-lstar-msr-hook]] 通过重写 `IA32_LSTAR` MSR 指向自建入口 + 伪造 Shadow SSDT，达到“全局 syscall 拦截”；ARM64 没有 LSTAR，改 `KiSystemService` 机器码，属同一目标的不同架构实现。
- **按表项 hook**：[[code-analysis-reverse-windows-arm64-ssdt-compactoffset-trampoline-hook]] 改 `KiServiceTable` 的 CompactOffset，只影响单个 syscall；本卡改公共入口，影响全部 syscall，补丁点与粒度不同。
- **ARM64 inline hook/trampoline 通用做法**：[[mobile-android-kpm-inline-hook-arm64-trampoline-relocation]] 提供 Android 内核的 trampoline、PC 相对重定位与页表改权限思路，可对照移植。
- **写只读内存**：MDL 写内核只读页的通用做法还见 [[code-analysis-reverse-windows-pte-hook-page-table-isolation-inline-hook]]；ARM64 上无法用 CR0.WP，MDL 是原文采用的替代。
- **检测工具**：原文的 WOARKD 通过扫描 syscall 与内核结构检测此类 hook，可参考其扫描点。

## 检测与防御

- **代码完整性**：对比 `KiSystemService` 入口字节与干净 `ntoskrnl`（符号/哈希），检查是否被替换为 `adrp/add/br` 三指令跳转；扫描内核可执行节中出现 trampoline 模式与 Code Cave 特征（两个 NOP + 0、非模块映像页的可执行内存）。
- **缓解**：启用 PatchGuard/KPP、HVCI、DSE、Secure Boot；HVCI 可阻止修改内核代码页；驱动签名与易受攻击驱动阻止列表；监控 `MmMapLockedPagesSpecifyCache` 对内核代码页的写映射。
- **行为**：监控异常 IRQL 下的 `RtlCopyMemory` 写代码段、`KiSystemService` 附近页表项被改为可写、系统调用路径中出现未知驱动代码；ETW/EDR 内核回调与调用栈异常。
- **响应**：调试环境用干净符号恢复入口字节并卸载驱动；生产环境依赖 HVCI/PatchGuard 与重启清除。
