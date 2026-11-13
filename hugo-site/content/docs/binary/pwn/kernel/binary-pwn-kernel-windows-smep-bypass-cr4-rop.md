---
id: binary-pwn-kernel-windows-smep-bypass-cr4-rop
title: SMEP 绕过：内核 ROP 链 pop rcx;ret + mov cr4,rcx 清 CR4.SMEP 后跳用户态 shellcode
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-smep-bypass-cr4-rop
tags:
- windows
- kernel
- pwn
- smep
- rop
- cr4
- kva-shadow
- lpe
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V592
  verified_at: '2026-11-12T15:37:32+08:00'
  notes: 已对照原文/截图核对 pop rcx;ret(nt!HvlEndSystemInterrupt 附近 0x...743f52c0)、mov cr4,rcx(KiEnableXSave+0xb4e6, 0x...749a41cf)、CR4 0x370678->0x270678、关KVAS后0x2506f8、ROP链0x818/0x820/0x828/0x830、whoami=system。已修正原文误归因：0x50 蓝屏实际发生在关KVAS+清SMEP后，由旧偏移shellcode读错EPROCESS字段导致；KVAS开启+清SMEP时实测为0xFC。PoC未本机执行。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-windows-smep-bypass-cr4-rop/
draft: false
kb_aliases:
- SMEP bypass
- CR4.SMEP 清零
- 内核 ROP 绕过 SMEP
- ret2usr 绕过
- mov cr4,rcx gadget
- HEVD SMEP bypass
---

## 一句话结论

当内核控制流劫持只能跳到用户态 shellcode、而 Windows 8+ 的 SMEP 禁止 Ring0 从用户页取指（蓝屏 `0xFC`）时，用被覆盖的内核栈布置 ROP 链：`pop rcx; ret` 装入清掉 bit 20 的 CR4 值，`mov cr4, rcx; ret` 写回 CR4 关闭 SMEP，再返回用户 shellcode——ROP 本身在内核态执行，写 CR4 合法，取指检查已被解除。

## 原理

- **SMEP 的强制点**：CR4 第 20 位。`CR4.SMEP=1` 时，任何从用户模式地址（PTE 的 User 位=1）发起的指令取指都会触发页错误，与页表 NX/XD 位无关——这是 CPU 在取指阶段的检查，不依赖操作系统配合。Windows 8+ 默认开启，蓝屏码 `0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY`，Arg1 就是被尝试执行的用户虚拟地址（例如堆上 `VirtualProtect(PAGE_EXECUTE_READWRITE)` 的 shellcode 地址），Arg2 为其 PTE 内容。
- **为什么直接 `ret2usr` 失败**：栈溢出把返回地址覆盖成用户 shellcode 地址后，`ret` 使 CPL 仍为 0、但 RIP 指向用户页，CPU 先做 SMEP 取指检查 → `#PF` → 蓝屏。文章先尝试 `VirtualProtect`/把 shellcode 放常量内存、并在 IOCTL 前 `pause`，均无效，证实拦截点在 CPU 而非页保护。
- **为什么不能“直接关闭”**：CR4 是特权寄存器，用户态无法写；Windows 8+ 也没有提供关闭 SMEP 的受支持开关。文章中调试器 `r cr4=<清 bit20 的值>` 能生效属于调试环境手段，且还需要先关闭 KVA Shadow（见下）才看得到用户页，不是攻击者可用路径。
- **ROP 绕过的本质**：第一次劫持的返回地址指向内核 text 中的 gadget（CPL0 执行，页在内核映像内，不受 SMEP 限制）；gadget 链在内核态完成 `CR4.SMEP:=0`，此后再把返回地址弹成用户 shellcode 地址时，取指检查已关闭，用户页可执行。即“用内核 ROP 做一次特权寄存器写入”替代“直接 ret 用户页”。
- **gadget 选择**：需要一对 `pop rcx; ret` 与 `mov cr4, rcx; ret`。文章实例：`pop rcx; ret` 取 `nt!HvlEndSystemInterrupt+0x1e`（`...743f52c0: 59 c3`）；`mov cr4, rcx; ret` 取 `nt!KiEnableXSave+0xb4e6` 函数体 `btr rcx,12h; mov cr4,rcx; ret` 中的 `mov cr4,rcx` 指令地址（`...749a41cf`）。当前 CR4 值经调试器 `r cr4` 读到 `0x370678`，清 bit20 得 `0x270678`。
- **KVA Shadow 的决定性影响**：开启 KVAS 时内核与用户使用分离的页表（CR3 切换），内核页表中的用户页被标记为 NX——此时即使 SMEP 已清零，从用户地址取指仍会触发页错误（文章在只清 SMEP、未关 KVAS 时实测仍为 `0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY`）。文章在实验机注册表 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management` 新建 DWORD `FeatureSettingsOverride=3`、`FeatureSettingsOverrideMask=3` 并重启关闭 KVAS 后，CR4 实测 `0x2506f8`，手动清零与 ROP 两种方式都成功进入用户 shellcode 并拿到 SYSTEM（文中另一次 `0x50 PAGE_FAULT_IN_NONPAGED_AREA` 发生在已关 KVAS、清 SMEP 之后，是旧偏移 shellcode 读错 EPROCESS 字段所致，与 KVAS 无关）。这是靶场配置，真实目标默认不会允许攻击者关 KVAS；真实利用更常见的是把提权载荷放进内核可执行内存（RWX vmalloc、W^X 破坏等）而不是 ret2usr。
- **KASLR**：gadget 地址随内核基址随机化。本例靶机在调试器下直接使用固定地址；真实利用需先泄露内核基址再按偏移取 gadget（或使用不依赖固定 gadget、纯 data-only 的绕过思路）。

## 触发条件

- 已有内核控制流劫持原语（如 IOCTL 栈溢出），可把 ROP 链写到被覆盖的栈上，并知道栈上返回地址偏移。
- 目标 SMEP 开启（Win8+ 默认）；能获得内核基址或 gadget 绝对地址（KASLR 泄露或调试环境已知）。
- 用户 shellcode 页在内核态可见：靶场通过关闭 KVAS 实现；否则本路径不适用，应改用内核内存载荷。
- 用户 shellcode 页已按 `PAGE_EXECUTE_READWRITE` 映射且地址已知（`VirtualAlloc` 返回）。

## 利用步骤

1. 先按直接 `ret2usr` 验证拦截：返回地址写用户 shellcode → 蓝屏 `0xFC`，确认 SMEP 开启且 Arg1 为 shellcode 地址。
2. 取得目标机当前 CR4 值（调试器 `r cr4` 或内核读寄存器代码），清除 bit 20 得到写回值（示例 `0x370678 → 0x270678`；关 KVAS 的机器为 `0x2506f8`）。
3. 在 nt 映像中找 gadget：`pop rcx; ret`、`mov cr4, rcx; ret`（`u`/`uf` 反汇编或 ROPgadget 扫描，地址按 KASLR 基址换算）。
4. 布局 payload：`0x810` 填充 + `[pop_rcx_ret][cr4_clear][mov_cr4_rcx_ret][user_shellcode]`，总长 `0x840`，经 `DeviceIoControl` 送入（同一栈溢出入口）。
5. 驱动返回：`ret` → pop rcx;ret → mov cr4,rcx;ret → 用户 shellcode 在 Ring0 执行（接 token 窃取载荷），返回后 `whoami` 为 `nt authority\system`。

## PoC

```c
// 同一内核栈溢出入口（HEVD 0x222003），返回地址处换成 ROP 链
unsigned long long *p = (unsigned long long *)stackspace;
RtlFillMemory(stackspace, 0x810, 'A');
p[0x818 / 8] = pop_rcx_ret;              // 例：nt!HvlEndSystemInterrupt+0x1e  (59 c3)
p[0x820 / 8] = cr4_value & ~(1ULL << 20); // 例：0x2506f8（关 KVAS 的靶机实测 CR4 清 bit20）
p[0x828 / 8] = mov_cr4_rcx_ret;          // 例：nt!KiEnableXSave+0xb4e6 处的 mov cr4,rcx; ret
p[0x830 / 8] = (unsigned long long)shellcode; // 用户态 RWX 页，SMEP 已清
DeviceIoControl(hDevice, 0x222003, stackspace, 0x840, NULL, 0, &info, NULL);
```

gadget 地址为文章靶机实例值，含 KASLR 随机化；PoC 未在本机执行。

## 变体与关联

- 变体：不改 CR4 的路径——把 shellcode 放进内核可执行内存（RWX vmalloc、W^X 破坏、内核堆喷射的可执行页），天然绕过 SMEP；纯 data-only 提权（直接改 Token/PreviousMode）无需执行用户代码，也不触发 SMEP。SMAP 约束的是内核态数据访问用户页，需要 `stac/clac` 或换内核缓冲，与本卡取指绕过是不同机制。
- 关联卡片：[[binary-pwn-kernel-windows-driver-stack-overflow-ioctl-ret-hijack]]（前置劫持原语）、[[binary-pwn-kernel-windows-shellcode-token-steal-eprocess]]（清 SMEP 后执行的内核载荷）、[[binary-pwn-kernel-rwx-vmalloc-user-shellcode-exec]]（内核 RWX 页替代 ret2usr 的思路）。

## 检测与防御

- **防御**：保持 SMEP/SMAP、KVA Shadow、KASLR、HVCI/VBS 全开；启用 CET Shadow Stack 与内核 CFG，使返回地址/间接跳转劫持更难；hvci 下 CR4 写受 hypervisor 保护。根本修复仍是驱动侧消除栈溢出。
- **检测**：`0xFC` 蓝屏的 Arg1 指向用户态地址（说明有 ret2usr 尝试）；内核崩溃转储中返回链出现 nt 模块中段 gadget 地址；异常写入 CR4 的行为（需 hypervisor/VBS 遥测）；普通进程对驱动设备发超大 IOCTL 后触发系统崩溃。
