---
id: binary-pwn-kernel-windows-shellcode-token-steal-eprocess
title: Windows 内核 shellcode 遍历 EPROCESS ActiveProcessLinks 窃取 System Token 提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-kernel-shellcode-token-stealing
tags:
- windows
- kernel
- pwn
- shellcode
- token-stealing
- eprocess
- active-process-links
- lpe
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V592
  verified_at: '2026-11-12T15:37:33+08:00'
  notes: 已对照原文/截图核对 gs:[0x188]取KTHREAD、+0xB8取ApcState.Process、19045偏移 UniqueProcessId=0x440/ActiveProcessLinks=0x448/Token=0x4B8、旧版0x2E0/0x2E8/0x358触发0x50、swapgs;sysretq 返回、whoami=system。已将一句话表述修正为KTHREAD->ApcState.Process。PoC未本机执行，偏移随build变化。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-windows-shellcode-token-steal-eprocess/
draft: false
kb_aliases:
- token stealing
- Token 窃取
- EPROCESS 遍历
- ActiveProcessLinks 遍历
- 内核 shellcode 提权
- 替换 Token 提权
---

## 一句话结论

在 Ring0 执行的 shellcode 以 `gs:[0x188]` 取当前线程（KTHREAD），再经 `ApcState.Process` 取所属 EPROCESS，沿 `ActiveProcessLinks` 双向链表遍历所有进程，按 `UniqueProcessId == 4` 找到 System 进程，把其 `EPROCESS.Token` 指针写到当前（或预先拉起的 cmd.exe）进程的 Token 字段，即窃取 SYSTEM 令牌完成提权——纯数据遍历，不调用任何内核导出函数。

## 原理

- **进程链表**：Windows 每个进程的 `EPROCESS` 通过 `ActiveProcessLinks`（`LIST_ENTRY`）串成全局双向循环链表，`Flink` 指向下一个进程的 `ActiveProcessLinks` 字段。链表包含 System（PID 4）等所有进程，在任意进程上下文里都能遍历到。
- **定位当前进程**：`gs` 指向 KPCR；`KPCR.Prcb.CurrentThread` 在 `gs:[0x180+8]=gs:[0x188]`，得到当前 `KTHREAD`；`KTHREAD.ApcState.Process`（旧版本 +0x220，Win10 19045 为 +0xB8）即所属进程的 `EPROCESS` 基址（KPROCESS 位于 EPROCESS 起始处）。
- **定位字段**：EPROCESS 字段偏移在同一 Windows build 内固定，且是相对偏移、与 KASLR 基址无关，所以不需要先泄露内核基址。文章靶机（Windows 10 19045）实测：`UniqueProcessId=+0x440`、`ActiveProcessLinks=+0x448`、`Token=+0x4B8`；另一份沿用旧版的 shellcode 用 `+0x2E0/+0x2E8/+0x358`，在该 build 上偏移全错，执行即 `0x50 PAGE_FAULT_IN_NONPAGED_AREA` 蓝屏——偏移必须按目标 build 取（`dt nt!_EPROCESS` 或对应版本公开偏移表）。
- **遍历技巧**：把 `EPROCESS+0x448` 处的 `Flink` 读出来指向 `next+0x448`，减 `0x448` 即回到 `next` 的 EPROCESS 基址；也可以以 link 地址为基准直接读相邻字段（`link-8` 即 `UniqueProcessId`，因为它在链字段前 8 字节；`link+0x70` 即 `Token`，因为 0x4B8-0x448=0x70）。比较 PID 是否等于 4 判定 System。
- **替换 Token 为什么有效**：进程访问检查基于 `EPROCESS.Token` 指向的 `_TOKEN` 对象；把它换成 System 的高权令牌后，当前进程及其后续子进程即拥有 SYSTEM 权限。更稳妥的写法保留当前 Token 指针低 3 位引用计数标志（`and rdx,~7; and rcx,7; add rdx,rcx` 再写回），避免引用计数错乱导致退出时崩溃。
- **返回用户态**：文章第一种实现按调用约定恢复保存的寄存器后 `ret`；实际生效的第二种实现从 KTHREAD/TrapFrame 恢复 `rcx/r11/rsp/rbp` 后 `swapgs; sysretq` 直接回 ring3。二者都要求 shellcode 已能执行（SMEP 关闭或位于内核可执行内存）。
- **为什么不用 API**：`PsGetCurrentProcess`/`ZwOpenProcess` 等需要解析导出表并易被 SSDT/ETW 类监控发现；纯数据遍历代码短、无导入、可移植性好，是内核 shellcode 的通用提权收尾。

## 触发条件

- 已有 Ring0 任意代码执行：内核栈溢出 + SMEP 绕过，或内核 RWX 页、池溢出劫持回调等原语。
- EPROCESS 字段偏移与目标 build 匹配（本文为 Windows 10 19045 的 0x440/0x448/0x4B8；跨版本必须重查）。
- 若按 PID 定位待提权进程，需先在用户态 `CreateProcess` 拉起目标（如 `cmd.exe`）并把其 PID 写入 shellcode 占位符；按当前进程替换则无需 PID。
- shellcode 需可执行：SMEP 开启时配合 CR4 ROP 等绕过，或放入内核可执行内存。

## 利用步骤

1. 用户态准备：`VirtualAlloc(PAGE_EXECUTE_READWRITE)` 存放 shellcode；如需指定 PID，`CreateProcessA("cmd.exe")` 后把 `pi.dwProcessId` 写到 shellcode 中预留的 4 字节占位（如 `0x41414141` 处）。
2. 组装遍历逻辑：`gs:[0x188]` → KTHREAD → `[+ApcState.Process]` 得当前 EPROCESS；循环 `cmp [rax+0x440],4`，不匹配则 `rax=[rax+0x448]-0x448` 继续。
3. 命中 System 后：`rcx=[system+0x4B8]`，按需合并引用计数低位后写 `[current+0x4B8]=rcx`。
4. 恢复寄存器并 `swapgs; sysretq`（或按原调用约定 `ret`）回到用户态。
5. 用内核控制流劫持原语执行该 shellcode（栈溢出入口 `DeviceIoControl` 0x222003 + SMEP 绕过）；返回后在用户态 `whoami` 验证为 `nt authority\system`。

## PoC

```asm
; 内核 shellcode 核心（Windows 10 19045 偏移，示意；实际需按目标 build 核对）
mov rax, gs:[188h]          ; KTHREAD = KPCR.Prcb.CurrentThread
mov rax, [rax+0B8h]         ; ApcState.Process -> 当前 EPROCESS
mov rbx, rax                ; 保存当前进程 EPROCESS
walk:
cmp dword ptr [rax+440h], 4 ; UniqueProcessId == System(4)?
je found
mov rax, [rax+448h]         ; Flink -> next.EPROCESS+448h
sub rax, 448h               ; 回到 next EPROCESS 基址
jmp walk
found:
mov rcx, [rax+4B8h]         ; System 进程 Token
mov [rbx+4B8h], rcx         ; 写入当前进程 Token
; 恢复寄存器后 swapgs; sysretq（或按调用约定 ret）返回用户态
```

文章靶机用按上述偏移实现的 shellcode 完成提权，返回后 `whoami` 为 `nt authority\system`；PoC 为按原文逻辑整理的最小示意，未在本机执行。

## 变体与关联

- 变体：按 PID 定位用户预拉起的 `cmd.exe` 再替换其 Token（文章第一版思路）；用 `ActiveProcessLinks.Blink` 反向遍历；以当前线程而非进程为锚点；data-only 变体不执行 shellcode，改用任意写原语直接修改 `EPROCESS.Token`（如 CVE-2024-35250 一类的任意位写）。
- 关联卡片：[[binary-pwn-kernel-windows-driver-stack-overflow-ioctl-ret-hijack]]（代码执行入口）、[[binary-pwn-kernel-windows-smep-bypass-cr4-rop]]（SMEP 开启时的执行前提）、[[binary-pwn-kernel-windows-cng-pool-overflow-pipe-data-queue-token-steal]]（Windows 池溢出到任意读写后同样以 token 替换收尾）。

## 检测与防御

- **防御**：消除内核任意代码执行入口（驱动校验、SMEP/SMAP/KVA/KASLR/HVCI 全开）；启用内核 CFG/CET 与 PPL 保护关键进程，即使 Token 被换也限制后续操作。
- **检测**：`EPROCESS.Token` 指向的 `_TOKEN` 突然与 System 进程相同而进程镜像不是系统进程；进程令牌来源异常（ETW 进程/令牌审计）；内核崩溃转储中 shellcode 特征（`gs:[188h]` 读取、EPROCESS 偏移常量 0x440/0x448/0x4B8 的指令序列）；`swapgs; sysretq` 出现在非预期内核页。
