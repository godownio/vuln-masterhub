---
id: code-analysis-reverse-windows-process-notify-callback-analysis
title: WinDbg 枚举 PspCreateProcessNotifyRoutine 定位 Defender 进程创建回调与检测点
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: kernel-process-notify-callback-analysis
tags:
- reverse-engineering
- windows
- kernel
- windbg
- notify-routine
- defender
- edr
- process-creation
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:53:40+08:00'
  notes: 已对照原文与 img/11/12/14/16 核对：img/11 dq nt!PspCreateProcessNotifyRoutine 数组、img/12 x WdFilter!*CreateProcess* 符号、img/14 db/du Msaccess.exe、img/16 du Powerpoint.exe/AcroRd32.exe；正文中的 MpGetImageNormalizedName、CreationStatus=0xC0000022、MpGetProcessContextById、MpSetProcessDocOpenRule、MpSendProcessMessage、MpSetProcessExempt/Hardening、IoThreadToProcess、白名单 Rtl* 比对与 60 秒超时均能对应。原文对 MpSendProcessMessage 等为推测，卡内已标 medium 并注明；无版本区间。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-process-notify-callback-analysis/
draft: false
kb_aliases:
- PspCreateProcessNotifyRoutine
- 进程创建回调
- MpCreateProcessNotifyRoutineEx
- 内核回调枚举
- Defender 内核检测点
- PS_CREATE_NOTIFY_INFO
---

## 一句话结论

`nt!PspCreateProcessNotifyRoutine` 数组保存了所有通过 `PsSetCreateProcessNotifyRoutineEx` 注册的进程创建回调；在双机内核调试中用 `dq` 读数组、对表项清低 4 位后 `dps` 取回调函数指针，再用 `x WdFilter!*CreateProcess*` 与 `u` 反汇编，就能定位 Defender 的 `MpCreateProcessNotifyRoutineEx` 并读出其检测维度：路径规范化、父进程上下文、文档打开规则、白名单比对、以 `CreationStatus=0xC0000022` 拒绝创建等。

## 原理

- `PsSetCreateProcessNotifyRoutineEx` 注册回调时，内核分配一个回调块并把指针放入 `PspCreateProcessNotifyRoutine` 数组；数组表项是带低位标志的编码指针，因此读取后要按 `0x10` 对齐（清低 4 位）再解引用。
- 回调块的第二个 qword（偏移 +8）是函数指针；`dps <对齐地址> L2` 会显示“标志/引用计数 + 回调函数符号”，从而把内核数组项还原为具体驱动函数。
- 进程创建回调的第三个参数是 `PS_CREATE_NOTIFY_INFO`（反汇编中 `rdi`）：`+0x08` 为标志位、`+0x28` 为 FileObject、`+0x30` 为 `ImageFileName`、`+0x40` 为 `CreationStatus`。回调可通过写入 `CreationStatus` 拒绝创建，例如 `0xC0000022` 即 `STATUS_ACCESS_DENIED`。
- Defender 的 `WdFilter!MpCreateProcessNotifyRoutineEx` 先对镜像路径做规范化再判断，避免符号链接/长路径等路径欺骗；随后依次检查父进程上下文、文档打开规则、关键进程豁免、进程加固策略、调用线程与目标进程关系、白名单路径前缀，最后还可能通过 `MpSendProcessMessage` 把信息送到用户态做进一步判定（原文对这一步的具体用途表示未完全确认）。
- 因为回调处于进程创建路径上，分析这些函数等于直接读出杀软在“新进程诞生”这一点的全部判定条件；结合反汇编中的字符串引用（如 `Msaccess.exe`、`Powerpoint.exe`、`AcroRd32.exe`）可以还原其文档类进程监控策略。

## 触发条件

- 已能通过双机内核调试连接目标 Windows（见关联的调试环境卡），并加载 `nt`、`WdFilter` 等符号。
- 目标机加载了使用进程创建通知回调的 AV/EDR 驱动（文章为 Windows Defender 的 WdFilter）。
- 需要观察的是内核态检测逻辑，而不是用户态服务或云查杀结果；用户态判定部分只能看到消息发送点。
- 反汇编地址与偏移随 Windows/Defender 版本变化，跨版本需重新定位。

## 利用步骤

1. 枚举进程创建回调数组：
   ```text
   kd> dq nt!PspCreateProcessNotifyRoutine L20
   ```
   跳过全 0 表项，记录非零项。
2. 对每个表项清低 4 位后解引用，读取回调块：
   ```text
   kd> dps fffff8283`48008580 L2
   fffff8283`48008580  00000000`00000020
   fffff8283`48008588  fffff80a`83aaf690 WdFilter!MpCreateProcessNotifyRoutine
   ```
3. 用符号通配确认 Defender 的进程回调函数集合：
   ```text
   kd> x WdFilter!*CreateProcess*
   ```
   典型结果包含 `MpCreateProcessNotifyRoutineEx`、`MpCreateProcessNotifyRoutine`、`MpCreateProcessContext` 等。
4. 反汇编主回调，按调用点拆解检测逻辑：
   ```text
   kd> u WdFilter!MpCreateProcessNotifyRoutineEx L50
   ```
5. 重点标记以下指令/调用（文章中的偏移）：
   - `mov rbx,qword ptr [rdi+30h]`：取 `ImageFileName`；
   - `call WdFilter!MpGetImageNormalizedName`：路径规范化，防路径欺骗；
   - `mov dword ptr [rdi+40h],0C0000022h`：把 `CreationStatus` 写成拒绝访问；
   - `call WdFilter!MpGetProcessContextById` + `bts dword ptr [rcx+34h],0Fh`：按父进程 ID 取上下文并置标志；
   - `call WdFilter!MpSetProcessDocOpenRule`：文档打开规则；
   - `call WdFilter!MpSendProcessMessage`：发往用户态（用途原文未确认）；
   - `call WdFilter!MpSetProcessExempt` / `MpSetProcessHardening`：关键进程豁免与加固策略；
   - `call qword ptr [WdFilter!_imp_IoThreadToProcess]` + `cmp rax,rbx`：检查创建调用者，防远程创建；
   - `FltParseFileName` / `RtlEqualUnicodeString` / `RtlPrefixUnicodeString`：白名单文件与目录前缀比对。
6. 读取扫描超时配置：
   ```text
   kd> dq [fffff80a`83a77990]+18 L1
   fffff80a83a779a8 000013880000ea60
   ```
   该 qword 含两个 DWORD：`0x00001388`=5000、`0x0000EA60`=60000；原文取 60000 毫秒，即默认扫描超时 60 秒。
7. 结合字符串交叉引用确认文档类监控名单：`db`/`du` 指向的 Unicode 字符串可见 `Msaccess.exe`、`Powerpoint.exe`、`AcroRd32.exe`。

## PoC

```text
kd> dq nt!PspCreateProcessNotifyRoutine L20
kd> dps fffff8283`48008580 L2
kd> x WdFilter!*CreateProcess*
kd> u WdFilter!MpCreateProcessNotifyRoutineEx L50
kd> u WdFilter!MpCreateProcessNotifyRoutineEx+0x137 L30
kd> db fffffc58a`f7ddb018 L30
kd> du poi(fffffc58a`f7ddb018)+8
kd> dq [fffff80a`83a77990]+18 L1
```

```text
# 关键反汇编片段（原文）
fffff80a`83ab8d6c  mov rbx,qword ptr [rdi+30h]
fffff80a`83ab8d8f  call WdFilter!MpGetImageNormalizedName
fffff80a`83ab8ea2  mov dword ptr [rdi+40h],0C0000022h
fffff80a`83ab921e  call WdFilter!MpGetProcessContextById
fffff80a`83ab9241  call WdFilter!MpSetProcessDocOpenRule
fffff80a`83ab93e4  call WdFilter!MpSendProcessMessage
```

## 变体与关联

- 变体：不同 AV/EDR 的进程回调函数名不同，仍可按“数组表项 → 清低位 → 回调块 +8 → 函数指针”的流程枚举；符号缺失时用 `ln <addr>` 或驱动基址 + 偏移定位。
- 变体：除进程创建外，文件/镜像加载、线程创建、句柄操作（`ObRegisterCallbacks`）也各有回调数组或注册路径，可沿用同一分析方法，见线程回调卡。
- 边界：文章对 `MpSendProcessMessage`、`MpSetProcessHardening` 的具体语义多为推测；Windows/Defender 版本变化会改变地址与偏移，卡内偏移仅对应文章环境。
- 关联：[[code-analysis-reverse-windows-kernel-debugging-vmware-windbg]]（调试环境）、[[code-analysis-reverse-windows-thread-notify-callback-analysis]]（线程创建回调分析）、[[pentest-c2-windows-process-hollowing-pe-injection]]（进程创建检测对注入手法的影响）。

## 检测与防御

- 检测（防御方视角）：进程创建通知回调本身就是 EDR 的核心检测点；应确保其注册未被卸载或 patch，监控 `PsSetCreateProcessNotifyRoutineEx` 相关回调数组的异常变化（如安全产品回调被摘除）。
- 检测（攻击方视角/审计）：若目标使用 WdFilter 这类回调，进程创建会被路径规范化、父进程、文档规则与白名单多重检查；异常父进程（文档编辑器拉起 cmd/powershell）、非白名单路径、远程创建都会进入判定。
- 加固：保持 AV/EDR 内核回调完整、启用驱动签名与内核完整性保护；对内核调试接口与驱动加载做审计，防止攻击者用调试器读取或篡改回调数组。
