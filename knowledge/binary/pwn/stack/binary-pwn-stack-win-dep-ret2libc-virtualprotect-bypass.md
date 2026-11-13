---
id: binary-pwn-stack-win-dep-ret2libc-virtualprotect-bypass
title: Windows DEP 绕过：Ret2Libc 调 VirtualProtect/VirtualAlloc 恢复页执行并跳入 shellcode
type: scenario
domain: binary
path: binary/pwn/stack
technique: win-dep-ret2libc-page-permission-bypass
aliases:
- DEP 绕过
- 数据执行保护
- Data Execution Prevention
- NX/XD 绕过
- VirtualProtect 绕过 DEP
- VirtualAlloc 绕过 DEP
- ZwSetInformationProcess 关闭 DEP
- Ret2Libc 绕过 DEP
tags:
- windows
- dep
- nx
- ret2libc
- rop
- virtualprotect
- virtualalloc
- stack-overflow
- shellcode
- mitigation-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V524
  verified_at: '2026-11-11T14:42:39+08:00'
  notes: 已对照原文与唯一截图核对：DEP 模式(仅为基本Windows程序/除选定外全部启用，可选动态关闭；AlwaysOn/AlwaysOff、/noexecute)、软件DEP=SafeSEH、硬件DEP=NX/XD、ZwSetInformationProcess改_KEXECUTE_OPTIONS、VirtualProtect/VirtualAlloc/memcpy到RWX页五种绕过思路均与原文一致；原文明确“具体攻击过程不再演示”，卡片如实标注“无 PoC（原文仅给机制与思路）”、confidence=medium 并给出边界（ASLR配合、\x00截断、页边界/栈对齐），符合要求；原文无受影响版本区间，未设 affected_versions 合理。dedup 候选均为 Pentest-C2 shellcode loader（进程内主动 VirtualAlloc 执行）或 x64dbg dump，非栈溢出控制流劫持，非同链；全库 dup-scan 无本卡 pair。注意：OptIn 系原文“Option”的规范化命名，属修正而非错误。
---

## 一句话结论

DEP（数据执行保护）按页禁止数据页执行，但页权限本身可被进程内 API 修改：Windows 栈溢出中先构造 ROP/Ret2Libc 链调用 `VirtualProtect` 把 shellcode 所在页改为可执行（或 `VirtualAlloc` 申请可执行内存、`ZwSetInformationProcess` 关闭进程 DEP），再跳回数据区执行 shellcode，即可绕过 DEP。

## 原理

- **DEP 是什么**：DEP 将内存的代码区与数据区明确区分，默认堆页、栈页、内存池页不可执行；指令指针指向不可执行数据页时抛异常。Windows XP SP2 起支持。
- **软件 DEP 与硬件 DEP**：软件 DEP 即 SafeSEH，目标是阻止利用 SEH 执行数据区代码；真正的 DEP 是硬件 DEP，需要 CPU 支持——AMD 称 NX（No-Execute Page-Protection），Intel 称 XD（Execute Disable Bit），二者本质相同：在页表项中增加"可执行"位。
- **DEP 模式**：OptIn（仅为基本 Windows 程序和服务启用，可被应用动态关闭）、OptOut（除白名单外全部启用，也可被应用动态关闭）、AlwaysOn（全部进程强制启用，不可关闭，仅 64 位系统可启用）、AlwaysOff（全部禁用，可动态开启）。启动项 `/noexecute` 控制模式。
- **为什么可绕过**：DEP 是"页级不可执行"，而非"数据不可被改写为可执行"——只要攻击者能让进程自己调用 API 修改页属性或关闭 DEP，或跳转到进程中已有的 RWX 页，数据区代码即可执行。DEP 是进程级保护，若进程加载了未启用 DEP 的 DLL，为兼容性可能整体不开 DEP，这类进程可直接攻击。
- **关闭 DEP 的底层**：进程的 DEP 设置保存在 `KPROCESS` 结构体的 `_KEXECUTE_OPTIONS` 标志中，`ZwSetInformationProcess`（用户态 `SetProcessInformation`）可修改它，从而关闭当前进程 DEP。

## 触发条件

- Windows 进程存在栈溢出（或其他可控控制流劫持），能覆盖返回地址/函数指针。
- DEP 已启用且当前模式可被进程内 API 关闭（OptIn/OptOut），或攻击者选择"改页属性/分配可执行内存/利用已有 RWX 页"路线（AlwaysOn 下仍可用这类路线）。
- 能定位目标 API（`VirtualProtect`/`VirtualAlloc`/`memcpy`）与所需 gadget 的地址：DEP 常与 ASLR 同开，需信息泄露、非 ASLR 模块或部分覆盖配合。
- 溢出写入受 `strcpy` 等字符串函数限制时，注意 API 参数中的 `\x00` 字节截断问题（如 `VirtualProtect` 的保护值常量）。

## 利用步骤

1. **攻击未启用 DEP 的进程**：进程级 DEP 未开启（如加载了未启用 DEP 的 DLL），直接在栈上布置 shellcode 并覆盖返回地址跳过去，无需绕过。
2. **`ZwSetInformationProcess` 关闭 DEP**：构造栈帧劫持控制流，以合适的参数调用该 API 把当前进程 `_KEXECUTE_OPTIONS` 中的 DEP 标志清掉，再跳回数据区执行 shellcode。
3. **`VirtualProtect` 改页属性**：ROP 链依次布置 `VirtualProtect(shellcode_addr, size, PAGE_EXECUTE_READWRITE, &old)` 的参数与返回地址，调用后对应页变为可执行，函数返回时跳入 shellcode。难点：shellcode 起始地址需动态确定（常需栈泄露），且参数含 `\x00`，遇 `strcpy` 类溢出会被截断。
4. **`VirtualAlloc` 分配可执行内存**：ROP 调 `VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` 得到 RWX 内存，再用 `memcpy`/`read` 等把 shellcode 复制进去，随后跳转执行。
5. **利用已有可执行内存**：程序内存中若存在 RWX 段（如 JIT/旧式解压缓冲区），ROP 调 `memcpy` 把 shellcode 复制到该段再跳转，比 API 链简单但依赖目标进程内存布局，需要运气。

## PoC

无 PoC（原文仅给出机制与思路，明确未演示具体攻击过程；第 2~5 步为通用 Ret2Libc/ROP 链骨架，实际偏移、gadget 与地址需按目标程序分析）。

通用链结构（32 位示意，仅说明调用约定，非可执行 exp）：

```text
[填充至返回地址][VirtualProtect 地址][返回后跳 shellcode 的地址]
[shellcode_addr][size][PAGE_EXECUTE_READWRITE=0x40][可写地址(存旧保护)]
[shellcode...]
```

## 变体与关联

- 变体：64 位下调用约定为 `rcx/rdx/r8/r9`，需 `pop rcx/pop rdx/pop r8/pop r9` 等 gadget 或 ret2csu 构造参数。
- 变体：`SetProcessDEPPolicy`、`NtSetInformationProcess` 同样可改变进程 DEP 状态；AlwaysOn 模式下这些调用会失败，只能走"改页/新分配可执行内存"路线。
- 关联：[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]——Linux 的同类思路（mprotect 将页改为 RWX 后 ret2shellcode），本卡是其 Windows DEP/NX 对应物。
- 关联：[[binary-pwn-stack-win32-aslr-partial-overwrite-jmp-eax]]——Windows 32 位 ASLR 部分覆盖；DEP 与 ASLR 常同时开启，二者需组合绕过（该卡提到 DEP 开启时需 VirtualProtect/ROP 链）。
- 关联：[[binary-pwn-stack-ret2text-win-plus-one-align]]、[[binary-pwn-stack-win64-movsx-length-iret-segment-shellcode]]——其他 Windows 栈溢出控制流技巧。
- 边界：软件 DEP（SafeSEH）应作为独立机制考虑；只关闭 DEP 而不处理 ASLR 时，ROP 链地址仍需可预测；字符串溢出截断、栈对齐、页边界（参数跨页）都会导致链失效。

## 检测与防御

- 修复：对全部进程启用 AlwaysOn 模式（64 位）或通过 EMET/Exploit Protection 强制 DEP，使进程无法动态关闭；编译时启用 `/NXCOMPAT` 并确保依赖 DLL 均启用 DEP。
- 加固：DEP 与 ASLR、CFG、GS、SafeSEH 组合使用；避免进程中出现 RWX 页（W^X）；对 JIT 使用双映射（写与执行分离）。
- 检测：进程调用 `VirtualProtect`/`VirtualAlloc` 将数据页改为 RWX、或调用 `SetProcessInformation` 关闭 DEP 的行为；崩溃转储中 EIP 指向栈/堆等非映像区域；利用防护日志中的 DEP 违规记录。
- 响应：定位修改页权限的调用栈与可控输入路径，封堵溢出点并重新编译启用 DEP 的版本。
