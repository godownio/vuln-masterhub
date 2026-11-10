---
id: code-analysis-reverse-windows-absolute-jump-inline-hook-detour
title: 绝对跳转 inline hook：32 位 mov eax,imm32/jmp eax（7 字节）、64 位 mov r10,imm64/jmp r10（13 字节）避开 E9 rel32 ±2GB 不可达，钩子内先恢复原字节防无限递归
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: absolute-jump-inline-hook-avoid-rel32-range
tags:
- windows
- hook
- inline-hook
- patch
- x64
- detours
- evasion
- reverse-engineering
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:30:58+08:00'
  notes: 已对照原文核对；本次核对未读取图片；32 位 B8+imm32+FF E0 共 7 字节、64 位 49 BA+imm64+41 FF E2 共 13 字节的绝对跳转编码，VirtualProtect 改 PAGE_EXECUTE_READWRITE 后 memcpy 写入，钩子内先 memcpy 回原字节再调用原函数以防止递归，均与原文代码逐行一致；原文只给出 MessageBoxW 示例，卡内把 IAT/SSDT/Detours 归为跳过的旁支与变体，处理与原文内容相符；未验证点：避开 E9 rel32 正负 2GB 的成因解释与「必须覆盖整条指令」的边界处理属通用原理补全，原文未展开；未执行任何代码
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-absolute-jump-inline-hook-detour/
draft: false
kb_aliases:
- inline hook 绝对跳转
- mov eax,jmp eax hook
- mov r10,imm64 jmp r10
- 13 字节 64 位 hook
- 跨 2GB 跳转不可达
- 解除 hook 防递归
- Detours DetourAttach
---

## 一句话结论

在函数入口改写机器码的 inline hook，如果目标函数与自己的钩子函数相距超过 ±2GB，`E9 rel32`（5 字节）会因重定位算不出偏移而失败；改用「把绝对地址装进寄存器再 `jmp reg`」——32 位 `B8 imm32` + `FF E0`（7 字节，`mov eax,addr; jmp eax`）、64 位 `49 BA imm64` + `41 FF E2`（13 字节，`mov r10,addr; jmp r10`）——就能在任何距离跳转，代价是覆盖的字节更多、被覆盖的原指令必须完整保存并在钩子里先恢复再调用原函数，否则会无限递归。

## 原理

- **inline hook 的本质是"改代码"**：在目标函数第一条指令处写入跳转，执行流先进入自己的处理函数；处理函数里做记录/改参数/拦返回值，再跳回原函数继续执行。与 IAT hook 不同，它不依赖导入表，因此对「内部调用、`GetProcAddress` 动态解析、系统 DLL 内部互调」同样有效。
- **`E9` 相对跳转的硬限制**：`E9` 后面是 32 位有符号相对偏移（`rel32`），可达范围约 ±2GB。x64 下 DLL 与 EXE 的加载基址由系统随机分配，钩子函数在注入的 DLL 里、目标在 `System32` 里时，两者经常超出这个范围，patch 上去一跳就跑到错误地址（进程直接崩溃）。这不是写法问题，是编码本身的限制。
- **绝对跳转绕开距离限制**：`mov reg, imm32/imm64` 把目标地址作为**立即数**写进寄存器，随后 `jmp reg` 无条件跳到该值，与当前 EIP/RIP 无关。
  - 32 位：`B8 <addr32>` + `FF E0` = 7 字节（`mov eax, addr` / `jmp eax`）。
  - 64 位：`49 BA <addr64>` + `41 FF E2` = 13 字节（`mov r10, addr` / `jmp r10`）；用 `r10` 是因为它属于调用者保存寄存器、不在常见调用约定里传参，不会污染原函数的参数。
- **必须覆盖整条指令**：patch 长度 7/13 字节，若落在一条长指令（如 `push rbp; mov rbp,rsp` 之类组合）中间会造成半条指令，跳回去执行时立即非法。工程做法是按长度反汇编，取「刚好 ≥ 7/13 字节」的整指令边界；文章的做法是直接假定 `MessageBoxW` 入口前 7/13 字节是可覆盖的完整指令（系统 API 的 hotpatch 前缀通常允许）。
- **递归的来源**：钩子函数体里如果直接 `call` 原函数名，而原函数入口已被改成跳到钩子，就会无限递归。解决方式是**调用前先把原字节写回**（`memcpy(Hookedfunc, originalBytes, 7/13)`），调用完再重新安装钩子。这是 inline hook 的通用写法，也是它与 IAT hook（只需保存函数指针）最大的实现差异。
- **写代码段要改页属性**：代码页默认只读/可执行，写入前必须 `VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)`，写完恢复原保护。
- **detection/利用的双面性**：同一套机制既能用于"拦截 API 观察行为/改参数"（调试、外挂、沙箱 hook），也能用于"钩住杀软/EDR 关注的 API，让它看到正常返回值"（免杀）。Detours 是微软开源的实现，内部同样是改写入口并生成 trampoline，只是它替用户处理了指令长度与相对跳转。

## 触发条件

- 目标是 Windows PE，能在目标进程内执行代码（注入 DLL、`LoadLibrary`、APC、调试器注入等）。
- 目标函数入口可写（有 `VirtualProtect` 权限：同用户/管理员），且未被 PatchGuard/CET/CFG 等机制保护。
- 目标函数的首条指令序列长度 ≥ patch 长度，或存在可用的 hotpatch 前缀（`mov edi,edi` / 5 字节 NOP 区）。
- 64 位场景下必须用 13 字节方案或提前把 trampoline 放到 ±2GB 内（分配近地址再 `E9` 过去）。

## 利用步骤

1. 取目标函数地址：`GetProcAddress(GetModuleHandleW(L"user32.dll"), L"MessageBoxW")`（或直接 `&MessageBoxW`）。
2. 确定 patch 长度与原始字节：32 位 7 字节、64 位 13 字节；`memcpy(originalBytes, addr, len)` 备份。
3. 构造跳转字节：32 位 `0xB8,0x00,0x00,0x00,0x00,0xFF,0xE0`，把钩子函数地址填到第 2 字节起；64 位 `0x49,0xBA,<8 字节地址>,0x41,0xFF,0xE2`，地址从第 3 字节起。
4. `VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)` → `memcpy(addr, code, len)` → 恢复 `old` 权限。
5. 钩子函数内：先 `memcpy(addr, originalBytes, len)` 恢复原指令，再调用原函数（或用备份的函数指针），返回前重新 `installHook()`；用全局保存的 `originalBytes` 保证可重入。
6. 触发一次原调用验证：正常应看到钩子函数的输出/副作用，同时原功能仍然工作。
7. 卸载时把 `originalBytes` 写回并恢复页属性；DLL 卸载前必须卸载钩子，否则后续调用会跳到已释放的 DLL 地址崩溃。

## PoC

32 位绝对跳转（7 字节）：

```c
#include <Windows.h>

static LPVOID g_target   = NULL;
static BYTE   g_original[13] = {0};

void installHook(LPVOID hookedFunc, LPVOID targetFunc)
{
    DWORD oldProtect = 0;
    /* mov eax, imm32 ; jmp eax */
    BYTE code[7] = { 0xB8, 0, 0, 0, 0, 0xFF, 0xE0 };
    memcpy(g_original, hookedFunc, sizeof(code));          /* 先备份 */

    DWORD_PTR addr = (DWORD_PTR)targetFunc;
    memcpy(&code[1], &addr, sizeof(DWORD_PTR));            /* 填绝对地址 */
    VirtualProtect(hookedFunc, sizeof(code), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(hookedFunc, code, sizeof(code));
    VirtualProtect(hookedFunc, sizeof(code), oldProtect, &oldProtect);
}

int myMessageBoxW(HWND h, LPCWSTR text, LPCWSTR cap, UINT type)
{
    /* 先恢复原字节，避免调用原函数又跳回自己造成无限递归 */
    memcpy(g_target, g_original, 7);
    int r = MessageBoxW(h, text, cap, type);
    installHook(g_target, (LPVOID)myMessageBoxW);          /* 重新挂钩 */
    return r;
}
```

64 位绝对跳转（13 字节）：

```c
void installHook64(LPVOID hookedFunc, LPVOID targetFunc)
{
    DWORD oldProtect = 0;
    /* mov r10, imm64 ; jmp r10 */
    BYTE code[13] = { 0x49, 0xBA, 0,0,0,0,0,0,0,0, 0x41, 0xFF, 0xE2 };
    memcpy(g_original, hookedFunc, sizeof(code));

    DWORD_PTR addr = (DWORD_PTR)targetFunc;
    memcpy(&code[2], &addr, sizeof(DWORD_PTR));
    VirtualProtect(hookedFunc, sizeof(code), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(hookedFunc, code, sizeof(code));
    VirtualProtect(hookedFunc, sizeof(code), oldProtect, &oldProtect);
}
```

Detours 等价写法（库内部自行处理 trampoline 与相对跳转可达性）：

```c
auto msgbox = (void*)MessageBoxA;
DetourTransactionBegin();
DetourUpdateThread(GetCurrentThread());
DetourAttach(&msgbox, MyMessageBoxA);
DetourTransactionCommit();
```

## 变体与关联

- 跳转编码变体：`push imm32; ret`（32 位，6 字节）、`FF 25 <绝对地址>`（`jmp [mem]`，x64 下 14 字节，从数据槽读地址）、`push imm64` 需配 `ret` 在 x64 不可靠，故主流是 `mov r10/jmp r10`。
- 空间优化：x64 下若能把 trampoline/钩子放在目标 ±2GB 内（`VirtualAlloc2`/`NtAllocateVirtualMemoryEx` 指定 hint），可以退回 5 字节 `E9`，覆盖更少、更不易撞到指令边界。
- 组合用法：inline hook + IAT hook 双管（IAT 拦导入调用、inline 拦内部调用）；被 hook 的函数清单本身就是 EDR 的检测点，攻击侧则用 unhook（从磁盘重载 `.text`、按 `.pdata` 用磁盘副本覆盖被改函数）恢复。
- 关联：[[code-analysis-reverse-windows-x86-inline-hook-packet-intercept]]（`E9` 相对跳转的 5 字节版本与封包拦截场景）、[[code-analysis-reverse-windows-iat-hook-install-messagebox]]（改 IAT 槽而非改代码）、[[code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service]]（内核态 SSDT 的同类"改表项"手法）、[[pentest-c2-module-unhooking-pdata-runtime-function-fnv1a]]（检测/移除他人 inline hook 的做法）。

## 检测与防御

- 检测：函数入口前若干字节被改为 `B8/FFE0`、`49BA/41FFE2`、`E9`、`FF25` 等跳转模式；`.text` 段出现 RWX 页或哈希与磁盘不一致；`VirtualProtect` 对代码段频繁改权限；跳转目标落在非模块映射区（匿名可执行内存）。
- 防御：启用 CFG/CET（间接跳转/阴影栈约束）、ACG（禁止动态代码）、PPL 保护关键进程；对关键 API 使用直接系统调用/自带实现以绕开被 inline hook 的入口；内核侧启用 PatchGuard 与 HVCI。
- 分析侧：拿到样本后先在 IDA 里看 API 入口是否被 patch，再用「磁盘副本 vs 内存映像」逐函数哈希比对还原真实代码。
