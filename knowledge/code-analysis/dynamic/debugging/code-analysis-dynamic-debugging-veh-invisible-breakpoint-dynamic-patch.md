---
id: code-analysis-dynamic-debugging-veh-invisible-breakpoint-dynamic-patch
title: VEH 隐形断点与动态补丁：AddVectoredExceptionHandler 捕获异常后改 CONTEXT 控制程序流程
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: veh-invisible-breakpoint-dynamic-patch
aliases:
- VEH 隐形断点
- AddVectoredExceptionHandler 断点
- VEH 动态补丁
- VEH 修改 CONTEXT
- 向量化异常处理
- VEH 内存保护
tags:
- windows
- veh
- exception-handling
- breakpoint
- dynamic-patching
- reverse-engineering
- debugging
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:49:47+08:00'
  notes: 已对照原文核对：VEH优先级、int 0x2C隐形断点、CONTEXT/Eip修改、只读页写入拦截与崩溃动态补丁均出自原文示例；原文为原理性示例，未提供可执行目标/未复跑。
---

## 一句话结论

在目标进程内注册 VEH（`AddVectoredExceptionHandler(1, Handler)`），把目标指令替换成会触发异常的指令（如 `int 0x2C`、除零、非法访问），或在只读内存上让写入触发 `0xC0000005`；处理程序从 `EXCEPTION_POINTERS->ContextRecord` 读取/修改寄存器与 `Eip`，返回 `EXCEPTION_CONTINUE_EXECUTION` 让程序从修复后的位置继续执行，即可实现不依赖调试器、不留下 `0xCC` 字节的“隐形断点”、运行时动态补丁与只读内存写入拦截。

## 原理

- **VEH 是进程级、优先级高于 SEH**：SEH 链表在线程栈上，只对当前线程生效；VEH 处理程序以双向链表存放在进程堆中，对进程内所有线程生效。异常分发顺序为调试器 → VEH（从链表头开始，后注册的优先）→ SEH → 系统默认处理。因此 VEH 可以在 SEH/崩溃处理前拦截异常。
- **EXCEPTION_POINTERS 提供完整现场**：`ExceptionRecord` 含 `ExceptionCode`（如 `0xC0000094` 除零、`0xC0000005` 访问违规）与 `ExceptionAddress`；`ContextRecord` 含寄存器、`Eip`、`Esp` 等。修改 `ContextRecord` 再返回 `EXCEPTION_CONTINUE_EXECUTION`，系统会按修改后的上下文继续执行。
- **隐形断点**：把目标地址的指令临时改成 `int 0x2C`（自定义异常码）或构造除零/访问违规，VEH 处理程序按异常码/地址命中后读取寄存器与内存；处理完把原指令恢复、调整 `Eip` 指向原始指令，程序继续运行。整个过程不写入 `0xCC`，不依赖调试寄存器，反调试的断点扫描难以发现。
- **动态补丁/崩溃修复**：目标指令 `call dword ptr [eax]` 因 `eax=NULL` 崩溃时，VEH 可把 `Eax` 改为合法对象地址，或把 `Eip += 5` 跳过整条 call；返回继续执行即可避免崩溃，无需修改磁盘文件。
- **内存保护**：把关键内存页设为 `PAGE_READONLY`，目标程序写入时触发 `0xC0000005`；VEH 判断异常地址落在保护区内后，临时 `VirtualProtect` 为可写、替换写入数据（如正确注册码），再恢复只读并继续执行。
- **风险**：修复不当会重复触发同一异常形成死循环；VEH 链表在多线程注册/卸载时可能损坏；保护程序可能遍历 VEH 链表检测异常处理程序。

## 触发条件

- 目标为 Windows PE，分析者能在目标进程内执行代码（注入 DLL、调试器脚本、loader 等）。
- 已知目标指令地址或关键内存区域，能修改指令字节/内存保护属性。
- 异常码与触发地址可区分，处理程序能准确判断是否自己需要处理。
- 目标未启用会阻止 `AddVectoredExceptionHandler`/代码页修改的强保护（部分加壳/EDR 会检测 VEH 链表与页属性变更）。
- 分析者能接受 VEH 被目标自身反调试逻辑检测的风险。

## 利用步骤

1. 用调试器/静态分析定位目标指令地址（如注册码校验、加密函数入口、崩溃点）与指令长度。
2. 编写符合 `LONG NTAPI Handler(_EXCEPTION_POINTERS*)` 原型的处理程序，使用 `NTAPI` 调用约定。
3. 在目标进程内 `AddVectoredExceptionHandler(1, Handler)` 注册到链表头部；如需低优先级则 `First=0`。
4. 选择触发方式：
   - 隐形断点：把目标指令首字节改为 `int 0x2C`（或构造除零/访问违规），记录原字节；
   - 内存保护：`VirtualProtect` 把关键区域设为 `PAGE_READONLY`；
   - 崩溃修复：直接运行到崩溃指令。
5. 处理程序中按 `ExceptionCode`/`ExceptionAddress` 判断命中，读取寄存器/内存，修改 `ContextRecord`（`Eip`/`Eax`/`Ecx` 等），必要时恢复原指令/内存属性。
6. 返回 `EXCEPTION_CONTINUE_EXECUTION` 继续执行；未命中时返回 `EXCEPTION_CONTINUE_SEARCH`。
7. 加入异常计数阈值（如同一异常超过 3 次返回 `CONTINUE_SEARCH`）避免死循环；完成后 `RemoveVectoredExceptionHandler` 卸载。

## PoC

除零异常处理（修改 ECX 修复）：

```c
LONG NTAPI MyVEH(_EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0xC0000094) {
        ExceptionInfo->ContextRecord->Ecx = 1; // 原 ECX=0 导致除零
        // 或 ExceptionInfo->ContextRecord->Eip += 2; // 跳过 idiv ecx
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
AddVectoredExceptionHandler(TRUE, MyVEH);
__asm { mov eax, 1; mov ecx, 0; idiv ecx; }
```

只读内存写入拦截：

```c
LONG NTAPI ProtectKeyVEH(_EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0xC0000005 &&
        (DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress >= KEY_ADDR &&
        (DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress < KEY_ADDR + KEY_SIZE) {
        DWORD oldProtect;
        VirtualProtect((LPVOID)KEY_ADDR, KEY_SIZE, PAGE_READWRITE, &oldProtect);
        memcpy((LPVOID)KEY_ADDR, correctKey, sizeof(correctKey));
        VirtualProtect((LPVOID)KEY_ADDR, KEY_SIZE, oldProtect, &oldProtect);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
```

崩溃修复：

```c
if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0xC0000005 &&
    (DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == CRASH_ADDR) {
    ExceptionInfo->ContextRecord->Eax = validObjAddr; // 或 Eip += 5 跳过 call [eax]
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

## 变体与关联

- **触发指令变体**：`int 0x2C`、`int 3`、除零 `idiv`、空指针写、非法指令、单步 TF；不同异常码便于区分。
- **内存保护变体**：`PAGE_READONLY`/`PAGE_NOACCESS` + `0xC0000005` 拦截读写；也可用 `PAGE_GUARD` 一次性异常。
- **断点替代**：硬件断点（DR0-DR3）+ VEH 捕获 `EXCEPTION_SINGLE_STEP`，不改代码字节；与本卡的软件指令替换互补。
- **关联**：[[code-analysis-reverse-anti-debug-exception-timing-checksum-bypass]]（SEH/INT 2D/TF/RDTSC 反调试与绕过）、[[pentest-c2-hardware-breakpoint-veh-amsi-etw-bypass]]（硬件断点 + VEH 修改 CONTEXT 绕过 AMSI/ETW）。

## 检测与防御

- **检测**：枚举进程 VEH 链表，发现指向非模块/匿名可执行内存的处理程序；监控 `AddVectoredExceptionHandler` 调用与异常频率；检查代码页是否被改成 `int 0x2C` 等非原始字节；监控 `VirtualProtect` 把关键页改为只读后频繁异常。
- **防御**：对关键代码段做完整性校验（磁盘/内存哈希比对）；检测 VEH 链表异常节点；启用 CFG/CET、ACG 等缓解；反调试逻辑可结合 VEH 链表检查与异常时序判断。
- **分析侧注意**：处理程序必须用 `NTAPI`；返回值只能是 `EXCEPTION_CONTINUE_EXECUTION` 或 `EXCEPTION_CONTINUE_SEARCH`；多线程注册/卸载需同步；避免死循环。
- **边界**：目标若使用内核态异常回调/“隐形 VEH”或检测 VEH 链表，用户态 VEH 可能被发现或失效。
