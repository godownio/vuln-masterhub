---
id: code-analysis-reverse-windows-detours-funcptr-offset-calling-convention
title: Detours 在 32 位进程里 hook：函数指针必须按 DetourFindFunction 导出名或模块基址+偏移取，替换函数必须与目标调用约定/参数签名一致
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: detours-attach-funcptr-source-and-calling-convention-match
tags:
- windows
- hook
- detours
- inline-hook
- x86
- reverse-engineering
- calling-convention
- trampoline
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:48:38+08:00'
  notes: 已对照原文核对；本次核对未读取图片；卡片与正文一致（v4.0.1 nmake 编译、ucrtbased/ucrtbase 函数指针来源、DetourFindFunction 修饰名 ?MyPuts@@YAXPBD@Z、非导出函数基址+偏移 0x1100/0x1120、cdecl/stdcall/fastcall/usercall/thiscall 差异、stdcall+push ecx 模拟 thiscall 的 PoC）。正文截图中的 IDA/nmake 输出、栈平衡汇编片段未验证；本文为 RE 手法，非漏洞链，无受影响版本可标。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-detours-funcptr-offset-calling-convention/
draft: false
kb_aliases:
- Detours hook 踩坑
- DetourAttach 拿不到函数
- DetourFindFunction 修饰名
- 模块基址加偏移 hook 非导出函数
- __thiscall hook push ecx
- 调用约定不匹配栈不平衡
- DetourTransactionBegin Attach Commit
---

## 一句话结论

用 Detours 在 32 位 Windows 进程里做函数 hook，失败和崩溃几乎都来自两点：一是「目标函数指针」取错源（直接写库函数名会链接到自己模块的 CRT，Debug/Release 下 `puts` 分别落在 `ucrtbased.dll` 与 `ucrtbase.dll`；非导出函数只能靠「模块基址 + 偏移」），二是替换函数与被替换函数的**调用约定和参数签名**不一致（cdecl/stdcall 谁清栈、fastcall 用 ecx/edx 传参、__thiscall 的 this 在 ecx），栈一不平衡目标进程就崩。

## 原理

- **Detours 的 hook 形态**：`DetourAttach` 把目标函数开头若干字节改写成一条跳转，指向你的替换函数；同时把被覆盖的那几条完整指令拷贝到一块新内存（trampoline），末尾补一条跳回「目标函数 + 被覆盖字节数」的 jmp。`DetourAttach` 的第一个参数是二级指针，提交时会被填成 trampoline 地址，所以替换函数里通过它调用原函数，不会递归回自己。
- **为什么要按指令边界算字节数**：跳到新函数只需 5 字节，但目标函数前 5 字节可能切在一条指令中间，直接覆盖会破坏指令；Detours 会向前找到完整指令边界算出的字节数 n，拷贝前 n 字节进 trampoline，多于 5 字节的部分用 `0xCC` 填充。
- **必须成组调用**：`DetourTransactionBegin()` → `DetourUpdateThread(GetCurrentThread())`（把当前线程纳入事务，避免改代码瞬间执行到半截指令）→ `DetourAttach(&pOrig, pNew)` → `DetourTransactionCommit()`。取消 hook 同样四步，只把 Attach 换成 `DetourDetach`。多个函数可在同一事务里连续 Attach。
- **函数指针取错的根因**：`static int (*RealPuts)(const char*) = puts;` 里的 `puts` 是编译期解析到你 DLL 自己导入表里的符号。Debug 版 DLL 导入 `ucrtbased.dll!puts`，Release 版目标进程用的是 `ucrtbase.dll`/`api-ms-win-crt-stdio-11-1-0.dll!puts`，两者地址不同，`DetourAttach` 改的是你 DLL 里那条 thunk，目标进程的调用完全不经过它，表现为「hook 装上但没生效」。
- **正确取指针的两种方式**：导出函数用 `DetourFindFunction("模块名.dll", "导出名")`，函数名要与导入表/导出表里的名字完全一致（C++ 有名称修饰，例如 `?MyPuts@@YAXPBD@Z`）；非导出函数用 `GetModuleHandleA("目标.exe") + IDA 里算出的函数偏移`（偏移 = 函数地址 − 映像基址，注意 PE 头占前 0x1000，`.text` 从 0x401000 起而基址是 0x400000 时偏移是 0x1100 这类换算）。
- **调用约定为什么必须对齐**：32 位下 cdecl 由调用方 `add esp, n` 清栈，stdcall 由被调用方 `ret n` 清栈。替换函数若是 stdcall 而目标是 cdecl，参数栈被清两次，栈指针错位直接崩；fastcall/usercall 的前两个参数走 ecx/edx，替换函数从栈取参就会拿到垃圾。
- **__thiscall 的绕法**：C++ 成员函数的 this 通过 ecx 传，其余参数走栈、被调用方清栈，与 `__stdcall` 只差 this 的传递方式。把替换函数声明成 `__stdcall`（同样的参数列表），并在函数入口用内联汇编 `push ecx` 把 this 存到栈上、需要时 `pop ecx` 再用，即可模拟 thiscall；调用原函数的函数指针类型也要写成同一个 `__stdcall` 签名，且自行保证 push/pop 后堆栈平衡。

## 触发条件

- 目标是 32 位 Windows 进程，攻击者能以 DLL 形式让目标加载 hook 逻辑（注入、DLL 劫持、调试器加载等；本文只关注 hook 本身）。
- 目标函数所在页可改为可写（Detours 自己会改页属性），且函数首部有足够字节可覆盖；函数被内联或首部过短会导致 hook 失败。
- 已知目标函数位置：导出函数有确定导出名，非导出函数需要对应版本的二进制偏移（ASLR 关闭或用模块基址动态相加）。
- 已知目标函数的调用约定、参数个数与类型；否则栈会被破坏。

## 利用步骤

1. 编译 Detours（x86 Native Tools 下 `nmake`，产出 `lib.X86/detours.lib`），把 `detours.h`、`detours.lib` 引入工程；关闭 SDL 检查与「符合模式」，否则 `DetourAttach(&(PVOID)f, ...)` 会报「& 要求左值」。
2. 定位目标函数：库/系统函数用 `DetourFindFunction("ucrtbase.dll", "puts")`；目标 EXE 自己的非导出函数用 IDA 取值减基址得偏移，运行时 `GetModuleHandleA("目标.exe") + 偏移` 还原地址。
3. 写替换函数：参数个数/类型与目标一致，调用约定一致；需要原函数时用 DetourAttach 填好的 trampoline 指针调用。
4. 在 `DLL_PROCESS_ATTACH` 里按 Begin → UpdateThread → Attach → Commit 的顺序安装；需要卸载时在 DETACH 分支同样四步改用 DetourDetach。
5. 验证：在替换函数里打日志/断点确认命中，再比对返回值与原始行为；若未命中，先查函数指针来源（是否指向了另一个 CRT 副本），再查是否被内联。

PoC（hook 目标 EXE 的非导出函数 `add_func`，偏移 0x1100）：

```c
PVOID g_pOriginAdd = NULL;

int MyFunc(int a, int b) {
    ((int(*)(int, int))g_pOriginAdd)(a, b);   /* 经 trampoline 调原函数 */
    return a - b;                             /* 篡改返回值 */
}

void hook_add() {
    DWORD addOffset = 0x1100;
    DWORD baseAddr = (DWORD)GetModuleHandleA("detours_practise.exe");
    g_pOriginAdd = (PVOID)(addOffset + baseAddr);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID)g_pOriginAdd, MyFunc);
    DetourTransactionCommit();
}
```

PoC（hook 成员函数：stdcall 替代 thiscall，push/pop ecx 保 this）：

```c
int __stdcall MyFunc(int a, int b) {
    __asm { push ecx }                        /* 保存 this */
    int c = a + b;
    __asm { pop ecx }
    int d = ((int (__stdcall *)(int, int))g_pOriginAdd)(a, b);
    return c + d;
}
```

## 变体与关联

- **导出名变体**：`DetourFindFunction` 模块名可写 `ucrtbase.dll`、`api-ms-win-crt-*.dll`、目标自有 DLL；C++ 导出需带修饰名（`dumpbin /exports` 取）。
- **偏移来源变体**：ASLR 开启时先 `GetModuleHandle` 取运行时基址再加偏移；也可用 PDB/符号服务器直接拿 RVAs。
- **hook 粒度变体**：同一事务批量 Attach/Detach 多个函数；不主动卸载时 hook 生命周期与 DLL 一致，可省去 Detach。
- **同类技术**：手写 `E9 rel32`/绝对跳转 inline hook、IAT hook、硬件断点 hook；Detours 只是把「算指令边界 + 建 trampoline + 事务化改页」封装好的框架。
- **关联**：`code-analysis-reverse-windows-absolute-jump-inline-hook-detour`（Detours 在 x64 下必须改用绝对跳转的原因）、`code-analysis-reverse-windows-x86-inline-hook-packet-intercept`（手写 E9 hook 的寄存器保存与回跳细节）。

## 检测与防御

- **检测**：比对进程内存中关键函数首字节是否被改成 jmp（如 `E9`/`FF 25`/`B8+FF E0`），与磁盘映像不一致即为 inline hook；Detours 会在目标函数首部留下特征并创建匿名可执行内存块（trampoline），可用内存扫描 + 页属性异常（RWX、非映像私有页）发现。
- **防御**：对关键进程启用控制流保护（CET/CFG 对间接跳转的限制）、定期校验代码段完整性、开启 ASLR 使「固定偏移 hook」失效；限制可注入的 DLL 加载路径（签名校验、DLL 搜索顺序加固）。
