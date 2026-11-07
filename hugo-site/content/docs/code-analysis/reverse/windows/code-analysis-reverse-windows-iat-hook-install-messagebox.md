---
id: code-analysis-reverse-windows-iat-hook-install-messagebox
title: IAT Hook 安装：遍历导入表定位 IAT 槽，VirtualProtect 改权限后替换函数指针
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: iat-hook-install
tags:
- windows
- pe
- iat-hook
- import-table
- hook
- dll-injection
- reverse-engineering
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:14:28+08:00'
  notes: 已对照原文与25张图核对：导入表索引1、IMAGE_IMPORT_DESCRIPTOR 的 Name/OriginalFirstThunk/FirstThunk、IMAGE_THUNK_DATA 最高位判序号、IMAGE_IMPORT_BY_NAME、遍历 INT/IAT 匹配 MessageBoxW、VirtualProtect 改页写钩子、DllMain attach/detach 安装卸载、卸载前不恢复会跳已释放内存崩溃，均与原文代码及图12/20-25一致；图21 显示 Hooked 弹窗、图23 注入成功、图25 crack.exe 弹 51HOOK，属已打通。未验证点：未在本机编译运行；卡中 PoC 用 PVOID/sizeof(PVOID) 泛化原文 DWORD/4 字节写法，语义等价并注明 x64 需 IMAGE_THUNK_DATA64。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-iat-hook-install-messagebox/
draft: false
kb_aliases:
- IAT Hook
- 导入地址表 Hook
- GetIatAddr
- MessageBoxW Hook
- 导入表遍历
- VirtualProtect IAT
- DLL 注入 Hook
---

## 一句话结论

IAT Hook 的做法是：解析目标 PE 的导入表，找到目标 DLL 的 `IMAGE_IMPORT_DESCRIPTOR`，按 `OriginalFirstThunk`/`FirstThunk` 遍历导入项并匹配函数名，拿到对应的 IAT 槽地址；用 `VirtualProtect` 把该槽所在页改为可写，写入自己的钩子函数地址，再恢复页权限。此后目标调用该 API 时会跳到钩子函数，钩子内可调用保存的原函数指针完成原逻辑。

## 原理

- PE 的导入表（数据目录索引 1）由一组 `IMAGE_IMPORT_DESCRIPTOR` 组成，每个描述一个 DLL：`Name` 指向 DLL 名，`OriginalFirstThunk` 指向导入名称表（INT），`FirstThunk` 指向导入地址表（IAT）。
- 文件中的 INT/IAT 项都是 `IMAGE_THUNK_DATA`：最高位为 1 表示按序号导入，否则 `AddressOfData` 指向 `IMAGE_IMPORT_BY_NAME`（`Hint` + 函数名）。加载器解析导入时，会把 IAT 中的函数名 RVA 替换成真实函数地址；运行时 IAT 槽就是“函数指针数组”。
- Hook 安装器遍历导入表：对每个 `IMAGE_IMPORT_DESCRIPTOR`，比较 `Name` 与目标 DLL（如 `user32.dll`）；匹配后同时遍历 INT 和 IAT，按 `pINT->u1.Function` 找到 `IMAGE_IMPORT_BY_NAME`，比较函数名（如 `MessageBoxW`）；命中时返回当前 IAT 槽指针（`pIAT`）。
- IAT 槽所在页通常是只读的；直接写入会触发访问违例。需要 `VirtualProtect(slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &old)`，写入钩子函数地址，再恢复原权限。
- 钩子函数必须与目标 API 的调用约定、参数、返回值完全一致（如 `WINAPI`/`__stdcall`）；钩子内通过全局变量保存原函数指针，先/后调用原函数，实现拦截、修改参数或替换返回值。
- 卸载时把 IAT 槽写回原函数地址并恢复页权限；如果在 DLL 卸载前不恢复，IAT 仍指向已卸载 DLL 中的钩子函数，后续调用会跳转到已释放内存导致崩溃。
- 根因是“IAT 是进程内可写的函数指针表”，攻击者只要能在目标进程内执行代码（DLL 注入、LoadLibrary、APC 等）并有改页权限，就能重定向导入调用。IAT Hook 只能覆盖通过 IAT 调用的函数；直接 `GetProcAddress` 调用、内部调用或未导入的函数不在 IAT 中。

## 触发条件

- 目标为 Windows PE（EXE/DLL），目标 API 通过导入表调用（不是动态 `GetProcAddress`）。
- 攻击者能把 Hook DLL 加载进目标进程（DLL 注入、`LoadLibrary`、侧加载、调试器注入等）。
- 进程对 IAT 所在页有 `VirtualProtect` 权限（同用户/管理员，或目标未启用缓解）。
- 目标架构与 Hook DLL 一致（32 位 DLL 只能注入 32 位进程，64 位同理）。
- 钩子函数签名/调用约定与目标 API 完全匹配。

## 利用步骤

1. 在目标进程中获取模块基址（`GetModuleHandleA(0)` 或注入 DLL 的 `DllMain` 参数）。
2. 解析 DOS 头 `e_lfanew` → NT 头 → 可选头 `DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]`。
3. 遍历 `IMAGE_IMPORT_DESCRIPTOR`，按 `Name` 匹配目标 DLL；同时遍历 INT/IAT，按 `IMAGE_IMPORT_BY_NAME.Name` 匹配目标函数，返回 IAT 槽指针。
4. 保存 IAT 槽原值（原函数地址），`VirtualProtect` 改页为 RWX，写入钩子函数地址，恢复页权限。
5. 钩子函数内调用原函数或修改参数/返回值；需要时在 `DLL_PROCESS_DETACH` 恢复 IAT 槽。
6. 用测试程序调用目标 API，确认弹窗/返回值被劫持；卸载后确认恢复原行为。

## PoC

```cpp
#include <Windows.h>

typedef int(WINAPI* PFN_MessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);
static PVOID g_iatSlot = nullptr;
static PVOID g_original = nullptr;

int WINAPI HookMessageBoxW(HWND h, LPCWSTR text, LPCWSTR caption, UINT type)
{
    auto orig = (PFN_MessageBoxW)g_original;
    return orig(h, L"hooked", caption, type);
}

PVOID GetIatSlot(const char* dllName, const char* funcName)
{
    auto base = (BYTE*)GetModuleHandleA(nullptr);
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    auto dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + dir->VirtualAddress);

    for (; desc->Name; desc++) {
        if (_stricmp((char*)(base + desc->Name), dllName) != 0) continue;
        auto intThunk = (PIMAGE_THUNK_DATA)(base + desc->OriginalFirstThunk);
        auto iatThunk = (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);
        for (; intThunk->u1.Function; intThunk++, iatThunk++) {
            if (intThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            auto byName = (PIMAGE_IMPORT_BY_NAME)(base + intThunk->u1.AddressOfData);
            if (strcmp((char*)byName->Name, funcName) == 0) return iatThunk;
        }
    }
    return nullptr;
}

BOOL Install()
{
    g_iatSlot = GetIatSlot("user32.dll", "MessageBoxW");
    if (!g_iatSlot) return FALSE;
    g_original = *(PVOID*)g_iatSlot;
    DWORD old = 0;
    if (!VirtualProtect(g_iatSlot, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    *(PVOID*)g_iatSlot = (PVOID)HookMessageBoxW;
    VirtualProtect(g_iatSlot, sizeof(PVOID), old, &old);
    return TRUE;
}

BOOL Uninstall()
{
    DWORD old = 0;
    if (!VirtualProtect(g_iatSlot, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    *(PVOID*)g_iatSlot = g_original;
    VirtualProtect(g_iatSlot, sizeof(PVOID), old, &old);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) Install();
    else if (reason == DLL_PROCESS_DETACH) Uninstall();
    return TRUE;
}
```

## 变体与关联

- **定位变体**：按 DLL 名+函数名、按序号导入、按哈希匹配函数名、解析延迟导入表（Delay Import）；64 位需用 `IMAGE_THUNK_DATA64` 与 `IMAGE_ORDINAL_FLAG64`。
- **写入变体**：`VirtualProtect`、`VirtualProtectEx`、`WriteProcessMemory`、直接改 PTE；跨进程 Hook 需要 `VirtualProtectEx`/`WriteProcessMemory`。
- **钩子变体**：只改 IAT 槽、同时 Hook 多个 API、IAT + inline hook 组合、延迟导入/转发导出。
- **关联**：[[code-analysis-reverse-windows-iat-hook-lstrcmp-xxtea]]（IAT Hook 的识别与还原）；[[code-analysis-reverse-windows-x86-inline-hook-packet-intercept]]（inline hook 的另一条路径）；[[code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch]]（PE 代码空洞/相对调用补丁）。
- **边界**：目标用 `GetProcAddress` 动态调用、API 未出现在导入表、页不可写且无法改权限、或进程有 IAT 保护/CFG 时，IAT Hook 失效；x64 下 IAT 项为 8 字节，注意指针宽度。

## 检测与防御

- **检测**：IAT 槽指向的地址不在对应 DLL 的导出范围内；IAT 页出现 RWX/可写；DLL 加载后 IAT 被修改；`VirtualProtect` 对 IAT 页的调用。
- **防御**：启用 CFG/CET/ACG 等缓解；监控 IAT 完整性；对敏感 API 使用直接系统调用/动态解析；限制 DLL 注入与未签名 DLL 加载。
- **加固**：代码签名/白名单、受保护进程（PPL）、ETW 监控 IAT 修改；分析侧可用 PE 对比工具检查 IAT 与磁盘导入表差异。
