---
id: code-analysis-reverse-windows-x64-e9-thunk-inline-hook-restore-call
title: x64 下 patch E9 跳转 thunk 实现 inline hook：rel32 相对偏移公式 + 恢复原字节后调用原函数
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: x64-e9-thunk-inline-hook-restore-call
tags:
- windows
- hook
- inline-hook
- e9
- x64
- patch
- thunk
- reverse-engineering
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V507
  verified_at: '2026-11-11T04:36:21+08:00'
  notes: 已对照13470原文与全部19图核对：图01-07复现call fun(0x...1280)→ILT E9 thunk表→真实fun(0x...1920)；图10-14展示改jmp 0x...1900与E9 12060000，rel32=0x1900-0x12EE=0x612与卡一致；图15-19为公式、VirtualProtect、备份oldAddrHard与fun1内memcpy还原后调用funaddr。dedup复核：与既有 absolute-jump-inline-hook-detour（函数入口写5/7/13字节新跳转、解决超±2GB）差异成立——本卡目标为链接器已存在的E9跳转thunk，仅改4字节rel32操作数、无需trampoline/指令边界处理，触发条件与PoC不同；与x86-inline-hook-packet-intercept（x86函数头E9+naked）环境实现不同；库内无其他thunk hook卡，故force add保留成立。近邻重叠提示：E9公式、恢复原字节、VirtualProtect属inline hook通用知识，与本卡thunk特异点共存，建议后续读者两卡并读。另：'dllexport生成thunk'表述略泛化，实际与Debug/增量链接相关，卡内触发条件已列增量链接、hotpatch，可接受；原文int强转64位地址的局限卡内已注明。非组件版本类无需affected_versions；无sources/source_url。未复跑PoC（需Windows x64编译环境）。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-x64-e9-thunk-inline-hook-restore-call/
draft: false
kb_aliases:
- E9 thunk hook
- 跳转 thunk 补丁
- inline hook 初识
- rel32 相对偏移 hook
- x64 E9 inline hook
- 恢复原字节调用原函数
---

## 一句话结论

x64 程序里同一模块的函数调用常先经过链接器生成的 `E9 rel32` 跳转 thunk（`call thunk` → `jmp 真实函数`）；把这 4 字节相对偏移改成自己的 hook 函数偏移，就能把经过该 thunk 的所有调用重定向；hook 函数入口先把原偏移写回再调用原函数，即可完成一次可恢复的 inline hook。由于 thunk、真实函数与同模块 hook 函数距离远小于 ±2GB，5 字节 E9 就足够，不必使用 13 字节绝对跳转。

## 原理

- **调用链**：MSVC 对 `__declspec(dllexport)` 等函数会生成跳转 thunk。`main` 中看到的是 `call 0x...280`，`0x...280` 处是 `E9 xx xx xx xx`，真正函数体在 `0x...920`。即“call 先进入 thunk，thunk 再用 E9 跳到实现”。
- **E9 编码**：`E9` 后跟 32 位有符号相对偏移（rel32），目标地址 = `指令地址 + 5 + rel32`；反推 `rel32 = 目标地址 - (指令地址 + 5)`。x86/x64 都是 5 字节指令，偏移按小端写入 4 字节。原文示例 `E9 12060000` 对应 `0x...1900 - 0x...12EE = 0x612`。
- **重定向**：把 thunk 的 rel32 改成 hook 函数地址的相对偏移后，所有经过该 thunk 的调用都会跳到 hook；未经过该 thunk（直接 call 真实函数体、已被内联）的调用不受影响。
- **x64 下的 E9 可达性**：rel32 是 32 位，只能覆盖 ±2GB。thunk、真实函数与同一模块内的 hook 函数通常在同一映像，距离远小于 2GB，因此 5 字节 E9 在 x64 下仍然可用；只有当 hook 函数在另一个模块且距离超过 ±2GB（例如注入 DLL 去 hook `System32` 的系统 DLL）时，才必须改用 13 字节 `mov r10, imm64; jmp r10` 绝对跳转或把 trampoline 放进 ±2GB 范围。这是对“x64 不能使用 E9”这一常见误解的澄清。
- **恢复与调用原函数**：hook 函数体里若直接 `call` 原函数名，会再次经过被改的 thunk 造成无限递归。做法是在 hook 入口用 `memcpy` 把备份的原 4 字节 rel32 写回，此时 thunk 恢复正常，再调用原函数即进入真正实现；若需要持续 hook，应在原函数返回后重新写入偏移。原文示例中 `fun` 是死循环、调用后不返回，因此没有重新安装。
- **写代码段**：`.text` 默认只读，写入前需 `VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)`，写完恢复原保护。
- **常见坑**：rel32 计算要用有符号 32 位差值（原文把 64 位地址强转 `int` 后相减，依赖差值在 ±2GB 内才成立）；直接跳到函数中部或非指令边界会因指令流错位触发访问异常（原文第一次直接把 thunk 指向 fun 内部就演示了这一点）。

## 触发条件

- 目标为 Windows x64 PE，且目标函数的调用确实经过 E9 thunk（MSVC dllexport、导入跳板、增量链接、hotpatch 等场景常见）。
- hook 函数与 thunk 的距离在 ±2GB 内（同模块最稳妥）。
- 能对代码页调用 `VirtualProtect` 改权限，进程未被 ACG/代码完整性强制保护阻止改写。
- 多线程场景需暂停其他线程或加锁，避免写入 4 字节时被其他线程读到半截偏移。

## 利用步骤

1. 在调试器（x64dbg）中定位调用点：断在 `main`/调用方，看到 `call <thunk>`。
2. 跟到 thunk 地址，确认其字节为 `E9 rel32`，并记下真实函数地址（`jmp <fun>` 注释）与 thunk 地址。
3. 在代码中取 `fun` 与 `fun1`（hook 函数）的地址；`fun` 的地址就是 thunk 地址。
4. 计算新偏移：`rel32 = (int32_t)((char*)fun1 - ((char*)fun + 5))`，并把 thunk 原第 1~4 字节备份为 `oldRel`。
5. `VirtualProtect` 把 thunk+1 处 4 字节改为 `PAGE_EXECUTE_READWRITE`，写入新 rel32，恢复页属性。
6. hook 函数入口先 `memcpy` 写回 `oldRel`，执行自定义逻辑（弹窗、记录参数等），再调用原函数；需要持续 hook 时在返回后重新写入新 rel32。
7. 触发一次原调用验证：应看到 hook 的副作用且原功能仍正常。

## PoC

```cpp
#include <Windows.h>
#include <cstdint>
#include <cstring>

extern "C" __declspec(dllexport) void fun() {
    while (true) { Sleep(1000); printf("hello world\n"); }
}

static int32_t g_oldRel = 0;

void fun1() {
    // 1) 先恢复 thunk 的原相对偏移，避免调用原函数时再次跳回 hook
    memcpy((char*)fun + 1, &g_oldRel, 4);

    MessageBoxW(0, L"hooked", L"hook", 0);

    // 2) 此时 thunk 已恢复，调用即进入真正的原函数
    fun();
    // 若原函数会返回且需持续 hook：在此重新写入新偏移
}

void hook() {
    char* thunk = (char*)fun;                       // fun 的地址即链接器 thunk
    int32_t newRel = (int32_t)((char*)fun1 - (thunk + 5)); // rel32 = 目标 - (指令+5)
    g_oldRel = *(int32_t*)(thunk + 1);              // 备份原 4 字节偏移

    DWORD oldProtect = 0;
    VirtualProtect(thunk + 1, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(int32_t*)(thunk + 1) = newRel;                // 小端写入 E9 的操作数
    VirtualProtect(thunk + 1, 4, oldProtect, &oldProtect);
}
```

```text
# 预期：调用 fun() 时先弹出 MessageBox（fun1），关闭后进入真正的 fun 死循环；
# 说明经过 thunk 的调用已被重定向，且 hook 内调用原函数未递归。
```

## 变体与关联

- 变体：hook 真实函数入口的前 5 字节而不是 thunk，需要处理指令边界并构造 trampoline（备份被覆盖指令，执行后跳回）。
- 变体：x64 下 hook 目标超出 ±2GB 时，改用 13 字节 `49 BA imm64; 41 FF E2`（`mov r10, imm64; jmp r10`）绝对跳转。
- 变体：`FF 25 <绝对地址>`（`jmp [mem]`，x64 下 14 字节）从数据槽取地址；hotpatch 使用函数前的 5 字节 NOP 区。
- 关联：[[code-analysis-reverse-windows-absolute-jump-inline-hook-detour]]（±2GB 不可达时改用绝对跳转）、[[code-analysis-reverse-windows-x86-inline-hook-packet-intercept]]（x86 函数头 5 字节 E9 hook + naked 保存现场）、[[code-analysis-reverse-windows-detours-funcptr-offset-calling-convention]]（Detours 框架封装）。
- 边界：hook 函数与 thunk 距离超过 ±2GB、thunk 被内联/优化掉、调用直接落在真实函数体、代码页受 ACG/完整性保护、多线程无锁写入时，本方案失败或崩溃。

## 检测与防御

- 检测：比对内存中 thunk/函数头字节与磁盘映像，出现 `E9` 且目标落在非模块映射区或 hook 函数地址；代码页出现 RWX 或非映像私有可执行页；`VirtualProtect` 对 `.text` 频繁改权限。
- 防御：启用 ACG/代码完整性保护与 CFG/CET（对间接跳转的约束）；定期校验代码段哈希；关键进程防止第三方 DLL 注入；对可疑 `E9` 重定向做内存扫描。
- 分析侧：遇到行为异常但磁盘文件干净时，优先检查模块入口/导出 thunk 是否被改为指向匿名可执行内存。
