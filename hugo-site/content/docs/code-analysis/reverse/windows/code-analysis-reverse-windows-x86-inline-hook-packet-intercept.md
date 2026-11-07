---
id: code-analysis-reverse-windows-x86-inline-hook-packet-intercept
title: x86 Inline Hook：5 字节 E9 相对跳转拦截发包/加密函数
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: x86-inline-hook
tags:
- reverse-engineering
- hook
- x86
- win32
- packet
- code-injection
- virtualprotect
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:33:39+08:00'
  notes: 已对照原文与61张图核对：x86 函数头 9 字节备份、E9 rel32 覆盖 5 字节、naked+PUSHAD/PUSHFD 后 [ESP+0x24/0x28/0x2C] 取返回地址与参数、恢复原指令 jmp 回原函数、VirtualProtect 改页属性均与原文一致（图54-61）。未验证点：示例硬编码序言仅适配 Add，未在本机编译执行；frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-x86-inline-hook-packet-intercept/
draft: false
kb_aliases:
- inline hook
- 内联钩子
- E9 hook
- 函数头覆盖
- 封包拦截 hook
- naked hook
---

## 一句话结论

在 x86 目标函数头写入 5 字节 `E9` 相对跳转，把执行流劫持到 naked hook 函数，保存寄存器后读取/修改参数，再执行被覆盖的原指令并跳回，即可拦截发包/加密函数、抓取封包或插入自定义逻辑。

## 原理

- `E9 rel32` 是相对近跳转，目标地址 = 指令地址 + 5 + rel32；覆盖函数头 5 字节即可把入口改到 ±2GB 范围内的任意地址。
- hook 函数必须用 `_declspec(naked)` 取消编译器自动生成的函数序言，由自己保存现场：`PUSHAD` 压入 8 个通用寄存器（0x20 字节），`PUSHFD` 压入标志寄存器（4 字节）。因此进入 hook 后返回地址位于 `[ESP+0x24]`，第一个参数位于 `[ESP+0x28]`，第二个参数位于 `[ESP+0x2C]`。
- 读取参数后要恢复现场（`POPFD`/`POPAD`），再执行目标函数被覆盖的原始指令（例如 `push ebp; mov ebp,esp; sub esp,0xC0`），最后 `jmp target+5` 回到原函数剩余部分。
- 对封包函数下钩后，每次经过即可取得 buffer 指针、长度、socket 等参数；也可以修改 buffer/长度，或写入标志位决定是否放行，从而实现抓包、改包或阻断。
- 该实现只适用于 x86。x64 下地址超过 4 字节，E9 相对跳转无法覆盖整个地址空间，需要 14 字节绝对跳转或 trampoline。

## 触发条件

- 32 位 x86 目标进程；
- 目标函数头至少 5 字节可覆盖，且要处理指令边界（5 字节跨指令时需要更长的 trampoline）；
- 能调用 `VirtualProtect` 把目标页改为 `PAGE_EXECUTE_READWRITE`；
- 多线程环境需要暂停其它线程或加锁，避免写入瞬间执行到半截指令。

## 利用步骤

1. 定位目标函数地址（如加密 call 或 send 包装）。
2. `VirtualProtect(addr, 9, PAGE_EXECUTE_READWRITE, &old)`；备份前 9 字节；用 `0x90` 填充。
3. 构造 `E9` + `(hookAddr - addr - 5)`，写回前 5 字节；记录 `retAddr = addr + 5`。
4. naked hook 中 `PUSHAD/PUSHFD`，从 `[ESP+0x24]` 取返回地址、从 `[ESP+0x28]` 起取参数，记录或修改 buffer。
5. `POPFD/POPAD`，执行被覆盖的原指令，`jmp retAddr`。
6. 卸载：再次 `VirtualProtect`，写回备份的 9 字节，恢复页属性。

## PoC

32 位 x86、MSVC 的最小示例（以 Add 函数演示 hook 结构）：

```cpp
CHAR  opCode[9] = {0};
DWORD dwRetData = 0, dwRetAddr = 0, dwParam1 = 0, dwParam2 = 0;

int Add(int a, int b) { return a + b; }

_declspec(naked) void HookFun() {
    __asm { PUSHAD }
    __asm { PUSHFD }
    __asm {
        MOV EAX, [ESP+0x24]
        MOV [dwRetAddr], EAX
        MOV EAX, [ESP+0x28]
        MOV [dwParam1], EAX
        MOV EAX, [ESP+0x2C]
        MOV [dwParam2], EAX
    }
    // 此处可记录/修改参数（如封包 buffer、长度）
    __asm { POPFD }
    __asm { POPAD }
    __asm {
        PUSH EBP
        MOV EBP, ESP
        SUB ESP, 0xC0
        jmp [dwRetData]
    }
}

VOID SetInlineHook(DWORD dwHookAddr, DWORD dwTargetAddr) {
    DWORD old = 0, tmp = 0, rel = 0;
    VirtualProtect((LPVOID)dwHookAddr, 9, PAGE_EXECUTE_READWRITE, &old);
    memcpy(opCode, (LPVOID)dwHookAddr, 9);
    memset((LPVOID)dwHookAddr, 0x90, 9);
    char code[5] = {0};
    code[0] = (char)0xE9;
    rel = dwTargetAddr - dwHookAddr - 5;
    *(PDWORD)(code + 1) = rel;
    memcpy((LPVOID)dwHookAddr, code, 5);
    dwRetData = dwHookAddr + 5;
    VirtualProtect((LPVOID)dwHookAddr, 9, old, &tmp);
}
```

说明：示例中硬编码的 `PUSH EBP/MOV EBP,ESP/SUB ESP,0xC0` 只适配演示函数的序言；真实目标应先备份再执行原指令，不能硬写。该实现没有多线程保护，多线程下会因竞态崩溃。

## 变体与关联

- E9 短跳转 vs x64 的 14 字节绝对跳转。
- trampoline：备份并执行被覆盖的完整指令，hook 返回时先走 trampoline，再跳回原函数。
- hotpatch（函数前 5 字节 NOP + 2 字节短跳）等其它布局。
- 关联卡片：[[code-analysis-reverse-windows-game-packet-pipeline-code-injection]]、[[code-analysis-reverse-windows-game-packet-buffer-encryption-locate]]。

## 检测与防御

- 检测：比较 .text 段哈希或函数头字节（`E9`/`0xCC`）、检查页属性是否为 RWX、扫描 hook 跳转、调试器检测。
- 防御：代码完整性校验、签名、反调试、关键函数校验和；服务端权威校验。
- 注意：无锁写入/卸载 hook 会因指令撕裂导致崩溃；卸载时必须完整恢复原字节与页属性。
