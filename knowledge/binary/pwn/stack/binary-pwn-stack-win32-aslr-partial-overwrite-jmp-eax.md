---
id: binary-pwn-stack-win32-aslr-partial-overwrite-jmp-eax
title: Windows 32 位 ASLR 部分地址覆盖绕过：仅覆写返回地址低 2 字节跳到固定偏移 jmp eax
type: scenario
domain: binary
path: binary/pwn/stack
technique: win32-aslr-partial-return-overwrite
aliases:
- ASLR 部分覆盖
- 返回地址低两字节覆盖
- 32 位 ASLR 绕过
- jmp eax 跳板
- 映像基址随机化
tags:
- windows
- aslr
- stack-overflow
- partial-overwrite
- jmp-eax
- x86
- memory-protection
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V515
  verified_at: '2026-11-11T11:46:02+08:00'
  notes: 已对照原文及全部13张图核对（01 PE结构、02 注册表 MoveImage、03/04 VS 常规与 /GS- 设置、05 /DYNAMICBASE 是+DEP 否、06/07 两次启动基址 0x00FC0000 vs 0x00C00000 仅高 2 字节变化、08 test 反汇编、09/10 栈与返回地址、11 gadget 候选 00C123E5/00C22649/00C228BF/00C24ED5、12 返回地址被覆写 00C123E5、13 EIP=EAX=0093F988 执行 shellcode）：技术点/寄存器接力/PoC 与原文截图一致。修正：原文 010 Editor 头注释写 Size 206，但数组实际为 202 字节且 ReadFile 读取 202（196 缓冲区+4 saved EBP+2 返回地址覆盖），卡片原『Payload 布局（206 字节）』已改为 202 并注明原文头注释误标。原文未涉及组件版本，affected_versions 留空正确。dedup：仅自匹配 duplicate；其余（Linux 单字节覆盖后门、x64 movsx 长度、jmp esp+funn.dll 样本、格式串改返回地址等）均 related/new，非同一链。未执行任何利用。
---

## 一句话结论

32 位 Windows 的映像基址随机化只改变模块加载基址的高 2 字节，模块内地址的低 2 字节固定；在栈溢出中只覆盖返回地址的低 2 字节（高 2 字节由系统/调用链保留），就能跳到目标模块内固定偏移的 `jmp eax` 等跳板，再借寄存器指向栈上 shellcode 执行，无需泄露或猜测随机化后的完整地址。

## 原理

- **ASLR 的随机化粒度**：启用 `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` 的模块由系统在加载时选择基址；在 32 位 Windows 上观察到的效果是基址高 2 字节随机、低 16 位（模块内偏移）保持不变，因此模块内任何地址的低 2 字节都是确定的。
- **部分地址覆盖**：栈溢出覆盖返回地址时只写最低 2 字节，高 2 字节保持原返回地址的值（合法调用者地址的高位），返回地址被重定向到同一 64KB 区域内的固定偏移——攻击者只需知道 gadget 相对于模块的偏移。
- **寄存器接力**：栈上 shellcode 的绝对地址虽然每次进程启动随机（堆栈随机化），但溢出拷贝完成后寄存器常指向缓冲区（原文 `memcpy` 后 `eax` 指向 `str`），使用模块内低 2 字节固定的 `jmp eax`（或 `call eax`）即可间接跳到 shellcode，不必知道栈地址。
- **未启用 ASLR 的模块**：旧版第三方组件（如 Adobe Flash Player ActiveX）常未设置 DYNAMICBASE，加载地址完全固定，可直接作为跳板/ROP 来源，属于“绕过未启用 ASLR 的模块”这一变体。
- **兼容性开关**：注册表 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\MoveImage` 控制映像随机化——`0` 禁用、`-1` 强制对所有可随机化映像生效、其他值（或不存在该项）按模块标识正常工作；此外堆栈随机化在进程启动时确定，PEB/TEB 也在 Windows XP 起做了随机化。
- **成立范围**：本技巧针对 32 位进程且目标模块低 16 位不变的情况；若同时启用 DEP（栈不可执行）则还需 ROP 链，若模块随机化粒度覆盖低 16 位则不成立。

## 触发条件

- 32 位 Windows 进程，目标模块启用 DYNAMICBASE（ASLR），且其基址低 2 字节固定。
- 存在可控制返回地址的栈溢出；GS 未启用或可绕过；DEP 关闭（原文实验只开 ASLR）或已有 ROP。
- 溢出后某寄存器（如 `eax`）指向 shellcode/可控缓冲区，且模块内存在低 2 字节固定的 `jmp eax`/`call eax` 跳板。
- 或存在未启用 ASLR 的已加载模块可作为固定地址跳板。

## 利用步骤

1. 确认保护：PE 头 `DllCharacteristics` 是否含 `DYNAMICBASE`；注册表 `MoveImage` 是否为禁用/强制；用两次启动对比模块基址，确认低 2 字节不变。
2. 用调试器观察溢出函数的栈布局，确认返回地址偏移与覆盖长度（原文 196 字节缓冲区、拷贝 202 字节）。
3. 在模块内搜索跳板 gadget（如 `jmp eax`），记录其低 2 字节（原文候选 0x123E5、0x22649、0x228BF、0x24ED5，选择位于同一 64KB 区域且可用的一个）。
4. 构造 payload：`shellcode + 0x90 填充 + 2 字节跳板地址`，只覆盖返回地址低 2 字节。
5. 触发溢出：`memcpy` 后 `eax` 指向栈上 shellcode，`jmp eax` 执行 shellcode（原文弹出计算器验证）。

## PoC

存在溢出的示例程序（无 GS）：

```c
#include <stdio.h>
#include <Windows.h>

char ShellCode[202];

void test(char *szBuffer) {
    char str[196] = { 0 };
    memcpy(str, szBuffer, 202);   // 溢出：覆盖保存的返回地址
}

int main() {
    memset(ShellCode, 0, 202);
    HANDLE hFile = CreateFileA("111.txt", GENERIC_READ, NULL, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dwReadSize = 0;
    ReadFile(hFile, ShellCode, 202, &dwReadSize, NULL);
    test(ShellCode);
    return 0;
}
```

Payload 布局（202 字节；原文 010 Editor 头注释误标 Size 206，实际数组与 ReadFile 均为 202）：

```text
[ shellcode (~200 字节，含 0x90 填充) ][ 返回地址低 2 字节：E5 23 ]
```

对应模块内 `jmp eax` gadget（低 2 字节固定）与执行结果：

```text
00C123E5  jmp eax     <- 仅覆盖低 2 字节，高 2 字节沿用原返回地址
EIP = EAX = 0093F988  <- jmp eax 后跳入栈上 shellcode（calc 弹出）
```

## 变体与关联

- 变体：用未启用 ASLR 的模块（如旧版 Flash ActiveX）做固定地址跳板/ROP，属于“攻击未启用 ASLR 模块”，比部分覆盖更直接。
- 变体：64 位进程的基址随机化粒度更低（页内 12 位固定），部分覆盖通常覆盖低 1~2 字节；配合栈泄露可进一步控制。
- 变体：若 DEP 开启，部分覆盖可跳到模块内 `VirtualProtect`/ROP 链先关闭 DEP，再执行 shellcode。
- 关联：[[binary-pwn-stack-ret2text-win-plus-one-align]]、[[binary-pwn-stack-win64-movsx-length-iret-segment-shellcode]]（其他 Windows 利用/绕过技巧）。
- 边界：模块未启用 DYNAMICBASE 时无需绕过；系统禁用 ASLR（MoveImage=0）时直接固定地址；模块随机化低 16 位不固定、或返回地址高 2 字节不可预测（跨 64KB 边界）时部分覆盖失败。

## 检测与防御

- 修复：所有模块（含第三方组件）启用 `/DYNAMICBASE`，系统保持 ASLR 开启（不要设置 MoveImage=0）；同时开启 DEP/GS/CFG 组合。
- 加固：避免可控寄存器指向可执行栈（DEP）；编译器栈保护（/GS）；Control Flow Guard 限制间接跳转目标。
- 检测：崩溃转储中返回地址落在模块内 `jmp eax` 等跳板附近、且栈上有 shellcode 特征；利用防护（EMET/Exploit Protection）的 ASLR/DEP 审计日志。
