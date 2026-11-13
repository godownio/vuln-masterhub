---
id: binary-pwn-stack-win-gs-vtable-overwrite-bypass
title: Windows /GS 虚函数绕过：溢出改写栈上 this 指针，虚调用在 canary 校验前 call 到缓冲区 shellcode
type: scenario
domain: binary
path: binary/pwn/stack
technique: win-msvc-gs-vtable-call-before-canary-check
aliases:
- 覆盖虚函数绕过 GS
- GS 虚表绕过
- vtable 绕过 GS
- this 指针覆盖
- 虚调用劫持
- MSVC GS bypass
tags:
- pwn
- stack
- windows
- gs
- canary
- vtable
- cpp
- msvc
- shellcode
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:46:31+08:00'
  notes: 已对照原文与截图01-10核对：/GS序言xor ebp、尾声__security_check_cookie（图3/8/9），虚调用mov eax,[ebp-8]→mov edx,[eax]→call eax（图2），payload前4字节为shellcode地址、末4字节写缓冲区地址覆盖[ebp-8]；已修正“204字节覆盖canary”表述（204=200+4只到[ebp-8]，canary在[ebp-4]）。dedup与Linux析构虚表卡为related非同链。未实测执行（无32位Windows/关ASLR环境），PoC为结构示意。
---

## 一句话结论

MSVC 的 /GS 只在**函数返回前**用 `xor ebp` 逆运算与 .data 中的 `__security_cookie` 比较来校验 canary；如果被溢出的 C++ 函数在返回之前先执行了一次虚函数调用，攻击者就可以在覆盖 canary 的同时改写编译器缓存的 this 指针（`[ebp-8]`），使虚调用从攻击者缓冲区读取“虚表指针”并 `call` 到 shellcode——控制流在 canary 校验之前就被劫持，GS 形同虚设。

## 原理

- **GS 校验时机**：函数序言里 `mov eax, ds:__security_cookie; xor eax, ebp; mov [ebp-4], eax`，函数尾声再 `mov ecx,[ebp-4]; xor ecx,ebp; call __security_check_cookie`（内部 `cmp ecx, ds:__security_cookie; jne fail`）。校验只发生在正常返回路径上；任何在校验之前发生的控制流转移都不会经过它。
- **虚调用发生在函数体中间**：C++ 成员函数调用虚函数时，编译器生成 `mov eax,[ebp-8]`（this）→ `mov edx,[eax]`（虚表指针）→ `mov ecx,[ebp-8]` → `mov eax,[edx]`（虚函数地址）→ `call eax`。若 this 指针被缓存在栈帧 `[ebp-8]`，且栈溢出范围覆盖到这里，this 就完全由攻击者控制。
- **溢出覆盖布局**：示例函数 `void gsv(char* src){ char buf[200]; memcpy(buf, src, 204); MyFunc(); }`——`buf` 与 canary 之间有 4 字节的 this 缓存槽（`[ebp-8]`），memcpy 204 字节（buf 200 + 4）恰好覆盖到 `[ebp-8]` 的 this 缓存槽；即使溢出再多 4 字节破坏 `[ebp-4]` 的 canary 也无所谓，因为劫持发生在校验之前。
- **两步间接寻址变“虚表”**：payload 最后 4 字节写入**缓冲区自身地址**，覆盖 `[ebp-8]`，于是 this = 缓冲区；虚调用取 `[this]` 即 payload **前 4 字节**（写入 shellcode 起始地址，如缓冲区+偏移处的 `90 90`）；`call` 直接落到 shellcode。调试器中可清楚看到 `[ebp-8]` 从原对象地址变成 payload 中的地址。
- **危害**：任意代码执行（本例 shellcode 弹 MessageBox，实际可为任意载荷）。前提是地址可预测（无 ASLR/处于同一进程会话）或已通过信息泄露获得缓冲区地址。

## 触发条件

- 目标为 MSVC 编译的 32 位 C++ 程序（本文 x86，`call eax`/4 字节指针），函数启用 /GS。
- 存在栈缓冲区溢出（memcpy/strcpy 等），且溢出长度能覆盖到保存 this 指针的栈槽与 canary。
- 被溢出函数在返回前会调用虚函数（或其他经栈上指针的间接调用）。
- 程序未启用 CFG（控制流防护）/CET 等间接调用保护，或目标地址合法可被 CFG 接受；ASLR 关闭或地址可预测/可泄露。
- 仅用于授权测试与本地实验。

## 利用步骤

1. 在 x64dbg/WinDbg 中定位被溢出函数：确认 /GS 已开启（序言有 `__security_cookie` xor ebp），并确定 `buf` 到 `[ebp-8]`（this 缓存槽）的偏移。
2. 用可控长度输入先观察多少字节开始覆盖 `[ebp-8]` 与 canary（本例 204 字节 memcpy 对应 buf 200 字节 + 4 字节 this 槽）。
3. 确定缓冲区在栈上的地址（无 ASLR 时固定；有 ASLR 时可先用 printf/泄漏或同进程信息）。把 shellcode 放在 payload 前部，记录其入口地址。
4. 构造 payload：前 4 字节 = shellcode 入口（如缓冲区+偏移）；中段 = shellcode（可用 NOP 填充）；最后 4 字节 = 缓冲区首地址（覆盖 `[ebp-8]`，充当 this/虚表指针）。
5. 运行程序触发溢出与紧随其后的虚调用，确认 EIP 落在 shellcode；若 crash，检查 this 槽偏移与地址是否正确（栈对齐/编码差异会导致偏移变化）。
6. 将 shellcode 换成目标载荷（写文件、反弹 shell），评估进程权限与 DEP 限制（必要时 ROP 改内存属性）。

## PoC

```cpp
// 关键结构示意（32 位 MSVC，/GS 开启）
class GSVirtual {
public:
    void gsv(char* src) {
        char buf[200];
        memcpy(buf, src, 204);  // 溢出：覆盖 [ebp-8] 的 this 缓存与 [ebp-4] 的 canary
        MyFunc();               // 虚调用发生在 canary 校验之前
    }
    virtual void MyFunc() {}
};
```

```text
# payload 布局（204 字节，地址以实际进程为准）
[0x00..0x03]  shellcode 入口地址（小端，如 buf+0x10）
[0x04..0x03+len]  shellcode（MessageBoxA / 任意载荷）
...
[0xC8..0xCB]  缓冲区首地址（覆盖 [ebp-8]，作为 this 指针）
# 虚调用取 [this] = payload 前 4 字节 -> 作为“虚表指针” -> call shellcode
```

```text
# 调试器观察点
mov eax, dword ptr ss:[ebp-8]   ; eax 由原对象地址变为 payload 缓冲区地址
mov edx, dword ptr ds:[eax]     ; edx = payload[0..3] = shellcode 地址
call eax                        ; 直接进入 shellcode，未经过 __security_check_cookie
```

## 变体与关联

- 变体：this 指针不在 `[ebp-8]` 时，按编译器实际保存位置（寄存器溢出槽、对象数组、返回前回调的函数指针）调整覆盖偏移；核心是“校验前的间接调用目标可被溢出改写”。
- 变体：64 位 MSVC 下指针为 8 字节、参数经寄存器传递，但同样存在栈上对象/this 槽被覆盖后虚调用劫持的路径；需重新计算偏移。
- 变体：若启用 CFG，虚调用目标必须在合法函数入口集合内，纯栈上 shellcode 地址会被拦截；可改为篡改虚表指向合法函数（如 system 包装）或结合 ROP。
- 关联：[[binary-pwn-stack-win-gs-seh-overwrite-bypass]]（同一 GS 缺陷的异常路径绕过）、[[binary-pwn-stack-win-gs-dotdata-cookie-replace-bypass]]（同时改 .data 种子的另一种绕过）、[[binary-pwn-stack-cpp-unwind-destructor-vtable-hijack-skip-canary]]（Linux 下靠异常展开+析构虚调用跳过 canary，思路同源）、[[binary-pwn-stack-ivanti-cve-2025-0282-clientcapabilities-vtable-rop]]（真实产品中的 this/虚表覆盖）。

## 检测与防御

- 检测：审计 MSVC 编译的 C++ 代码中“栈缓冲区 + 返回前虚调用”的函数；调试时关注 `[ebp-8]` 这类 this 缓存槽是否在溢出范围内；运行时监控返回前 `call eax` 的目标是否位于栈/堆（非法模块）——CFG/ETW 可告警。
- 防御：开启 /GS 的同时开启 CFG（/guard:cf）与 ASLR/DYNAMICBASE、DEP；消除栈溢出（安全字符串函数、边界检查）；避免把对象指针/this 缓存暴露在可溢出的栈区间；对高价值进程使用 CET/硬件影子栈；编译器升级到支持更强缓解的版本。
- 说明：本文是 Windows /GS 的虚调用绕过场景（32 位 MSVC 教学程序），severity 记为 high，confidence medium（原文 PoC 在关 ASLR 的实验环境验证，真实目标需地址泄露）。
