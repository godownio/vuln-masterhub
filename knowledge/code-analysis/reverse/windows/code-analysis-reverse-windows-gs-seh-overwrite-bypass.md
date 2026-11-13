---
id: code-analysis-reverse-windows-gs-seh-overwrite-bypass
title: Windows /GS 的 SEH 绕过：溢出覆盖栈上异常处理指针指向缓冲区 shellcode，异常分发先于 canary 校验
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: win-msvc-gs-seh-record-overwrite-bypass
aliases:
- 攻击异常处理绕过 GS
- SEH 覆盖绕过 GS
- 异常处理指针覆盖
- SEH 链劫持
- GS SEH bypass
- __except_handler4
tags:
- pwn
- stack
- windows
- gs
- canary
- seh
- exception
- shellcode
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:46:35+08:00'
  notes: 已对照原文与截图4/5核对：SEH handler原为00452560 __except_handler4、位于0x0019FF54，被payload覆盖后为90909090/0019FDD0；buf首址0x0019FDD0、偏移388(0x184)、payload 392字节末4字节D0 FD 19 00，strcpy+strcat双写放大溢出且异常分发先于canary校验，均与原文一致。dedup与SafeSEH/SEHOP/未注册模块等卡为related但保护条件与利用路径不同，非同链。未实测执行（无32位Windows实验环境）。
---

## 一句话结论

GS 只保护函数的返回地址/栈帧，不保护栈上的结构化异常处理（SEH）链；当栈溢出长度足以覆盖栈中的异常处理记录指针（本例 `0x0019FF54` 处的 handler 指针），把异常分发目标改为缓冲区中的 shellcode，并制造一个异常，系统在展开异常时会先 `call` 被覆盖的 handler——异常路径不经过函数返回，canary 校验被完全跳过。

## 原理

- **SEH 链在栈上**：32 位 Windows 的每个线程维护 `FS:[0]` 指向栈上的 `EXCEPTION_REGISTRATION_RECORD` 链表，记录里有 `Next` 与 `Handler` 两个指针。函数用 `__try/__except` 或编译器生成的 `__except_handler4` 时，这些结构就位于该函数的栈帧中，**和局部缓冲区同处一个栈**。
- **异常分发优先于返回**：栈溢出破坏 canary（或访问非法地址）会触发异常；系统先遍历 SEH 链调用 handler，再谈函数是否正常返回。`__security_check_cookie` 只在正常函数尾声执行，异常展开路径不会走到它。
- **覆盖 handler 指针**：调试可见 buf 首地址 `0x0019FDD0`、SEH 记录指针位于 `0x0019FF54`，相差 0x184=388 字节；payload 第 388~391 字节写入 buf 首地址（`0x0019FDD0`），即把栈上“指向 SEH 记录/处理器的指针”覆盖为缓冲区地址，使异常分发跳到缓冲区里的 shellcode。
- **双重复制放大溢出**：示例函数 `strcpy(buf, szBuffer); strcat(buf, szBuffer);` 先把输入拷入 buf，再把同一输入追加一次；即使单次输入长度有限，拼接后也会成倍增长并越过 canary 到达 SEH 记录（同时 canary 被破坏，正好用来触发异常）。
- **危害**：任意代码执行；且不需要知道 canary，也不需要覆盖返回地址。

## 触发条件

- 32 位 Windows x86 程序，函数使用 SEH（`__try/__except`、`__except_handler4` 或 CRT 生成的结构），且 SEH 记录位于可被溢出的栈范围内。
- 栈溢出可写长度足以到达 SEH 记录（本例约 388 字节，视栈帧布局而定）。
- 程序未启用 SafeSEH（或模块无 SafeSEH 表）/SEHOP；DEP 未阻止栈上执行（或已 ROP 绕过）。
- 溢出会自然触发异常（覆盖 canary 后在返回时触发，或访问非法地址），也可主动让程序抛异常。
- 仅用于授权测试与本地实验。

## 利用步骤

1. 在 x64dbg/WinDbg 中查看异常链（`!exchain` 或栈视图），确认 SEH handler 指针（如 `__except_handler4`）在栈上的地址。
2. 计算 buf 首地址到 SEH 记录指针的偏移（本文 388 字节）；确认 payload 长度足以覆盖。
3. 将 shellcode 放在 payload 开头，在偏移 388~391 处写入 buf 首地址（小端）。
4. 提交超长输入（本程序经 strcpy+strcat 双写，长度会翻倍），让 canary 被破坏并在函数返回时触发异常；异常分发读被覆盖的 handler 指针，跳到 shellcode。
5. 命中后替换 shellcode 为真实载荷；若 SafeSEH/SEHOP 启用，改用“指向合法模块中已有指令/ROP 链”的 handler 或先绕过保护。
6. 记录寄存器/栈状态，评估 DEP 与 ASLR 对载荷的影响。

## PoC

```cpp
// 关键结构示意（32 位 MSVC，/GS 开启，SEH 在栈上）
char szBuffer[] = { /* shellcode + padding + buf 地址 */ };

void test(char* szBuffer) {
    char buf[200] = {0};
    strcpy(buf, szBuffer);   // 溢出
    strcat(buf, szBuffer);   // 再追加一次，长度翻倍越过 canary 到 SEH 记录
}

int main() {
    test(szBuffer);          // 全局缓冲区作为输入
    return 0;
}
```

```text
# payload 布局（392 字节，地址以实际调试为准）
[0x00..]      shellcode（MessageBoxA 等）
...
[0x184..0x187]  buf 首地址 0x0019FDD0（小端 D0 FD 19 00）
# 覆盖栈上 SEH 处理指针：0x0019FF54 处由 __except_handler4 变为 buf 地址
# 异常触发 -> 系统遍历 SEH -> call 被覆盖的 handler -> 执行 buf 中 shellcode
```

```text
# 调试观察（节选）
0019FF54  90909090   ; 原为 00452560 <gs.__except_handler4>，被 payload 覆盖
0019FF58  0019FDD0   ; 指向缓冲区
```

## 变体与关联

- 变体：SafeSEH 启用时，handler 必须指向模块合法处理函数；可尝试覆盖 SEH 链的 Next 指针、利用未启用 SafeSEH 的模块，或走 ROP 链。
- 变体：SEHOP 校验链完整性，可尝试伪造链尾/利用异常展开前的其他劫持点；64 位 Windows 用表驱动异常（.pdata/UNWIND_INFO），思路变为覆盖异常目录/展开信息。
- 变体：不依赖 strcat 翻倍，直接用超长 strcpy 也可溢出到 SEH 记录；只要偏移算准。
- 关联：[[binary-pwn-stack-win-gs-vtable-overwrite-bypass]]（同篇的虚调用绕过，利用“校验前的间接调用”）、[[binary-pwn-stack-win-gs-dotdata-cookie-replace-bypass]]（同时改 .data 种子的绕过）、[[binary-pwn-stack-win-dep-ret2libc-virtualprotect-bypass]]（Windows DEP 绕过与 SEH/ROP 相关思路）。

## 检测与防御

- 检测：审计使用 SEH 且存在栈溢出的 32 位程序；调试时关注 SEH 链指针是否被输入覆盖；运行时监控异常分发目标是否落在栈/堆（非模块地址）。
- 防御：启用 SafeSEH（/SAFESEH）与 SEHOP；开启 /GS、DEP、ASLR、CFG；用 /GS 之外的安全字符串函数消除溢出；对关键进程启用 CET；移除不必要的 __try/__except 结构或将其移到独立栈帧。
- 说明：本文是 Windows /GS 的 SEH 路径绕过场景（32 位 MSVC 教学程序），severity 记为 high，confidence medium（原文 PoC 在关闭部分缓解的实验环境验证）。
