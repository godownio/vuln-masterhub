---
id: binary-pwn-stack-win-gs-dotdata-cookie-replace-bypass
title: Windows /GS 双写绕过：任意 4 字节写同时改 .data 中的 Cookie 种子与栈上 canary，让校验等式成立
type: scenario
domain: binary
path: binary/pwn/stack
technique: win-msvc-gs-dotdata-seed-and-stack-canary-replace
tags:
- pwn
- stack
- windows
- gs
- canary
- security-cookie
- arbitrary-write
- msvc
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:46:33+08:00'
  notes: 已核对：.data种子0x0050C004、ebp 0x0019FD80、堆0x0069BEB0、偏移0xFFE70154、种子X^ebp=0x90896D10均与原文及截图6/7/10一致；已修正返回地址示例为原文载荷末4字节0x0019FCBC（原误写0x0019FCFC），并把调试观察中[ebp+C]标注改正为参数i（截图10显示该处即i=0x90909090，canary在[ebp-4]）。dedup与相邻变量覆盖卡为related非同链。未实测执行（依赖关ASLR/固定地址）。
url: /docs/binary/pwn/stack/binary-pwn-stack-win-gs-dotdata-cookie-replace-bypass/
draft: false
kb_aliases:
- 同时替换栈和 .data 中的 Cookie
- GS cookie 种子改写
- security_cookie 双写
- .data Cookie 覆盖
- canary 等式绕过
- GS 任意地址写绕过
---

## 一句话结论

MSVC 的 canary 由 `__security_cookie`（.data 中的种子）与 `ebp` 异或生成，函数返回时用同一等式校验；若程序同时存在“栈溢出”和“任意地址 4 字节写”两个原语，攻击者可以一边把栈上 canary 覆盖为任意值 X，一边把 .data 中的种子改写为 `X ^ ebp`，使 `(X ^ ebp) == seed` 成立而通过校验，再正常 `ret` 到被覆盖的返回地址执行 shellcode。

## 原理

- **生成**：序言里 `mov eax, ds:__security_cookie; xor eax, ebp; mov [ebp-4], eax`——栈上 canary = seed ^ ebp。
- **校验**：尾声 `mov ecx,[ebp-4]; xor ecx,ebp; call __security_check_cookie`，其中 `cmp ecx, ds:__security_cookie; jne __report_gsfailure`——用同样的逆运算恢复 seed 并比较。
- **等式可被同时满足**：校验只要求“栈上值与 ebp 异或后等于当前 .data 种子”。若攻击者能改写 .data 种子，则对任意想要的栈上值 X，把种子改成 `X ^ ebp` 即可；此后函数返回校验通过，`pop ebp; ret` 走被溢出的返回地址。
- **两个原语的组合**：示例程序 `test(char* s, int i, char* src)` 中：
  - `if (i < 0x9995) { char* buf = s + i; *buf = src[0]; *(buf+1)=src[1]; ... }`——`i` 只有上限检查没有下限，`s` 是堆指针，`i` 为负时 `buf` 指向低地址（本例 .data 的 `__security_cookie`，地址 0x0050C004），实现任意（低地址）4 字节写；
  - `memcpy(dest, src + 8, 212)`——把 payload 第 9 字节起复制进 200 字节栈缓冲 dest，212 字节覆盖 canary（`[ebp-4]`）、saved ebp 与返回地址。
- **payload 布局**：前 4 字节 = 新的 cookie 种子值 `X ^ ebp`；第 5~8 字节 = 目标种子地址相对堆指针的 32 位偏移；第 9 字节起 = shellcode（复制到栈上）；返回地址指向 shellcode。
- **限制**：需要 ebp 与 .data/堆地址可预测（无 ASLR 或已泄露）；堆地址随机时偏移需每次调试修正，通用性差——原文作者也明确提到“堆的起始地址并不是固定的，要手动修改”。

## 触发条件

- 目标存在栈缓冲区溢出，且溢出能覆盖 canary 与返回地址。
- 同一进程/输入路径上存在任意地址写原语（哪怕只有 4 字节，例如无下限的数组下标、相对指针写）。
- `__security_cookie` 所在 .data 页可写（默认可写），且地址可预测/可泄露。
- 能控制 ebp 或已知函数栈帧的 ebp 值（决定种子改写值）。
- 仅用于授权测试与本地实验。

## 利用步骤

1. 调试验证 GS 开启，确认 canary 生成/校验等式（`xor ebp` 与 `cmp ds:__security_cookie`）。
2. 找到任意写原语能到达的 .data 种子地址（本例 0x0050C004），并确定堆/输入缓冲区地址，计算相对偏移（32 位负数亦可）。
3. 选择覆盖到栈上的 canary 值 X（如 0x90909090），计算新种子 `X ^ ebp`（需要当前函数的 ebp，通常在无 ASLR 时固定）。
4. 构造 payload：`[X ^ ebp][种子相对偏移][shellcode...][返回地址]`，其中返回地址指向栈上 shellcode。
5. 运行触发：任意写先改种子，memcpy 溢出覆盖 canary 与返回地址；函数返回时校验通过，ret 执行 shellcode。
6. 若目标启用 ASLR，先通过信息泄露获得 ebp/堆/.data 地址；地址不可预测时该方法退化为需要爆破或改走其他路径。

## PoC

```cpp
// 关键结构示意（32 位 MSVC，/GS 开启）
void test(char* s, int i, char* src) {
    char dest[200] = {0};
    if (i < 0x9995) {                 // 只有上限、没有下限
        char* buf = s + i;            // i 为负 -> 指向低地址（.data 的 __security_cookie）
        *buf = *src; *(buf+1) = *(src+1);
        *(buf+2) = *(src+2); *(buf+3) = *(src+3);   // 任意 4 字节写
    }
    memcpy(dest, (char*)(src + 8), 212);            // 溢出：覆盖 canary/ebp/ret
}
```

```text
# payload 布局（212 字节复制到 dest，地址以实际调试为准）
[0x00..0x03]  新的 cookie 种子 = X ^ ebp（例：0x90909090 ^ 0x0019FD80 = 0x90896D10）
[0x04..0x07]  种子地址相对堆指针的偏移（例：0x50C004 - 0x69BEB0 = 0xFFE70154）
[0x08..]      shellcode（memcpy 后位于 dest）
...
[0xD0..0xD3]  返回地址（指向 dest 内 shellcode，原文载荷末 4 字节为 0x0019FCBC）

# 校验时：ecx = [ebp-4](0x90909090) ^ ebp(0x0019FD80) = 0x90896D10
#          cmp ecx, ds:[0x0050C004](已被写成 0x90896D10) -> 相等 -> 通过
```

```text
# 调试观察（节选）
ebp = 0x0019FD80
[ebp+8]  = 0x0069BEB0   ; 堆指针 s
[ebp+C]  = 0x90909090   ; 参数 i（观察用 112 个 0x90 时的第 5~8 字节，非 canary）
[ebp-4]  canary 最终由 payload 尾部的 0x90 填充覆盖为 0x90909090
__security_cookie @ 0x0050C004（被 payload 前 4 字节改写）
```

## 变体与关联

- 变体：若能读 .data 种子（信息泄露），可直接把栈上 canary 写成泄露值而非双写；双写是在“能写不能读”时的替代。
- 变体：任意写原语可能是数组负下标、相对指针、格式化写、堆溢出写相邻配置等；关键是能稳定写 4 字节到种子地址。
- 变体：只改栈上 canary 的低字节（NUL 覆盖）或部分字节，配合种子猜测/爆破（fork 场景）。
- 关联：[[binary-pwn-stack-win-gs-vtable-overwrite-bypass]]（同篇虚调用绕过）、[[binary-pwn-stack-win-gs-seh-overwrite-bypass]]（同篇 SEH 绕过）、[[binary-pwn-stack-fork-canary-bytewise-bruteforce]]（逐字节爆破 canary）、[[binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak]]（canary 低字节泄露）。

## 检测与防御

- 检测：审计“只有上限没有下限”的索引/偏移计算与相对指针写；调试时关注 `__security_cookie` 所在 .data 页是否被写入（可设置内存断点）；运行时监控 .data 种子页的异常写。
- 防御：所有数组/偏移访问做上下界双重校验；开启 ASLR/DYNAMICBASE 使种子、栈、堆地址不可预测；/GS 配合 DEP/CFG；把 cookie 种子放入只读页或在启动后 mprotect 保护（需自定义实现）；消除任意写原语（参数化、边界检查）。
- 说明：本文是 Windows /GS 在“栈溢出 + 任意 4 字节写”组合下的双写绕过场景（32 位 MSVC 教学程序），severity medium、confidence low（依赖无 ASLR/固定地址，原文最终 payload 需按调试环境手动修正偏移）。
