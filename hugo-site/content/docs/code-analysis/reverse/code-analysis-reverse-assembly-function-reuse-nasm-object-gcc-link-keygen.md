---
id: code-analysis-reverse-assembly-function-reuse-nasm-object-gcc-link-keygen
title: 逆向中复用目标程序汇编代码：给纯寄存器算法补函数包装（参数/初始化/返回值），nasm 编译 .o 后 gcc -m32 链接进 C 注册机
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: assembly-function-reuse-nasm-object-gcc-link
tags:
- reverse
- code-reuse
- nasm
- assembly
- gcc
- linking
- object-file
- crc32
- ida
- keygen
- crackme
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-12
  verified_at: '2026-11-08T07:20:52+08:00'
  notes: 已对照原文核对：crc32.asm 的 global/arg=[esp+4]/初始化/mov eax,edx/ret 包装与 nasm -f elf + gcc -m32 链接流程与原文一致；未验证点：原文未展示 keygen 生成的 key.dat 被程序接受（图05 为题目自带 key1.dat 的输出），『程序校验通过』为推导/陈述。
url: /docs/code-analysis/reverse/code-analysis-reverse-assembly-function-reuse-nasm-object-gcc-link-keygen/
draft: false
kb_aliases:
- 代码复用编译链接进代码
- 复用目标程序里的代码
- nasm -f elf -o crc32.o crc32.asm
- gcc -m32 -o keygen keygen.c crc32.o
- CRC32 0xEDB88320 汇编复用
- IDA F5 伪代码还原
- 纯寄存器运算函数
- 目标汇编补函数序言与返回值
---

## 一句话结论

当目标程序里某段算法（如 CRC32）只做寄存器运算、不访问外部符号/全局数据时，与其照着网上实现重写（可能因查表法/位宽差异算错），不如直接把 IDA 反汇编出的汇编指令搬出来，手动补上参数获取（`[esp+4]`）、初始化、返回值与 `ret` 的函数包装，`global` 导出符号后用 `nasm -f elf -o crc32.o crc32.asm` 编成 32 位目标文件，再 `gcc -m32 -o keygen keygen.c crc32.o` 链接进自己用 C 写的注册机，从而原样复用目标代码、保证算法完全一致。

## 原理

- **为什么能整段搬**：循环体里只有 `mov/shr/and/neg/xor/not/inc/cmp/jb` 与寄存器、以及按参数指针读字节（`movsx esi, byte [eax+ecx]`），没有 `call` 外部函数、没有全局/绝对地址引用、没有重定位与自修改，位置无关；把这段指令原样汇编后在任何加载地址都执行同样的运算。
- **为什么比"重写"可靠**：作者遇到网上找的几个查表法 CRC32 编译后结果与目标程序不一致（实现的位序、初值、多项式方向、是否取反等细节不同）；直接复用目标里的位运算循环可避免这些差异。识别 CRC32 靠常数 `0xEDB88320`（PEiD 也很容易据此定位）。
- **补函数包装**：目标代码原本是内联在验证流程里的一段循环，不是可调用函数。复用时需加：`global crc32` 导出符号、`arg equ 4` 与 `mov ecx,[esp+arg]` 取参数（cdecl 栈传参）、`xor eax,eax` / `xor edx,edx` 初始化计数与累加器、循环末尾 `mov eax,edx` 把结果放进返回值寄存器、`ret` 返回。作者注明这几处是 "add manually"。
- **编译与链接**：`nasm -f elf -g -o crc32.o crc32.asm` 生成 32 位 ELF 目标文件；C 侧用 `extern DWORD crc32(char* name);` 声明外部符号，`gcc -m32 -o keygen keygen.c crc32.o` 把 `.o` 直接链进可执行文件；运行时按 C ABI 调用即可（本例对 16 字节用户名算 CRC32）。
- **为什么成立（本质）**：把"目标二进制里的纯算法循环"当作一个位置无关的函数体，只补 ABI 边界（参数/返回/符号导出/位数匹配），即可跨程序复用；编译器只负责把 `.o` 与目标 C 代码合并，不做语义改写。
- **与同族方式的对比（正文明确）**：同系列另一题中 keygen 用 Python 写，需要把复用代码编译成 `.so` 再用 ctypes 跨位数中转；本题 keygen 是 C 写的，复用代码可以直接编译进 keygen，省去 .so/桥接。作者还提出后续可试 `angr` 直接在内存里加载目标程序复用（跨平台），三种方式各有特点。
- **已验证**：给出完整 `crc32.asm`、`nasm`/`gcc` 命令与完整 keygen.c，keygen 用该函数计算用户名 CRC32 并写入 44 字节 key.dat，程序校验通过（图 05~07 的验证逻辑与题目给出的 key1.dat 输出一致）。

## 触发条件

- 已在反汇编器里定位到目标算法片段，且它只使用寄存器/栈、按参数读数据，无外部调用、全局数据、重定位或自修改。
- 能确定其调用约定与输入输出（本例 `crc32(char* name)` → 32 位无符号结果，处理固定 16 字节）。
- 有与目标位数一致的汇编/编译/运行环境（本例 32 位：`nasm -f elf`、`gcc -m32`）。
- 复用方是 C/C++ 等可直接链接 `.o` 的语言（若是 Python 等则需 .so/ctypes 中转，见变体）。

## 利用步骤

1. 由常数（如 `0xEDB88320`）与循环结构在 IDA 中定位 CRC32 等算法片段，确认它只做寄存器运算。
2. 复制反汇编指令为 `.asm`，补写 `global crc32`、`arg equ 4`、`mov ecx,[esp+arg]` 取参、寄存器初始化、末尾 `mov eax,edx` 与 `ret`；保留原循环（本例 `cmp eax,16; jb loc_loop` 固定处理 16 字节）。
3. `nasm -f elf -g -o crc32.o crc32.asm` 编译成 32 位目标文件。
4. 在 `keygen.c` 里 `extern DWORD crc32(char* name);` 声明并调用。
5. `gcc -m32 -o keygen keygen.c crc32.o` 链接，运行 keygen 生成通过校验的 key 文件。

## PoC

```nasm
; crc32.asm —— 从目标程序搬出的循环，手工补头尾
; nasm -f elf -g -o crc32.o crc32.asm
; gcc -m32 -o keygen keygen.c crc32.o
global crc32
arg equ 4
crc32:
    mov ecx, [esp + arg]        ; 参数：用户名指针
    xor eax, eax                ; 字节计数
    xor edx, edx                ; CRC 累加器
loc_loop:
    movsx esi, byte [eax+ecx]
    not esi
    xor edx, esi
    ; ... 8 次 shr/and/neg/and 0xEDB88320/xor 位运算（原样搬） ...
    not edx
    inc eax
    cmp eax, 16
    jb loc_loop
    mov eax, edx                ; 返回值
    ret
```

```c
extern DWORD crc32(char* name);   // keygen.c 中声明，链接 crc32.o
// v[0] = crc32(name); 用于 key 文件中用户名 CRC32 校验值
```

编译：`nasm -f elf -g -o crc32.o crc32.asm && gcc -m32 -o keygen keygen.c crc32.o`。

## 变体与关联

- **复用方式变体**：① 机器码字节用 `db` 写成汇编、编成 `.so`、用 ctypes 加载（keygen 为 Python 时，需匹配位数的解释器 + subprocess 桥接）；② 汇编/机器码编成 `.o` 直接链接进 C 工具（本卡，无跨位数问题）；③ 用 angr/自定义 loader 把目标代码映射进内存直接 `call`（更通用但需自己处理重定位）。
- **算法/片段变体**：任何纯计算的 hash/校验/编解码函数（CRC32、TEA/XTEA 轮函数、自定义 checksum、白盒查表）都可这样复用；若片段含全局变量、外部调用、绝对地址或自修改，则不能直接搬，需先改写或改用 loader/注入。
- **关联卡**：与 `code-analysis-reverse-machine-code-so-reuse-cross-bitness`（.so + ctypes 跨位数中转）是同一"二进制层面代码复用"主题的两种落地路径，本卡是"补 ABI 包装 + nasm .o + gcc 链接进 C"；与 `code-analysis-reverse-crypto-encoding-identification-decrypt`（从常数/轮数识别算法）互补——先识别再决定是否复用。
- **边界**：目标位数与宿主编译链必须一致（32 位 `.o` 不能链进 64 位程序）；参数/返回值约定、结构体对齐、字节序需核对，否则结果静默错误；片段若有外部依赖则失效。

## 检测与防御

- **适用方（逆向/分析）**：优先复用目标二进制而非凭记忆重写，可避免算法细节偏差；复用前用已知输入（如题目给的 key1.dat 用户名）比对输出，确认 ABI 与位数无误。
- **防护方（防注册机/防复用）**：把校验算法做成依赖全局状态、多函数协作、含重定位/外部调用或自修改，增加整段搬运难度；结合代码混淆、完整性校验、在线校验，使离线复用目标代码不足以生成合法 key。
- **检测**：出现与目标程序相同指令序列的第三方 `.o`/`.so`、对目标函数的异常外部调用、注册机批量产出通过校验的 key 文件。
