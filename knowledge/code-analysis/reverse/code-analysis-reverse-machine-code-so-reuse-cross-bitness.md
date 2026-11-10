---
id: code-analysis-reverse-machine-code-so-reuse-cross-bitness
title: 二进制层面代码复用：把目标函数机器码字节编译成共享库，用 ctypes 跨位数调用
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: machine-code-bytes-to-shared-library-reuse
aliases:
- 机器码编译成 .so
- db 字节复用函数
- ctypes CDLL 复用目标代码
- 跨 32/64 位子进程桥接
- 二进制代码复用 keygen
tags:
- reverse
- code-reuse
- machine-code
- shared-library
- ctypes
- cross-bitness
- nasm
- keygen
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:12:06+08:00'
  notes: 已对照原文核对：db 机器码写 namehash.asm、nasm -f elf + ld -m elf_i386 -shared、32 位 Python3.4.10 ctypes CDLL、64 位主脚本 subprocess 取 stdout、关 ASLR 规避段错误，均与正文一致；原文已成功编译并产出 key，PoC 用省略字节示意合理。与 assembly-function-reuse-nasm-object-gcc-link-keygen 为同一主题的两种落地路径（.o 直链 C vs .so+ctypes 跨位宽桥接），dedup 与 dup-scan 均判 related，不删；confidence medium 与跨位数/ASLR 依环境而定相符。无版本字段。
---

## 一句话结论

对于只使用寄存器与栈局部变量、不访问外部符号/全局数据/绝对地址的「纯算法」函数，可以直接把它的机器码字节从反汇编器里抠出来，用 `db` 写成汇编、编译成共享库，再用 ctypes 加载调用，从而在注册机/分析脚本里原样复用目标代码、省去手工重写算法；当目标函数位数与主脚本不同时，用一个匹配位数的 Python 子进程 + ctypes 桥接，主脚本通过 subprocess 取返回值。

## 原理

- 为什么能整段搬：函数体若是位置无关（PIC）的——只做寄存器运算、栈上局部变量、参数经栈/寄存器传入、无 `call` 到外部、无全局数据引用、无需重定位的绝对地址——那么它的机器码字节在任意加载地址都能正确执行。把这段字节当数据 `db 0x55, 0x83, ...` 交给汇编器、导出符号 `function`，即可被外部按 C ABI 调用。
- 为什么用 `db` 机器码而不是伪汇编：从 Ghidra 复制伪汇编常夹杂二进制值、需手工调整；直接复制机器码字节最省事，也便于让工具整理生成。二者功能等价，机器码更不易出错。
- 位数 / ABI 桥接：32 位机器码必须编成 32 位 `.so`（`nasm -f elf` + `ld -m elf_i386 -shared`，或 `gcc -m32 -shared`），64 位进程不能 `CDLL` 一个 32 位 `.so`。解法是编译一个 32 位 Python，用它的 ctypes 加载 `.so` 并把结果打印到 stdout；主脚本（64 位 Python）用 `subprocess.run` 调这个 32 位解释器并解析输出。
- 参数/返回值约定：按 cdecl 用 `ctypes` 声明 `argtypes=[c_int, c_char_p]`、`restype=c_uint`，与函数从栈取参（`[esp+4]`、`[esp+8]`）一致；位数、调用约定、结构体对齐都要核对，否则结果静默错误或崩溃。
- 为什么有价值：注册机、算法验证、协议还原里常有「难重写但易复用」的 hash/校验函数，直接复用二进制比逆向重写更可靠省时；本例即用它复用用户名 hash 函数 `FUN_00401000` 供 keygen 调用。
- 边界与坑：32 位程序在 amd64 上可能因 ASLR 段错误（关 `randomize_va_space` 可绕过，gdb 下常正常）；目标函数一旦含全局变量、外部调用、重定位、绝对地址或自修改代码就不能直接搬。作者还讨论过两种更通用但复杂得多的替代框架：写 loader 把代码映射进内存直接 `call`（免位数限制但要自己处理重定位），或远程线程注入目标进程复用代码（通用但受 OS/架构限制）。confidence=medium：跨位数桥接与 ASLR 表现依具体环境而定。

## 触发条件

- 已定位到一个纯算法子函数，能确定其入口/出口字节范围与调用约定；
- 函数体位置无关、无外部依赖/重定位/绝对地址/自修改；
- 能得到与目标位数一致的运行/编译环境，或愿意用「匹配位数的解释器 + subprocess」桥接；
- 调用方需要的输入输出可用基本 C 类型表达。

## 利用步骤

1. 在反汇编器里确认函数为纯寄存器/栈代码，记录入口机器码字节与调用约定。
2. 把机器码字节写成 `.asm`（`global function` + 逐行 `db ...`），用 nasm 编译成 `.o`。
3. 按目标位数链接成 `.so`（32 位用 `ld -m elf_i386 -shared` 或 `gcc -m32 -shared`）。
4. 用匹配位数的 Python + ctypes 声明 `argtypes` / `restype` 并调用。
5. 位数不一致时，主脚本用 `subprocess.run([...], capture_output=True)` 调匹配位数的解释器，解析 stdout 取结果。

## PoC

```asm
; nasm -f elf namehash.asm -o namehash.o
; ld -m elf_i386 -shared namehash.o -o namehash.so   (等价 gcc -m32 -shared ...)
section .text
global function
function:
    db 0x55, 0x83, 0xec, 0x08, 0x8b, 0x44, 0x24, 0x10
    db 0x33, 0xed, 0x33, 0xd2, 0x8b, 0x4c, 0x24, 0x14
    ; ... 其余机器码字节从目标函数提取，此处省略 ...
    db 0xc3
```

```python
# 32 位 Python 侧
from ctypes import *
import sys
lib = CDLL('./namehash.so')
lib.function.argtypes = [c_int, c_char_p]
lib.function.restype = c_uint
print(hex(lib.function(len(sys.argv[1]), sys.argv[1].encode())))
```

```python
# 64 位主脚本
import subprocess
h = subprocess.run(['<32bit-python>', 'namehash.py', name],
                   capture_output=True, text=True).stdout.strip()
```

（字节与函数名均为示意，实际须从目标二进制提取。）

## 变体与关联

- 变体：直接编译 Ghidra 伪汇编（需清理夹杂的二进制值）；用 Unicorn/QEMU 模拟执行该函数片段；写自定义 loader 把代码映射进内存直接 `call`；远程线程注入目标进程复用代码；用 ctypes 直接调用目标已加载的 DLL/SO 导出函数。
- 关联：crackme keygen（同篇另一卡）、标准算法常数识别、跨架构动态分析、位置无关代码（PIC）判定。

## 检测与防御（分析侧注意 / 保护侧）

- 分析侧：复用前务必确认无重定位/外部引用，否则会静默得到错误结果或崩溃；位数、调用约定、结构体对齐逐一核对；ASLR 引起的段错误可先关 ASLR 排查，并在 gdb 下对比行为。
- 保护侧（提高复用成本）：让关键函数依赖全局状态、外部调用、重定位/绝对地址或自修改代码，使其不再是位置无关的纯片段；加完整性校验与反调试。
- 边界：本技巧只适合「简单纯算法代码复用」，不适合带 I/O、堆、全局状态或跨模块引用的复杂函数。
