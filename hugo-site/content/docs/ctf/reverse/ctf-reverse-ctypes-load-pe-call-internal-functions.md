---
id: ctf-reverse-ctypes-load-pe-call-internal-functions
title: ctypes 加载原 PE 调用内部函数：GenKey/B90/D30 复用，Python 只逆 E70/B10
type: scenario
domain: ctf
path: ctf/reverse
technique: ctypes-load-pe-call-internal-functions
tags:
- ctf
- reverse
- ctypes
- windows
- pe
- rc4
- dynamic-analysis
- key-recovery
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:55+08:00'
  notes: 已对照原文核对：ctypes.WinDLL 加载 box.exe、GenKey/B90/D30 按偏移调用、逆 E70/B10 的变换与原文脚本一致；仅 Windows 可复现，未在本机执行。
url: /docs/ctf/reverse/ctf-reverse-ctypes-load-pe-call-internal-functions/
draft: false
kb_aliases:
- ctypes 调用原二进制函数
- WinDLL 加载 EXE
- 原函数复用逆向
- GenKey B90 D30
- box.exe 逆向
- 动态调用内部函数
---

## 一句话结论

当逆向目标的关键步骤（如魔改 RC4 的 KSA/PRGA、复杂 Key Schedule）难以静态重写时，可在 Windows 上用 `ctypes.WinDLL` 加载原 PE，取 `_handle` 作为基址，用 `CFUNCTYPE` 按偏移调用内部函数（如 GenKey/B90/D30），只把可逆的简单变换（XOR 掩码、循环移位、减法）用 Python 逆回去，从而快速解出 flag。

## 原理

- **PE 可作为 DLL 加载**：Windows 的 `LoadLibrary`/`ctypes.WinDLL` 可以加载 EXE（只要它没有以不兼容方式运行）；`mod._handle` 给出模块基址，内部函数地址 = 基址 + IDA 偏移。
- **按偏移调用**：`CFUNCTYPE(restype, argtypes...)(base + offset)` 把任意地址转成可调用函数指针；不需要导出表/符号，只要知道偏移和调用约定。
- **复用复杂逻辑**：魔改 RC4 的 KSA/PRGA、AES S-box/key schedule、函数指针链等静态重写容易出错；直接调用原函数，输入/输出缓冲区即可得到正确中间值。
- **只逆简单变换**：主校验链 `B10 → RC4 KSA/PRGA → E70`，其中 B10/E70 是可逆的字节级变换（异或线性掩码、循环右移、减索引）；Python 逆 E70 得到 RC4 输入，调用原 B90/D30 做 RC4 解密，再逆 B10 得到明文。
- **调用约定/参数**：用 `CFUNCTYPE` 声明返回值和参数类型（指针/整数/长度）；注意 32/64 位 Python 与 PE 架构一致，`c_void_p`/`c_ubyte * n` 缓冲区要保持在调用期间存活。
- **前提**：目标可在分析机加载（依赖 DLL 齐全、无强反调试/驱动保护）；函数不依赖未初始化的全局状态或 GUI/网络；知道函数偏移与调用约定。

## 触发条件

- Windows PE（EXE/DLL）中的关键算法由难以静态复现的函数实现（魔改 RC4/AES、函数指针链、VM）。
- 目标能在分析机加载，依赖库齐全，反调试不阻止 `LoadLibrary`。
- 已通过 IDA/Ghidra 定位函数偏移、参数与返回值。
- Python 与 PE 架构一致（32 位 PE 用 32 位 Python，64 位 PE 用 64 位 Python）。

## 利用步骤

1. 用 IDA 分析 main，定位校验链与关键函数偏移（如 GenKey 0x18E0、B90 0x1B90、D30 0x1D30）。
2. 用 `ctypes.WinDLL(path)` 加载 PE，`base = mod._handle`；定义 `CFUNCTYPE` 原型。
3. 调用 GenKey 生成密钥；调用 B90 初始化 S-box；调用 D30 对密文做 PRGA 解密。
4. 在 Python 中逆简单变换（E70 的 XOR 掩码、B10 的循环右移/减法），得到中间缓冲。
5. 调用原函数处理中间缓冲，再逆另一层变换，得到 flag。
6. 若函数依赖全局初始化，先调用入口/初始化函数，或按 IDA 逻辑手动设置全局变量。
7. 交叉验证：用原程序跑同一输入，确认输出与 Python 结果一致。

## PoC

```python
import ctypes

path = r"box.exe"
mod = ctypes.WinDLL(path)
base = mod._handle
addr = lambda off: base + off

GenKey = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)(addr(0x18E0))
B90 = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)(addr(0x1B90))
D30 = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)(addr(0x1D30))

key_buf = (ctypes.c_ubyte * 9)()
GenKey(ctypes.byref(key_buf))

# 逆 E70：final[i] ^= (91*i-89) ^ (16*i)
pre_rc4 = [b ^ (((91*i - 89) ^ (16*i)) & 0xFF) for i, b in enumerate(final_bytes)]

S = (ctypes.c_ubyte * 256)()
B90(S, ctypes.byref(key_buf), 9)
buf = (ctypes.c_ubyte * 42)(*pre_rc4)
D30(S, buf, 42)

def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xFF

flag = bytes(((ror(b ^ ((55*i) & 0xFF), 3) - i) & 0xFF) ^ 0x3C
             for i, b in enumerate(buf))
print(flag.decode())
```

## 变体与关联

- 变体：Linux `.so`/ELF 用 `ctypes.CDLL`；无导出符号时同样按基址+偏移调用。
- 变体：PE 无法直接加载时，用 Unicorn/Qiling 模拟执行目标函数（需映射 PE、设置寄存器/栈）。
- 变体：只调用 Key Schedule/解密函数，其余用 Python 复现；或把原函数包成 CLI/服务供脚本调用。
- 关联：[[ctf-reverse-ios-macho-unicorn-mach-ipc-rc4]]（Unicorn 模拟调用）、[[ctf-reverse-android-arm64-jni-unicorn-offline-oracle]]（Unicorn 离线 oracle）、[[ctf-reverse-go-paper-bin-rc4-custom-xxtea-multilayer]]（多层 RC4/XTEA 逆向）。

## 检测与防御

- CTF 分析：先确认 PE 架构与 Python 位数一致；`WinDLL` 失败时检查依赖 DLL/位数/反调试。
- 防御：发布时剥离符号/加壳只能提高静态分析成本；若担心被直接调用，可做完整性校验、反调试、函数级混淆，但无法阻止有权限的本地动态调用。
- 该技术为离线逆向，不影响运行中的服务；仅用于授权 CTF/安全研究。
