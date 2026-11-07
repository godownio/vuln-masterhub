---
id: ctf-reverse-godot4-gdextension-rc4-hotpatch-shellcode
title: Godot GDExtension 伪 DLL 逆向：RC4 解密 + 12 字节热补丁跳转自解密 shellcode + 魔改 Base64/LCG 求逆
type: scenario
domain: ctf
path: ctf/reverse
technique: godot-gdextension-rc4-hotpatch-shellcode
aliases:
- GDExtension 伪 DLL
- RC4 伪装 DLL
- 12 字节跳板
- 运行时热补丁
- 自解密 shellcode
- 魔改 Base64 倒序表
- LCG 0x1010193
- NoMyBank
tags:
- reverse
- godot
- gdextension
- windows
- pe
- rc4
- hotpatch
- shellcode
- base64
- lcg
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:12:57+08:00'
  notes: 已对照原文核对：RC4 key G00dLuck2U、12 字节 mov rax; jmp rax 热补丁、0x180002700 loader、0x491 字节 XOR 0xBA shellcode、倒序字母表+[s1,s0,s3,s2] 魔改 Base64+LCG 扰动均一致；原文无图片；PoC 目标常量用占位符，未实际运行。
---

## 一句话结论

Godot 的 GDExtension 外部 DLL 可以伪装成高熵、无 `MZ` 头的加密文件，由 EXE 内自定义加载器用硬编码 RC4 key 解密后 `LoadLibraryExW`；真实 DLL 初始化时又会把静态可见的 TEA 校验函数入口热补丁成 `mov rax, imm64; jmp rax` 的 12 字节跳板，跳到一段从 `.data` 取 blob、逐字节 XOR 0xBA 自解密的 shellcode；真正的校验在 shellcode 里做“倒序字母表 + 输出顺序 [s1,s0,s3,s2] 的魔改 Base64 + LCG 掩码/rol8/XOR”，逆完才能拿到 key。

## 原理

- **伪 DLL 层**：附件 `libextension.dll` 没有 `MZ` 头、熵很高、`file` 无法识别，不是损坏文件，而是被 RC4 加密的真 DLL。`NoMyBank.exe` 中有自定义加载逻辑：读入文件 → RC4 KSA/PRGA → 写临时文件 → `LoadLibraryExW`；RC4 key 以字符串 `G00dLuck2U` 硬编码在 EXE 中。
- **真实 DLL**：RC4 解密后得到正常 PE32+ x64 DLL，导出 `dllchecker_library_init`；字符串包含 `show_flag_dialog`、`Flag Checker`、`enter your key`、`Good job! Here is your gift:`、`Wrong!` 等，说明它才是宝箱最终逻辑。
- **静态诱饵**：DLL 中有一个完整的 TEA 风格函数，长度、常量、写回方式都很像“把 40 字节 key 分块加密后比较”，很容易让人沿它逆；但它只是烟雾弹。
- **运行时热补丁**：DLL 初始化时先把 TEA 函数所在页改成可写可执行，再向函数入口写入 12 字节跳板：
  ```text
  48 B8 <imm64>   ; mov rax, <new_target>
  FF E0           ; jmp rax
  ```
  新目标是 `0x180002700` 的 loader。也就是说，静态看到的 TEA 函数在运行时根本不会执行。
- **自解密 shellcode**：`0x180002700` 从 `.data` 中取 0x491 字节 blob，每个字节 XOR 0xBA，写入可执行内存，再把原校验函数的参数传给这段 shellcode。真实算法在 shellcode 里，静态分析必须先把 blob 解出来再反汇编。
- **shellcode 算法**：
  1. 自定义 Base64：alphabet 为 `ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/`（大写倒序、小写倒序、数字倒序，最后 `+/`）；对每 3 字节算出标准 4 个 sextet 后，输出顺序改为 `[s1, s0, s3, s2]`。
  2. 二次扰动：
     ```text
     seed = 0x114514
     x ^= (seed >> ((i * 8) % 24)) & 0xff
     x = rol8(x, 2) ^ 0xBA
     seed = seed * 0x1010193 + 0x12345678
     ```
  3. 与 `.rdata` 中 56 字节常量比较。
- **求逆**：先逆二次扰动（`x = ror8(y ^ 0xBA, 2)`，再 XOR 同一 mask，seed 同步更新），再按 `[s1,s0,s3,s2]` 的逆序映射回 `[s0,s1,s2,s3]`，按标准 Base64 公式还原 3 字节。
- 根因是“客户端校验逻辑无论如何分层，最终都要在本地执行”；RC4 伪装、热补丁、自解密 shellcode、魔改 Base64 只是提高逆向成本，不能改变客户端可被完全复现的事实。

## 触发条件

- 目标是 Godot 4 游戏，使用 GDExtension 外部 DLL，且 DLL 被加密/伪装。
- EXE 中存在自定义 DLL 加载器（读文件、RC4/异或解密、写临时文件、`LoadLibraryExW`）。
- 真实 DLL 初始化时会修改自身代码页（`VirtualProtect` RWX）并写入跳板/补丁。
- 校验算法在自解密 shellcode 或动态生成代码中，静态反汇编看不到完整逻辑。
- 允许动态调试/内存 dump/本地复现（CTF/授权逆向场景）。

## 利用步骤

1. 检查 `libextension.dll` 是否缺少 `MZ`、熵是否异常高；在 `NoMyBank.exe` 中搜索 `LoadLibraryExW`、`VirtualProtect`、RC4 KSA/PRGA 特征与可打印 key 字符串。
2. 用硬编码 RC4 key 解密伪 DLL，确认得到 PE32+ x64 DLL 与导出函数 `dllchecker_library_init`。
3. 在 IDA/Ghidra 中查看 DLL 初始化函数与字符串 xref；识别 TEA 风格函数只是诱饵。
4. 定位初始化中的 `VirtualProtect` + 12 字节写入（`48 B8 ... FF E0`），记录被 patch 的函数与跳转目标。
5. 找到 loader 从 `.data` 取 blob、逐字节 XOR 0xBA 的逻辑；离线提取 blob 并 XOR 0xBA，得到 shellcode。
6. 反汇编 shellcode，恢复自定义 Base64 表、输出顺序、LCG/rol8/XOR 扰动与 56 字节目标常量。
7. 按逆序求逆得到输入 key；若还有 `o/e/i -> 0/3/1` 之类的展示替换，按成功分支还原最终 gift。

## PoC

RC4 解密伪 DLL：

```python
def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data)); i = j = 0
    for idx, b in enumerate(data):
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out[idx] = b ^ s[(s[i] + s[j]) & 0xff]
    return bytes(out)

real_dll = rc4(open("libextension.dll", "rb").read(), b"G00dLuck2U")
open("libextension.dec", "wb").write(real_dll)
```

逆二次扰动 + 逆魔改 Base64：

```python
def ror8(x, n): return ((x >> n) | ((x << (8 - n)) & 0xff)) & 0xff

alphabet = b"ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
inv = {c: i for i, c in enumerate(alphabet)}

target = bytes.fromhex("<56 字节目标常量>")
stage1 = bytearray()
seed = 0x114514
for i, y in enumerate(target):
    t = ror8(y ^ 0xBA, 2)
    mask = (seed >> ((i * 8) % 24)) & 0xff
    stage1.append(t ^ mask)
    seed = (seed * 0x1010193 + 0x12345678) & 0xffffffff

out = bytearray()
for i in range(0, len(stage1), 4):
    c0, c1, c2, c3 = stage1[i:i+4]
    s1, s0 = inv[c0], inv[c1]
    s3 = 0 if c2 == ord("=") else inv[c2]
    s2 = 0 if c3 == ord("=") else inv[c3]
    out.append(((s0 << 2) | (s1 >> 4)) & 0xff)
    if c2 != ord("="):
        out.append((((s1 & 0x0f) << 4) | (s2 >> 2)) & 0xff)
    if c3 != ord("="):
        out.append((((s2 & 0x03) << 6) | s3) & 0xff)
print(out.decode())
```

## 变体与关联

- **伪装变体**：RC4、XOR、AES、zlib 压缩、无 `MZ` 头、附加随机填充；先看熵与加载器逻辑。
- **热补丁变体**：12 字节 `mov rax, imm64; jmp rax`、5 字节 `jmp rel32`、`push imm64; ret`、IAT hook、VEH 异常处理；关键是找到 `VirtualProtect` 与写入目标。
- **shellcode 变体**：XOR 单字节/多字节、AES、自定义 Base64、LCG、rol/ror；先 dump 解密后的内存再反汇编。
- **关联**：[[ctf-reverse-godot4-embedded-pck-encrypted-resource-aes-cfb]]（本题第一层：内嵌 PCK 与资源解密）；[[ctf-reverse-godot-pck-gdc-decompile-patch-repack]]（Godot pck/gdc 基础）；[[code-analysis-reverse-windows-x86-inline-hook-packet-intercept]]（Windows inline hook/热补丁的另一场景）。
- **边界**：若 shellcode 从网络下发、使用硬件绑定密钥或反调试检测到分析环境就改变行为，需要动态 dump/仿真；仅用于授权逆向。

## 检测与防御

- **检测**：DLL 无 `MZ`/高熵、EXE 中 `LoadLibraryExW` + RC4 特征、DLL 初始化调用 `VirtualProtect` 写入可执行页、`.data` 中存在高熵 blob 且运行时 XOR 解密。
- **防御**：游戏发行方不要把关键校验/flag 放在客户端；使用服务端校验、代码签名与完整性校验；对 GDExtension 做签名/白名单。
- **加固**：反调试、代码混淆、运行时自解密只能提高成本；客户端最终必须能执行校验，逻辑仍可被 dump/复现。
