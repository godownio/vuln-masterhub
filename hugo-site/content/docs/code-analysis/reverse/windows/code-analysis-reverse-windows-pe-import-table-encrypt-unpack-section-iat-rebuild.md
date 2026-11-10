---
id: code-analysis-reverse-windows-pe-import-table-encrypt-unpack-section-iat-rebuild
title: 加密导入表的 PE 壳：新增 .unpack 节与自建导入表，stub 解密 .mixed 后用 LoadLibraryA/GetProcAddress 重建原 IAT 再跳 OEP
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-import-table-encrypt-unpack-section-iat-rebuild
tags:
- pe
- windows
- reverse
- packer
- import-table
- iat-rebuild
- loadlibrary
- getprocaddress
- entrypoint
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V361
  verified_at: '2026-11-09T02:28:43+08:00'
  notes: 已对照原文全文与9张图核对：07/09.png 为新增 .unpack 节表、NumberOfSections=2、SizeOfImage=0x3000、Import Table RVA=0x203C，08.png 为 .unpack 内自建导入表（kernel32.dll/LoadLibraryA/GetProcAddress、ILT/IAT 0x200E/0x201E/0、Directory Entry ILT=IAT=0x2030、Name=0x2000），06.png 为加壳后 MessageBox 正常运行。.mixed 三合一加密、stub 解密后 LoadLibraryA/GetProcAddress 回填 0x401148 原 IAT、EP=0x2100 与原文表格/字节流一致。原文为技术教学无组件版本，affected_versions 留空正确。dedup top 候选（shellcode 内嵌 PE 手动映射、PEB 动态 API 解析、IAT 隐藏）均非'加密原导入表+新增节自建导入表+重建 IAT'构造，与同篇最小异或壳卡技术原子不同，dedup_review 成立。dup-scan.json（2026-11-08 19:10）早于建卡（2026-11-09 01:44），无涉及本卡 pair。未验证点：未在本机重跑 Python/PE 修改；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pe-import-table-encrypt-unpack-section-iat-rebuild/
draft: false
kb_aliases:
- 加密导入表加壳
- IAT 重建壳
- .unpack 节
- LoadLibraryA/GetProcAddress 重建 IAT
- 导入表加密
- 壳代码导入表
---

## 一句话结论

只加密 `.code`/`.data` 的壳无法隐藏导入表——Windows Loader 必须先按导入表填 IAT，程序才能调用外部函数；把导入表连同业务节一起加密、再新增一个自带导入表的 `.unpack` 节存放壳代码，由 stub 在运行时解密原节、用 `LoadLibraryA`/`GetProcAddress` 模拟 Loader 重建原始 IAT，最后跳回 OEP，就能让导入表也变成密文。

## 原理

- **为什么导入表不能直接加密**：加载 PE 时 Windows Loader 读取 DataDirectory 的 Import Table，加载所需 DLL 并把函数地址写进 IAT；原导入表被加密后 Loader 无法解析，`call [IAT]` 拿不到 `MessageBoxA`，即使代码解密正确也会崩溃。因此壳必须自己承担 Loader 的导入解析工作。
- **壳代码需要自己的导入表**：stub 要调用 `LoadLibraryA` 和 `GetProcAddress`（均在 kernel32.dll），所以新增的 `.unpack` 节需要一套完整、合法的导入表：DLL 名字符串、Hint/Name 表、ILT/IAT 数组、Import Directory Entry 与结束项；同时把 DataDirectory 的 Import Table 指向这套新表，Loader 会先为壳解析这两个函数。
- **加密与解密范围**：目标程序已把原 `.code`/`.data`/`.idata` 三节合并为 `.mixed`（同一节，FOA 0x200、大小 0x200、RVA 0x1000），对整节异或 0x7F 即相当于把所有业务内容加密；stub 在入口先对 `.mixed` 解密，之后再访问其中的字符串与原始 IAT 才是明文。
- **新增节与头部调整**：`NumberOfSections` 1→2；在节表末尾追加 `.unpack` 头（VirtualSize 0x1000、VirtualAddress 0x2000、SizeOfRawData 0x200、PointerToRawData 0x400、Characteristics 0xE0000060 可写可执行）；文件尾部补 0x200 个 0；`SizeOfImage` 由 0x2000 调到 0x3000。
- **stub 重建 IAT 的流程**：解密 `.mixed` → `push` "user32.dll" 字符串地址 → `call [LoadLibraryA IAT]` 得到模块基址 → `push` "MessageBoxA" 字符串地址、`push eax` → `call [GetProcAddress IAT]` 得到函数地址 → 把返回值写回原始 IAT 槽（本例 0x401148）→ `mov eax, 0x401000; jmp eax` 跳回 OEP。原始代码里的 `call [0x401148]` 因此恢复可用，无需改动业务指令。
- **为什么比"异地重建"简单**：保留原导入表结构与原始调用指令，只把它解密后按原样回填地址；不需要改所有导入函数的调用地址，stub 复杂度与原程序的导入函数数量无关（始终只需 LoadLibraryA/GetProcAddress 两个 API）。
- **边界**：需要能新增节并正确维护节表/SizeOfImage/Import Directory；stub 中的字符串与 IAT 地址按镜像基址 0x400000 硬编码，ASLR/重定位场景需调整；若 Loader 校验签名或完整性，改动头部与节表会暴露。

## 触发条件

- 目标 PE32 的节布局允许新增一个可写可执行节，且镜像基址/节地址已知（本例手工构造的最小 PE，`.mixed` 在 RVA 0x1000、0x200 字节）。
- 原程序导入表与代码位于被加密的同一节内（三节合一），加密后 Loader 无法解析原导入表。
- 壳自带导入表可被 Loader 正常解析（DataDirectory 指向新表，结构完整）。
- 无签名/完整性校验阻断头部修改。

## 利用步骤

1. 对目标 `min_PE1.1.exe` 的 `.mixed` 节（FOA 0x200，0x200 字节）逐字节异或 0x7F，保存 `packed_PE1.1.exe`。
2. 新增 `.unpack` 节：`NumberOfSections` 改为 2；节表末尾写节头（名 ".unpack"、VirtualSize 0x1000、VA 0x2000、SizeOfRawData 0x200、PointerToRawData 0x400、Characteristics 0xE0000060）；文件尾部追加 0x200 字节 0；`SizeOfImage` 改为 0x3000。
3. 在 `.unpack` 内布置壳自己的导入表：`kernel32.dll`、`LoadLibraryA`、`GetProcAddress` 字符串与 Hint/Name 项；ILT/IAT 数组（0x200E、0x201E、0）；Import Directory Entry（ILT RVA 0x2030、Name RVA 0x2000、IAT RVA 0x2030）与全 0 结束项。
4. 汇编 stub（解密 `.mixed` → LoadLibraryA/GetProcAddress → 回填原 IAT → 跳 OEP），写入 FOA 0x500（RVA 0x2100）。
5. 修改头部：`AddressOfEntryPoint` = 0x2100；DataDirectory 的 Import Table RVA = 0x203C（新导入表 Directory Entry 的 RVA）。
6. 运行：Loader 先解析壳的两个 API，stub 解密并重建原 IAT 后跳回 0x401000，程序正常弹出 MessageBox。

## PoC

```python
# 1) 加密合并后的 .mixed 节
key = 0x7F
with open("min_PE1.1.exe", "rb") as f:
    pe = bytearray(f.read())
for i in range(0x200, 0x400):
    pe[i] ^= key
with open("packed_PE1.1.exe", "wb") as f:
    f.write(pe)

# 2) 把 stub 写到新增 .unpack 节的 FOA 0x500（RVA 0x2100）
unpack_code = bytes([
    0xB8,0x00,0x10,0x40,0x00, 0xB9,0x00,0x02,0x00,0x00,          # mov eax,0x401000; mov ecx,0x200
    0x80,0x30,0x7F, 0x40, 0xE2,0xFA,                             # xor [eax],0x7F; inc eax; loop
    0x68,0x50,0x11,0x40,0x00,                                    # push 0x401150 ("user32.dll")
    0xFF,0x15,0x30,0x20,0x40,0x00,                               # call [0x402030] LoadLibraryA
    0x68,0x5D,0x11,0x40,0x00,                                    # push 0x40115D ("MessageBoxA")
    0x50,                                                        # push eax
    0xFF,0x15,0x34,0x20,0x40,0x00,                               # call [0x402034] GetProcAddress
    0xA3,0x48,0x11,0x40,0x00,                                    # mov [0x401148],eax 回填原 IAT
    0xB8,0x00,0x10,0x40,0x00, 0xFF,0xE0                          # mov eax,0x401000; jmp eax
])
with open("packed_PE1.1.exe", "rb") as f:
    pe = bytearray(f.read())
pe[0x500:0x500+len(unpack_code)] = unpack_code
with open("packed_PE1.1.exe", "wb") as f:
    f.write(pe)
```

```text
; 头部关键字段
FOA 0x86  NumberOfSections        = 2
FOA 0xD0  SizeOfImage             = 0x3000
FOA 0xA8  AddressOfEntryPoint     = 0x2100   ; stub 在 FOA 0x500 -> RVA 0x2100
FOA 0x100 Import Table RVA        = 0x203C   ; 指向 .unpack 内新导入表
; .unpack 导入表（FOA 0x400 / RVA 0x2000 起）：kernel32.dll / LoadLibraryA / GetProcAddress
; ILT/IAT: 0x200E, 0x201E, 0；Directory Entry: ILT=0x2030 Name=0x2000 IAT=0x2030
```

原文按此流程运行加壳后的程序，正常弹出原始 MessageBox，说明导入表加密 + stub 重建 IAT 成立。

## 变体与关联

- **IAT 重建方式**：stub 解密后解析原导入目录、循环对每个 DLL/函数调用 LoadLibraryA/GetProcAddress 批量回填，适用于导入函数多的程序；也可用 API 哈希/PEB 遍历隐藏 LoadLibraryA 字符串。
- **壳代码隐藏**：把 `.unpack` 的导入表也加密，stub 用更底层方式（PEB + 导出表解析）自举；或把壳放进新增的 TLS 回调/附加节。
- **基础版本**：只加密 `.code`/`.data`、不改导入表的最小壳见 [[code-analysis-reverse-windows-pe-simple-xor-packer-code-cave-stub]]。
- **相关 PE 修改**：给现有 EXE 追加导入 thunk 见 [[code-analysis-reverse-windows-pe-exe-add-import-thunk-rdata-string-rip-relative]]；入口点补丁见 [[code-analysis-reverse-windows-pe-section-squeeze-entrypoint-shellcode-patch]]。
- **脱壳对应**：此类壳的 OEP 在 stub 末尾 `jmp` 目标处；dump 内存后需按原导入结构修复 IAT（参考 [[code-analysis-reverse-unpacking-iat-redirect-key-jump-nop-two-instance-copy]]、[[code-analysis-reverse-unpacking-ollydbg-run-trace-condition-importrec-tracer]]）。

## 检测与防御

- **静态特征**：新增节（如 `.unpack`）同时可写可执行；`AddressOfEntryPoint` 落在该节；DataDirectory 的 Import Table 指向一个只导入 kernel32 的 `LoadLibraryA`/`GetProcAddress` 的极简导入表；原导入表所在节数据为高熵密文；`SizeOfImage`/节表被改动。
- **动态特征**：入口先解密自身镜像大段数据，再调用 `LoadLibraryA`/`GetProcAddress` 并把返回地址写入原 IAT 区域，最后跳转到解密后的代码区；进程内存中出现"先密后明"的节与延迟填写的 IAT。
- **防御**：签名与完整性校验；AV/EDR 对"壳式导入表（仅 LoadLibrary/GetProcAddress）+ W+X 新节 + EP 在非原代码节"组合告警；逆向侧在 stub 跳 OEP 处断点 dump、按原 IAT 结构修复后还原原始导入。
