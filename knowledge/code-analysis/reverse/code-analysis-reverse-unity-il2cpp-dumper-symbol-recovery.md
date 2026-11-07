---
id: code-analysis-reverse-unity-il2cpp-dumper-symbol-recovery
title: Unity IL2CPP 逆向：GameAssembly/libil2cpp + global-metadata 经 Il2CppDumper 恢复符号并导入 IDA/Ghidra
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: unity-il2cpp-dumper-symbol-recovery
aliases:
- Unity IL2CPP 逆向
- Il2CppDumper 使用
- GameAssembly.dll 分析
- global-metadata.dat
- libil2cpp.so 符号恢复
- DummyDll dump.cs script.json
- IL2CPP IDA 脚本
tags:
- reverse
- unity
- il2cpp
- il2cppdumper
- ida
- ghidra
- dnspy
- metadata
- game
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:03:19+08:00'
  notes: 已对照 content.md 与 18 张图核对：GameAssembly.dll 19,922KB、il2cpp_data/Metadata/global-metadata.dat 4,665KB、Il2CppDumper 输出 DummyDll/dump.cs/script.json/il2cpp.h/stringliteral.json/ida.py/ghidra.py、dnSpy 查看 DummyDll 均一致。未在本机运行 Il2CppDumper/IDA/Ghidra。frontmatter 无 sources/source_url。
---

## 一句话结论

Unity IL2CPP 游戏把 C# 编译成 `GameAssembly.dll`（Windows）或 `libil2cpp.so`（Android/Linux）中的机器码，但为反射保留了 `Data/il2cpp_data/Metadata/global-metadata.dat`；用 Il2CppDumper 解析两者，可生成 DummyDll、`dump.cs`、`script.json`、`il2cpp.h`、`stringliteral.json` 和 IDA/Ghidra 脚本，在反汇编器中恢复类名/方法名/字符串并定位关键逻辑。

## 原理

- **IL2CPP 编译链**：C# → IL → IL2CPP 转 C++ → 平台 C++ 编译器 → 机器码。运行时不再依赖 Mono JIT，代码以 AOT 原生代码存在，直接反编译只能得到汇编/伪代码。
- **元数据是突破口**：Unity 为支持反射、序列化等能力，必须保留类名、方法名、字段、字符串常量等元数据到 `global-metadata.dat`；Il2CppDumper 解析该文件，再在可执行文件中定位对应的函数地址，把“元数据”和“机器码地址”关联起来。
- **输出物的用途**：
  - `DummyDll/`：方法体为空但保留命名空间、类名、方法签名、字段/属性，可用 dnSpy/ILSpy 查看高层结构；
  - `dump.cs`：所有类/方法定义的纯文本，适合 grep 关键词（encrypt、flag、password 等）；
  - `script.json`：方法地址（RVA/偏移）与名称映射，供 IDA/Ghidra 脚本重命名函数；
  - `il2cpp.h`：`Il2CppObject`、`Il2CppString`、`Il2CppArray`、`Il2CppClass`、`MethodInfo` 等运行时结构体，导入后反编译更易读；
  - `stringliteral.json`：字符串常量地址映射，可按字符串地址反查引用函数；
  - `ida.py`/`ida_with_struct.py`、`ghidra.py`/`ghidra_wasm.py`：反汇编器脚本。
- **为什么有效**：即使方法体是机器码，恢复符号后可以像分析 C/C++ 程序一样按类名/方法名定位；再结合 DummyDll 的签名和 stringliteral 的字符串引用，能快速从“无意义地址”收敛到关键函数。
- **边界**：`global-metadata.dat` 与 Unity 版本/Il2CppDumper 版本需匹配；元数据被加密/混淆时需先解密；强混淆（控制流平坦化、VM、字符串加密）会削弱符号恢复的效果，但仍可作为入口。

## 触发条件

- 目标为 Unity IL2CPP 打包：根目录有较大的 `GameAssembly.dll`，`Data/il2cpp_data/Metadata/global-metadata.dat` 存在；Mono 打包则是 `Data/Managed/Assembly-CSharp.dll` 等可直接反编译的 dll。
- 能获取可执行文件与 `global-metadata.dat`（Windows 游戏目录、Android APK 的 `lib/<abi>/libil2cpp.so`、iOS IPA 的 `Payload` 主二进制）。
- 有 Il2CppDumper（含对应平台版本）与 IDA/Ghidra、dnSpy/ILSpy。
- 元数据未加密，或已通过脱壳/解密还原；若加密，需要先处理保护。

## 利用步骤

1. **识别打包方式**：检查 `GameAssembly.dll` 与 `Data/il2cpp_data/Metadata/global-metadata.dat`；Mono 游戏则检查 `Data/Managed/*.dll`。
2. **运行 Il2CppDumper**：`Il2CppDumper.exe <executable> <global-metadata.dat> <output>`；按提示选择 Auto/Manual/Auto(Advanced)，Auto 失败时手动指定平台、架构、Unity 版本。
3. **查看输出**：用 dnSpy 打开 `DummyDll/Assembly-CSharp.dll` 了解类结构；用文本编辑器/grep 搜索 `dump.cs`；用 `stringliteral.json` 找关键字符串地址。
4. **IDA 导入符号**：打开 `GameAssembly.dll`，`File → Script file` 运行 `ida_with_struct.py`，依次选择 `script.json` 与 `il2cpp.h`；函数名会被重命名并应用结构体。Ghidra 用 `ghidra.py`（WASM 用 `ghidra_wasm.py`）。
5. **定位关键逻辑**：按类名/方法名搜索（如 `PlayerController_Update`），或按 `stringliteral.json` 的地址在 IDA 中查交叉引用；结合 DummyDll 的方法签名理解参数。
6. **动静结合**：静态分析遇到困难时，用 CE/调试器动态跟踪（见 [[code-analysis-reverse-unity-il2cpp-ce-trigger-embedded-pe]]）。

## PoC

```bash
# Windows x64 示例
Il2CppDumper.exe .\GameAssembly.dll .\Game_Data\il2cpp_data\Metadata\global-metadata.dat .\output\

# Android 示例：从 APK 解出 lib/<abi>/libil2cpp.so 与 assets/bin/Data/Managed/Metadata/global-metadata.dat
Il2CppDumper.exe .\libil2cpp.so .\global-metadata.dat .\output\
```

```text
输出目录：
DummyDll/            # dnSpy/ILSpy 查看类结构
dump.cs              # grep encrypt/decrypt/flag
script.json          # IDA/Ghidra 函数地址与名称映射
il2cpp.h             # Il2CppString/Il2CppArray/MethodInfo 等结构体
stringliteral.json   # 字符串常量地址
ida.py / ida_with_struct.py
ghidra.py / ghidra_wasm.py
```

```text
IDA：File -> Script file -> ida_with_struct.py
  1) 选择 script.json
  2) 选择 il2cpp.h
之后可在函数窗口按类名/方法名搜索，或按字符串地址查交叉引用。
```

## 变体与关联

- Android/iOS 变体：Android 分析 `libil2cpp.so`，iOS 分析 IPA 主二进制；元数据位置随打包方式不同（assets、Data/Managed/Metadata 等）。
- 工具变体：Il2CppInspector、Cpp2IL 等可替代 Il2CppDumper；Ghidra 脚本适合无 IDA 环境。
- 保护变体：元数据加密、字符串加密、控制流平坦化、VM 保护需要先脱壳/解密；可结合 Frida 动态 dump 元数据或内存中的方法地址。
- 关联：[[mobile-android-unity-il2cpp-frida-gadget-infinite-revival]]（Android IL2CPP + Frida Hook 的实战）；[[code-analysis-reverse-unity-il2cpp-ce-trigger-embedded-pe]]（CE 动态触发与释放 PE 分析）。
- 边界：版本不匹配会导致解析失败/符号错位；方法体仍为机器码，变量名/局部类型可能丢失，需要人工推断。

## 检测与防御

- 防御方（游戏保护）：加密/混淆 `global-metadata.dat`，剥离或加密字符串常量，使用控制流平坦化/VM 保护关键逻辑；增加反调试/反 dump/完整性校验。
- 但元数据是反射所需，完全隐藏成本高；不要把核心算法或密钥只放在客户端，服务端校验关键结果。
- 分析方：只在授权环境分析；保留原始文件与哈希，先备份再修改；对加密元数据先做脱壳/解密并记录版本。
