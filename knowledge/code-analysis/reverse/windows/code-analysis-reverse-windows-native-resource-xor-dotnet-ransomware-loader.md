---
id: code-analysis-reverse-windows-native-resource-xor-dotnet-ransomware-loader
title: C++ 原生加载器从资源定位密文、1024 字节分块异或解密出 .NET 勒索模块并经 CLRCreateInstance 偏移调用
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: native-resource-block-xor-dotnet-module-clr-host-loader
aliases:
- 中文勒索软件加载器
- FindResourceA __ 资源
- 分块异或解密 shellcode
- .NET 模块内存加载
- CLRCreateInstance 偏移调用
- .NET Reactor 4.8-4.9
tags:
- windows
- reverse
- malware-analysis
- ransomware
- loader
- dotnet
- clr-hosting
- resource
- xor
- dotnet-reactor
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V531
  verified_at: '2026-11-11T16:51:53+08:00'
  notes: 已对照原文与图07-12核对：FindResourceA取'__'资源0x3F363、LoadResource/LockResource(图07/08)、FUN_XorDecode_ShellCode_1整体异或+1024字节分块FUN_XorDecode_ShellCode_2+尾部处理+FUN_FinaDecode_ShellCode(图09)、解密后MZ/v4.0.30319(图10)、DIE显示.NET Reactor 4.8-4.9(图11)、mscoree.CLRCreateInstance偏移调用(图12)均一致；dedup候选RedLine原生多阶段加载器、双RCData加载器等为不同机制，非同链；原文无受影响版本。
---

## 一句话结论

该 C++ 外层先异或解密字符串并做 CLR 环境检查，随后用 `FindResourceA` 找到名为 `__` 的资源（大小 0x3F363），`LoadResource`/`LockResource` 取指针后先整体异或一次，再以 1024 字节为块循环二次异或并处理尾部，最终解出完整 .NET PE；该模块受 .NET Reactor 4.8–4.9 保护，de4dot 脱壳后由 `mscoree.CLRCreateInstance`（v4.0.30319）按内存偏移调用 `StartAction()` 等勒索功能。

## 原理

- **资源藏密文**：PE 资源段可以存放任意二进制，加载器用 `FindResourceA(ModuleHandleA, "__", 0xA)` 定位（类型 10/RCDATA），`SizeofResource` 得到长度 `0x3F363`，`LockResource` 取得内存指针；静态分析时资源目录中出现短名 `__` 与约 259KB 数据即高度可疑。
- **三段式异或解密**：先 `FUN_XorDecode_ShellCode_1` 对整块做一次异或（释放到堆），再按 `1024` 字节循环调用 `FUN_XorDecode_ShellCode_2`（`Src` 每次前进 1024，`Src+0x400` 指向第二缓冲），对 `Size % 1024` 的尾部单独处理，最后 `FUN_FinaDecode_ShellCode` 做收尾解密。调试器内存窗口中可先看到密文，逐步解密后出现 `MZ` 头与 `v4.0.30319` 版本串，即为 .NET PE。
- **内存加载而非落盘**：解出的 .NET 模块不写入文件，而是通过 `GetProcAddress(mscoree, "CLRCreateInstance")` 取得宿主接口，加载后按偏移（如 `v91 + 12`、`v92 + 36`）调用模块内函数；dnSpy 的模块列表/内存 dump 是拿到该模块的主要途径。
- **保护与反分析**：外层还包含 `Cor_Enable_Profiling` 环境变量与 `mscorjit.dll`/`clrjit.dll` 模块检查（另有专卡）；内层 .NET 模块被 .NET Reactor 4.8–4.9 保护，Detect It Easy 显示 `PE32 .NET Reactor(4.8-4.9) .NET(v4.0.30319)`，需 de4dot/.NET Reactor Slayer 脱壳后才能读到 `StartAction`、`encryptDirectory`、`AES_big_Encrypt` 等勒索逻辑。

## 触发条件

- 目标为 Windows，执行了该 C++ 外层样本；
- 进程环境通过加载器的 CLR 环境检查（未启用 profiler、未加载 JIT 模块）；
- 具备 IDA/x64dbg、Detect It Easy、dnSpy、de4dot 等分析工具，用于资源提取与内存 dump。

## 分析/提取步骤

1. 用 Detect It Easy 确认外层 PE32、无壳或轻量壳；在 IDA 中定位 `FindResourceA` 调用，记录资源名 `__`、类型 `0xA` 与长度 `0x3F363`；
2. 也可直接用 Resource Hacker 导出该资源密文，按静态代码中的异或密钥与 1024 字节分块逻辑离线解密；动态则在 `LockResource` 返回后下断，观察 `FUN_XorDecode_ShellCode_1/2` 与 `FUN_FinaDecode_ShellCode` 的输入输出；
3. 在解密函数返回、`CLRCreateInstance` 调用前 dump 解密后的缓冲区，确认 `MZ`/`PE` 头与 `v4.0.30319` 字符串，保存为 `payload.dll`；
4. Detect It Easy 显示 .NET Reactor 保护；用 de4dot 或 .NET Reactor Slayer 脱壳，dnSpy 打开后可看到 `Encrypts`、`GendarmerieForm` 等类与 `StartAction()`、`encryptDirectory()`；
5. 继续分析密钥封装与加密分支（RSA 公钥封装随机口令、AES-CFB/CBC 分流），完成样本定性。

## PoC

无独立 PoC（原文为样本分析）。关键代码形态：

```c
hResInfo = FindResourceA(ModuleHandleA, "__", (LPCSTR)0xA);
v11 = SizeofResource(ModuleHandleA, hResInfo);        // 0x3F363
FUN_XorDecode_ShellCode_1(v64);                      // 整体异或
do { FUN_XorDecode_ShellCode_2(Src, 0x400u, (char *)Src + rgsabound.cElements);
     Src = (char *)Src + 1024; }
while (--lpString);
FUN_FinaDecode_ShellCode(lpString, &v94, v12 + 1, v15); // 收尾 -> .NET PE
```

## 变体与关联

- 与库内 `code-analysis-reverse-windows-redline-native-multistage-shellcode-clr-resource-loader` 同类：原生加载器 + 资源密文 + 异或解密 + CLR 宿主 + .NET Reactor；本案差异是资源名 `__`、1024 字节分块两段异或、以及按偏移调用 .NET 方法，未使用 `0x400000` 固定基址映射；
- 与 `code-analysis-reverse-windows-dotnet-multistage-resource-assembly-load-dump` 对比：后者是纯 .NET 的 `Assembly.Load` 多阶段，本案是原生进程内的资源解密 + CLR 非托管宿主；
- 其他变体：资源名随机化、按块大小/密钥分段异或、解密后再压缩（gzip/LZMA）等。

## 检测与防御

- 监控 PE 资源段中出现高熵大块数据（RCDATA/短名资源）与 `FindResourceA`+`LockResource`+异或循环组合；
- 监控非 .NET 进程调用 `mscoree.CLRCreateInstance` 并加载内存程序集的行为；
- 对 .NET Reactor 等保护壳样本，静态扫描难以定性，应结合内存 dump 与行为（批量文件加密、删除原文件、写勒索信）；
- 防御侧保持备份、限制可执行文件运行、开启 EDR 对进程加载 CLR 与批量文件操作的告警。
