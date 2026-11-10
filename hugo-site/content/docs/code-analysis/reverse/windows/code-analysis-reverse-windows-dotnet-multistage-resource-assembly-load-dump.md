---
id: code-analysis-reverse-windows-dotnet-multistage-resource-assembly-load-dump
title: 多阶段 .NET 内存加载链：资源 GetObject 自引用解密 → Assembly.Load/Activator.CreateInstance，dnSpy 模块列表逐阶段 dump
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dotnet-multistage-resource-assembly-load-module-dump
tags:
- reverse
- windows
- dotnet
- malware
- loader
- multi-stage
- assembly-load
- activator
- dnspy
- net-reactor
- unpacking
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T11:55:57+08:00'
  notes: 已对照原文与54张图核对：Grab 资源、ps=2F45H8F4PE4EQS5D8585TD、i=89110 自引用异或-减法循环、Assembly.Load/GetTypes()[3]/Activator.CreateInstance、Aads(ivmsL 410922字节 Bitmap)、Tyrone(wHzyWQnRZ、Array.Resize)、.NET Reactor Slayer 61 calls/1533 methods 均与原文一致；已修正正文中 \u0020 变量名占位缺失。未运行样本复现
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-dotnet-multistage-resource-assembly-load-dump/
draft: false
kb_aliases:
- Snake 加载器
- pago 4094.exe
- Grab 资源解密
- Aads.dll
- Tyrone.dll
- Assembly.Load
- Activator.CreateInstance
- dnSpy 模块 dump
- .NET Reactor Slayer
---

## 一句话结论

VB.NET 样本的 `Form1` 构造函数从窗体资源取 `Grab` 字节数组，用硬编码 22 字节字符串做“异或 + 减后一字节”的自引用循环解密，然后 `Assembly.Load(data2)` 加载程序集、`GetTypes()[3]` 取类型、`Activator.CreateInstance(type, args)` 在内存中执行下一阶段；后续 `Aads.dll`、`Tyrone.dll` 也各自从资源/Bitmap 取密文并解密，dnSpy 的“模块”列表能看到这些内存模块，在解密后/加载前下断点并跳到模块即可逐阶段 dump，最后用 .NET Reactor Slayer 反混淆。

## 原理

- **资源藏二进制**：.NET 程序可以把载荷放进窗体资源（`.resources` 里的二进制或 Bitmap）。`ResourceManager.GetObject("Grab")` 取出的对象可以是 `byte[]`（阶段一）或 `Bitmap`（阶段二 `ivmsL`，410922 字节）。静态看资源名/大小就能判断是否存在后续阶段。
- **自引用解密循环**（阶段一，`Form1` 构造函数）：
  ```csharp
  byte[] data2 = resources.GetObject("Grab") as byte[];
  string ps = "2F45H8F4PE4EQS5D8585TD";      // 22 字节
  for (int i = 89110; i >= 0; i += -1) {
      data2[i % data2.Length] = Convert.ToByte(
          (Convert.ToInt32((int)((char)data2[i % data2.Length] ^ ps[i % 22]))
           - Convert.ToInt32(data2[(i + 1) % data2.Length]) + 256) % 256);
  }
  ```
  循环从高下标往低下标走，`data2[(i+1) % len]` 在此前已经被更新，因此是自引用（反馈式）解密；必须严格按同样的方向和取模在内存中原地执行才能还原，不能简单地把密文当独立块做 XOR。
- **内存加载而非落盘**：`Assembly.Load(data2)` 把字节数组作为程序集加载到当前 AppDomain，`GetTypes()[3]` 选中载荷入口类型，`Activator.CreateInstance(type, args)` 用窗体控件参数构造实例并触发执行。相比释放 DLL 到磁盘，这种方式的文件痕迹少，但模块仍会出现在 dnSpy 的模块列表/进程内存中。
- **后续阶段**：
  - `Aads.dll`：同样被混淆；`HeapSort.GetObject(x10)` 中 `x10 = "ivmsL"`，从 `ResourceManager` 取 Bitmap，代码经过字节数组搜索和排序算法（堆排序/快速排序/插入排序等）处理，解密出下一阶段。
  - `Tyrone.dll`：模块列表里出现后，`smethod_0(string_0)` 调 `ResourceManager.GetObject(string_0)`；资源名 `wHzyWQnRZ`，再用与阶段一类似的“异或 + 减后一字节 + 256 取模”循环并 `Array.Resize` 去掉末尾一字节，得到 MZ 头，dump 为最终 `pago.exe`。
- **反混淆**：`Tyrone.dll` 与最终 `pago.exe` 都被 .NET Reactor 保护；用 .NET Reactor Slayer 勾选 Decrypt Methods Body、Deobfuscate Control Flow、Decrypt Resources、Dump Embedded Assemblies、Remove Anti Tamper & Anti Debug 等选项，日志会显示移除 61 处 obfuscator 调用、内联 1533 个方法，输出 `Tyrone_Slayed.dll`，之后才可读。
- **为什么用 dnSpy 模块列表**：Assembly.Load 后程序集没有对应磁盘文件，普通“打开文件”看不到；dnSpy 调试时“模块”窗口会列出 `Aads`、`Tyrone`、`ReactionDiffusion` 等内存模块及版本/时间戳，右键“转到模块”或 dump 即可拿到阶段文件。

## 触发条件

- 样本为 .NET（可用 DIE 确认 PE32/PE32+、.NET v4.0.x、VB.NET/C#），静态看到窗体资源名（如 `Grab`、`ivmsL`）与 `ResourceManager.GetObject`、`Assembly.Load`、`Activator.CreateInstance`。
- 有 dnSpy（32 位样本用 dnSpy32）和隔离的 Windows 虚拟机/沙箱；样本必须在断网/快照环境运行。
- 解密循环依赖的资源长度/迭代上界（如 89110）在样本中固定；不同样本需重新读常量。
- 需要 .NET Reactor Slayer 或 de4dot 等反混淆工具处理后续阶段。

## 利用步骤

1. DIE 确认 .NET 与位数；dnSpy 打开样本，定位入口 `Main`/窗体构造函数，搜索 `GetObject`、`Assembly.Load`、`Activator.CreateInstance`。
2. 记录资源名、解密循环的 key/上界/取模表达式；在 `Assembly.Load` 前下断点。
3. 在隔离环境运行到断点，查看局部变量 `data2` 是否以 `4D 5A`（MZ）开头；若不是，检查循环方向与 `(i+1)%len` 的读取顺序。
4. 打开“模块”窗口，找到新加载的模块（如 `Aads`、`Tyrone`），右键 dump 到文件；或直接在模块内下断点、跳到模块继续分析。
5. 对 dump 出的阶段重复步骤 1-4；注意下一阶段的资源名可能来自局部变量（如 `x10 = "ivmsL"`、`\u0020 = "wHzyWQnRZ"`）。
6. 最终阶段用 .NET Reactor Slayer 反混淆，再按 Main 的方法调用顺序（信息收集、外传、键盘钩子等）分析。
7. 记录每阶段 IOC（哈希、资源名、模块名、解密常量），用于 YARA/检测。

## PoC

阶段一解密循环的 Python 等价实现（必须保持从高到低、原地修改）：

```python
def decrypt_stage1(blob: bytes, ps: bytes = b"2F45H8F4PE4EQS5D8585TD", start: int = 89110) -> bytes:
    data = bytearray(blob)
    n = len(data)
    for i in range(start, -1, -1):
        j = i % n
        k = (i + 1) % n
        data[j] = ((data[j] ^ ps[i % len(ps)]) - data[k] + 256) % 256
    return bytes(data)

# 期望结果以 b"MZ" 开头，可写文件后用 dnSpy 打开
out = decrypt_stage1(open("Grab.bin", "rb").read())
assert out[:2] == b"MZ"
open("Aads.dll", "wb").write(out)
```

阶段二/三的循环在结构上同族（异或 + 减后一字节 + 256 取模），但密钥/资源名/上界不同；原文没有完整给出 `Aads` 的排序解密细节，建议以动态断点 + dump 为准，不要凭静态片段猜参数。

## 变体与关联

- **.NET 资源加载器族**：[[code-analysis-reverse-windows-redline-dotnet-aes-resource-dropper]] 用 AES/Base64 解密资源后落盘并启动进程；本卡是内存 `Assembly.Load` 多阶段链，痕迹与 dump 方式不同。
- **远程载荷加载**：[[pentest-c2-dotnet-3des-remote-pdf-virtualalloc-shellcode-loader]] 从远程 PDF 取 3DES 载荷并用 VirtualAlloc 执行 shellcode；[[pentest-c2-dotnet-singlefile-embedded-dll-delegate-loader]] 是单文件内嵌 DLL + 委托调用。
- **反混淆**：.NET Reactor Slayer 与 de4dot/dnSpy 组合；字符串/控制流混淆的自动化还原见 [[code-analysis-reverse-obfuscation-obfuscar-dnlib-string-auto-decrypt]]、[[code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt]]。
- **其它阶段 dump 思路**：AgentTesla 阶段 DLL 还原见 [[code-analysis-reverse-unpacking-agenttesla-stage-dll-xor-subtract-archive]]。
- **边界**：Assembly.Load 的载荷可能带反调试/反虚拟机；dnSpy 调试时需在快照虚拟机、断网、禁用共享文件夹；不同 .NET 版本（4.0/4.8）可能影响模块窗口显示。

## 检测与防御

- **CLR 使用日志**：.NET 程序集加载会在 `%LOCALAPPDATA%\Microsoft\CLR_v4.0_32\UsageLogs\<exe>.log` 留下记录（含程序集名、版本、PublicKeyToken），可作为加载器/后续阶段的取证线索。
- **检测内存加载**：监控 `Assembly.Load(byte[])`、`Activator.CreateInstance` 与资源读取组合；启用 AMSI/.NET ETW、Sysmon 模块加载与进程内存扫描；对无磁盘对应的 .NET 模块告警。
- **样本处置**：只在隔离虚拟机/沙箱运行，使用快照；不要在生产机双击；分析前记录哈希与网络隔离。
- **YARA/静态特征**：窗体资源名（`Grab`、`ivmsL`）、硬编码密钥字符串、`GetObject`+`Assembly.Load`+`GetTypes()[N]` 组合可作为规则特征。
- **合规**：仅分析授权/自有样本；不要将样本或解密后的载荷上传到未授权环境。
