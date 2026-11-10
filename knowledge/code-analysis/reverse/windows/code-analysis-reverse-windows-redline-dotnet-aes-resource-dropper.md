---
id: code-analysis-reverse-windows-redline-dotnet-aes-resource-dropper
title: RedLine .NET 加载器：AES/Base64 内嵌资源解密，落盘 NetFlix 诱饵与 svchost/chrome/winlogon 并启动（主体带 SmartAssembly 混淆）
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: redline-dotnet-aes-resource-dropper
aliases:
- RedLine 加载器
- RedLine 初始执行
- .NET 内嵌资源 AES 解密落盘
- ResourceManager 资源解密
- Rfc2898DeriveBytes AES 加载器
- SmartAssembly 样本
- NetFlix Checker by xRisky v2.exe
- winlogon.exe 伪装
tags:
- windows
- dotnet
- malware
- loader
- dropper
- aes
- base64
- smartassembly
- process-start
- redline
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V283
  verified_at: '2026-11-08T04:58:52+08:00'
  notes: 已对照原文与全部 33 张图核对：ResourceManager(ihbdrrxizcopssvf)+Rfc2898DeriveBytes(ASCII 密码/盐,100,16B)+固定 IV AES 解密 3 个资源、路径标记/环境变量选择、File.WriteAllBytes+Process.Start、qafsxyjv 隐藏启动（cidWZLVK5xmjQYn2nQiLnw==）均一致。已修正 SmartAssembly 归属：SmartAssembly 在落盘的 winlogon.exe 主体（img/09），加载器本身 dnSpy 可见 Main（img/02-06）；原卡误写加载器带 SmartAssembly 保护。修正后 verify。未执行样本；原文未声明样本版本，未设置 versions。
---

## 一句话结论

RedLine 样本是 .NET（C# / .NET 4.0.30319）加载器：`Main` 用 `ResourceManager("ihbdrrxizcopssvf", Assembly.GetExecutingAssembly())` 读取 3 个内嵌资源，用 `Rfc2898DeriveBytes`（ASCII 密码/盐、100 次迭代、16 字节 key）+ 固定 IV 的 AES 解密资源，再按硬编码路径写入当前目录或 `Environment.GetEnvironmentVariable` 解出的目录——落盘 `NetFlix Checker by xRisky v2.exe`（诱饵/子程序）、`%AppData%\Roaming\svchost.exe`、`%AppData%\Roaming\winlogon.exe`（以及同目录 chrome.exe），满足条件时 `Process.Start` 启动；真正的 RedLine 主体是伪装成 `winlogon.exe` 的 SmartAssembly 混淆程序。

## 原理

- **资源解密**：`Main` 中定义 `string[3][]` 配置，每项含路径选择标记、路径/文件名密文、资源名和启动标记；`ResourceManager` 从当前程序集读取内嵌资源字节，用 AES 解密后 `File.WriteAllBytes` 落盘。AES 使用 `Aes.Create()` + `Rfc2898DeriveBytes(长 ASCII 密码, ASCII 盐, 100).GetBytes(16)` 派生 key，IV 为固定 ASCII 字符串，`CryptoStream` 以 Decrypt 模式解密。
- **路径选择**：若路径标记等于某个 Base64 常量，则写入 `Directory.GetCurrentDirectory()`；否则把标记用同一 AES/Base64 函数解密后交给 `Environment.GetEnvironmentVariable` 取环境变量（如 `%AppData%`），再 `Path.Combine` 得到目标路径。
- **落盘与启动**：三个资源分别落到下载目录（`NetFlix Checker by xRisky v2.exe`）、`%AppData%\Roaming\svchost.exe`、`%AppData%\Roaming\winlogon.exe`；脚本比较解密后的启动标记与固定 Base64 常量，命中则 `Process.Start(text)`。另一函数 `qafsxyjv` 用 `ProcessStartInfo { WindowStyle = Hidden, CreateNoWindow = true }` 启动解密的文件名（Base64 常量 `cidWZLVK5xmjQYn2nQiLnw==`），实现隐藏执行。
- **伪装与混淆**：`winlogon.exe` 文件描述为 “Google Chrome”，`svchost.exe`/`chrome.exe` 使用系统/浏览器同名文件降低可疑度；加载器本身可直接在 dnSpy 中查看 `Main`/资源逻辑，落盘的 `winlogon.exe`（真正 RedLine 主体）带 SmartAssembly 保护，需用 .NET Reactor Slayer 反混淆后分析窃取逻辑。
- **为什么有效**：载荷以 AES 密文存放在 .NET 资源中，静态字符串/资源扫描看不到明文 PE；落盘名伪装成系统进程/浏览器；隐藏窗口启动减少用户感知；资源按路径标记分派，增加人工分析成本。
- **边界**：AES 密码、盐、IV、资源名均硬编码在样本中，可静态提取并离线解密；样本行为是落盘+启动，若落盘目录不可写/被杀软拦截则链断；SmartAssembly 混淆可被 Slayer/de4dot 处理。

## 触发条件

- 运行 .NET Framework 4.0+ 的 Windows 主机；样本可执行（用户双击、钓鱼投递或母体加载）。
- 当前目录或目标环境变量目录（`%AppData%` 等）可写。
- 样本未被 AV/EDR 在落盘或 `Process.Start` 阶段拦截；加载器的资源解密在运行时完成，不依赖先还原 `winlogon.exe` 的 SmartAssembly 混淆。
- 后续 `winlogon.exe` 等子程序可运行（取决于权限与防护）。

## 利用步骤

1. 用 dnSpy 打开样本，定位 `Main`；识别 `string[3][]` 配置、`ResourceManager`、`Rfc2898DeriveBytes`、`Aes.Create`、`File.WriteAllBytes`、`Process.Start`。
2. 提取资源名与 `ResourceManager` 基名（示例 `ihbdrrxizcopssvf`），在 dnSpy 资源树/反射中导出 3 个资源字节。
3. 还原 AES 参数：密码/盐为 ASCII 常量，100 次迭代派生 16 字节 key，IV 为固定 ASCII；对每个资源解密得到 PE 字节与目标文件名/环境变量。
4. 解密路径标记，确定三个落盘路径（下载目录、`%AppData%\Roaming\` 等）与启动条件；对照样本运行后的文件系统变化验证。
5. 如需动态确认，在 `File.WriteAllBytes` 与 `Process.Start` 下断点，记录写入路径、文件哈希与启动参数；也可用 .NET Reactor Slayer 反混淆后再分析 `qafsxyjv` 的隐藏启动逻辑。
6. 对落盘的 `winlogon.exe`/`svchost.exe`/`chrome.exe` 做二次分析（实际 RedLine 主体为 `winlogon.exe`，见关联卡）。

## PoC

无独立脚本；以下为静态还原要点（字符串以样本为准，不在卡中展开完整密钥）：

```text
# 1) dnSpy 定位
Main -> string[3][] 配置
ResourceManager("<资源基名>", Assembly.GetExecutingAssembly())
Rfc2898DeriveBytes("<ASCII 密码>", Encoding.ASCII.GetBytes("<ASCII 盐>"), 100).GetBytes(16)
Aes.Create() + CryptoStream(Decrypt) -> File.WriteAllBytes(path, bytes)
if (decrypt(marker) == "<固定 Base64>") Process.Start(path)

# 2) 导出资源并用上述参数离线 AES 解密
#    资源 1 -> 当前目录/下载目录 NetFlix Checker by xRisky v2.exe
#    资源 2 -> %AppData%\Roaming\svchost.exe
#    资源 3 -> %AppData%\Roaming\winlogon.exe

# 3) 隐藏启动函数 qafsxyjv
ProcessStartInfo {
  FileName   = decrypt("<Base64 文件名常量>"),
  Arguments  = <参数>,
  WindowStyle = Hidden,
  CreateNoWindow = true
}
```

## 变体与关联

- [[pentest-c2-dotnet-singlefile-embedded-dll-delegate-loader]]：同为 .NET 内嵌资源/单文件加载，但那张卡是把 DLL 释放后用 `GetDelegateForFunctionPointer` 调用导出函数；本卡是 AES 加密资源落盘并 `Process.Start`，属于 dropper 而非反射加载。
- [[code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample]]：多层 .NET 样本分析与 AES-256-CBC 载荷还原，可对照资源加密/分层投递。
- [[code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt]]：.NET 字符串/资源混淆自动还原；本卡的密码/盐/IV 同样可从混淆后代码中提取。
- 变体：路径标记可切换当前目录/环境变量；启动标记可控制哪些资源被执行；资源名/密钥随样本版本变化。
- 边界：本文只分析到加载器与落盘；后续 RedLine 主体的窃取逻辑见 [[defense-forensics-redline-stealer-collection-geofence]]。

## 检测与防御

- **检测（静态）**：.NET 样本中出现 `ResourceManager` + `Rfc2898DeriveBytes` + `Aes.Create` + `File.WriteAllBytes` + `Process.Start` 组合；资源名/基名异常；SmartAssembly 特征；字符串中有 `NetFlix Checker`、`svchost.exe`、`winlogon.exe`、`chrome.exe` 等伪装名。
- **检测（动态/主机）**：进程从 `%AppData%\Roaming` 或用户下载目录启动 `winlogon.exe`/`svchost.exe`/`chrome.exe`，且文件描述/签名与系统文件不符；同一进程短时间内写入多个 PE 并调用 `Process.Start`；隐藏窗口的 `CreateNoWindow` 子进程。
- **防御**：启用 AMSI/Defender 与行为监控；限制用户目录可执行文件运行（AppLocker/WDAC）；对 `%AppData%` 下新 PE 告警；监控 `ResourceManager`/AES 资源解密样本；及时隔离并分析落盘子文件。
- **响应**：保存样本与解密后的资源（哈希）；检查 `%AppData%\Roaming` 与下载目录的可疑 PE；终止伪装进程并按关联卡排查 RedLine 窃取痕迹。
