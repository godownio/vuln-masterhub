---
id: code-analysis-reverse-obfuscation-txt-fragment-keyword-reflection-assembly
title: PowerShell 从多个单行 txt 分片读取注入关键词并拼回反射调用：load/GetType/getMethod/Invoke/NewPE2.PE/Execute，二进制串隐藏 aspnet_compiler 路径
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: powershell-txt-fragment-keyword-reflection-assembly
aliases:
- txt 分片关键词
- 多文件关键词拆分
- <##> 注释切断 Reflection.Assembly
- Framework.txt 二进制串隐藏路径
- t.ps1 混淆
- NewPE2.PE Execute 关键词拆分
tags:
- obfuscation
- powershell
- malware-analysis
- string-concealment
- dotnet
- reflection
- defense-evasion
- asyncrat
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V424
  verified_at: '2026-11-09T17:23:24+08:00'
  notes: 已对照原文与图13/14/15/16/17核对：NewPE2.txt=NewPE2.PE、Execute.txt=Execute、Invoke.txt=invoke、load.txt=load、Gettype.txt=Gettype、getMethod.txt=getMethod 六个单行 txt 由 t.ps1 Get-Content 读入；[<##>Reflection.Assembly<##>] 块注释切断；Framework.txt 为空格分隔 8 位 0/1 位串，FH 以 ToByte(sub,2)+ASCII.GetString 还原 C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe（CyberChef From Binary→To Hex→From Hex 可复现）；[double[]] $Uk=byet.txt|iex、$tLx=runpe.txt|iex 与 fun_alosh(ali1/ali3/ali4.txt) 变换均与图一致。未验证点：fun_alosh 完整算法与 PE 明文原文未展开，卡内已标注；样本未复跑。dedup 候选（braced-variable、image-masquerade、AMSI bypass 等）均不同链；dup-scan.json(11-08) 早于建卡(11-09) 无本卡 pair；无 sources/source_url、无文章 ID/原文 URL/长段摘录，path code-analysis/reverse/obfuscation 合法；非组件类无受影响版本。颗粒度：单一混淆原子（跨文件关键词拆分+位串路径），与 RunPE 卡按义拆分清晰。
---

## 一句话结论

t.ps1 不在脚本正文里写 `Load`、`GetType`、`getMethod`、`Invoke`、`NewPE2.PE`、`Execute` 这些高价值关键词，而是把每个词单独放进 `C:\Users\Public` 下的一个单行 txt（load.txt、Gettype.txt、getMethod.txt、Invoke.txt、NewPE2.txt、Execute.txt），运行时用 `Get-Content` 读入再拼成 `[Reflection.Assembly]::Load(...).GetType(...).GetMethod(...).Invoke(...)`；`Reflection.Assembly` 本身再用 `<##>` 块注释切成 `[<##>Reflection.Assembly<##>]`；注入宿主路径 `aspnet_compiler.exe` 则以“0/1 二进制字符串”存于 Framework.txt，由脚本按 8 位一组转 ASCII 还原。静态扫描脚本主体只能看到一堆 `Get-Content` 和无意义文本文件。

## 原理

- **关键词物理分散**：`NewPE2.PE`、`Execute`、`invoke`、`load`、`Gettype`、`getMethod` 分别保存在同名 txt 中（每个文件只有一行）。恶意脚本用变量逐个读取后作为参数/方法名拼接，最终组成 .NET 反射调用。检测规则通常匹配脚本内的 `Assembly.Load`、`GetMethod(`、`Invoke(`、`NewPE2`、`Execute` 等字符串；这些词在单个文件中都被拆散，匹配不到完整调用。
- **`<##>` 切断记号**：PowerShell 中 `<# ... #>` 是块注释，出现在表达式内部也会被忽略但保留词法边界。`[<##>Reflection.Assembly<##>]` 解析时等价于 `[Reflection.Assembly]`，却让“Reflection.Assembly”这一连续字符串在文本里被打断，绕过基于文本匹配的静态规则。
- **二进制串藏路径**：Framework.txt 存储的是一长串以空格分隔的 0/1 位串；脚本函数 `FH` 以每 8 位为一组 `[Convert]::ToByte(substring, 2)`，再 `ASCII.GetString` 还原出 `C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe`。这样注入宿主路径不以明文出现在脚本或配置里，CyberChef 的 From Binary→To Hex→From Hex 可快速还原（分析侧）。
- **`Get-Content | iex` 构造数组**：`[double[]] $tLx = Get-Content 'runpe.txt' | iex`、`[double[]] $Uk = Get-Content 'byet.txt' | iex` 把文本文件内容当 PowerShell 表达式执行，得到用于解密的 double 型字节数组；文件内容看起来像普通数字/文本，不是脚本。
- **自定义字节变换**：`fun_alosh()` 读取 ali1.txt/ali3.txt 等单行文本作为参数/掩码，对传入的字节数组做自定义变换（原文截图只展示片段，未给出完整算法），用于把两份 PE（DLL 与 EXE）从文本数据还原为可加载的字节。
- **为什么有效**：样本没有任何一处出现完整的敏感调用；单行 txt 文件混在同目录的普通文本里；路径与 PE 数据都是编码/二进制形式；`Get-Content | iex` 让静态引擎难以判定“这只是数据”。只有动态执行到拼接处才能还原真实调用。

## 触发条件

- PowerShell 可执行，且攻击者能投放整组文本文件与 t.ps1 到同一目录（本例为 `C:\Users\Public`）。
- 脚本引用的 txt 必须齐全：少一个关键词就拼不出完整方法名/路径。
- 目标环境未启用会拦截 `Get-Content | iex` 或脚本块日志的强检测；内存中的反射加载未被 AMSI 拦截。

## 利用步骤

1. 把注入链所需关键词分别写入单行 txt：`NewPE2.txt`=`NewPE2.PE`、`Execute.txt`=`Execute`、`Invoke.txt`=`invoke`、`load.txt`=`load`、`Gettype.txt`=`Gettype`、`getMethod.txt`=`getMethod`，以及注入宿主路径的二进制串 `Framework.txt`、两份 PE 的数值数组 `runpe.txt`/`byet.txt`、变换参数 `ali1/ali3/ali4.txt`。
2. t.ps1 运行时从各 txt 读入关键词到变量，按反射调用的顺序拼装。
3. 先调用 `FH()` 把 Framework.txt 的 0/1 位串还原为 `aspnet_compiler.exe` 完整路径。
4. 用 `fun_alosh()` 对 runpe.txt/byet.txt 的字节数组做变换，得到 DLL 与 EXE 字节。
5. 执行 `[<##>Reflection.Assembly<##>]::Load(dll字节).GetType("NewPE2.PE").GetMethod("Execute").Invoke($null, @(宿主路径, $null, exe字节, $true))`（实际顺序与参数见注入卡）。
6. 验证：脚本块日志/调试器中可见大量 `Get-Content ...\*.txt` 后紧跟 `Assembly.Load` 与 `Invoke`；目录中存在一组同风格单行 txt。

## PoC

按原文结构重写的最小示意（文件名与内容为原文可见值，未执行）：

```powershell
# 关键词分散读取（每个 txt 只有一行）
$mow  = Get-Content -Path 'C:\Users\Public\NewPE2.txt'
$dlea = Get-Content -Path 'C:\Users\Public\Execute.txt'
$yliu = Get-Content -Path 'C:\Users\Public\Invoke.txt'
$tLx  = Get-Content -Path 'C:\Users\Public\load.txt'
$Uk   = Get-Content -Path 'C:\Users\Public\Gettype.txt'
$ym   = Get-Content -Path 'C:\Users\Public\getMethod.txt'

# 二进制位串还原注入宿主路径
Function FH([String]$SKey) {
    $bytes = [System.Collections.Generic.List[Byte]]::new()
    for ($i = 0; $i -lt $SKey.Length; $i++) {
        $bytes.Add([Convert]::ToByte($SKey.Substring($i,1), 2))
    }
    return [System.Text.Encoding]::ASCII.GetString($bytes.ToArray())
}
$hostPath = FH (Get-Content -Path 'C:\Users\Public\Framework.txt' -Raw)

# 反射调用用变量的形式拼出（示意）
[<##>Reflection.Assembly<##>]::Load($dllBytes).
    GetType($mow).GetMethod($dlea).Invoke($null, @($hostPath, $null, $exeBytes, $true))
```

说明：原文截图只给出变量读取与最终调用片段，`fun_alosh` 实现与变量间完整拼接顺序未全部展示；以上为按截图重写的结构示意，未执行。

## 变体与关联

- [[code-analysis-reverse-obfuscation-hta-vbscript-hyphen-fill-string]]：同样是“往字符串里插入分隔符/注释打断关键词”的思路（连字符填充），本卡是跨文件拆分 + 块注释。
- [[code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock]]、[[code-analysis-reverse-obfuscation-powershell-braced-variable-format-reorder]]：PowerShell 其它编码/重排混淆。
- [[pentest-c2-managed-runpe-reflection-newpe2-aspnet-compiler]]：本卡还原出的反射调用所执行的注入动作。
- [[pentest-initial-access-wsf-remote-script-bits-zip-loader-chain]]：这些 txt 与 t.ps1 由 WSF/BITS/zip 链投放到 `C:\Users\Public`。
- 变体：关键词可拆到注册表值、环境变量、ADS、图片元数据或远程配置；分隔符可换成 `+` 拼接、`-f` 格式串、字符码数组；二进制串可换成 base64/hex/自定义编码。
- 边界：txt 缺失、目录被清理、脚本块日志/AMSI 记录到真实拼接后的调用时失效；分析者可通过 CyberChef 按 8 位二进制快速还原路径。

## 检测与防御

- 检测：PowerShell 脚本在同一目录连续 `Get-Content` 多个单行 txt，随后出现 `Assembly.Load`/`GetMethod`/`Invoke` 的动态调用；文本中出现 `<##>` 夹在括号/标识符之间（`[<##>...<##>]`）。
- 检测：目录中存在一组语义化命名的单行 txt（load/Gettype/getMethod/Invoke/NewPE2/Execute），旁边还有一长串 0/1 位串文本；文件创建时间集中在同一分钟。
- 检测：`Get-Content ... | iex` 的脚本块日志；AMSI 记录到 `ToByte(...,2)` + `ASCII.GetString` 的位串解码。
- 防御：启用 PowerShell 脚本块日志与 AMSI；EDR 监控脚本宿主/`powershell.exe` 对公共目录的批量文本读取；限制 `C:\Users\Public` 下脚本执行；对“脚本读取同目录多文本后反射加载 .NET”的行为链告警。
- 分析侧：CyberChef `From Binary`（8 位、空格分隔）→ `To Hex` → `From Hex` 可还原 Framework.txt；按 txt 文件名即可推出缺失的反射调用关键词。
