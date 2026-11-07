---
id: ctf-forensics-docm-vba-xor-powershell-encodedcommand-deflate
title: Word 宏三段载荷：VBA XOR+Base64 解出 PowerShell，-EncodedCommand 解码后再 Deflate 解压取出最终脚本
type: scenario
domain: ctf
path: ctf/forensics
technique: docm-vba-xor-powershell-deflate-chain
tags:
- ctf
- forensics
- vba
- docm
- powershell
- deflate
- base64
- xor
- maldoc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:31:02+08:00'
  notes: 已对照原文满江红核对：VBA unxor(Base64 key XOR)、powershell -e UTF-16LE、DeflateStream 解压最终 Read-Host 校验脚本三层结构与原文一致；最终 flag 与原文一致。
url: /docs/ctf/forensics/ctf-forensics-docm-vba-xor-powershell-encodedcommand-deflate/
draft: false
kb_aliases:
- VBA 宏分析
- PowerShell -e
- EncodedCommand
- DeflateStream 解压
- 多层载荷
- 满江红
- maldoc 分析
---

## 一句话结论

启用宏的 Word 文档里，VBA 的 `unxor(ciphertext,start)` 把 Base64 解码出的密钥与密文逐字符异或，再 `Execute` 拼出 `WScript.Shell`、`.Run` 和完整命令；第二层是 `powershell -e <base64>`（UTF-16LE），解码后通过 `DeflateStream` 解压内嵌 Base64 数据，第三层才是最终密码校验脚本——逐层静态还原即可取出 flag，无需运行宏。

## 原理

- **第一层 VBA XOR**：宏中保存密文数组和一个 Base64 编码的密钥；`unxor` 先 Base64 解码密钥，再 `Chr(key(i+start) Xor Asc(Mid(ciphertext,i,1)))` 逐字节还原明文。攻击者分段调用 `unxor(...,0)`、`unxor(...,10)`、`unxor(...,20)`，分别得到 `WScript.Shell`、`.Run` 与完整命令，最后 `Execute` 执行。
- **第二层 PowerShell -EncodedCommand**：还原出的命令是 `powershell -e <Base64>`；PowerShell 的 `-e/-EncodedCommand` 使用 UTF-16LE 编码，脚本用 `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))` 解码。
- **第三层 Deflate**：解码后的脚本用大小写混淆的 `.('ieX')`（Invoke-Expression）执行一个表达式：把内嵌 Base64 解码成 MemoryStream，交给 `System.IO.Compression.DeflateStream`（Decompress 模式），再用 StreamReader 读出最终脚本并执行。
- **最终脚本**：一个 `Read-Host "Password"` 的校验逻辑，正确口令就是 flag（原文 `FLAG{w0w_7h3_3mb3dd3d_vb4_1n_w0rd_4u70m471c4lly_3x7cu73d_7h3_p0w3r5h3ll_5cr1p7}`）。
- **静态分析要点**：DOCM 是 ZIP，`word/vbaProject.bin` 是 OLE 复合文档；可用 olevba/olevba、`strings` 或 Office 宏编辑器提取源码。Deflate 原始流用 `zlib.decompress(data, -15)`（wbits=-15）解压；PowerShell Base64 用 UTF-16LE 解码。
- **根因/价值**：恶意文档常用“VBA 混淆 → PowerShell 编码命令 → 压缩内嵌脚本”多层载荷规避检测；分析时按层剥离，不执行任何宏或脚本。

## 触发条件

- 目标为启用宏的 Word 文档（.doc/.docm），宏中有 Base64+XOR 的 `unxor` 类函数和 `Execute` 调用。
- 第二层使用 `powershell -e/-EncodedCommand` 或 `FromBase64String` + `Encoding::Unicode`。
- 第三层使用 `DeflateStream`/`GZipStream` 等压缩流加载内嵌数据。
- 分析环境具备 olevba、Python zlib、PowerShell 解码能力；不需要联网或执行样本。

## 利用步骤

1. 将 `.docm` 改后缀为 `.zip` 解压，或直接用 olevba/olevba 提取 `word/vbaProject.bin` 中的宏源码。
2. 阅读 VBA：找到 `unxor` 的密钥 Base64 与密文数组，按 `key(i+start) XOR Asc(cipher[i])` 还原各段字符串，得到 `WScript.Shell`、`.Run` 和 PowerShell 命令。
3. 提取 `powershell -e` 后的 Base64，按 UTF-16LE 解码：`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($s))` 或 Python `base64.b64decode(s).decode('utf-16le')`。
4. 在解码后的脚本中找到内嵌 Base64 与 `DeflateStream`；提取 Base64，`zlib.decompress(base64.b64decode(s), -15)` 解压。
5. 读取解压出的最终脚本；若是密码校验，直接提取比较的字符串作为 flag。
6. 全程不运行宏/PowerShell；如需验证，在隔离环境用静态解码结果。

## PoC

```python
import base64, zlib

# 第二层：PowerShell -EncodedCommand 的 UTF-16LE Base64
ps = base64.b64decode("<powershell -e 后面的Base64>").decode("utf-16le")
print(ps)

# 第三层：脚本中的内嵌 Base64 + Deflate 原始流
embedded = "<内嵌Base64>"
final_script = zlib.decompress(base64.b64decode(embedded), -15).decode("ascii", errors="ignore")
print(final_script)
```

原文还原出的最终校验片段：

```powershell
$input = Read-Host "Password"
if ($input -eq "FLAG{w0w_7h3_3mb3dd3d_vb4_1n_w0rd_4u70m471c4lly_3x7cu73d_7h3_p0w3r5h3ll_5cr1p7}") {
    Write-Output "Correct!"
} else { Write-Output "Incorrect" }
```

## 变体与关联

- 第一层变体：XOR 密钥来自 Base64、硬编码数组、环境变量；也可能用 Chr/StrReverse/Replace 混淆。
- 第二层变体：`-EncodedCommand`、`-e`、`FromBase64String` + Unicode/ASCII、多层 `iex`。
- 第三层变体：Deflate、GZip、Brotli；原始流用负 wbits，带头用默认 wbits。
- 关联卡片：[[ctf-forensics-docm-vba-base64-xor-powershell-download-url]]（VBA Base64+XOR 还原下载 URL）、[[ctf-forensics-docm-vba-project-password-dpb-bypass]]、[[ctf-forensics-phishing-email-xor-docx-base64-key]]。
- 边界：若宏使用未知加密/远程加载，需动态沙箱或内存取证；本卡只覆盖静态可还原的三层结构。

## 检测与防御

- 企业侧禁用宏、启用 Mark-of-the-Web/受保护视图；邮件网关拦截含宏文档。
- 检测 `vbaProject.bin` 中的 `AutoOpen`/`Document_Open`、`Shell`/`WScript.Shell`、`powershell -e`、`DeflateStream` 等组合特征。
- 启用 AMSI/脚本块日志，监控 PowerShell 编码命令与压缩流加载；限制 PowerShell 执行策略。
- 分析侧：只在隔离环境静态解包，不执行宏；对解码后的脚本再做一次沙箱/静态检查。
