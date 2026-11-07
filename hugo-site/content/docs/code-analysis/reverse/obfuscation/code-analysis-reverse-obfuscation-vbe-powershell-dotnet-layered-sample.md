---
id: code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample
title: VBE→PowerShell→.NET 三层嵌套样本分析：MSXML2 Base64 解码、AES-256-CBC 载荷还原与 procdump 抓进程镂空
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: vbe-powershell-dotnet-layered-deobfuscation
tags:
- reverse
- obfuscation
- vbe
- vbscript
- powershell
- aes
- dotnet
- process-hollowing
- remcos
- malware-analysis
- procdump
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V153
  verified_at: '2026-11-06T07:43:51+08:00'
  notes: 已对照原文与20张图核对：VBE 解码→inputCommand Base64→MSXML2.DOMDocument/ADODB.Stream 落盘 C:\Temp\script_*.ps1→AES-256-CBC(PKCS7/KeySize=256) 解密 CipherMatrix→Assembly.Load 反射 MAFFIA.ProcessHollowing.Execute→Aspnet_compiler.exe 进程镂空→Remcos 字符串（polizoci.exe、7.2.0 Pro、BreakingSecurity.net），以及 procdump -ma -t -w 截图与 strings 证据均一致；路径/无 sources/source_url/无 affected_versions。未验证点：未复跑样本；卡片'在进程启动时触发 dump'措辞不准，原文图8 显示进程退出后触发 dump（-t 为终止时 dump，-w 等待启动）。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample/
draft: false
kb_aliases:
- VBE 样本分析
- 多层 VBE 混淆
- VBS→PowerShell→.NET
- MSXML2 ADODB.Stream Base64
- AES CipherMatrix 解密
- Aspnet_compiler process hollowing
- procdump 内存 dump
---

## 一句话结论

邮件附件 `.vbe` 经 VBE 解码得到 VBS，主逻辑把 `inputCommand` 用 MSXML2/ADODB.Stream 做 Base64 解码写入 `C:\Temp\script_<random>.ps1` 并隐藏执行；该 PowerShell 用硬编码 key/IV 的 AES-256-CBC 解密 `$CipherMatrix` 得到下一层脚本；下一层用 `Assembly.Load` 加载内存程序集并反射调用 `MAFFIA.ProcessHollowing.Execute` 注入 `Aspnet_compiler.exe`，最终加载 Remcos RAT。分析时逐层静态解密 + `procdump -ma -t -w` 捕获短命进程内存，可避免被“落盘文件干净”误导。

## 原理

- **第一层 VBE**：VBE 是 VBScript Encoded 编码格式，可还原为 VBS。样本入口在 `inputCommand`（超长 Base64），`ExecuteCommand` 用 `MSXML2.DOMDocument.6.0` 创建 `bin.base64` 节点，把文本写入 `dataNode.Text`，经 `ADODB.Stream`（先二进制后文本、UTF-8）解码出 PowerShell 脚本。
- **落地与隐藏执行**：脚本写入 `C:\Temp\script_<randomName>.ps1`，通过 `powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -NoLogo` 执行，结束后删除临时文件；因此主机侧只留下短暂脚本与父进程 `wscript.exe`。
- **第二层 PowerShell**：脚本包含 `$CipherMatrix`（Base64 加密数据数组）、`$KeyCipher` 与 `$VectorCipher`；`Process-CipherBlock` 使用 `Aes.Create()`，`Mode=CBC`、`Padding=PKCS7`、`KeySize=256`、`BlockSize=128`，解密后得到下一层 PowerShell。
- **执行向量**：`Invoke-StealthExecution` 定义三种方式：`[scriptblock]::Create($s)` 内存执行、写临时 `.ps1` 后执行并删除、`powershell -EncodedCommand` 子进程执行，用于规避检测。
- **第三层 .NET**：脚本把 `$moduleBytes`（Base64 程序集）还原，`Assembly.Load()` 后反射定位 `MAFFIA.ProcessHollowing` 类的 `Execute` 方法；`Execute(targetProcessPath, payload)` 创建挂起进程（`CreateProcessA` + `CREATE_SUSPENDED`），在目标进程 `VirtualAllocEx(MEM_COMMIT|MEM_RESERVE, 0x3000)`，写入 PE 头/节数据、处理重定位，最后 `ResumeThread` 恢复执行。
- **宿主选择**：`C:\Windows\Microsoft.NET\Framework\v4.0.30319\Aspnet_compiler.exe` 作为合法 .NET 工具被用作宿主，落盘 exe 本身干净、沙箱可能只报脚本；恶意代码只在内存中，因此需要内存 dump。
- **取证要点**：`procdump -ma -t -w aspnet_compiler.exe <out.dmp>` 在进程启动时触发 dump（`-t` 为终止时 dump，`-w` 等待进程启动），解决进程闪退导致手工附加失败的问题；`strings -n 8` 从 dump 中检索 Remcos 标识、路径、键盘记录与浏览器凭证字符串。

## 触发条件

- 样本为 `.vbe`/`.vbs` 邮件附件或包含多层 Base64/AES 的 PowerShell 脚本。
- 分析环境允许静态解码（Python/CyberChef）与运行/监控样本（隔离虚拟机）。
- 具备 `procdump`、`strings`、dnSpy 等工具；目标宿主为 `Aspnet_compiler.exe` 等短命 .NET LOLBin。

## 利用步骤

1. 识别样本类型与哈希，使用 VBE 解码工具/脚本把 `.vbe` 还原为 `.vbs`。
2. 定位 `inputCommand` 大段 Base64，提取后用 Python 解码（大文本不要依赖在线工具，避免截断遗漏）：

```python
import base64
s = open('input.txt', encoding='utf-8').read().strip()
open('layer2.ps1', 'wb').write(base64.b64decode(s))
```

3. 审阅 `layer2.ps1`：提取 `$CipherMatrix`、`$KeyCipher`、`$VectorCipher`；删除其中的执行逻辑，仅保留 AES 解密并输出到文件，运行得到 `layer3.ps1`。
4. 审阅 `layer3.ps1`：提取 `$moduleBytes` 的 Base64，解码为 `decoded_file.bin`；用 dnSpy 反编译，定位 `MAFFIA.ProcessHollowing.Execute` 及 `CreateProcessA`/`VirtualAllocEx`/`WriteProcessMemory`/`ResumeThread` 调用链。
5. 动态分析：在隔离环境启动样本，用 procdump 预监听短命宿主进程：

```bat
procdump -ma -t -w aspnet_compiler.exe "C:\dump\aspnet_compiler_full.dmp"
```

6. 对 dump 做字符串分析，确认家族与行为：

```bat
strings.exe -n 8 aspnet_compiler_full.dmp > dump_strings.txt
```

7. 提取 IOC：`C:\ProgramData\lalas\polizoci.exe`、`Remcos Agent initialized`、`7.2.0 Pro`、`BreakingSecurity.net`、键盘记录/浏览器凭证相关字符串等。

## PoC

无攻击 PoC（样本分析场景）。最小 AES 解密框架：

```powershell
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$aes.KeySize = 256
$aes.BlockSize = 128
$aes.Key = [Convert]::FromBase64String($KeyCipher)
$aes.IV  = [Convert]::FromBase64String($VectorCipher)
$dec = $aes.CreateDecryptor()
$plain = $dec.TransformFinalBlock([Convert]::FromBase64String($CipherMatrix), 0, [Convert]::FromBase64String($CipherMatrix).Length)
[IO.File]::WriteAllBytes('layer3.ps1', $plain)
```

## 变体与关联

- 变体：第二层执行向量可切换为 `ScriptBlock.Create`、临时 `.ps1` 或 `-EncodedCommand`；分析时要分别定位真实载荷。
- 变体：第三层可改用 `InstallUtil.exe`、`RegAsm.exe`、`MSBuild.exe` 等 .NET LOLBin 作为宿主；注入 API 序列仍是 `CreateProcess(SUSPENDED) → VirtualAllocEx → WriteProcessMemory → ResumeThread`。
- 变体：载荷可换成其他 RAT/Stealer；内存字符串中的家族标识与配置路径是主要判据。
- 关联：Windows 进程空心化 PE 注入、PowerShell 整数数组混淆与 ScriptBlock 执行、Remcos loader 链、内存 dump/脱壳。

## 检测与防御

- 邮件/网关：拦截 `.vbe`、`.vbs`、`.js` 等脚本附件；监控 `wscript.exe` 启动 `powershell.exe` 的父子链与隐藏窗口参数。
- 主机：监控 `C:\Temp\script_*.ps1`、`MSXML2.DOMDocument` + `ADODB.Stream` 组合、PowerShell `-EncodedCommand`、以及 `Aspnet_compiler.exe` 的异常网络连接/子进程/内存注入行为（该工具正常不应联网）。
- 内存/EDR：检测跨进程 `VirtualAllocEx` + `WriteProcessMemory` + `ResumeThread` 序列与未签名 PE 镜像；对短命进程启用启动即 dump。
- 取证：procdump `-ma -t -w` 捕获内存，strings/YARA 匹配 Remcos 标识与配置；提取持久化路径与 C2。
- 响应：隔离主机、清除 `C:\ProgramData\lalas\` 等落地文件、重置浏览器保存的凭据与 Cookie、轮换相关账号密码。
