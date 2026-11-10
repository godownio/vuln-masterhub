---
id: code-analysis-reverse-windows-xworm-v5-aes-config-plugin-rat-capabilities
title: XWormRAT V5 .NET 远控分析：MD5(mutex) 派生 AES-ECB 配置解密、命令分派、XLogger 键记录与 Plugins DLL 插件化
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: xworm-v5-aes-config-derivation-plugin-rat-analysis
tags:
- reverse
- windows
- dotnet
- xworm
- rat
- aes
- config-decryption
- keylogger
- plugins
- malware-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V342
  verified_at: '2026-11-08T21:47:44+08:00'
  notes: 已对照原文及35张图片核对：AlgorithmAES.Decrypt 的 MD5(Helper.SB(GClass0.Mutex)) + Array.Copy 0/15 两次拷贝成 32 字节 AES-256-ECB、NetTransferTCP.string_0/Port、SpecificSystemSettings.KEY/string_0/Groub、GClass0.USBNM 解密与截图一致；Read(byte[]) 命令分派（pong/rec/CLOSE/uninstall/update 等）、XLogger 键码映射、XWorm-Crack Plugins 39 个 DLL 均有截图佐证。与既有 XWorm V5.2 Pastebin 死信箱 C2 提取卡（同一活动、共享 IOC）聚焦点不同：本卡为内置配置的密钥派生/解密算法与能力面，非同一结论，保留。无 sources/文章ID/来源URL；路径 code-analysis/reverse/windows 存在。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-xworm-v5-aes-config-plugin-rat-capabilities/
draft: false
kb_aliases:
- XWorm 配置解密
- XWorm V5 分析
- AlgorithmAES.Decrypt
- MD5(mutex) AES-ECB 密钥
- XWorm 插件架构
- XLogger 键盘记录
- NetTransferTCP 配置
---

## 一句话结论

GitHub 投递链最终落地的 XWormRAT V5.x 是 .NET 远控：它把 C2 域名/端口、AES 密钥、分组等配置以 Base64 密文写在 `SpecificSystemSettings`/`NetTransferTCP` 等字段中，运行时用 `AlgorithmAES.Decrypt` 以「互斥体字符串的 MD5 摘要复制填充成 32 字节 AES-256 密钥、ECB 模式」解出；随后按 `pong/rec/CLOSE/uninstall/update/DW/FM/LN/RunShell/...` 等指令分派功能，键盘记录由 `XLogger` 映射虚拟键码，截图/窃密/HVNC/勒索等功能通过 `Plugins` 目录下的 DLL 动态加载。

## 原理

- **配置字段与解密入口**：样本类被混淆（随机类名、`[GeneratedCode("MyTemplate","14.0.0.0")]` 等），关键配置字段为 `NetTransferTCP.string_0`（C2 域名）、`NetTransferTCP.Port`（端口）、`SpecificSystemSettings.KEY`、`SpecificSystemSettings.string_0`、`SpecificSystemSettings.Groub`（分组）、`GClass0.USBNM`（USB 传播名）等；运行时逐一调用 `AlgorithmAES.Decrypt(...)` 并把结果写回静态字段。
- **密钥派生**：`AlgorithmAES.Decrypt` 创建 `RijndaelManaged` 与 `MD5CryptoServiceProvider`，计算 `MD5(Helper.SB(GClass0.Mutex))` 得到 16 字节摘要，把摘要两次拷贝进 32 字节密钥缓冲（第二次偏移 15，末尾字节保持 0），作为 AES-256 密钥；`Mode = CipherMode.ECB`，输入先 `Convert.FromBase64String` 再 `TransformFinalBlock` 解密，`Helper.BS` 转回字符串。由于密钥来自样本内的互斥体字符串，同一构建的配置可离线复算。
- **配置来源可变**：V5.0 样本可直接在配置中写 IP/端口（如 `198.23.187.140:4646`）；V5.2 样本则把 Pastebin 死信箱 URL 写入样本，运行时拉取返回的域名/端口（如 `localbeheaders.mcgo.io:4411`）再填入配置。这使同一份 RAT 只需换死信箱内容即可换 C2。
- **命令分派**：`Read(byte[])` 把解密后的指令按分隔符切分，按首字段比较执行：`pong`（心跳/重置间隔）、`rec`（重启程序）、`CLOSE`（关闭 socket 退出）、`uninstall`、`update`（下载更新并解压替换）、`DW`（执行 PowerShell）、`FM`（内存加载并执行载荷）、`LN`（从 URL 下载文件）、`Urlopen/Urlhide`（浏览器/当前进程打开网页）、`PCShutdown/PCRestart/PCLogoff`（电源操作）、`RunShell`（执行 shell 命令）、`StartDDos/StopDDos`（DDoS 线程）、`StartReport/StopReport`（进程标题监控）、`Xchat/Hosts/Shosts`（系统/hosts 信息回传）、`ngrok/plugin/savePlugin`（插件与隧道）、`OfflineGet`（写 log.tmp）、`$Cap`（截屏）。
- **键盘记录**：`XLogger` 把按键码映射为可读文本——数字直接转字符，`Space/Return/Escape/LControlKey/RControlKey/RShiftKey/LShiftKey` 等转为 `[SPACE]`/`[ENTER]`/`[ESC]`/`[CTRL]`/`[Shift]` 等标记，再写入日志供回传。
- **插件化能力**：`Plugins` 目录包含 39 个 DLL（`Chromium.dll`、`Stealer.dll`、`Ransomware.dll`、`HVNC.dll`、`HRDP.dll`、`Keylogger.dll`、`RemoteDesktop.dll`、`ReverseProxy.dll`、`RunPE.dll`、`StartupManager.dll`、`Regedit.dll`、`Clipboard.dll`、`Microphone.dll`、`Ngrok-Installer.dll` 等），按需动态加载，功能逻辑与 EagleMonitorRAT/Xeno-RAT 类似；因此样本本体只是加载器与通信框架，实际危害取决于下发/加载的插件。

## 触发条件

- 分析对象为 XWorm V5.x .NET 样本（PE32/.NET，常见 VB.NET/混淆器，版本串 `XWorm V5.x`、`Worm V5`）。
- 样本可运行且能访问外网（若依赖 Pastebin 死信箱取 C2）；离线分析则需定位互斥体字符串与加密字段。
- 分析环境具备 dnSpy/ILSpy/de4dot；动态调试需注意反调试/反沙箱（`Thread.Sleep`、互斥体、环境检查）。
- 仅用于授权恶意样本分析与防御研究。

## 利用步骤

1. 用 Detect It Easy 确认 .NET 与编译器信息；用 de4dot 去混淆，恢复可读类名/方法名（若失败则按字符串与调用关系定位）。
2. 在 dnSpy 中定位 `AlgorithmAES.Decrypt` 与 `SpecificSystemSettings`/`NetTransferTCP`/`GClass0` 字段，确认配置字段与其赋值处（`Main` 线程启动前）。
3. 找到密钥来源 `GClass0.Mutex`（互斥体字符串），按 `MD5(mutex)` 两次拷贝成 32 字节密钥、AES-256-ECB 解密 Base64 字段，离线还原 C2 域名/端口、分组、USB 传播名等。
4. 若样本使用 Pastebin 死信箱，提取 `pastebin.com/raw/<id>` 直接请求获取真实 C2（参考已有 XWorm 死信箱提取方法）。
5. 跟踪 `Read(byte[])`/命令分派逻辑，整理指令表与参数格式；检查 `XLogger` 键记录与 `Plugins` 加载器（Assembly.Load/LoadFile、插件名列表）。
6. 结合网络流量/沙箱报告确认上线协议与插件下发，输出 IOC（C2、互斥体、版本串、插件名、哈希）。

## PoC

```python
import base64, hashlib
from Crypto.Cipher import AES

mutex = "<从样本 GClass0.Mutex 提取的字符串>"
h = hashlib.md5(mutex.encode("utf-8")).digest()      # 16 字节
key32 = h[:15] + h[:16] + b"\x00"                    # 模拟两次 Array.Copy(..., 0/15, 16)
cipher = AES.new(key32, AES.MODE_ECB)

def dec(field_b64: str) -> str:
    data = base64.b64decode(field_b64)
    return cipher.decrypt(data).decode("utf-8", errors="ignore").rstrip("\x00")

# 用样本中 SpecificSystemSettings / NetTransferTCP 的 Base64 字段逐个解密
```

```text
配置示例（V5.0 直连）：198.23.187.140 / 4646 / <123456789> / <Xwormmm> / USB.exe
死信箱示例（V5.2）：pastebin.com/raw/<id> 返回 localbeheaders.mcgo.io:4411
```

## 变体与关联

- **版本/配置变体**：V5.0 直连 IP，V5.2 用 Pastebin 死信箱；字段名与混淆器版本不同，但 `AlgorithmAES`/`SpecificSystemSettings` 的解密结构一致。
- **载荷形态变体**：GitHub 仓库中的 .txt 载荷有「PowerShell 直接 `Assembly.Load` 加载 PE」与「PowerShell 先执行 shellcode、shellcode 再加载 PE」两种，最终都落地 XWormRAT；配置解密对两者通用。
- **插件生态**：插件 DLL 可替换/扩展（窃密、浏览器、HVNC、勒索、代理、RunPE 等），分析时需同时检查 `Plugins` 目录与下发通道，不能只看主样本。
- **关联**：死信箱 C2 提取、GitHub raw 载荷托管、regsvr32 Run 键持久化、AMSI patch 等前置环节均有独立卡片；本卡聚焦 RAT 本体的配置解密与能力面。

## 检测与防御

- **静态特征**：搜索 `XWorm V5`/`Worm V5`、`AlgorithmAES`、`NetTransferTCP`、`SpecificSystemSettings`、`XLogger`、`Plugins` 等字符串与类名；.NET 样本可用 de4dot + dnSpy 快速确认。
- **网络检测**：封禁已知 C2 域名/IP 与 Pastebin 死信箱 URL；检测进程周期性回连、Base64 配置拉取与插件下载；对 `pastebin.com/raw/` 等死信箱访问做可疑上下文告警。
- **主机检测**：监控互斥体、`ProgramData`/`%TEMP%` 下的插件 DLL 加载、键盘记录行为（键码轮询/日志写入）、截屏与 HVNC 相关 API 调用。
- **防御**：AMSI/EDR 覆盖 .NET 内存加载与反射调用；限制 PowerShell 下载执行与未签名 DLL 加载；及时隔离并取证，按 IOC 排查同源 GitHub 仓库与死信箱。

