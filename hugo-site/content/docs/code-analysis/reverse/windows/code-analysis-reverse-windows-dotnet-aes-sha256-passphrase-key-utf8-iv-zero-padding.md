---
id: code-analysis-reverse-windows-dotnet-aes-sha256-passphrase-key-utf8-iv-zero-padding
title: .NET 样本内嵌 AES 参数还原：key=sha256(口令短语)、IV=UTF8 短语、Padding=Zeros，解 base64 常量取二级 C2
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dotnet-aes-sha256-key-utf8-iv-zero-padding-decrypt
tags:
- dotnet
- dnspy
- aes
- cbc
- sha256
- base64
- malware
- c2
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:36:57+08:00'
  notes: 已对照原文核对；本次核对未读取图片；dnSpy 反编译出的 AesManaged + CipherMode.CBC + PaddingMode.Zeros、IV=tbbliftalildywic(16 字符)、key=SHA256(UTF8(vudzvuokmioomyialpkyydvgqdmdkdxy))、base64 密文常量与 Replace(NUL) 去零填充均与正文一致；解密截图与后续 xml 内容未读图验证
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-dotnet-aes-sha256-passphrase-key-utf8-iv-zero-padding/
draft: false
kb_aliases:
- dnSpy 还原 AES 参数
- sha256 派生 key 解 .NET 载荷
- AesManaged 硬编码 IV
- PaddingMode.Zeros 去 NUL
- base64 常量解密出 URL
---

## 一句话结论

.NET 加载器把下一级载荷写成 base64 常量并用 `AesManaged` 解密时，key 常常不是明文串而是 `SHA256(某句口令短语)`，IV 是一句恰好 16 字符的字符串，`PaddingMode` 还可能是 `Zeros` 而非 PKCS7；因此"拿程序里看得见的两个字符串当 key/IV 直接试"必然失败，必须按 `ComputeHash(UTF8(短语))` 派生 key、按 `Encoding.UTF8.GetBytes(IV短语)` 取 IV、解密后 `Replace("\0","")` 去 NUL，才能取出真正的 C2 URL。

## 原理

- `AesManaged` 的三个属性决定能否解开：`Key`（长度 16/24/32 → AES-128/192/256）、`IV`（必须 16 字节）、`Padding`。任何一个猜错都只会得到乱码，且错误表现一致（无法区分"key 错"还是"padding 错"）。
- 常见派生方式：`Key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(passphrase))`——结果为 32 字节，即 AES-256；`IV = Encoding.UTF8.GetBytes(ivPhrase)`，短语通常被作者凑成正好 16 个字符。二者都是"人可读短语"，静态看很容易被误当成直接可用的 key/IV。
- `PaddingMode.Zeros` 不做 PKCS7 填充，明文尾部是 `\0` 字节；所以反编译里几乎总能见到 `.Replace("\0", string.Empty)`——这行是"Zeros 填充"的强指纹，也说明解出来的是文本（URL/脚本）而不是二进制。
- 密文以 `Convert.FromBase64String("<常量>")` 形式内嵌在方法体里，长度必为 16 的倍数；偏移量可从 base64 长度反推块数。
- 解出的是什么往往决定下一步：本例解出的是第二个下载 URL（同一 C2 域名下的 `.xml`），即"每层只给下一个地址"的多级载荷设计，静态还原比动态跑更省事也更安全。

## 触发条件

- 拿到一个 .NET 样本（`.dll`/`.exe`/`.exe.config` 指到的附属程序集），可用 dnSpy/ILSpy 反编译。
- 代码里出现 `AesManaged`/`RijndaelManaged` + `CreateDecryptor` + base64 常量三件套，且没有现成的 key/IV 明文配对。
- 样本可静态读到 `ComputeHash`/`SHA256`、`Encoding.UTF8.GetBytes`、`Replace("\0", "")` 等调用。
- 需要在不执行样本的前提下拿到下一级地址或脚本。

## 利用步骤

1. dnSpy 打开样本，定位解密函数（`CreateDecryptor(aesManaged.Key, aesManaged.IV)`），顺静态字段看 `cipherMode`、`paddingMode`、key 来源、IV 来源。
2. 认 key 的派生：若字段是"字符串 → `ComputeHash(UTF8(...))`"，就按同一算法复算（SHA256 → 32 字节）；若是直接 `GetBytes`，注意长度必须 16/24/32。
3. 认 IV：`Encoding.UTF8.GetBytes("...")`，检查是否正好 16 字符。
4. 取出 base64 常量，按 `CBC` + `Zeros` 填充解密，去掉 `\0` 尾巴。
5. 结果若是 URL，继续下载下一级；若是脚本/PE，保存后转静态分析（不要直接执行）。
6. 复算时保持与样本完全一致的编码（UTF-8 无 BOM）与填充模式，否则会得到"看起来像乱码"的假失败。

## PoC

```python
import base64, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ct  = base64.b64decode("<BASE64_CONST>")
key = hashlib.sha256("vudzvuokmioomyialpkyydvgqdmdkdxy".encode()).digest()  # 32B -> AES-256
iv  = b"tbbliftalildywic"                                                   # 16B

ct = ct[:len(ct) - len(ct) % 16]
d  = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
pt = (d.update(ct) + d.finalize()).rstrip(b"\x00")   # PaddingMode.Zeros
print(pt.decode("utf-8", "replace"))
```

```csharp
// 与样本等价的 C# 复算（Padding 必须设 Zeros，否则会抛/解错）
using (var aes = new AesManaged()) {
    aes.Mode    = CipherMode.CBC;
    aes.Padding = PaddingMode.Zeros;
    aes.Key     = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("<passphrase>"));
    aes.IV      = Encoding.UTF8.GetBytes("<16 char iv>");
    using (var dec = aes.CreateDecryptor(aes.Key, aes.IV)) { /* CryptoStream 读 -> UTF8 字符串 */ }
}
```

## 变体与关联

- 变体（key 来自资源/配置）：`Key` 取自 `csrss.exe.config`、内嵌资源或注册表值时，先解包配置再复算；本例配置里给的就是下一级 URL。
- 变体（真正二进制载荷）：解出的是 PE/shellcode 时，后续常见 `VirtualAlloc(0x3000, 0x40)` + `Marshal.Copy` + `CreateThread`（本例同一类里就有此调用），转 `code-analysis/reverse/windows` 的注入/加载器分析。
- 变体（Padding 为 PKCS7）：去掉 `Replace("\0","")` 逻辑，改用去填充；两种都试一遍成本极低。
- 变体（取样本时响应不同）：同一 URL 用不同 User-Agent 请求可能返回不同内容（浏览器看到带注释的源码、命令行工具拿到另一份），取证时应用多种客户端交叉比对再下结论。
- 关联：[[code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample]]（AES-256-CBC + Assembly.Load 的同类多层 loader）、[[code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell]]（多层解码逐层静态还原的方法论）。
- 边界：若 key 由环境指纹（机器名/MAC/域名）参与派生，静态复算会失败，需要动态提取或逆向派生函数本身。

## 检测与防御

- 检测：进程中 `AesManaged` 解密后紧跟 `DownloadData`/`WebClient` 的组合；同一进程内 base64 常量 → 解密 → 网络请求的时序特征（可用 ETW/.NET Profiling API）。
- 加固：终端侧阻断未签名的 .NET 程序集加载与 `Assembly.Load(byte[])`；限制 Office/脚本宿主派生 .NET 进程。
- 狩猎：批量扫描 .NET 样本中 `ComputeHash` + `CreateDecryptor` 同现的方法，抽出 base64 常量离线解密，可批量提取 C2 而无需执行。
- 响应：解出的 URL 与域名作为 IOC 下发；`.exe.config` 一类附属文件不要当"无害配置"忽略，它常是二级地址的载体。
