---
id: code-analysis-reverse-windows-blacknet-config-aes-pbkdf2-extract
title: BlackNET 样本配置解密：dnSpy 定位 MainController，PBKDF2-SHA1(1000)+AES-CBC 还原 C&C 地址
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: blacknet-config-aes-pbkdf2-extract
tags:
- reverse
- windows
- dotnet
- dnspy
- malware
- blacknet
- aes
- pbkdf2
- config-extraction
- c2
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:31:01+08:00'
  notes: 已对照原文与全部 30 图核对：图08 MainController 构造函数中 Host=MYn+RlRF...GRTHA==、AESKey=aGIZbml1...SRGrvC64、AESStatus=True、Y=|BN|、ID=HacKed_、MTX=BN 与卡内一致；图11 getAlgorithm 使用 new Rfc2898DeriveBytes(secretKey, Encoding.Unicode.GetBytes(常量 salt))、KeySize=256、IV=GetBytes(BlockSize/8)=16、Key=GetBytes(KeySize/8)=32、Padding=PKCS7，AES_Decrypt 为标准 Base64→CryptoStream(CBC)→Encoding.Unicode；图09 CyberChef 显示 PBKDF2 384bit/1000 次/SHA1/salt HEX，图10 用 IV 前 16 字节、Key 后 32 字节解出 http://192.168.65.129/blacknet，与卡内 IV16+Key32、PBKDF2-SHA1(1000)、AES-CBC/PKCS7、Unicode 结论一致。未验证点：卡内 Python PoC 的 SALT_STR 为占位符（图11 中常量 salt 可见，但为免 OCR 猜字未回填；按卡内步骤 3 从样本 getAlgorithm 取即可复算），未在本机复跑；frontmatter 无 sources/source_url；BlackNET 框架无受影响版本。kb show 存在；dedup top1 为自身，其余候选（Java RAT H2 配置、VShell AES-CBC、WCDB SQLCipher 等）算法/结构不同，非同链；dup-scan 无本篇 pair。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-blacknet-config-aes-pbkdf2-extract/
draft: false
kb_aliases:
- BlackNET 配置提取
- MainController Host 解密
- BlackNET AESKey
- Rfc2898DeriveBytes 配置解密
- 僵尸网络 C2 配置还原
---

## 一句话结论

BlackNET（开源 .NET 远控）把 C&C 地址以 Base64 密文存放在 `MainController.Host`，同类的 `AESKey` 与 `AESStatus` 也在该类中；当 `AESStatus=true` 时，样本用 `Rfc2898DeriveBytes(AESKey, Encoding.Unicode.GetBytes(<内置 salt>))`（默认 SHA1、1000 次迭代）派生 48 字节，前 16 字节作 IV、后 32 字节作 AES-256 Key，再对 Base64 解码后的 Host 做 AES-CBC/PKCS7 解密并以 Unicode 读取，即可还原 `http://<C2>/blacknet`。

## 原理

- **配置位置**：BlackNET 木马主类 `MainController` 的构造函数中硬编码了 `Host`（Base64 密文）、`ID`、`AESKey`、`AESStatus`、`MUTEX`、`Y`（Splitter）、持久化/传播/反分析等布尔配置。dnSpy 打开样本后直接搜索 `MainController` 或字符串 `AESKey` 即可定位。
- **密钥派生**：`getAlgorithm(secretKey)` 调用 `new Rfc2898DeriveBytes(secretKey, Encoding.Unicode.GetBytes("<常量 salt>"))`；.NET 默认使用 HMAC-SHA1、1000 次迭代、UTF-8 编码 password。随后 `rijndaelManaged.KeySize = 256`，`IV = rfc.GetBytes(BlockSize/8)`（16 字节），`Key = rfc.GetBytes(KeySize/8)`（32 字节），即 PBKDF2 输出前 48 字节按 IV16+Key32 切分。
- **解密流程**（`AES_Decrypt`）：`Convert.FromBase64String(encryptedData)` → `CryptoStream` + `CreateDecryptor()`（AES-CBC、PKCS7）→ 读取明文 → `Encoding.Unicode.GetString()`。因此 Host 字符串是「Unicode 明文 → AES-CBC 加密 → 标准 Base64」的结果。
- **为什么能还原**：AESKey、salt、迭代次数、IV/Key 切分规则全部硬编码在样本里；拿到样本即可离线复算，不需要运行木马或连接 C&C。
- **与通信协议的关系**：解密得到的 C&C 基址用于 `check_panel.php`/`connection.php`/`getCommand.php`/`receive.php` 请求；配置中的 `Y`（Splitter，默认 `|BN|`）决定上线信息分隔符，`ID` 为 Victim ID 前缀。配置还原后可进一步做流量检测与 IOC 提取。

## 触发条件

- 拿到 BlackNET 样本（.NET PE），可用 dnSpy/de4dot/ILSpy 反编译；样本未被强混淆到无法识别字符串。
- `MainController` 中存在 `Host`、`AESKey`、`AESStatus` 字段；`AESStatus=true`（为 false 时 Host 可能是明文或未加密配置）。
- 能读取 `getAlgorithm` 中的 salt 常量与迭代次数（默认 1000/SHA1，但可能被修改）。
- 分析环境具备 Python + pycryptodome 或 CyberChef，可离线复算 PBKDF2/AES。

## 利用步骤

1. 用 `de4dot` 去混淆（如有），再用 dnSpy 打开样本，搜索 `MainController` 或字符串 `AESKey`/`AESStatus`。
2. 记录 `Host`（Base64 密文）、`AESKey`、`AESStatus`；确认 `AESStatus` 为 true。
3. 打开 `getAlgorithm`，记录 `Rfc2898DeriveBytes` 的 salt 常量、迭代次数与哈希算法；打开 `AES_Decrypt` 确认 CBC/PKCS7 与 Unicode 输出。
4. 用 CyberChef：`Derive PBKDF2 key`（passphrase=AESKey，Key size=384 bits，iterations=1000，SHA1，salt=常量字符串的 UTF-16LE 十六进制）→ 输出 48 字节；`From Base64`（Host）→ `AES Decrypt`（CBC，Key=第 16–47 字节，IV=前 16 字节，Input Raw，Output Hex）→ `Find/Replace` 去掉 `00` → 得到 C&C URL。
5. 或用 Python 复算（见 PoC），打印明文并去掉尾部 NUL。
6. 将 C&C 基址、Victim ID 前缀、Splitter、持久化配置等整理为 IOC/配置报告，交给流量检测与主机排查。

## PoC

```python
import base64, hashlib
from Crypto.Cipher import AES

HOST_B64 = "MYn+RlRFKfSH5VfgtxZzDLyFoZyVheu9N9V8KK04NE2S3Fi8Q9dN399J5d+/OYaQAQOmxWp2osMb7wGRTHA=="
AES_KEY  = "aGIZbml1aHVeWmRKXhTIQOUHldVXiM0bhGMhJUVMRr1cxZEIVDdadIfEme1lSRGrvC64"
SALT_STR = "<getAlgorithm 中 Encoding.Unicode.GetBytes 的常量字符串>"

salt = SALT_STR.encode("utf-16-le")                  # .NET Encoding.Unicode
dk   = hashlib.pbkdf2_hmac("sha1", AES_KEY.encode(), salt, 1000, 16 + 32)
iv, key = dk[:16], dk[16:48]                        # IV 16 + Key 32
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(HOST_B64))
print(pt.decode("utf-16-le").rstrip("\x00"))        # 例：http://192.168.65.129/blacknet
```

CyberChef 等价流程：

```text
Derive PBKDF2 key (passphrase=AESKey, key size=384 bits, iterations=1000,
  hashing=SHA1, salt=HEX(UTF-16LE(salt常量)))
From Base64 (Host)
AES Decrypt (key=dk[16:48], iv=dk[0:16], mode=CBC, input=Raw, output=Hex)
Find / Replace (regex 00 -> 空)
```

原文实测输出：

```text
http://192.168.65.129/blacknet
```

## 变体与关联

- `AESStatus=false`：Host 可能直接为明文 URL，或使用其它简单编码；先检查该字段再决定是否解密。
- 参数变体：salt 常量、迭代次数、KeySize（128/192/256）、哈希算法可能被 builder 或改版修改；务必以样本中 `getAlgorithm` 为准。
- 输出变体：部分版本用 UTF-8 而非 Unicode 解码；若明文乱码，尝试两种编码。
- 关联：解密出的 C&C 基址用于 BlackNET HTTP(S) 心跳通信（`check_panel/connection/getCommand/receive`），可结合流量检测卡做全网狩猎；同理可提取 `ID`/`Y` 等字段用于解码上线载荷。
- 边界：本卡针对 BlackNET 开源框架的默认实现；强混淆/自定义加密的变种需按实际代码重新分析。

## 检测与防御

- 检测（样本侧）：YARA/字符串扫描 `MainController`、`AESKey`、`AESStatus`、`Rfc2898DeriveBytes`、`HacKed_`、`|BN|`、`check_panel.php` 等特征；dnSpy 分析时优先看 `MainController` 构造函数。
- 检测（主机侧）：排查 `Client.exe`/`watcher.exe`、文件描述 `Windows Update Assistant`、`%TEMP%` 下 `xmrig.exe`、`Passwords.txt`、`CookiesCh.sqlite` 等 BlackNET 产物。
- 防御：封禁解出的 C&C 域名/IP 与 `/blacknet/` 路径；对 .NET 远控常见持久化（启动项、计划任务、Watchdog）做基线检查；对可疑样本做离线配置提取，避免直接运行。
- 响应：用解出的 Host/ID/Splitter 解码流量中的上线与心跳数据，确定受控主机与攻击者基础设施；隔离主机并重置凭据。
