---
id: code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt
title: Quasar RAT 1.4.1 配置解密：masterKey 经 Rfc2898DeriveBytes(salt,50000) 派生 AES-256 key 与 64 字节 HMAC key，校验后解出 C2/互斥体/证书
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: quasar-rat-aes256-hmac-settings-decrypt
tags:
- quasar-rat
- dotnet
- malware-analysis
- config-extraction
- aes-256-cbc
- hmac-sha256
- pbkdf2
- dnspy
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V281
  verified_at: '2026-11-08T05:26:49+08:00'
  notes: 已对照原文与图15-17核对：Class28(string masterKey) 用 Rfc2898DeriveBytes(masterKey, Class28.byte_2, 50000).GetBytes(32)/(64)；method_3 使用 AES-256-CBC/PKCS7、HMACSHA256(byte_1) 校验前 32 字节、读 16 字节 IV 后解密，卡内密文布局 HMAC(32)||IV(16)||CT 与代码一致；图16 的静态串 string_7 是否即 masterKey 卡内已注明需按调用点确认。解密配置字段与原文一致。未执行解密。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt/
draft: false
kb_aliases:
- Quasar RAT 配置解密
- Quasar Aes256
- AesCryptoServiceProvider 配置提取
- HMACSHA256 配置校验
- Rfc2898DeriveBytes 50000
- Quasar Settings 解密
---

## 一句话结论

Quasar RAT 1.4.1 的客户端配置由 `Aes256` 类加密：构造时用 `Rfc2898DeriveBytes(masterKey, 内置 salt, 50000)` 派生 32 字节 AES key 和 64 字节 HMAC key；密文格式为 `HMAC-SHA256(IV+密文) 32B || IV 16B || AES-256-CBC/PKCS7 密文`。拿到样本后用 dnSpy 定位 `Aes256`/`Class28` 与 `method_3`，取出 masterKey 与 salt 常量，即可离线还原 Hosts、Mutex、Install Name、Startup Name、Client Tag、ServerSignature、Certificate 等配置。

## 原理

- Quasar 是开源 .NET RAT，builder 把服务器地址、安装名、互斥体、证书等设置序列化后加密嵌入客户端；客户端启动时用同一 `Aes256` 类解密。算法在开源代码里公开，样本通常只做类名/字段名混淆（本例反编译为 `Class28`、`method_3`、`byte_0`/`byte_1`/`byte_2`），逻辑不变。
- **密钥派生**：`Class28(string masterKey)` 中 `new Rfc2898DeriveBytes(masterKey, Class28.byte_2, 50000)`；`GetBytes(32)` 得到 `byte_0`（AES-256 key），`GetBytes(64)` 得到 `byte_1`（HMAC-SHA256 key）。`.NET` 的 `Rfc2898DeriveBytes` 默认 HMAC-SHA1、50000 次迭代；`byte_2` 是静态 salt。
- **加密/解密格式**：解密函数（本例 `method_3(byte[] input)`）先 `HMACSHA256(byte_1).ComputeHash(input, 32, input.Length-32)` 对“跳过前 32 字节的剩余部分”求 HMAC，与 `input[0..32)` 比较，不等则抛 `Invalid message authentication code (MAC)`；随后读取 `input[32..48)` 作为 16 字节 IV，把剩余字节交给 `AesCryptoServiceProvider`（KeySize=256、BlockSize=128、CBC、PKCS7、Key=`byte_0`）解密，读出的明文即配置。
- **为什么可离线还原**：masterKey、salt、迭代次数、IV/Key 切分规则和 HMAC 覆盖范围全部硬编码在样本里；不需要运行 RAT 或连接 C2。
- **定位技巧**：dnSpy 搜索 `Rfc2898DeriveBytes`、`HMACSHA256`、`AesCryptoServiceProvider`、常量 `50000`，或按“32 字节头 + 16 字节 IV + 密文”的数据形态找静态 blob；再沿 `Class28` 构造函数的调用点确认 masterKey 来源（本例样本中存在一个 40 位十六进制静态字符串 `string_7`，需按实际调用点确认是否即 masterKey）。

## 触发条件

- 样本为 .NET PE，未被强混淆到 dnSpy 无法反编译；`Aes256` 类与设置 blob 仍在。
- 能定位 `Rfc2898DeriveBytes` 的 masterKey 参数与 salt 常量（可从构造函数/调用者/静态字段读取）。
- 能提取加密的 settings 字节串（静态字段、资源或初始化代码中的 byte 数组）。
- 分析环境可运行 Python + pycryptodome（或 CyberChef）复算 PBKDF2/HMAC/AES。

## 利用步骤

1. 用 `de4dot` 去混淆（如有），dnSpy 打开样本，搜索 `Rfc2898DeriveBytes` 或常量 `50000`，定位 `Aes256` 等价类（本例 `Class28`）。
2. 读取构造函数：确认 `GetBytes(32)` → AES key、`GetBytes(64)` → HMAC key、salt 静态数组、迭代次数 50000。
3. 沿 `Class28` 的调用点/静态字段找到 masterKey；同时定位加密 settings 的 byte 数组/资源。
4. 用 Python 复算：`hashlib.pbkdf2_hmac('sha1', masterKey, salt, 50000)` 取前 32 字节为 AES key、接下来 64 字节为 HMAC key；校验 `HMAC-SHA256(blob[32:]) == blob[:32]`。
5. 取 `blob[32:48]` 为 IV，`blob[48:]` 为密文，AES-256-CBC/PKCS7 解密，按 UTF-8/Unicode 读取配置。
6. 记录 Hosts、Version、Install Name、Mutex、Startup Name、Client Tag、ServerSignature、Certificate 等字段，用于 C2 阻断、样本同源分析与证书指纹。

## PoC

```python
import hashlib, hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

master_key = b"<从样本 Class28 调用点取到的 masterKey>"
salt       = b"<Class28.byte_2 静态 salt>"
blob       = bytes.fromhex("<加密 settings>")

d = hashlib.pbkdf2_hmac("sha1", master_key, salt, 50000)
aes_key, mac_key = d[:32], d[32:96]

assert hmac.compare_digest(hmac.new(mac_key, blob[32:], hashlib.sha256).digest(), blob[:32])
iv, ct = blob[32:48], blob[48:]
pt = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(pt.decode("utf-8", errors="replace"))
```

```text
# 原文样本解密结果（关键字段）
Version: 1.4.1
Hosts: namz.read-books.org:1337
Install Subdirectory: SubDir
Install Name: WindowsUpdate.exe
Mutex: 06f1c124-2f86-4205-a4b8-825abb0ee5d0
Startup Name: DqdCQdqc
Client Tag: TrumpUS
Log Directory Name: Logs
ServerSignature: <base64>
Certificate: <base64 DER>
```

## 变体与关联

- 变体：不同 Quasar 版本/二次开发可能改 salt、迭代次数、类名或把配置放入资源；按 `Rfc2898DeriveBytes` 与 HMAC 校验特征重新定位即可。
- 变体：AsyncRAT 等 .NET RAT 也用 AES/HMAC 配置，但 key 派生方式、密文布局不同；需按样本实际代码复算。
- 关联：BlackNET 的 PBKDF2+AES 配置解密见 `[[code-analysis-reverse-windows-blacknet-config-aes-pbkdf2-extract]]`；通用 AES 配置静态提取方法论见 `[[code-analysis-reverse-windows-aes-config-capa-xref-key-cyberchef]]`；本样本的投递链见 `[[pentest-initial-access-lol-cheat-video-sfx-vbs-quasar-rat]]`。
- 边界：样本被强混淆/加壳导致 masterKey 或 salt 被运行时计算、配置不在样本内而从 C2 拉取时，需动态调试取 key/解密结果。

## 检测与防御

- 检测：.NET 样本中出现 `Rfc2898DeriveBytes(..., 50000)`、`HMACSHA256`、`AesCryptoServiceProvider` 的 32 字节 HMAC 前缀 + 16 字节 IV 结构；Quasar 默认安装名 `WindowsUpdate.exe`、启动项名、互斥体与 1337 端口外联；配置文件/静态字段中出现 base64 证书与 `ServerSignature`。
- 防御：不要在客户端嵌入可离线解密的 C2 配置（至少用服务端下发/硬件绑定）；终端对 Quasar 默认特征、随机安装名、`%appdata%` 自启动做告警；网络侧阻断已知 C2 与非常用端口。
- 分析侧：把解出的证书/ServerSignature 作为同源样本聚类特征，结合 Mutex、Startup Name 做家族与攻击者基础设施关联。
