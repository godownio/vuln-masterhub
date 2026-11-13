---
id: code-analysis-reverse-windows-xrat-config-md5-aes-cbc-decrypt
title: xRAT（早期 Quasar）配置解密：MD5(Key) 作 AES-128 key、前 16 字节为 IV 的 AES-CBC/Base64
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: xrat-config-md5-aes-cbc-decrypt
tags:
- xrat
- quasar
- dotnet
- malware-analysis
- config-extraction
- aes-cbc
- md5
- base64
- dnspy
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V506
  verified_at: '2026-11-11T04:39:48+08:00'
  notes: 已对照原文 content.md 与全部 36 张截图核对：xRAT Builder(IP 192.168.153.130、Port 4782、Mutex euwrOpIHw3RXkWkMAnFM8g1VaEkg61vA)、GClass9 Settings 字段、解密结果(Version 2.0.0.0 RELEASE4.1、Hosts 192.168.153.130、Password 1234、Install Name .exe、Mutex 同 Builder)与卡片一致；原文 Go 解密实现 CalculateMD5(Key)→hex.DecodeString→16B AES-128 key、input[:16] 作 IV、AES-CBC+PKCS5 去填充与卡片/ PoC 一致。dedup：与 Quasar 1.4.1 PBKDF2+AES-256+HMAC 卡、本批 AsyncRAT 系卡均非同链，与 xRAT 流量卡为配置提取/流量取证两个互补场景。affected_versions 不适用（恶意工具/样本），未设置。未运行样本或 PoC。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-xrat-config-md5-aes-cbc-decrypt/
draft: false
kb_aliases:
- xRAT 配置解密
- Quasar 早期版本配置
- MD5 key AES 配置
- Aes_z_Decrypt
- xRAT Settings 提取
- 前 16 字节 IV
---

## 一句话结论

xRAT（QuasarRAT 的早期版本）客户端把配置字段以 Base64 保存：`AES key = MD5(Key)`（16 字节，即 AES-128），Base64 解码后的前 16 字节为 IV，其余为 AES-CBC 密文；在 dnSpy 的 `Settings`/`GClass9` 类中取出 `string_8` 这类 Key 字符串和待解密的 Base64 字段，用 MD5+AES-CBC 复算即可解出 Hosts、Port、Password、Mutex、Install Name 等配置。

## 原理

- xRAT 是 Quasar RAT 的早期版本（xRAT v2.0.0.0 RELEASE1 后演进为 Quasar v1.0.0.0），但它的配置加密与后期 Quasar 1.4.1 的 PBKDF2+AES-256+HMAC 不同：没有 PBKDF2、没有 HMAC 校验、没有 32 字节 HMAC 前缀。
- **密钥派生**：直接对 Key 字符串求 MD5，得到 16 字节摘要，作为 AES key（AES-128）。原文解密脚本 `CalculateMD5(key)` 返回十六进制字符串后 `hex.DecodeString` 还原为 16 字节。
- **密文布局**：配置字段先 Base64 编码；Base64 解码后前 16 字节即 AES-CBC 的 IV，后续字节为密文。AES-CBC/PKCS5(7) 解密后得到明文字段。
- **为什么可以离线解密**：Key 字符串（原文为 `public static string string_8`，builder 中以连接密码作为该值）与密文都在客户端程序集里，客户端启动时需要自行解密配置，因此分析者可复现；解密不需要连接 C2。
- **与后期 Quasar 的差异**：Quasar 1.4.1 用 `Rfc2898DeriveBytes(masterKey, salt, 50000)` 派生 32 字节 AES key 与 64 字节 HMAC key，密文带 HMAC 前缀；把 Quasar 1.4.1 的解密脚本直接套到 xRAT 上会失败，必须换成 MD5+AES-128+IV 前缀的写法。

## 触发条件

- 样本为 .NET PE，可被 dnSpy/de4dot 反编译。
- 能定位 `Settings`/`GClass9` 中的 Base64 配置字段与作为 Key 的静态字符串（原文为 `string_8`）。
- 能确认 Key 来源：在脚本/反编译代码中沿 `string_8` 的赋值或调用点确认其明文值（通常与 Builder 中设置的连接 Password 一致）。
- 分析机可运行 Python + pycryptodome 或 Go 复算。

## 利用步骤

1. de4dot 去混淆后用 dnSpy 打开样本，定位客户端主程序集与 `Settings`/`GClass9` 类。
2. 记录形如 `public static string string_N = "<Base64>"` 的配置字段，以及作为 Key 的字段（原文脚本取 `string_8`）。
3. 确认 Key 明文：查看 `string_8` 的赋值来源，或从 Builder/配置初始化代码中还原（原文样本解密出的配置中 Password 字段也会暴露该值）。
4. 对每个 Base64 字段：Base64 解码 → 前 16 字节 IV → 其余密文 → `AES-128-CBC`（key=MD5(Key)）解密并去 PKCS5/7 填充。
5. 输出明文字段：Version、Hosts、Password、Install Name、Mutex 等；用其做 C2 阻断与样本同源分析。
6. 若解密失败，检查是否把 Key 误当成 Base64 字段本身、是否漏了 Base64 解码、或样本是后期 Quasar（应改用 PBKDF2 方案）。

## PoC

```python
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key_str = b"<Settings.string_8 的明文 Key/Password>"
b64_cfg = "<Settings 中某个 Base64 配置字段>"

data = base64.b64decode(b64_cfg)
iv, ct = data[:16], data[16:]
aes_key = hashlib.md5(key_str).digest()   # 16 字节，AES-128
pt = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(pt.decode("utf-8", errors="replace"))
```

```text
# 原文解密结果示例（字段形态）：
# Version: 2.0.0.0 RELEASE4.1
# Hosts: 192.168.153.130
# Password: 1234
# Install Name: .exe
# Mutex: euwrOpIHw3RXkWkMAnFM8g1VaEkg61vA
```

## 变体与关联

- 变体：Key 字段名/类名会随混淆变化（`string_8`、`GClass9` 等仅为原文样本），按“MD5 + AES-CBC + 前 16 字节 IV”的代码形态定位更稳。
- 变体：同一系列后期版本改用 PBKDF2+AES-256+HMAC（Quasar 1.4.1），解密脚本不通用。
- 关联：[[code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt]]（后期 Quasar 的 PBKDF2 配置解密）、[[defense-forensics-xrat-traffic-aes-cbc-quicklz-decrypt]]（同一 Key 派生方式用于通信数据解密）、[[code-analysis-reverse-windows-asyncrat-family-config-pbkdf2-salt-decrypt]]（AsyncRAT 系配置解密）。
- 边界：Key 被运行时计算/从 C2 下发、配置字段被二次加密、样本被强混淆到无法定位 Settings 时，需要动态调试取 Key 与明文。

## 检测与防御

- 检测：.NET 样本中出现 `MD5` → 16 字节 key + `AesCryptoServiceProvider`（CBC）+ `Convert.FromBase64String` 的组合；Settings 类中成组的 Base64 字段；解出的 xRAT 默认互斥体、端口（原文示例 4782）与外联 IP。
- 防御/响应：用解出的 Hosts/Port、Mutex、Password 做阻断与家族聚类；终端对 xRAT/Quasar 常见行为（自启动、键盘记录、远程桌面）告警；限制 .NET 程序从临时目录运行。
- 分析侧：xRAT 与 Quasar 同源但配置算法不同，先看是否有 HMAC 前缀与 PBKDF2 调用，再决定用哪套解密器。
