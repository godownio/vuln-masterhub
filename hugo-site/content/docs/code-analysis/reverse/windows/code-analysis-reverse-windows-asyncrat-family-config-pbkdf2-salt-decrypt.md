---
id: code-analysis-reverse-windows-asyncrat-family-config-pbkdf2-salt-decrypt
title: AsyncRAT 系 RAT 配置离线解密：PBKDF2 派生 AES/HMAC 密钥 + 家族 salt 差异（VenomRAT/DcRAT/在野变体）
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: asyncrat-family-config-pbkdf2-salt-decrypt
tags:
- dotnet
- rat
- malware-analysis
- config-extraction
- pbkdf2
- aes-cbc
- hmac-sha256
- venomrat
- dcrat
- asyncrat
- dnspy
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V506
  verified_at: '2026-11-11T04:39:27+08:00'
  notes: 已对照原文 content.md 与全部 36 张截图逐张核对：VenomRAT/DcRAT Builder 配置(192.168.153.130:4449/8848、VenomByVenom/DcRatByqwqdanchun salt 与内容对应)、dnSpy Settings 字段、在野 DcRAT G18 解密函数(KeySize=256、CBC/PKCS7、HMAC(32)||IV(16)、salt=array[0]+string_0)、在野 VenomRAT 内存释放与配置均与卡片一致。核对中修正三处：1) PoC 的 hashlib.pbkdf2_hmac 未指定 dklen，默认仅 20B(SHA1)，mac_key 只剩 4B 会导致 HMAC 校验必败，已改 dklen=80 并注明 KeySize=256 样本用 dklen=96/d[:32]/d[32:96]；2) 原文仅称在野 VenomRAT AES key 16B，而在野 DcRAT 截图 KeySize=256(32B)，故标题/结论/原理从 AES-256 统一改为 AES-CBC 并按样本区分 16/32B；3) Quasar 1.4.1 关联描述更正(其密文布局同为 HMAC32||IV16||密文，差异在 KDF 输入与固定 32B key)。dedup 与库内 Quasar 1.4.1、EagleMonitorRAT、Xeno-RAT 等卡均非同链。未运行样本或 PoC。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-asyncrat-family-config-pbkdf2-salt-decrypt/
draft: false
kb_aliases:
- VenomRAT 配置解密
- DcRAT 配置解密
- AsyncRAT 配置解密
- PBKDF2 salt 家族识别
- VenomByVenom
- DcRatByqwqdanchun
- Settings 类配置提取
---

## 一句话结论

VenomRAT、DcRAT 及二者的在野变体沿用 AsyncRAT 的配置加密框架：客户端用配置中的 Key 与一个 salt 做 PBKDF2，派生 AES key 和 HMAC-SHA256 key（原文在野 VenomRAT 为 16 字节 AES key + 64 字节 HMAC key；在野 DcRAT 的解密函数设置 `KeySize=256`，即 32 字节 AES key）；加密配置的布局为 `HMAC(32B) || IV(16B) || AES-CBC/PKCS7 密文`。不同家族/样本的差异主要在 salt 常量或 salt 来源（VenomRAT 为 `VenomByVenom`、DcRAT 为 `DcRatByqwqdanchun`、在野 DcRAT 由函数参数传入、在野 VenomRAT 用固定 hex salt），在 dnSpy 中定位 Settings 类和解密函数、按样本参数复算即可离线解出 C2、端口、互斥体、证书等配置。

## 原理

- **为什么配置可离线解密**：RAT 客户端要在没有外部输入的情况下自行连回 C2，因此 C2 地址、端口、互斥体、证书等配置必须随样本携带且客户端能解密；解密所需的 Key、salt、迭代次数与算法全部硬编码在 .NET 程序集里，分析者拿到样本即可复现同一过程，不需要运行 RAT。
- **通用解密流程**（AsyncRAT 系）：`Rfc2898DeriveBytes(key, salt, iterations)` 按样本 `GetBytes(16)` 或 `GetBytes(32)` 得到 AES key、再 `GetBytes(64)` 得到 HMAC key（原文在野 VenomRAT 为 16 字节 AES key + 64 字节 HMAC key；在野 DcRAT 解密函数设置 `KeySize=256`，即 32 字节 AES key）；密文前 32 字节是 HMAC-SHA256（覆盖其后全部字节），随后 16 字节为 IV，剩余为 AES-CBC/PKCS7 密文。原文在野 DcRAT 样本的解密函数即为此形态：`AesCryptoServiceProvider`（KeySize=256、BlockSize=128、CBC、PKCS7、Key=this.W0），`HMACSHA256(this.byte_0)` 对 `memoryStream[32:]` 求哈希并与前 32 字节比较，读取 16 字节 IV 后流式解密。
- **家族差异只在 salt / 密钥输入**：
  - VenomRAT 项目：PBKDF2 salt 字符串为 `VenomByVenom`。
  - DcRAT 项目：PBKDF2 salt 字符串为 `DcRatByqwqdanchun`。
  - 在野 DcRAT：salt 不是字符串常量，而是作为函数参数在调用点传入（原文示例由 `array[0] + string_0` 拼出），必须看解密函数的调用处而不是构造函数。
  - 在野 VenomRAT：配置信息中的 Key 作为 PBKDF2 输入，派生 16 字节 AES key 与 64 字节 HMAC key，salt 的十六进制值为 `BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941`。
- **定位特征**：dnSpy 中搜索 `Rfc2898DeriveBytes`、`HMACSHA256`、`AesCryptoServiceProvider`、`CryptoStream`，或直接找 `Settings` 类中大量 `public static string string_N = "<Base64>"` 形态的字段；解密函数通常是 `byte[] xxx(byte[])` 且包含“前 32 字节 HMAC 校验 + 16 字节 IV”的特征。
- **解出的配置字段**：Hosts/Ports、Version、Install/Install Folder、Mutex、Certificate、Server_signature/Paste_bin、BS_OD、Group、Anti_Process/Anti 等；这些字段是 C2 阻断、样本同源聚类与家族识别的高价值 IOC。

## 触发条件

- 样本为 .NET PE，可被 de4dot/dnSpy 反编译（字符串与类名可能混淆，但 PBKDF2/AES/HMAC 调用形态仍在）。
- 能定位 Settings 类中的加密配置字段与对应解密函数。
- 能取得 PBKDF2 的输入 Key、salt 与迭代次数：常量、静态字段、构造函数或解密函数调用点。
- 分析机可运行 Python + pycryptodome（或 CyberChef）复算。

## 利用步骤

1. 对样本做 de4dot 去混淆，dnSpy 打开，定位 `Settings` 类与配置字段（`string_0`、`string_1` 等 Base64 串）。
2. 搜索 `Rfc2898DeriveBytes` / `HMACSHA256` / `AesCryptoServiceProvider`，找到 `byte[] decrypt(byte[])` 形态的解密函数，确认密文布局为 `HMAC(32)||IV(16)||密文`。
3. 确定 Key 与 salt：先看 `Settings`/解密函数里的静态常量；VenomRAT 试 `VenomByVenom`，DcRAT 试 `DcRatByqwqdanchun`；在野 DcRAT 回到调用点看 salt 参数如何拼出；在野 VenomRAT 看 Key 字段与 hex salt。
4. 按样本代码确认 PBKDF2 迭代次数（原文未给出统一值，需以样本为准）。
5. 用 Python 复算：PBKDF2 → AES key（16B 或 32B，以样本 `KeySize` 为准）+ 64B HMAC key；校验 HMAC；取 IV；AES-CBC 解密并去 PKCS7 填充。
6. 对每个 Base64/密文字段重复解密，记录 Hosts/Ports、Mutex、Certificate、Server_signature、Group 等字段。
7. 解密失败时，优先比对解密函数差异（salt 来源、AES key 长度是 16 还是 32、HMAC 覆盖范围、迭代次数），而不是换工具。

## PoC

```python
import hashlib, hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key_seed   = b"<Settings 中的 Key 或 PBKDF2 输入口令>"
salt       = b"<VenomByVenom / DcRatByqwqdanchun / 样本传入的 salt / hex salt>"
iterations = 50000  # 示例值，实际以样本 Rfc2898DeriveBytes 调用为准
blob       = bytes.fromhex("<HMAC32 || IV16 || 密文 的十六进制>")

# dklen 必须显式给出：默认只返回 SHA1 摘要长度（20B），mac_key 会不足
# 在野 VenomRAT：AES 16B + HMAC 64B → dklen=80
# 若样本设置 KeySize=256（如在野 DcRAT）：dklen=96，改为 d[:32]、d[32:96]
d = hashlib.pbkdf2_hmac("sha1", key_seed, salt, iterations, dklen=80)
aes_key, mac_key = d[:16], d[16:80]

assert hmac.compare_digest(
    hmac.new(mac_key, blob[32:], hashlib.sha256).digest(), blob[:32]
), "HMAC 不匹配：salt/Key/迭代次数或密文布局不对"

iv, ct = blob[32:48], blob[48:]
pt = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(pt.decode("utf-8", errors="replace"))
```

```text
# 解密后常见字段（原文示例）：
# Por_ts / Hosts / Ver_sion / Install / MTX(Mutex) / Certifi_cate
# Server_signa ture / Paste_bin / BS_OD / Group / Anti_Process / Anti
```

## 变体与关联

- 变体：同一框架的不同二次开发可能改 salt、迭代次数、AES key 长度（16/32）或把配置放进资源/运行时下发；按 `Rfc2898DeriveBytes` 与 HMAC 校验特征重新定位。
- 变体：Quasar RAT 1.4.1 也用 PBKDF2+AES-256+HMAC（密文布局同为 `HMAC32||IV16||密文`），但 KDF 输入（masterKey 与内置 salt）、迭代次数固定 50000、AES key 固定 32 字节，与本族按样本变化的 salt/`KeySize` 不同，不能直接套用本卡脚本。
- 关联：[[code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt]]（Quasar 家族配置解密）、[[code-analysis-reverse-windows-asyncrat-string-decrypt-mutex-tls-c2]]（AsyncRAT 变体用调试断点取明文的另一种路线）、[[code-analysis-reverse-windows-xrat-config-md5-aes-cbc-decrypt]]（xRAT/早期 Quasar 的 MD5+AES 配置解密）。
- 边界：强混淆导致 Key/salt 运行时计算、配置由 C2 下发、解密函数被魔改（HMAC 覆盖范围/填充方式变化）时，静态复算失败，需要动态调试取明文。

## 检测与防御

- 检测：.NET 样本中出现 `VenomByVenom`、`DcRatByqwqdanchun`、`Rfc2898DeriveBytes` + `HMACSHA256` + `AesCryptoServiceProvider` 的组合；Settings 类中成组的高熵 Base64 字符串；解密出的 C2 域名/IP、`VNM_MUTEX_*`、`DCR_MUTEX_*` 等互斥体前缀。
- 防御/响应：用解出的 Hosts/Ports、Certificate、Server_signature 做网络阻断与同源聚类；终端对 VenomRAT/DcRAT 常见互斥体、安装名与进程行为告警；对 .NET 进程的异常反射加载与网络连接做监控。
- 分析侧：把家族 salt 与配置字段作为样本家族判定特征，避免只凭文件名/图标归因。
