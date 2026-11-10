---
id: defense-forensics-xeno-rat-client-config-encryption-key-sha256
title: Xeno-RAT 配置提取与通信密钥推导：dnSpy 定位 C# 静态字段，EncryptionKey=SHA256(密码)，服务端 Config.json 明文对照
type: scenario
domain: defense
path: defense/forensics
technique: xeno-rat-config-extraction-sha256-key-derivation
aliases:
- Xeno-RAT 配置提取
- Xeno-RAT EncryptionKey
- SHA256 密码通信密钥
- xeno_rat_client Program 类
- Xeno-RAT Config.json
tags:
- forensics
- traffic-analysis
- c2
- rat
- dotnet
- config-extraction
- sha256
- dnspy
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V411
  verified_at: '2026-11-09T14:34:51+08:00'
  notes: 已对照原文与截图核对：dnSpy 中 xeno_rat_client.Program 的 ServerIp/ServerPort/EncryptionKey/delay/mutex_string/Install_path/startup_name 字段（图05/06/09）、Builder 的 SetEncryptionkey(CalculateSha256Bytes(textBox14)) 调用（图15）、SHA256("1234")=03ac6742…（图07）与样本 EncryptionKey 首字节 3,172,103,66,22,243,225,92 一致、Config.json 明文字段（图08）均属实。未验证点：PoC 为字段摘录，未实际用腾讯/火绒样本复现；v1.8.7 为分析对象而非受影响版本，故不设 affected_versions。
---

## 一句话结论

Xeno-RAT（C# 开源远控，原文分析 v1.8.7）的客户端把服务端 IP/端口、互斥体、延时、安装项等配置以明文静态字段写在 `xeno_rat_client.Program` 类中，唯一“加密”的通信密钥 `EncryptionKey` 只是配置密码的 SHA256（32 字节）；用 dnSpy 读取这些字段即可得到 C2 地址与 AES 密钥，服务端同目录的 `Config.json` 还以明文保存密码，可直接交叉验证。

## 原理

- **构建方式**：Xeno-RAT 控制端目录下有 `stub\xeno rat client.exe` 模板，Builder 用 dnlib `ModuleDefMD.Load` 载入模板，再逐项改写 `Program` 类的静态字段后另存为新木马（同时改版本资源）。因此默认 stub 中字段是占位值，生成样本中则是对应攻击者的真实配置。
- **关键静态字段**（`xeno_rat_client.Program`）：
  - `ServerIp`、`ServerPort`：C2 地址（stub 默认 `localhost`/1234，生成样本示例 `127.0.0.1`/4444）；
  - `EncryptionKey byte[32]`：通信 AES 密钥（stub 默认 0x00-0x1F 递增占位）；
  - `delay`（心跳间隔，如 5000）、`mutex_string`（互斥体名，如 `Xeno_rat_nd8912d`）、`Install_path`、`startup_name`。
- **密钥推导**：Builder 的 `SetEncryptionkey(moduleDefMD, Utils.CalculateSha256Bytes(textBox14.Text))` 表明 `EncryptionKey = SHA256(Password)`。验证：密码 `1234` 的 SHA256 为 `03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4`，与生成样本中 `EncryptionKey` 的 32 个字节完全一致。因此拿到样本即可用 `EncryptionKey` 直接解流量，无需知道原始密码；反过来密码弱时也可字典/Hashcat 验证。
- **服务端侧**：控制端当前目录 `Config.json` 明文保存 Builder/Listener 配置：`textBox15`（互斥体）、`textBox13`（端口）、`textBox14`（密码）、`textBox12`（IP）、`textBox2`（延时）、`string_key`（密码）、`ports` 数组等。取证时优先读它，不必逆向客户端。
- **为什么这是可复用手法**：.NET RAT 常把配置放在静态字段/常量并只对通信密钥做简单 KDF（此处就是一次 SHA256，无盐无迭代），静态分析成本极低；密钥与配置同处一体，取得样本等于取得解密能力。

## 触发条件

- 取得 Xeno-RAT 客户端样本（.NET，可用 dnSpy/ILSpy 打开；未加壳或已脱壳）。
- 或取得控制端目录（含 `Config.json`、`stub\`、`plugins\`）的磁盘/镜像。
- 需要进一步解密其流量（见关联卡）时，密钥即来自此处。

## 利用步骤

1. 用 dnSpy/ILSpy 打开客户端样本，展开命名空间 `xeno_rat_client`，定位 `Program` 类。
2. 读取静态字段：`ServerIp`、`ServerPort`、`mutex_string`、`delay`、`Install_path`、`startup_name`，得到 C2 与驻留配置。
3. 读取 `EncryptionKey` 的 32 字节数组；若还能拿到明文密码，用 SHA256 验证二者一致，确认密钥来源与版本（避免不同版本 KDF 变化）。
4. 若只有样本没有密码：直接使用 `EncryptionKey` 作为 AES-256 密钥解密流量（无需还原密码）。
5. 若拿到控制端主机：读取同目录 `Config.json`，以 `textBox14`/`string_key`/`ports`/`textBox15` 等字段交叉核对客户端配置并还原全部监听器。
6. 结合 `plugins\` 目录与插件 MD5（见关联卡）评估该样本具备的远控能力。

## PoC

```text
# dnSpy 中 xeno_rat_client.Program 的字段（生成样本示例）
ServerIp       = "127.0.0.1"
ServerPort     = 4444
EncryptionKey  = { 3, 172, 103, 66, 22, 243, 225, 92, ... }   # 32 字节
delay          = 5000
mutex_string   = "Xeno_rat_nd8912d"

# 密钥来源验证：SHA256("1234")
03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
# 与 EncryptionKey 字节逐一对应
```

```json
// 控制端 Config.json（明文字段示例）
{ "textBox15": "Xeno_rat_nd8912d", "textBox13": "4444", "textBox14": "1234",
  "textBox12": "127.0.0.1", "string_key": "1234", "ports": [4444] }
```

## 变体与关联

- 变体：同族或改版样本可能更换 KDF（加盐/多次迭代）或把配置改存资源段/Base64 常量，需按 Builder 的 Set 方法重新确认；若配置被二次加密，先在内存或 Builder 中定位明文。
- 关联：与 [[defense-forensics-eaglemonitorrat-traffic-protocol-decrypt]] 的配置 key 提取、AdaptixC2 配置块提取同属“.NET/C2 样本配置驱动流量解密”；与 [[code-analysis-reverse-windows-xworm-v5-aes-config-plugin-rat-capabilities]] 的静态配置/插件能力分析同类。
- 反向利用：拿到流量但无样本时，可先用弱密码字典对每帧尝试 `AES(SHA256(guess))` 解密，用解出明文的结构特征（如 0x00/0x01 标志、可打印主机信息、MZ 头）判定正确 key。

## 检测与防御

- 检测：样本中出现 `xeno_rat_client`、`Xeno_rat_` 互斥体前缀、`EncryptionKey` 32 字节静态数组；控制端主机存在 `Config.json` + `stub\xeno rat client.exe` + `plugins\*.dll` 组合；外联端口与配置一致的长连接心跳。
- 防御/取证：查封样本后先提取 key 再解流量；对 SHA256(常见弱密码) 作为密钥的样本建立字典；监控 `mscorlib` 动态加载（Assembly.Load）与 `RtlDecompressBuffer` 导入；对已知 mutex/hash/插件 MD5 建 IOC。
