---
id: defense-forensics-xrat-traffic-aes-cbc-quicklz-decrypt
title: xRAT 通信数据解密：长度前缀帧 + MD5(Password) 派生 AES key + 前 16 字节 IV + QuickLZ 解压
type: scenario
domain: defense
path: defense/forensics
technique: xrat-traffic-aes-cbc-quicklz-decrypt
tags:
- forensics
- traffic-analysis
- c2
- rat
- xrat
- quasar
- dotnet
- aes-cbc
- quicklz
- windows
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V506
  verified_at: '2026-11-11T04:39:50+08:00'
  notes: 已对照原文 content.md 与全部 36 张截图核对：原文抓包显示 xRAT 走裸 TCP(4782)无 TLS；通信解密复用 decrypt_xRAT_str，Password 作 key 经 MD5 得 16B AES-128 key，载荷前 16B 为 IV、其余 AES-CBC，解密后 QuickLZ 解压；原文示例 300000(0x30=48) 与后续 48 字节密文(96 hex)一致，AES 解密后 4F13...0A00 → QuickLZ 020000000A00 均与卡片一致。长度前缀宽度原文写作 300000（按 3 字节小端 0x30=48 解读），卡片已注明按小端长度前缀处理，属合理还原。dedup：与 Xeno-RAT(AES-256+LZNT1)、EagleMonitorRAT(4B 长度+PacketType+Rfc2898 派生)等流量卡帧结构/压缩算法不同，非同链。affected_versions 不适用（恶意工具/样本），未设置。未运行样本或 PoC。
url: /docs/defense/forensics/defense-forensics-xrat-traffic-aes-cbc-quicklz-decrypt/
draft: false
kb_aliases:
- xRAT 流量解密
- xRAT 通信模型
- QuickLZ 解压 RAT 流量
- AES-CBC QuickLZ
- xRAT 明文抓包
- 无 TLS RAT 流量
---

## 一句话结论

xRAT 客户端不使用 TLS，而是直接把 AES-CBC 加密后的数据走 TCP socket：帧先给出载荷长度，载荷前 16 字节为 IV、其余为 AES-CBC 密文，key 由 `MD5(配置中的 Password)` 得到；解密后再用 QuickLZ 解压，才能得到远控指令/回包的明文。抓包后按“长度分帧 → AES 解密 → QuickLZ 解压”三步即可还原通信内容。

## 原理

- **无 TLS 的裸 TCP 通信**：原文抓包显示 xRAT 的客户端与服务端直接建立 TCP 连接，没有 TLS 握手；因此拿到流量后不需要私钥/证书，只要知道应用层加密算法即可解密，这一点与 VenomRAT/DcRAT 的 TLS+gzip 双层模型不同。
- **密钥来源**：xRAT 复用配置解密中的 `decrypt_xRAT_str(key, input)`：`AES key = MD5(key)`（16 字节，AES-128）；通信时把配置中的 Password 作为 key 参数传入。
- **载荷布局**：每个消息先有一个长度字段（原文示例为 `300000`，即 0x30=48，与后续密文长度一致，按小端长度前缀处理），随后是加密载荷；载荷前 16 字节为 IV，后续为 AES-CBC/PKCS5(7) 密文。
- **解密后再解压**：AES 解密得到的数据仍是压缩数据，需要 QuickLZ 解压。原文示例：密文 48 字节 → AES 解密去填充得 `4F130000000600000000000080020000000A00` → QuickLZ 解压得 `020000000A00`。
- **为什么有效**：Length-prefixed 帧解决了 TCP 粘包/半包问题；IV 随包携带避免了固定 IV 的复用问题；整个协商只依赖本地配置中的 Password，因此从样本配置或内存中取出 Password 后即可离线批量解密。
- **局限**：QuickLZ 不同版本/初始化参数可能影响解压；如果样本二次开发改了压缩算法（如换成 LZNT1/gzip）或加了 TLS，需按实际代码调整。

## 触发条件

- 已捕获 xRAT 客户端与 C2 之间的 TCP 流量（pcap/pcapng）。
- 已从样本中解出配置（尤其是 Password）或从内存/调试器中取得该值。
- 能按长度前缀正确切分 TCP 流（Wireshark 的 Follow TCP Stream 或脚本重组）。
- 分析环境有 QuickLZ 解压实现（对应版本的库/脚本）。

## 利用步骤

1. 在 Wireshark 中过滤客户端与服务端 IP:port 的 TCP 流，Follow TCP Stream，按长度前缀切出每条消息的载荷。
2. 对每条载荷：取前 16 字节为 IV，其余为 AES-CBC 密文。
3. 用 `MD5(Password)` 作为 AES-128 key 解密并去 PKCS5/7 填充。
4. 对解密结果做 QuickLZ 解压，得到明文消息（上线信息、心跳、远控指令与回包等）。
5. 批量处理整个会话，按时间线还原攻击者操作；若明文包含文件传输/插件数据，可继续按文件头（如 `MZ`）提取落地载荷。

## PoC

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

password = b"<xRAT 配置中的 Password>"
frame_payload = bytes.fromhex(
    "<去掉长度前缀后的载荷：IV16 || AES-CBC 密文>"
)

iv, ct = frame_payload[:16], frame_payload[16:]
aes_key = hashlib.md5(password).digest()          # 16 字节，AES-128
plain = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), 16)
print("AES 解密后:", plain.hex())

# 再用 QuickLZ 解压 plain（库/脚本按目标版本选择）
# 原文案例：48 字节密文 -> 4F13...0A00 -> QuickLZ -> 020000000A00
```

```text
# 原文示例帧（十六进制）：
# 长度: 300000（0x30 = 48）
# 密文: 8954472455a849b42094be7cba1fc9d4...（共 48 字节）
# AES 解密后: 4F130000000600000000000080020000000A00
# QuickLZ 解压后: 020000000A00
```

## 变体与关联

- 变体：部分二次开发可能把 AES 换成 AES-256、把 QuickLZ 换成 LZNT1/gzip，或在外面再套一层 TLS；按实际代码的 `MD5`/`Rijndael`/压缩调用调整。
- 变体：配置解密与通信解密共用同一 Password，可先从静态配置解出 Password，再批量解流量。
- 关联：[[code-analysis-reverse-windows-xrat-config-md5-aes-cbc-decrypt]]（xRAT 配置解密与 Key 来源）、[[defense-forensics-xeno-rat-aes-cbc-lznt1-traffic-batch-decrypt]]（另一 .NET RAT 的 AES-CBC+LZNT1 流量解密）、[[defense-forensics-quasar-protobuf-tls-payload-decode]]（后期 Quasar 的 TLS 载荷解析）。
- 边界：Password 未知、压缩算法/参数不匹配、流量经过 TLS 或代理重打包、帧结构被修改时，需要结合样本逆向重新定位。

## 检测与防御

- 检测：内网出现无 TLS 的裸 TCP 长连接，载荷呈现“长度前缀 + 高熵数据”特征；同一客户端周期性发送固定长度心跳；样本配置中出现 xRAT/Quasar 特征字符串与 MD5+AES 调用。
- 防御/响应：用解出的 C2 IP/端口与 Password 做阻断与同源聚类；终端对 xRAT/Quasar 的进程、自启动与键盘记录行为告警；网络侧对非常用端口的裸 TCP C2 做基线告警。
- 分析侧：先判断是否有 TLS，再决定走“TLS 私钥/gzip”还是“MD5+AES+QuickLZ”路线，避免套错解密模型。
