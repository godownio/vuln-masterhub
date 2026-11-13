---
id: defense-forensics-asyncrat-servercert-p12-empty-pass-tls-gzip-decrypt
title: AsyncRAT 服务端自带无口令 p12 解 C2 流量：openssl 导出 ServerCertificate.p12 私钥，Wireshark 解 TLS 1.0 RSA_WITH_AES_128_CBC_SHA 后再解 gzip 载荷
type: scenario
domain: defense
path: defense/forensics
technique: asyncrat-servercert-p12-empty-password-tls-gzip-decrypt
aliases:
- AsyncRAT TLS 解密
- ServerCertificate.p12 私钥
- AsyncRAT 流量解密
- TLS_RSA_WITH_AES_128_CBC_SHA 解密
- RSA keys list 解密 C2
- AsyncRAT gzip 载荷
tags:
- forensics
- traffic-analysis
- tls
- asyncrat
- rat
- p12
- wireshark
- gzip
- incident-response
cve: []
severity: medium
confidence: high
affected_versions: AsyncRAT 0.5.8（原文服务端/Builder 版本，ServerCertificate.p12 由该版本生成）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V572
  verified_at: '2026-11-12T10:46:22+08:00'
  notes: 已对照原文（12924，472 行）与 18 张截图逐张核对：Alien Labs/APT-C-56/malpedia 背景（图01-03）、GitHub AsyncRAT-C-Sharp v0.5.8 2023-10-17（图04）、Builder DNS 192.168.153.131 与端口 6606/7707/8808（图05）、Windows 7 受控端上线 v0.5.8（图06）、dnSpy Settings 密文（图07）、CyberChef AES 解出 6606,7707,8808（图08）、Go 脚本输出（图09-11）、Wireshark ServerHello TLS 1.0 0x0301 + TLS_RSA_WITH_AES_128_CBC_SHA 0x002f（图12）、源码 Export(X509ContentType.Pkcs12) 无密码重载（图13）、11111.key 私钥（图14）、RSA keys list 192.168.153.131:8808 http（图15）、TLS 明文 1f8b08 gzip 帧（图16-17）、好压解压得 MessagePack 明文 Packet/ClientInfo/0xB4/0xD9 长度前缀（图18）。修正三处：私钥位数经 openssl 解析实为 RSA 4096（原写 2048）；环境表述改为受控端 Windows 7；PoC gzip 提取改用 zlib.decompressobj 逐帧解压（原 gzip.decompress 遇尾随帧会 BadGzipFile）。dedup：与 schannel-cipher-order-downgrade（不同环境路径）及 asyncrat-traffic-frame-gzip-msgpack-decrypt（下游帧解析）均非同一链；dup-scan 无涉及。affected_versions 保留 AsyncRAT 0.5.8（原文明确版本）。未验证点：未复现流量解密；pcap 未随文提供。
---

## 一句话结论

AsyncRAT 服务端生成的 `ServerCertificate.p12` 默认没有保护口令（源码用无密码重载 `X509Certificate2.Export(X509ContentType.Pkcs12)` 导出），因此取证方拿到服务端目录或镜像后可直接用空密码 `openssl pkcs12 -in ... -nodes` 导出私钥；若握手使用静态 RSA 密钥交换套件（原文为 TLS 1.0 `TLS_RSA_WITH_AES_128_CBC_SHA`），把私钥配进 Wireshark 的 RSA keys list 即可解密整段 C2 会话，TLS 明文中的 `1f 8b 08`（gzip）帧再解压即得通信载荷。

## 原理

- **p12 为何无口令**：AsyncRAT 服务端源码在证书生成处调用 `Settings.ServerCertificate.Export(X509ContentType.Pkcs12)`，该重载不传密码，导出的 PKCS#12 因此是空口令；服务端目录（及备份 `BackupCertificate.zip`）中的 `ServerCertificate.p12` 可被任何拿到文件的人导出证书与私钥。
- **为什么私钥能解流量**：`TLS_RSA_WITH_AES_128_CBC_SHA` 是静态 RSA 密钥交换——客户端生成 pre-master secret 后用服务器证书公钥加密，服务器用私钥解密，双方再由随机数与 pre-master 派生会话密钥。掌握服务器私钥即可离线还原会话密钥并解密全部记录。反之若协商 ECDHE 等前向保密套件，仅私钥不够，需要密钥日志或会话密钥。
- **AsyncRAT 的协商特征**：原文实验环境（受控端为 Windows 7）协商为 TLS 1.0 + `TLS_RSA_WITH_AES_128_CBC_SHA`（0x002F），属于非前向保密套件，这正是可直接用 p12 私钥解密的前提；ServerHello 中的记录层版本与套件要在抓包里确认。
- **TLS 之下的载荷**：解密后的应用层数据不是明文协议，而是以 `1f 8b 08` gzip 魔数开头的压缩帧；提取后按 gzip 解压即得 MessagePack 结构（Packet/ClientInfo/指令等），因此“TLS 解密 + gzip 解压”是完整还原 AsyncRAT 通信的前两层。

## 触发条件

- 已捕获 AsyncRAT C2 的 pcap（原文为 8808 端口），且 ServerHello 显示 `TLS_RSA_WITH_AES_128_CBC_SHA`（或其它静态 RSA 套件）；TLS 1.3/ECDHE 不适用。
- 能取得 AsyncRAT 服务端目录、服务器镜像或其备份中的 `ServerCertificate.p12`（默认空口令）。
- Wireshark 支持对应套件，且分析环境可导入私钥。
- 仅用于授权取证与恶意样本分析。

## 利用步骤

1. 从服务端目录/镜像/备份 `BackupCertificate.zip` 取得 `ServerCertificate.p12`；源码证据显示导出未设密码，直接回车作为导入口令。
2. 导出私钥（`-nodes` 输出未加密私钥，空口令直接回车）：
   ```bash
   openssl pkcs12 -in ServerCertificate.p12 -out certificate.pem -nodes
   ```
   输出中包含 `-----BEGIN PRIVATE KEY-----`（原文为 RSA 4096）与 `-----BEGIN CERTIFICATE-----`（CN=AsyncRAT Server）。
3. Wireshark → 编辑 → 首选项 → Protocols → TLS → RSA keys list，新增服务器 IP、C2 端口（如 8808）、协议与私钥文件（也可再附证书）。
4. 重新打开 pcap，确认 TLS 记录已解密；`Follow TCP Stream` 可见应用层数据以 `1f8b08` 开头。
5. 将单向原始字节导出（Raw），逐个提取 gzip 帧解压（Python `zlib.decompressobj(16+zlib.MAX_WBITS)` 或 CyberChef `From Hex` + `Gunzip`），得到 MessagePack 载荷；后续字段解析参见现有 AsyncRAT 流量帧解密卡。
6. 汇总解密出的 C2、指令与插件载荷作为 IOC 与证据，与主机侧日志交叉验证。

## PoC

```bash
# 空口令导出 AsyncRAT 服务端 p12 的私钥（直接回车）
openssl pkcs12 -in ServerCertificate.p12 -out certificate.pem -nodes
# MAC verified OK；certificate.pem 内含 BEGIN PRIVATE KEY / BEGIN CERTIFICATE
```

```python
# TLS 解密后导出的单向原始流：逐个提取 gzip 帧并解压（按 0x1f8b08 魔数起步）
import zlib
raw = open("stream.bin", "rb").read()
pos = raw.find(b"\x1f\x8b\x08")
while pos != -1:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip 容器，只解当前一帧
    out = d.decompress(raw[pos:])
    print(out[:200])  # MessagePack 明文（Packet/ClientInfo/...）
    consumed = len(raw) - pos - len(d.unused_data)
    pos = raw.find(b"\x1f\x8b\x08", pos + consumed)
```

```text
# Wireshark RSA keys list 示例（原文）：192.168.153.131  8808  http  11111.key
```

## 变体与关联

- 变体：若抓包协商的是 ECDHE 套件，单靠 p12 私钥不可解，需要在可控分析机上把静态 RSA 套件排到 SChannel 顺序最前并重启（见 [[defense-forensics-schannel-cipher-order-downgrade-rsa-tls-decrypt]]），或改用 `SSLKEYLOGFILE`/内存会话密钥。
- 关联：TLS 解出的 gzip/MessagePack 帧格式与批量解析脚本见 [[defense-forensics-asyncrat-traffic-frame-gzip-msgpack-decrypt-script]]；配置侧先解出 C2/证书见 [[code-analysis-reverse-windows-asyncrat-settings-config-pbkdf2-hmac-aes-decrypt]] 与 [[defense-forensics-asyncrat-memory-config-extract]]；默认证书测绘见 [[defense-detection-asyncrat-default-tls-cert-c2-mapping]]。
- 关联：同类“p12 私钥解 TLS”思路另见 RDP 取证 [[defense-forensics-rdp-pfx-tls-decrypt-scancode-replay]]。
- 边界：服务端改口令、改证书、启用 ECDHE/TLS 1.3，或流量含中间盒重协商时，本方法失效或只能部分解密。

## 检测与防御

- 检测：出站 TLS 使用非常用端口且套件为 `TLS_RSA_WITH_*`（非前向保密）可作为可疑 RAT 通信旁证；对 AsyncRAT 默认证书 CN（`AsyncRAT Server`）做 TLS 指纹告警。
- 防御：生产/红队环境禁用静态 RSA 套件、优先 ECDHE/TLS 1.3，使私钥泄露也无法解历史流量；保护服务端 p12 与备份文件，避免随镜像/目录泄露。
- 取证：私钥与解密结果按证据链保存；解出的 C2 域名/IP、插件 DLL（MZ 头）与指令时间线用于影响面评估与阻断。
