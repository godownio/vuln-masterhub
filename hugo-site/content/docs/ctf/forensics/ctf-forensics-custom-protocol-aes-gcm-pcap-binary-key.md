---
id: ctf-forensics-custom-protocol-aes-gcm-pcap-binary-key
title: 自定义协议 ET3RNUMX + AES-256-GCM 流量解密：从 Go 二进制字符串提取 key
type: scenario
domain: ctf
path: ctf/forensics
technique: custom-protocol-aes-gcm-pcap-binary-key
tags:
- forensics
- traffic-analysis
- aes-gcm
- pcap
- go
- base32
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:27+08:00'
  notes: 已对照原文协议解析脚本与 Base32 输出核对；key 与 flag 一致；PoC 未复跑。
url: /docs/ctf/forensics/ctf-forensics-custom-protocol-aes-gcm-pcap-binary-key/
draft: false
kb_aliases:
- ET3RNUMX
- AES-GCM 流量解密
- Go 二进制 key
- tcp.pcap
- base32 命令输出
- eternum
---

## 一句话结论

pcap 中的自定义协议以 `ET3RNUMX` 为 magic、后跟 4 字节长度、12 字节 nonce 和 ciphertext；12 字节 nonce 指向 AES-GCM。Go 二进制 `kworker` 使用 AES-NI，直接在字符串中搜索 32 字节密钥 `xfqGcVjrOWp5tUGCPFQq448nPDjILTe7`，用 `AESGCM(key).decrypt(nonce, ciphertext, None)` 逐帧解密，即可看到攻击者执行 `base32 /var/opt/secret` 及其输出，Base32 解码后得到 flag。

## 原理

- **协议识别**：TCP payload 中出现固定 magic `ET3RNUMX`（8 字节），紧随 4 字节大端长度，再后是 12 字节 nonce 和密文。12 字节是 GCM 的标准 nonce 长度，且密文尾部带 16 字节 tag，符合 AES-GCM 帧格式。
- **密钥定位**：Go 二进制去符号且使用 AES-NI，但 AES-256 密钥通常以 32 字节字符串常量形式存在；`strings`/IDA 搜索 32 字节可打印字符串，找到 `xfqGcVjrOWp5tUGCPFQq448nPDjILTe7`，用其作为 AES-256 密钥。
- **GCM 解密**：`AESGCM(key).decrypt(nonce, ciphertext, None)`；nonce 从帧头取 12 字节，ciphertext 为剩余部分（含 tag）。解密成功即得到明文帧。
- **为什么能解**：密钥硬编码在客户端/服务端二进制中，属于“密钥随样本落地”；GCM 的 nonce 不是秘密，随帧传输；只要拿到 binary 和 pcap，就能离线解密。
- **命令与编码**：解密后的明文显示攻击者执行 `base32 /var/opt/secret`，返回一行 Base32 字符串；Base32 解码得到 32 位十六进制 `665a4bf7903bb6ea0b05c1fa8a447f4e`，按题目格式加 `CISCN{}` 即 flag。
- **解析细节**：pcap 全局头 24 字节，每包 16 字节包头（`ts_sec, ts_usec, incl_len, orig_len`）；以太网头 14 字节，IP 头长度由 `(pkt[14] & 0x0F) * 4` 得到，TCP 头长度由 `(tcp[12] >> 4) * 4` 得到；去掉头后取 TCP payload，再按 magic 定位帧。

## 触发条件

- 有 pcap 和对应的客户端/服务端二进制（本例为 Go 二进制）。
- 协议含固定 magic、长度字段、12 字节 nonce；密文为 AES-GCM。
- 二进制中硬编码 32 字节 AES-256 密钥，或密钥可从配置/内存中提取。
- 密文帧在 TCP payload 中完整出现（未被分片截断，或可重组）。
- 明文是文本/命令输出，便于识别下一步编码。

## 利用步骤

1. 用 Wireshark/`strings` 观察流量，找固定 magic `ET3RNUMX` 和重复的帧结构。
2. 逆向/`strings` 二进制，搜索 32 字节可打印字符串；用 `rabin2 -zz`、`strings -n 32` 或 IDA 字符串窗口定位候选 key。
3. 解析 pcap：跳过 24 字节全局头，循环读 16 字节包记录，按 `incl_len` 取包；解析 Ethernet/IP/TCP 头，取 payload。
4. 在 payload 中查找 magic，读 4 字节长度，取 12 字节 nonce 和 length 字节密文；用 `AESGCM(key).decrypt(nonce, ciphertext, None)` 解密。
5. 打印所有明文帧，按时间排序；识别命令与输出。
6. 对输出中的 Base32/Base64/hex 继续解码，得到最终 flag。

## PoC

```python
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def parse_pcap(path):
    with open(path, 'rb') as f:
        f.read(24)  # global header
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', hdr)
            yield f.read(incl_len)

def tcp_payload(pkt):
    ip_hlen = (pkt[14] & 0x0F) * 4
    tcp = 14 + ip_hlen
    tcp_hlen = (pkt[tcp + 12] >> 4) * 4
    return pkt[tcp + tcp_hlen:]

key = b"xfqGcVjrOWp5tUGCPFQq448nPDjILTe7"   # 从二进制字符串提取的 32 字节 key
aes = AESGCM(key)
magic = b"ET3RNUMX"

for pkt in parse_pcap("tcp.pcap"):
    data = tcp_payload(pkt)
    idx = data.find(magic)
    if idx < 0 or idx + 12 > len(data):
        continue
    length = struct.unpack('>I', data[idx + 8:idx + 12])[0]
    if idx + 12 + length > len(data):
        continue
    frame = data[idx + 12:idx + 12 + length]
    nonce, ct = frame[:12], frame[12:]
    try:
        print(aes.decrypt(nonce, ct, None))
    except Exception:
        pass
```

原文解密后看到 `base32 /var/opt/secret` 的输出：

```text
IMZWGCZ33MI3WGNJYG4YDALJSMIYDCLJUMRSDILJYGUZDMLLBGRQTIN3BGY2WCMLBHF6QU===
```

Base32 解码：

```python
import base64
print(base64.b32decode("IMZWGCZ33MI3WGNJYG4YDALJSMIYDCLJUMRSDILJYGUZDMLLBGRQTIN3BGY2WCMLBHF6QU===").decode())
# 665a4bf7903bb6ea0b05c1fa8a447f4e
```

## 变体与关联

- 变体：nonce 可能是 8/12/16 字节；GCM 可能带 AAD，需在 `decrypt(nonce, ct, aad)` 中传入；密文可能先 Base64/hex 编码。
- 变体：密钥可能被拆分、XOR 混淆或从配置/KMS 派生；若 `strings` 找不到，动态调试或搜索 AES key schedule 前的内存。
- 变体：协议可能是 AES-CBC/ChaCha20；按 nonce 长度、tag 长度和二进制中的常量判断。
- 关联：[[defense-forensics-vshell-config-aes-cbc-traffic-aes-gcm-decrypt]]（C2 配置与 AES-GCM 帧解密）、[[crypto-aes-gcm-nonce-reuse-keystream-xor]]（GCM nonce 复用）、[[ctf-forensics-pcap-http-xor-exfil-key-recover]]（从 pcap/脚本提取 key）。
- 边界：若帧被 TCP 分片/重组，需先按 TCP 流重组再找 magic；若密钥不在二进制中，需从内存/配置文件提取；若 nonce 复用，可进一步做密钥流分析。

## 检测与防御

- **协议/密钥**：不要在客户端硬编码对称密钥；使用 TLS 或服务端密钥协商；密钥放入 KMS/HSM，定期轮换。
- **取证**：保留 pcap 与二进制；用 `strings`/IDA 搜索 32/16 字节密钥；按 magic/length/nonce 结构解析帧。
- **检测**：固定 magic + 12 字节 nonce + 长度字段的协议；二进制中出现 AES-NI 指令与 32 字节可打印常量；流量中出现高熵定长帧。
- **响应**：解密历史流量，提取命令与输出；轮换泄露密钥；排查被读取的 secret 文件与外传通道。
