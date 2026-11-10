---
id: ctf-forensics-udp-aes-ecb-key-header-xor-ole2-macro
title: UDP 载荷 AES-ECB：16 字节帧头异或 0xFF 作 key，解密 OLE2 宏 hex 再 XOR 爆破
type: scenario
domain: ctf
path: ctf/forensics
technique: udp-aes-ecb-header-xor-key-ole2-macro-xor
tags:
- ctf
- forensics
- pcap
- udp
- aes-ecb
- olevba
- xor
- ole2
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T13:10:43+08:00'
  notes: 已对照图07/08/10 的 UDP 第7/31 包 Data、图11 AES-ECB NoPadding 解密得 flag{This_Is_Test_FlaG}、图12 单字节 XOR 爆破 key=0x0a 得 flag{5958620afe4c56eb13e8fdb5e10d4f73} 核对；帧头 32 个十六进制字符=16 字节、异或 0xFF 得 key 525869ecc265ce059f20857f027e1509 已复算一致；原文 AES-EBC 为 ECB 笔误。属同一 UDP 题的单向链（解密→OLE2→宏），按挑战场景保留。未复现。
url: /docs/ctf/forensics/ctf-forensics-udp-aes-ecb-key-header-xor-ole2-macro/
draft: false
kb_aliases:
- UDP 流量 AES 解密
- 帧头异或 FF 作 key
- AES-ECB NoPadding
- OLE2 宏 olevba
- 宏 hex 单字节 XOR 爆破
- AES-EBC FF
---

## 一句话结论

pcap 中第 7 与第 31 个 UDP 包的 `Data` 字段是 hex 文本，解码后共享前 32 个十六进制字符（16 字节）的帧头 `ada796133d9a31fa60df7a80fd81eaf6`；把这段帧头逐字节异或 `0xFF` 得到 AES-128 key `525869ecc265ce059f20857f027e1509`，以 ECB/NoPadding 解密第 7 包得到测试 flag，解密第 31 包得到 OLE2 文档；`olevba` 从宏中提取 hex 串，单字节 XOR 爆破（key=0x0a）得到最终 flag。

## 原理

- **hex 文本封装的 UDP 协议**：自定义协议把二进制数据编码成十六进制字符串塞进 UDP payload；Wireshark 的 `Data` 字段可直接复制，做一次 hex 解码即可还原字节流。
- **帧头复用即密钥材料**：两个包的密文前 16 字节完全相同，说明它不是随机 IV，而是固定头部；出题人把这段头部与 `0xFF` 异或得到 AES key（`ad a7 96 13 …` → `52 58 69 ec …`）。这是“密钥藏在协议头”的典型构造。
- **AES-ECB 的可解性**：ECB 无 IV、分组独立、相同明文块产生相同密文块；验证用的第 7 包密文为 32 字节（AES-128 两块），使用 NoPadding 直接解密即可得到带 `flag{` 前缀的测试标记。
- **OLE2 + olevba**：第 31 包明文是 Office 复合文档（OLE2）；`olevba` 解析 `vbaProject.bin` 并输出宏源码，其中藏着一串 hex 密文。
- **单字节 XOR 爆破**：hex 解码后的密文逐字节异或同一个 key（0~255），用 `flag{` 前缀筛选即可确定 key=0x0a，得到最终 flag。`flag{` 前缀是最小 crib。

## 触发条件

- 有 pcap，且 UDP 流量中存在 hex 文本形式的自定义载荷。
- 至少两个包共享相同的帧头（可用于推导 key），或能从协议/二进制中获得 key。
- 加密为 AES-ECB（无 IV、密文长度为 16 的倍数）且明文是可识别格式。
- 解密结果可能是文档，需要 `oletools`/`olevba` 或等价的 OLE2 解析工具。
- 后续载荷是单字节 XOR 等可爆破的弱编码。

## 利用步骤

1. Wireshark 过滤 `udp`，定位可疑包（本题为第 7 与第 31 包）；查看 `Data` 字段。
2. 复制 `Data` 的 hex 文本，做十六进制解码，得到二进制载荷；对比两包前 32 个 hex 字符（16 字节），确认相同。
3. 将共享帧头逐字节异或 `0xFF`，得到 16 字节 AES key；用 AES-ECB/NoPadding 解密第 7 包的剩余密文，看到 `flag{This_Is_Test_FlaG}` 即验证 key 正确。
4. 解密第 31 包剩余密文，保存为 `.ole2`。
5. `pip3 install oletools && olevba download.ole2`，提取宏源码中的 hex 字符串。
6. 对 hex 解码后的字节做单字节 XOR 爆破，按 `flag{` 前缀筛选，得到最终 flag。

## PoC

```python
from Crypto.Cipher import AES

# 两包共享的 16 字节帧头（从 UDP Data 的 hex 文本解码后前 32 个 hex 字符）
header = bytes.fromhex("ada796133d9a31fa60df7a80fd81eaf6")
key = bytes(b ^ 0xFF for b in header)
print(key.hex())   # 525869ecc265ce059f20857f027e1509

# 第 7 包剩余密文（32 字节）
ct7 = bytes.fromhex(
    "114e62d593b31a3d9eb9061c446a5056"
    "98608c1e8a0e002b55272a33268c3752"
)
pt = AES.new(key, AES.MODE_ECB).decrypt(ct7)
print(pt)          # b'flag{This_Is_Test_FlaG}...'
```

```python
# 第 31 包解密后得到 OLE2，olevba 提取宏中的 hex 串
h = ("6c666b6d713f333f323c383a6b6c6f3e693f3c6f683b39"
     "6f326c6e683f6f3b3a6e3e6c3d3977")
for k in range(256):
    p = bytes(b ^ k for b in bytes.fromhex(h))
    if p.startswith(b"flag{"):
        print(k, p.decode())
# 10 flag{5958620afe4c56eb13e8fdb5e10d4f73}
```

```bash
# 宏提取
pip3 install oletools
olevba download.ole2
```

## 变体与关联

- **key 不是异或 0xFF**：可尝试与相邻包/固定魔数异或、取帧头哈希、或从同目录二进制字符串中找 16/32 字节 key。
- **ECB vs CBC**：密文分组重复且无 IV 时优先试 ECB；若首块解密乱码、后续正常，考虑 CBC 且 IV 被省略/复用。
- **宏载荷再编码**：宏里的 hex 可能是 Base64、UTF-16、压缩或 XOR；先做 `file`/熵判断，再选单字节/多字节 XOR。
- 关联：[[ctf-forensics-custom-protocol-aes-gcm-pcap-binary-key]]（自定义协议 AES-GCM）、[[ctf-forensics-docm-vba-base64-xor-powershell-download-url]]（宏提取与 XOR 去混淆）、[[ctf-forensics-pcap-http-xor-exfil-key-recover]]（pcap 中恢复 XOR key）。

## 检测与防御

- **协议设计**：不要用“固定帧头异或常量”当密钥；使用带认证的 AEAD（AES-GCM/ChaCha20-Poly1305）与真正的密钥管理，避免 ECB。
- **检测**：UDP 载荷为可打印 hex 文本、长度固定、前 16 字节跨包重复；同一源向固定目的地址发送大量小包；解密后出现 Office/OLE2 文件头 `D0 CF 11 E0 A1 B1 1A E1`。
- **响应**：提取并离线解密流量，检查 OLE2 宏执行的命令与下载地址；对端点上的 Office 宏执行策略（禁用宏、受保护视图）进行核查。
