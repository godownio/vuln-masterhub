---
id: ctf-forensics-pcap-http-xor-exfil-key-recover
title: PCAP HTTP 外传取证：从下载脚本提取 XOR key，解密 multipart 上传的 hex 数据
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-http-xor-exfil-key-recover
tags:
- ctf
- forensics
- pcap
- http
- xor
- exfiltration
- multipart
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:58:04+08:00'
  notes: 已对照原文与图06核对：HTTP 对象列表（JdRlPr1.py 907B、多个 multipart upload 781KB/1475KB/986KB/118KB/382KB）、脚本 XOR key G0G0Squ1d3Ncrypt10n、hex 上传与 xor_file 解密均一致；未复跑提取脚本。
url: /docs/ctf/forensics/ctf-forensics-pcap-http-xor-exfil-key-recover/
draft: false
kb_aliases:
- PCAP 外传取证
- HTTP 对象导出
- XOR 加密外传
- Baby Exfil
- 流量包解密
- multipart upload 取证
---

## 一句话结论

从 PCAP 中导出 HTTP 对象，先找到受害者下载的恶意 Python 脚本，脚本里硬编码了 XOR key；再提取同一攻击者服务器上的 multipart `upload` 请求体（文件内容为 XOR 后数据的 hex），用该 key 逐字节异或即可还原被窃取的文档/图片，拼接/OCR 得到 flag。

## 原理

- **HTTP 对象导出**：Wireshark 的“文件 → 导出对象 → HTTP”可按 Host/Content-Type 列出所有请求/响应；恶意脚本下载通常是 `text/x-python`，外传是 `multipart/form-data` 的 `upload`。
- **脚本泄露算法**：恶意脚本 `JdRlPr1.py` 包含 `key = "..."` 与 `xor_file(data, key)`，对 `C:\Users\squid\Desktop` 下 `.docx/.png/.jpeg/.jpg` 逐字节 XOR，`encrypted.hex()` 后作为 multipart 文件上传。
- **XOR 自逆**：`cipher[i] = plain[i] ^ key[i % len(key)]`，同一函数即可解密；key 短（示例 20 字节），直接复用。
- **hex 传输**：上传的 `file` 字段是 hex 字符串，需先 `bytes.fromhex` 再 XOR；如果上传的是原始二进制，则直接 XOR。
- **取证流程**：导出脚本 → 读 key/算法 → 导出 upload 请求体 → 解析 multipart 提取 file 内容 → fromhex → XOR → 保存恢复文件 → 查看/OCR/拼接 flag。

## 触发条件

- PCAP 包含完整的 HTTP 下载与上传流量（未加密/未分片丢失）；能导出对象或至少请求体。
- 恶意脚本可读，包含硬编码 key/算法；上传数据用简单 XOR/编码，key 可复用。
- 上传的 multipart 边界/字段可解析；数据完整（TCP 流重组成功）。
- 恢复的文档/图片中包含 flag 或下一步线索。

## 利用步骤

1. **导出 HTTP 对象**：Wireshark → 文件 → 导出对象 → HTTP，按 Content-Type 排序，找 `text/x-python` 的脚本下载与 `multipart/form-data` 的 `upload`。
2. **分析脚本**：打开恶意脚本，提取 `key`、XOR 函数、目标扩展名/路径；确认加密是逐字节 XOR + hex。
3. **导出上传数据**：对每个 `upload` 请求，导出 multipart body 或从 TCP 流中提取 `file` 字段内容（hex 字符串）。
4. **解密**：`encrypted = bytes.fromhex(hex_data)`；`plain = bytes(b ^ ord(key[i % len(key)]) for i,b in enumerate(encrypted))`；写入文件。
5. **查看结果**：恢复 `.docx/.png/.jpg`，用对应查看器/OCR/strings 找 flag；多文件可能需要拼接。
6. **验证**：检查文件头（PNG `\x89PNG`、DOCX `PK`、JPEG `\xFF\xD8`）确认解密正确。

## PoC

```python
def xor_file(data, key):
    return bytes(b ^ ord(key[i % len(key)]) for i, b in enumerate(data))

key = "G0G0Squ1d3Ncrypt10n"

with open("stolen.hex") as f:
    hex_data = f.read().strip()

encrypted = bytes.fromhex(hex_data)
decrypted = xor_file(encrypted, key)
with open("recovered.bin", "wb") as f:
    f.write(decrypted)
```

```text
Wireshark 导出对象示例：
35.238.80.16:8000  text/x-python      907 bytes   JdRlPr1.py
34.134.77.90:8080  multipart/form-data 781 kB      upload
34.134.77.90:8080  multipart/form-data 1475 kB     upload
...
```

原文从多个 upload 中恢复文件并得到 flag；key/文件名/扩展名依样本而定。本卡不执行 PoC。

## 变体与关联

- **其它编码**：Base64、hex、gzip/zlib 压缩后再 XOR；按脚本逆序解码。
- **其它外传通道**：DNS、ICMP、WebSocket、SMTP；先按协议导出 payload，再套用脚本算法。
- **密钥来源**：硬编码、环境变量、从 C2 下发、每文件随机 key（需找 key 传输）；若 key 随机且未泄露，需已知明文/密码分析。
- **关联**：[[ctf-forensics-pcap-http-order-vm-opcode-reconstruction]]（PCAP 还原 VM 指令）、[[ctf-forensics-pcap-multicast-base64-password-aes-zip-rgb-lsb]]（多层编码取证）、[[defense-forensics-winrm-ntlm-traffic-decrypt-soap-command]]（流量解密）。
- **边界**：需要完整流量与可读脚本；若使用强加密/TLS、key 不在流量中、或数据分片丢失，需其它取证手段。

## 检测与防御

- **网络检测**：HTTP 外传大文件、multipart 到陌生 IP、Python 脚本下载后紧跟上传；监控已知 C2/恶意域名。
- **终端检测**：脚本/进程遍历用户文档目录、读取 `.docx/.png/.jpg`、XOR 循环、hex 编码后 HTTP POST；文件完整性/EDR 规则。
- **数据保护**：敏感文档加密存储/DRM、最小权限、出网白名单；备份与恢复。
- **取证**：保留 PCAP/内存/磁盘镜像，按 HTTP 对象导出 → 脚本分析 → 解密 → 时间线还原。
