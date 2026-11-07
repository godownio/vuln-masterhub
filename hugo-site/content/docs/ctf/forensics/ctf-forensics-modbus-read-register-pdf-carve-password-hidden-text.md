---
id: ctf-forensics-modbus-read-register-pdf-carve-password-hidden-text
title: Modbus/TCP 读保持寄存器载荷重建 PDF：口令爆破后提取隐藏文字
type: scenario
domain: ctf
path: ctf/forensics
technique: modbus-read-register-payload-pdf-carve-password-hidden-text
tags:
- ctf
- forensics
- modbus
- ics
- pcap
- file-carving
- pdf
- password-cracking
- stego
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:21+08:00'
  notes: 已对照原文与图24-30核对：从 Modbus 功能码 3 响应 payload[9:9+byte_count] 拼接 output.pdf；PDF 口令 43305185；隐藏文字 flag{MB03_40001**}（后两位截图中被遮挡）。原文还提到地址/摩斯诱饵；未复跑脚本。
url: /docs/ctf/forensics/ctf-forensics-modbus-read-register-pdf-carve-password-hidden-text/
draft: false
kb_aliases:
- Modbus 功能码 3
- 读保持寄存器响应
- pcap 重建 PDF
- PDF 密码爆破
- PDF 隐藏文字
- 工控流量文件雕刻
---

## 一句话结论

工控流量题中，Modbus/TCP 功能码 3（读保持寄存器）的响应数据区可以按 2 字节寄存器顺序拼接成一个文件；把 pcap 中所有功能码 3 响应的 `register_data` 依次写入 `output.pdf`，即可从流量中“雕刻”出被拆散传输的 PDF，随后对 PDF 加密口令做爆破（原文得到 `43305185`），打开后复制/查看被高亮或隐藏的文字即可得到 flag。

## 原理

- Modbus/TCP 报文结构：`[Transaction ID(2)][Protocol ID(2)][Length(2)][Unit ID(1)][Function(1)][Byte Count(1)][Data...]`。功能码 3 是“读保持寄存器”响应，`Byte Count` 表示后续数据字节数，数据区由若干个 16 位寄存器组成（每 2 字节一个寄存器，网络字节序）。
- 文件传输伪装：题目把 PDF 文件按寄存器粒度切分，放进一连串功能码 3 响应中；每一帧的数据区只是文件的一段原始字节，寄存器语义并不重要，按抓包顺序把每帧 `register_data` 原样拼接即可还原文件。
- 重建判定：拼接结果以 `%PDF-` 开头、以 `%%EOF` 结尾（或能被 PDF 解析器打开），即可确认还原正确；若顺序错乱，需按 TCP 流序号/Transaction ID 排序后再拼接。
- PDF 加密：重建出的 PDF 设置了打开口令（`/Encrypt`），需要用 PDF 密码恢复工具（john/hashcat + pdf2john，或 GUI 工具）对弱口令做字典/掩码/暴力破解；原文得到 8 位数字口令 `43305185`。
- 隐藏文字：打开 PDF 后，正文中有被设为白色/高亮/透明或藏在注释/图层里的文字；选中复制（或提取文本层）即可得到 `flag{MB03_40001**}`。原文还遇到“最后一条流量含地址、下载是摩斯码”的诱饵，说明需要以实际重建文件的内容为准。

## 触发条件

- pcap/pcapng 中存在 Modbus/TCP 流量（TCP 502 端口），且包含功能码 3（读保持寄存器）响应。
- 响应数据区承载的是被切分的文件字节，按顺序拼接后能得到可识别文件（PDF/ZIP/图片等）。
- 重建出的 PDF 有打开口令；口令强度可被字典/掩码/暴力破解覆盖（本题为 8 位数字）。
- PDF 内存在隐藏/高亮/注释文字或可提取文本层。

## 利用步骤

1. 用 Wireshark 过滤 `tcp.port == 502`，确认 Modbus/TCP 流量；重点看功能码 3 的响应帧。
2. 按抓包顺序遍历所有功能码 3 响应，取 `payload[9:9+byte_count]` 作为寄存器数据，追加到缓冲区。
3. 将缓冲区写入 `output.pdf`，检查文件头 `%PDF-`、文件尾 `%%EOF`，用 PDF 阅读器确认能打开。
4. 若 PDF 加密，提取 hash（`pdf2john output.pdf > hash.txt`）后用 john/hashcat 爆破，或使用 PDF 密码恢复工具；原文得到口令 `43305185`。
5. 打开 PDF，检查正文高亮/白色文字、注释、图层、附件和元数据；选中复制隐藏文字或提取文本，得到 flag。
6. 若拼接顺序不对，按 TCP 流/Transaction ID 重排；若数据区有额外协议头，先按 MBAP+PDU 结构剥离。

## PoC

原文提取脚本：

```python
from scapy.all import rdpcap, TCP
import struct

packets = rdpcap("test.pcap")
data_bytes = bytearray()

for pkt in packets:
    if TCP in pkt and (pkt[TCP].dport == 502 or pkt[TCP].sport == 502):
        payload = bytes(pkt[TCP].payload)
        if len(payload) < 9:
            continue  # Modbus TCP 最短 9 字节（头+功能码+长度+数据）
        transaction_id = payload[0:2]
        protocol_id = payload[2:4]
        length = payload[4:6]
        unit_id = payload[6]
        function_code = payload[7]
        if function_code == 3:
            byte_count = payload[8]
            register_data = payload[9:9 + byte_count]
            for i in range(0, len(register_data), 2):
                data_bytes += register_data[i:i + 2]

with open("output.pdf", "wb") as f:
    f.write(data_bytes)

print("提取完成，保存为 output.pdf")
```

```text
PDF 口令：43305185
隐藏文字复制结果：flag{MB03_40001**}
（原文 flag 后两位在截图中被遮挡）
```

等价口令破解（标准工具链，原文使用 GUI 密码恢复工具）：

```bash
pdf2john output.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash
# 或 hashcat -m 10500 pdf.hash rockyou.txt
```

## 变体与关联

- 变体（功能码）：除功能码 3 外，功能码 16（写多个寄存器）也可承载文件字节；先按 `modbus.func_code` 过滤，再判断数据区是否符合文件头特征。
- 变体（协议）：同一思路适用于其他工控协议（S7comm、OPC UA、DNP3）的 payload 拼接；关键是识别文件头/尾并按流顺序重组。
- 变体（PDF 隐藏方式）：白色文字、高亮、透明文本、注释、图层、附件、元数据、压缩流中的文本；可用 `pdftotext`、`qpdf --qdf`、`mutool` 或 PDF 解析库提取。
- 关联：[[ctf-forensics-modbus-write-register-ieee754-abnormal-value]]（功能码 16 写寄存器异常值）、[[ctf-forensics-modbus-private-pcap-write-register-covert]]（写寄存器隐蔽载荷）、[[ctf-forensics-pcap-http-order-vm-opcode-reconstruction]]（pcap 载荷重建文件）。
- 边界：若功能码 3 响应只是普通工艺数据而非文件，拼接结果无文件头；若 PDF 口令强度高且无字典/掩码线索，爆破不可行；隐藏文字若被转为图片则需 OCR。

## 检测与防御

- 这是 CTF 取证题的解法，不是真实攻击链；对工控安全运营的启示是：Modbus/TCP 无认证、明文传输，攻击者可把任意文件/指令拆进寄存器读写流量中，绕过只看协议字段的检测。
- 检测：监控 Modbus 功能码 3/16 响应中数据区的熵与文件头特征（`%PDF`、`PK`、`\x89PNG`）；对异常长连接、连续读寄存器、固定寄存器区间的大流量告警；建立工控流量基线。
- 防御：工控网络分区与单向网关；Modbus/TCP 加 TLS/VPN 或使用安全协议（Modbus Security）；对寄存器读写做白名单与深度包检测；定期审计流量中的文件传输行为。
