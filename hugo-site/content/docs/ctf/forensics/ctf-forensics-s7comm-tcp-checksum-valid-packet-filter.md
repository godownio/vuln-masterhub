---
id: ctf-forensics-s7comm-tcp-checksum-valid-packet-filter
title: S7COMM pcap 按 TCP 校验和筛出未篡改分组：拼接有效载荷 hex→base32 还原 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: s7comm-tcp-checksum-valid-packet-ascii-concat
tags:
- ctf
- forensics
- pcap
- s7comm
- tcp
- checksum
- base32
- wireshark
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:21:45+08:00'
  notes: 已对照原文与全部25张图核对：S7COMM/TCP102报文（图24）、按TCP校验和筛出无错误分组、拼接hex后CyberChef From Hex→From Hex→From Base32输出flag{f9a99013-8980-4c8e-bb58-f9fc41c3e041}（图25）均一致。未验证点：未重新解析pcap；tcp.checksum.status筛选为等价方法，原文未给具体过滤器。
url: /docs/ctf/forensics/ctf-forensics-s7comm-tcp-checksum-valid-packet-filter/
draft: false
kb_aliases:
- 武功山杯 仙风三宝
- TCP 校验和过滤
- S7COMM 报文分析
- 校验和正确的分组
- base32 还原 flag
---

## 一句话结论

题目 pcap 中混有大量 S7COMM 报文，提示要求计算 TCP 校验和：只有校验和正确（未篡改）的分组载荷含真实数据，其余是干扰项；按序提取这些分组的十六进制载荷拼接，在 CyberChef 中连续执行 From Hex（本例两次）再 From Base32，即可还原 `flag{f9a99013-...}`。

## 原理

- **S7COMM over TCP/102**：pcap 中是西门子 S7 协议的请求/响应（Wireshark 显示 S7 Communication，端口 102），报文在 TCP 之上分片传输。
- **校验和作为选择器**：题目把真实数据只放进 TCP 校验和正确的分组，错误校验和的分组是诱饵（内容不可信或随机）。Wireshark 的 TCP 校验和验证会标出 good/bad（需在协议首选项启用 checksum validation）；也可按 RFC 1071 自行计算校验和筛选。
- **数据分层编码**：保留下来的分组载荷按序拼接后是一个十六进制字符串；From Hex 一次得到下一层十六进制文本，再次 From Hex 得到二进制/字符数据，最后 From Base32 得到 flag。原文 CyberChef 配方为 `From Hex → From Hex → From Base32`，输出 `flag{f9a99013-8980-4c8e-bb58-f9fc41c3e041}`。
- **为什么成立**：TCP 校验和是端到端完整性字段，抓包时错误的校验和通常意味着构造/篡改；出题人用“校验和是否正确”作为真/假数据的区分维度，属于利用协议字段做隐写选择器的思路。

## 触发条件

- 获得包含 S7COMM（或任意 TCP 协议）流量的 pcap，存在大量相似分组，其中部分校验和错误。
- 题目提示涉及 TCP 校验和/完整性校验，或观察到只有部分分组载荷呈现可打印数据。
- Wireshark 已启用 TCP checksum validation（否则显示 unverified），或能用脚本重新计算校验和。
- 真实数据经过十六进制/Base32 等分层编码，需要按提示尝试解码链。

## 利用步骤

1. 打开 pcap，过滤 `s7comm` 或 `tcp.port == 102`，确认协议与分组数量。
2. 启用 TCP 校验和验证（Wireshark 首选项 → Protocols → TCP → Validate the TCP checksum if possible），过滤 `tcp.checksum.status == 1`（good）保留正确分组；或写脚本按 RFC 1071 计算比对。
3. 按 frame.number 顺序导出这些分组的 TCP 载荷（hex），拼接成一个长十六进制串。
4. 在 CyberChef 中依次执行 From Hex（如结果仍是十六进制文本则再执行一次）与 From Base32；观察输出是否为 `flag{...}`。
5. 若解码失败，检查是否漏选/多选分组、分组顺序、是否需先剥离 S7COMM 头，以及 From Hex 的次数。

## PoC

Wireshark 过滤：

```
s7comm && tcp.checksum.status == 1
```

tshark 提取载荷（校验和正确的分组）：

```bash
tshark -r 1.pcap -Y 'tcp.checksum.status == 1' -T fields -e frame.number -e tcp.payload
# 按 frame.number 排序后拼接 tcp.payload（十六进制）
```

CyberChef 配方（原文）：

```
From Hex → From Hex → From Base32
```

输出：

```
flag{f9a99013-8980-4c8e-bb58-f9fc41c3e041}
```

要点：`tcp.checksum.status` 的取值随 Wireshark 版本（1=good、0=bad、2=unverified），筛选前先用 `tcp.checksum.status` 列确认；tshark 需与 Wireshark 相同版本/首选项才能自动判定。

## 变体与关联

- **IP/UDP 校验和**：同样可用 IP header checksum 或 UDP checksum 正确性作为真假数据选择器；思路是“协议完整性字段 → 隐写选择器”。
- **其它选择维度**：TCP 序号/确认号、窗口大小、TLL、时间间隔、报文长度也可作为分组筛选条件，取决于题目提示。
- **编码链变体**：十六进制 → Base32/Base64/ASCII85 → 压缩/加密；本题是 hex(hex(base32(flag))) 风格，需按输出特征逐层判断。
- **同族 pcap 卡**：`ctf-forensics-modbus-private-pcap-write-register-covert` 用 Modbus 私有功能码做隐蔽通道，本卡用 TCP 校验和筛选 S7COMM 真实分组，协议与选择器不同。

## 检测与防御

- 网络取证时启用并记录校验和验证结果，可用于识别被篡改/构造的分组与隐蔽通道。
- 对工控协议（S7COMM、Modbus 等）做深度包检测与白名单，限制非业务功能码/异常长度；保留 pcap 便于事后分析。
- 防守方不应仅依赖校验和判断内容可信（攻击者可构造正确校验和），需结合协议语义、业务基线和端点行为。
- 监控同一 S7 连接中出现大量校验和错误或格式异常的分组，可能是扫描/注入/隐写行为。
