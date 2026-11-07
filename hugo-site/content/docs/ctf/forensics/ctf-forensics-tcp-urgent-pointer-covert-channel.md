---
id: ctf-forensics-tcp-urgent-pointer-covert-channel
title: TCP 紧急指针隐写：URG 标志与 16 位 urgent_pointer 一一对应，ASCII 拼 base64
type: scenario
domain: ctf
path: ctf/forensics
technique: tcp-urgent-pointer-covert-channel
tags:
- forensics
- tcp
- pcap
- steganography
- urgent-pointer
- covert-channel
- tshark
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:46:38+08:00'
  notes: 已对照原文核对；4038 包中 28 个 URG=1 且 tcp.len=0、紧急指针 ASCII 拼 base64 解码一致
url: /docs/ctf/forensics/ctf-forensics-tcp-urgent-pointer-covert-channel/
draft: false
kb_aliases:
- TCP 紧急指针隐写
- urgent_pointer 隐写
- URG 标志信道
- 协议头隐写
- pcap 流量隐写
---

## 一句话结论

当流量题提示“都在流量里”而应用层载荷没有异常时，把 TCP 头里的 16 位 `urgent_pointer` 当作隐写载体：筛出 URG 标志为 1 的包，按时间顺序取出每个包的紧急指针值，它们都是可打印 ASCII，拼接后得到 base64，解码即 flag。

## 原理

- **协议头是天然隐蔽信道**：TCP 头的 16 位紧急指针字段只在 URG 标志置位时有语义，很多抓包分析工具默认不展示；攻击者/出题人可以把一个 ASCII 字符写进该字段，用 URG 位标记“有效载荷”。
- **载体唯一性验证**：本题 4038 个包中 URG 位为 1 的只有 28 个，且这 28 个包的 `tcp.len` 全为 0，说明应用层没有附带内容，排除“顺带用载荷混淆”的设计。
- **无诱饵验证**：检查“紧急指针非零但 URG 位为 0”的包，数量为零，说明 URG 位与字段值严格一一对应，不需要额外清洗。
- **解码链**：28 个值按时间顺序排列，每个值落在可打印 ASCII 范围，拼起来是一段 base64 文本；base64 解码得到闭合的 `flag{...}`。
- **通用方法**：协议头中所有 16 位字段都可作为候选载体——紧急指针、窗口大小、校验和、保留位、IP ID、TCP 时间戳；先统计字段值的分布与标志位对应关系，再判断是否为编码。

## 触发条件

- 抓到完整 pcap/pcapng，题目提示与流量/协议头相关，应用层载荷无明显异常。
- 存在大量 URG 标志置位或某个 16 位字段取值异常集中、且值域落在可打印 ASCII。
- 字段值与标志位存在严格对应关系（如 URG=1 时紧急指针才有意义），可作为“有效/无效”判据。
- 取出的字节流符合某种编码特征（base64、hex、ASCII 文本）。

## 利用步骤

1. 用 `tshark` 或 Scapy 统计各 TCP 标志位与字段值分布，重点看 URG、PSH、保留位、窗口大小、紧急指针。
2. 筛出 `tcp.flags.urg == 1` 的包，确认其 `tcp.len` 是否为 0，排除载荷干扰。
3. 反向检查 `tcp.urgent_pointer != 0 && tcp.flags.urg == 0` 的包数量，确认没有诱饵或需要额外过滤。
4. 按时间顺序导出紧急指针值，转为字节；检查是否全部可打印。
5. 拼接为文本，识别编码（本题为 base64），解码得到 flag。
6. 若字段值不是直接 ASCII，尝试按位拆解、异或固定值、或与其他字段组合。

## PoC

```bash
tshark -r TCP-urgent-pointer.pcapng \
  -Y "tcp.flags.urg==1" \
  -T fields -e frame.number -e tcp.urgent_pointer
```

```python
import base64
vals = [int(x) for x in open("urgent.txt")]
s = bytes(vals).decode()
print(base64.b64decode(s).decode())
```

原文得到 `flag{ch22r5_f0r_y0u}`；未在本机复跑。

## 变体与关联

- **字段变体**：IP ID、TCP 窗口大小、校验和、TCP 时间戳、VLAN 优先级、保留位；凡是协议允许但业务不用的字段都可承载数据。
- **编码变体**：直接 ASCII、低 7 位、每字段两字节、异或掩码、按包序号排序/反序。
- **判据变体**：用标志位（URG/PSH/ACK）标记有效包，或用特定五元组、时间间隔筛选。
- **关联**：与“协议头隐写”“pcap 载荷提取”同类；本卡强调先做载体唯一性与诱饵检查，再解码。

## 检测与防御

- 检测侧：监控 URG 标志异常频繁、紧急指针值集中在可打印 ASCII、窗口大小/ID 字段分布异常的主机流量。
- 防御侧：在边界设备规范化/清零未使用字段，或对协议头做一致性校验；对内部流量做基线，发现字段值分布突变。
- 取证侧：不要只看应用层载荷；先枚举协议头字段，统计标志位与字段的对应关系，再做编码识别。
