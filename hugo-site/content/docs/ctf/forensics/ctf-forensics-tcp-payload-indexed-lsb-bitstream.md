---
id: ctf-forensics-tcp-payload-indexed-lsb-bitstream
title: TCP payload 序号化 8-bit 记录取最低位：按嵌入序号重排 392 bit 还原隐藏文本
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-tcp-payload-indexed-lsb-bitstream
tags:
- forensics
- pcap
- tcp
- stego
- lsb
- covert-channel
- bitstream
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:33:29+08:00'
  notes: 已对照全文核对：The Least Secret 的 392 条 [序号:"8位二进制"] 记录、按 0..391 提取最低位、392 bit 转 ASCII 得 NSSCTF flag 的流程与原文一致；PoC 正则/取 b[-1] 的语义正确（原文正则 (\d)" 即取末位）。未验证点：文章未附该题流量/图片（img 01-05、06-10 为其他题目），无法复跑 pcap。
url: /docs/ctf/forensics/ctf-forensics-tcp-payload-indexed-lsb-bitstream/
draft: false
kb_aliases:
- TCP payload LSB 隐写
- 序号化二进制记录隐写
- 392 bit 隐写
- pcap 最低位提取
- 流量比特信道
---

## 一句话结论

当 pcap 的 TCP payload 中反复出现 `[序号:"8位二进制"]` 形式的文本记录时，整段 8 位串可能是掩护，真正的秘密只在每条记录的最低位：按嵌入序号 0..N 排序、逐条取 LSB 拼成 bit 流，每 8 位转一个字节即可还原隐藏文本（本例 392 条 → 392 bit → 49 字节 ASCII flag）。

## 原理

- **记录结构即信道**：抓包数据形如 `[237:"00110110"]`，方括号内是自增序号和 8 位二进制字符串。序号让接收方可以按逻辑顺序重组，避免 TCP 重传/乱序影响；8 位串表面看是完整数据，实际只有最低位（最后一个字符）承载信息。
- **为什么取最低位**：每条记录只贡献 1 bit，容量低但隐蔽；若把 8 位当普通二进制直接解码会得到乱码，而按记录序号取 LSB 后拼接，得到的 bit 流按 8 位分组正好是可读 ASCII。这是 LSB（least significant bit）隐写的流量版：载体从图像像素换成报文中的数值。
- **顺序来自数据本身**：本例共有 392 条记录，序号覆盖 0–391；按序号而非抓包顺序排，能抵抗重传与乱序。提取脚本先建立 `id -> 8位串` 的字典，再顺序取 `bits[id][-1]`。
- **解码**：392 bit = 49 字节；每 8 bit 转字符即 flag。若不可读，可尝试反向位序（LSB-first）、取其他位平面或反向映射（0/1 互换），这是比特隐写的常见变体。

## 触发条件

- 取得 pcap/pcapng，流量中有大量 TCP 包携带文本形式的 `[n:"[01]{8}"]` 记录。
- 记录序号连续（如 0–391），或可从时间/序列号恢复顺序。
- payload 未加密/未压缩；可用 tshark 导出 `tcp.segment_data`。
- 隐藏信息仅占每个 8 位串的最低位，直接转 ASCII 会失败，提示需要按 bit 平面处理。

## 利用步骤

1. 用 tshark 导出 TCP 段数据（十六进制）：
   ```bash
   tshark -nr message.pcapng -Y "tcp.len>=14" -T fields -e tcp.segment_data | xxd -r -p > records.txt
   ```
2. 用正则提取全部 `[id:"8位"]` 记录，按 id 建立映射。
3. 按 id 升序取每条 8 位串的最后一位，拼成 bit 字符串。
4. 每 8 bit 转一个 ASCII 字符，得到 flag/隐藏文本。
5. 若结果乱码：尝试取第一位（MSB）、反转 bit 顺序、0/1 互换，或检查是否有缺失序号需要跳过。

## PoC

```python
import re

text = open("records.txt", encoding="utf-8", errors="ignore").read()
pairs = re.findall(r'\[(\d+):"([01]{8})"\]', text)
bits = [""] * (max(int(i) for i, _ in pairs) + 1)
for idx, b in pairs:
    bits[int(idx)] = b[-1]          # 取最低位
s = "".join(bits)
print("".join(chr(int(s[i:i+8], 2)) for i in range(0, len(s), 8)))
```

本例运行结果为：

```text
NSSCTF{c0ngr4tu1ati0ns_U_4r3_r3a11y_a_LSB_m45ter}
```

## 变体与关联

- 位平面变体：取 MSB、第二位、反转顺序，或每 8 条记录组成一个字节后再取 LSB。
- 载体变体：同一思路可把秘密放在 IP TTL（64/65 映射 0/1）、CAN 帧末字节、ICMP payload 尾部等每包 1 bit/字节的字段中；区别只在"从哪里读位"和"如何排序"。
- 记录变体：序号可能是抓包序号、TCP 序列号或记录自带的 id；若没有显式序号，需按时间戳或 TCP stream 重组。
- 关联：图像 LSB（RGB 通道）与流量 LSB 的共同点是"载体值的高位是掩护、低位是数据"；检测时都应关注低位分布异常。

## 检测与防御

- CTF/取证：先 `tshark -T fields -e tcp.segment_data` 导出文本，正则统计记录格式；对疑似数值序列做 LSB/MSB、正反序的暴力尝试；用 CyberChef 的 From Binary 快速验证。
- 真实网络：关注 payload 中出现大量结构相同、仅低位变化的文本记录；对非业务协议的规律性小载荷做熵/周期性分析。
- 防御：对出站流量做协议白名单与 DLP；检测异常的低带宽、固定格式心跳；对可疑 pcap 保留原始包以便按序号重组。
- 边界：该手法容量低（1 bit/包），只适合短 flag/密钥；若记录被加密或序号缺失，需要额外恢复步骤。
