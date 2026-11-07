---
id: ctf-forensics-can-signal-id-filter-speed-peak-frame-hash
title: CAN pcap 干扰帧过滤 + 物理量解析：按 payload 唯一率找真实车速并哈希峰值帧号
type: scenario
domain: ctf
path: ctf/forensics
technique: can-id-filter-speed-peak-frame-hash
tags:
- ctf
- forensics
- can-bus
- pcap
- automotive
- signal-analysis
- hash
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:37:26+08:00'
  notes: 已对照原文脚本与图11核对：SocketCAN ID解析、unique payload筛选、data[3..4]/100、峰值137.96/帧号12149、sha256 flag一致
url: /docs/ctf/forensics/ctf-forensics-can-signal-id-filter-speed-peak-frame-hash/
draft: false
kb_aliases:
- The Rogue Beacon
- CAN 干扰帧过滤
- 真实车速信号
- payload 唯一率
- 峰值帧 sha256
- 车联网 pcap 取证
---

## 一句话结论

CAN pcap 中大量 ID 是固定模板的干扰/占线帧（出现次数多但 unique payload 很少），真实车速信号的特征是“帧数多且 payload 随时间连续变化（unique 比例高）”；按 ID 分组、用 unique payload 数筛出真实 ID，按 `data[3..4]` 大端解析车速（/100 km/h），取峰值速度所在帧号并对其做 SHA-256，即得 flag。

## 原理

- **SocketCAN pcap 结构**：CAN 帧在 Raw 层中前 4 字节是小端 CAN ID（需 `& 0x1FFFFFFF` 去掉标志位），第 8 字节之后是数据区；按 ID 分组即可分析每个信号的 payload 序列。
- **干扰帧特征**：CAN ID 固定、出现次数稳定（如 825 次）、payload 循环模板化（去重后只有 4~8 种）、数值跳动不连续或完全重复、DLC 可变但有效数据少；这些是占线/伪造/填充帧。
- **真实信号特征**：帧数多且 unique payload 数也多，数值随时间平滑变化（车速、转速等物理量）；用 `len(unique_payloads) > 100` 一类阈值即可把真实 ID 与干扰 ID 分开。
- **解析车速**：本题真实 ID 的 `data[3]`（高字节）与 `data[4]`（低字节）组成 16 位大端 `raw_speed`，`speed_kmh = raw_speed / 100`；遍历该 ID 的所有帧，记录峰值速度与对应帧号。
- **flag 计算**：题目要求对“峰值帧序号”做 SHA-256；`sha256(str(peak_frame))` 得到 64 位十六进制，即 flag（`9db878fd...`）。
- **为什么可行**：CAN 数据区对上层是任意字节，物理信号与干扰帧在统计特征上差异明显；按 ID + payload 唯一率筛选比逐帧肉眼观察可靠。

## 触发条件

- 拿到 CAN 总线 pcap（SocketCAN/Vector 等）、能解析 Raw 层与 CAN ID。
- 数据中包含至少一个真实物理量信号与多个干扰/填充 ID。
- 知道或能推断目标信号的字节偏移与缩放（本题 `data[3..4]` /100）。
- 题目要求对峰值帧号/峰值数据做哈希或拼接。

## 利用步骤

1. **按 ID 分组**：遍历 pcap，解析 `can_id = struct.unpack("<I", raw[0:4])[0] & 0x1FFFFFFF`，`data = raw[8:]`。
2. **计算唯一率**：对每个 ID 统计帧数与 unique payload 数；帧数多且 unique 多的 ID 为真实信号，unique 很少的为干扰。
3. **解析物理量**：按 `data[3]<<8 | data[4]` 取 16 位大端，除以 100 得 km/h；遍历记录峰值与帧号。
4. **计算 flag**：`hashlib.sha256(str(peak_frame).encode()).hexdigest()`。
5. **验证**：检查峰值是否合理（本题 137.96 km/h），帧号唯一；若信号字节偏移不同，尝试 `data[0..1]` 等其他组合。

## PoC

```python
from scapy.all import rdpcap, Raw
from collections import defaultdict
import struct, hashlib

can_data = defaultdict(list)
frame_no = 0
for pkt in rdpcap("The Rogue Beacon.pcap"):
    frame_no += 1
    if Raw not in pkt:
        continue
    raw = bytes(pkt[Raw])
    if len(raw) < 8:
        continue
    cid = struct.unpack("<I", raw[0:4])[0] & 0x1FFFFFFF
    can_data[cid].append((frame_no, raw[8:]))

real_id = None
for cid, lst in can_data.items():
    unique = {d for _, d in lst}
    if len(lst) > 100 and len(unique) > 100:
        real_id = cid
        break

peak_speed, peak_frame = -1, -1
for fn, data in can_data[real_id]:
    if len(data) < 5:
        continue
    speed = ((data[3] << 8) | data[4]) / 100.0
    if speed > peak_speed:
        peak_speed, peak_frame = speed, fn

print(real_id, peak_speed, peak_frame)
print(hashlib.sha256(str(peak_frame).encode()).hexdigest())
```

原文输出：真实 ID `0x4020000`、峰值 137.96 km/h、帧号 12149、flag `9db878fd06dd7587a91c0fb600e0e9f7c3ea310e75f36253ef57ac2d92dd8c29`。

## 变体与关联

- 变体：真实信号可能是转速/油门/温度，字节偏移与缩放不同；干扰帧可能用相同时间戳/重复帧；可用熵、差分、周期稳定性、DBC 文件辅助筛选。
- 关联：[[ctf-forensics-can-repeated-frame-trailing-byte-covert-channel]]（CAN 重复帧末字节隐蔽信道）、[[ctf-forensics-pcap-http-xor-exfil-key-recover]]（pcap 信号/密钥恢复）、[[pentest-recon-frontend-js-aes-key-encrypted-credential-mqtt-validation]]（车联网 MQTT 侧的另一类分析）。
- 同题：`The Rogue Beacon` 的干扰 ID 与真实车速 ID `0x4020000`。

## 检测与防御

- **CTF 之外**：CAN 总线无认证/加密，攻击者可注入伪造帧；车载网络应使用 SecOC/IDS、网关白名单、消息认证。
- **取证**：按 ID 统计 payload 唯一率、周期、差分，区分真实信号与注入/干扰帧；保留原始 pcap 与 DBC。
- **检测**：监控异常 ID、固定模板高频帧、与物理量不符的突变；对关键信号做范围/速率校验。
