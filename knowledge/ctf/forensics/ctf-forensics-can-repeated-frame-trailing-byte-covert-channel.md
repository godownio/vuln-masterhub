---
id: ctf-forensics-can-repeated-frame-trailing-byte-covert-channel
title: CAN 重复帧末字节隐蔽信道：按 ID 过滤 pcap 提取隐藏数据还原 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: can-repeated-frame-trailing-byte-covert-channel
aliases:
- CAP2
- CAN 隐蔽信道
- 重复帧末字节
- CAN pcap 取证
- 末字节隐写
tags:
- forensics
- can-bus
- pcap
- steganography
- covert-channel
- ctf
- automotive
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:51:07+08:00'
  notes: 已对照原文与图12/14核对：ID 157 成对重复帧、仅末字节变化、0.000000 重复时间戳作干扰、剔除后取末字节拼接得 05B2873A2FA21D297D3442FF、flag_ 前缀一致；原文正文称“最后一位(bit)”但截图与结果实为末字节，卡片已按数据说明并保留该注记。原文为 CTF 仿真 pcap，未在本机重放提取。
---

## 一句话结论

CAN pcap 中同一 ID 的帧成对出现、除最后一字节外完全相同，且重复帧使用相同时间戳（如 0.000000）作干扰；过滤该 ID、剔除重复时间戳帧后按时间顺序取末字节并十六进制拼接，即可还原隐藏数据（CAP2 中为 `05B2873A2FA21D297D3442FF`，flag 为 `flag_05B2873A2FA21D297D3442FF`）。

## 原理

- CAN 数据帧的 0–8 字节数据区对上层是任意字节，协议本身不校验“业务语义”；把隐藏信息放入周期性正常帧的末字节，其余字段保持合法值，可让流量在 ID/周期/长度上看起来正常。
- 成对帧 + 相同时间戳（0.000000）是干扰项：同一 ID 在极短时间出现两条几乎相同的帧，只有末字节不同；若不剔除伪造时间戳帧，提取序列会被重复值污染。
- pcap 保存原始帧与时间戳，按 ID 过滤后即可逐帧读取末字节；CAP2 的 12 个有效末字节 `05 B2 87 3A 2F A2 1D 29 7D 34 42 FF` 拼起来就是 flag 的十六进制主体。
- 该手法本质是协议字段隐蔽信道（covert channel）：用合法帧的未校验字段承载数据，规避基于 ID/频率/长度的粗粒度检测。

## 触发条件

- 拿到包含 CAN 流量的 pcap/日志，且能被 Wireshark/tshark 或文本工具解析。
- 存在同一 ID 的重复帧，除末字节外其余字段相同；有可区分的时间戳（含伪造的重复时间戳）。
- 需要已知/可猜测承载信道的 ID（可通过统计重复模式定位）。

## 利用步骤

1. 用 Wireshark 打开 pcap，或 `tshark -r cap2.pcap -Y "can" -T fields -e frame.time_epoch -e can.id -e can.data` 导出。
2. 统计各 ID 的帧数与重复模式，找“成对出现、仅末字节不同”的 ID（CAP2 为 157）。
3. 过滤该 ID，按时间戳排序；剔除时间戳重复（如 0.000000）的干扰帧。
4. 按时间顺序取每帧最后一个字节，十六进制拼接。
5. 将结果按 ASCII/hex 解读；CAP2 得到 `05B2873A2FA21D297D3442FF`，加 `flag_` 前缀即 flag。

## PoC

```bash
# 文本形态的 CAN 抓包（CAP2 可直接 grep；末字段为最后一字节）
grep " 157 " cap2.pcap | grep -v "^0.000000" | awk '{print $NF}' | tr -d '\n'
# 输出 05B2873A2FA21D297D3442FF（末字节序列）
```

```python
# 二进制 pcap：用 scapy 解析 CAN 帧
from scapy.all import rdpcap
from scapy.layers.can import CAN

frames = []
for pkt in rdpcap("cap2.pcap"):
    if pkt.haslayer(CAN) and pkt[CAN].id == 0x157:
        ts = float(pkt.time)
        if ts == 0.0:          # 剔除伪造时间戳重复帧
            continue
        frames.append((ts, bytes(pkt[CAN].data)))
frames.sort()
hexstr = "".join(f"{d[-1]:02X}" for _, d in frames)
print(hexstr)  # 05B2873A2FA21D297D3442FF
```

> 原文正文表述为“最后一位（bit）不同”，但截图与提取结果实际是**最后一字节**；以数据为准，按末字节提取。

## 变体与关联

- 变体：隐藏位放在最后一位 bit、counter 字段、DLC 或 ID 空间；提取时按位/按字段重组。
- 变体：用时间戳、帧间隔或帧顺序编码（时序隐蔽信道），而非载荷字节。
- 关联：[[iot-protocol-hartip-command9-quadrant-covert-channel]]（工控协议字段隐蔽信道）、[[ctf-forensics-tcp-urgent-pointer-covert-channel]]（协议头隐写）、[[ctf-forensics-modbus-private-pcap-write-register-covert]]（Modbus 寄存器隐蔽载荷）、[[iot-protocol-can-log-signal-mining]]（CAN 流量信号分析）。

## 检测与防御

- 检测：CAN IDS 统计同一 ID 的重复帧/相同时间戳/单字节差异；对周期性帧做基线比对，检测末字节异常熵或非物理量变化；跨帧关联发现成对噪声帧。
- 防御：SecOC 消息认证覆盖完整数据区；网关对重复/异常时间戳帧去重；对关键 ID 做白名单与速率限制。
- 取证：保留原始 pcap 与时间戳，先按 ID 分组再剔除重复时间戳，避免把干扰帧当数据。
