---
id: ctf-forensics-adsb-pcap-pymodes-fastest-icao-md5
title: ADS-B 报文 pcap 解码：pyModeS 提取 ICAO 与速度找最快飞机
type: scenario
domain: ctf
path: ctf/forensics
technique: adsb-pymodes-velocity-icao
tags:
- ctf
- forensics
- pcap
- ads-b
- mode-s
- aviation
- pymodes
- md5
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V604
  verified_at: '2026-11-12T18:39:53+08:00'
  notes: 已对照原文与全部8图核对：正文谍影重重2.0 用 tshark -T fields -r attach.pcapng -e tcp.payload 提取载荷，按 len==46、msg=d[18:] 截取 28 hex 报文，pyModeS pms.icao/pms.adsb.velocity 遍历得 v_max=[371,'79a05e']，md5('79A05E')=4cf6729b9bc05686a79c1620b0b1967b（小写 ICAO 不匹配，原文已试）；图03 为 mode-s.org 的 DF17/CA/ICAO/ME/PI 位域示例，与卡内结构说明一致。修正一处技术错误：原卡称 TC=4-8 也可能含速度信息，实际 TC=5-8 为地面位置、velocity 只处理 TC=19，已改为准确映射并注明原文代码注释 4<TC<9 的可疑写法。affected_versions 留空正确（CTF题）。dedup 报告判 new 且无 related 候选，与库内 CAN/Modbus/SMTP pcap 卡协议完全不同，保留。未验证点：pcap 附件未在本地复跑，md5 结果取自原文。
url: /docs/ctf/forensics/ctf-forensics-adsb-pcap-pymodes-fastest-icao-md5/
draft: false
kb_aliases:
- ADS-B 解码
- pyModeS
- 飞机速度 ICAO
- Mode-S DF17
- 谍影重重
- 最快飞机 md5
---

## 一句话结论

pcap 中若出现 112 位（28 个十六进制字符）的 Mode-S/ADS-B 报文，可用 `tshark -e tcp.payload` 提取载荷、再用 pyModeS 解码每条报文的 ICAO 地址与速度（`pms.adsb.velocity`），遍历取速度最大的飞机，按题目要求对 ICAO（大写）做 MD5 即为 flag。

## 原理

- **ADS-B 报文结构**：ADS-B 属于 Mode-S 扩展 squitter，下行格式 DF=17（二进制 `10001`）；一条报文 112 bit = 14 字节 = 28 个 hex 字符，字段依次为 DF(5)、CA(3)、ICAO(24)、ME(56)、PI(24)。ICAO 是飞机的 24 位地址，ME 的类型码（TC）决定内容：TC=1-4 为识别/呼号，TC=5-8 为地面位置，TC=9-18 为空中位置，TC=19 为速度；`pms.adsb.velocity` 只处理 TC=19 的报文，其余类型会抛异常（原文代码注释写 4<TC<9 或 TC=19，实际可解速度的是 TC=19，靠 try/except 跳过非速度报文）。
- **速度解码**：`pms.adsb.velocity(msg)` 返回 `(速度, 航向/角度, 垂直速率, 速度类型)`；只有速度类报文能解出速度，其他类型会抛异常，遍历时 try/except 跳过即可。
- **数据来源**：题目 pcap 常把 ADS-B 报文放在 TCP payload 的十六进制文本里；`tshark -T fields -e tcp.payload` 每行输出一段 hex，可能带时间戳/序号前缀，需按长度或位置截取 28 位报文。
- **为什么取最大速度**：题目描述“找飞得最快的飞机”，对所有可解码报文求速度最大值，记录对应 ICAO；按格式对 ICAO 做 `md5(ICAO.upper())` 得到 flag（大小写按题目要求，原文小写不匹配、大写才正确）。
- **识别信号**：pcap 中大量等长 28 hex 字符串、DF 字段以 `8D`/`8` 开头、无正常应用层协议；可能是 ADS-B 原始报文。

## 触发条件

- pcap 捕获了 ADS-B/Mode-S 原始报文（常见于 1090MHz 接收机转发的 TCP/UDP 数据）。
- 报文以十六进制文本或二进制形式存在，能被提取为 28 位 hex。
- 题目要求定位某类飞机（最快、特定呼号、特定位置）并按规则生成 flag。

## 利用步骤

1. 用 `tshark -T fields -r <pcap> -e tcp.payload > 1.txt` 提取 TCP 载荷；UDP 用 `-e udp.payload`。
2. 过滤长度合适的行，截取 28 位十六进制报文（去掉时间戳/序号前缀）。
3. 用 pyModeS 遍历：`pms.icao(msg)` 取 ICAO，`pms.adsb.velocity(msg)` 取速度；异常跳过。
4. 记录速度最大值及对应 ICAO；若题目要求呼号可用 `pms.adsb.callsign(msg)`。
5. 按题目格式对 ICAO（注意大小写）做 MD5/其它编码得到 flag。

## PoC

```python
import pyModeS as pms
from hashlib import md5

with open('1.txt', encoding='utf-8') as f:
    data = [s for s in f.read().splitlines() if s != '']

v_max = [0, '']
for d in data:
    if len(d) != 46:          # 视 tcp.payload 前缀长度调整
        continue
    msg = d[18:]              # 截取 28 位报文，偏移按实际数据调整
    icao = pms.icao(msg)
    try:
        v = pms.adsb.velocity(msg)
        if v[0] > v_max[0]:
            v_max = [v[0], icao]
    except Exception:
        pass

print(v_max)                  # [371, '79a05e']
print(md5(v_max[1].upper().encode()).hexdigest())
```

## 变体与关联

- **变体（解码目标）**：呼号/识别（TC 1-4）、位置（TC 9-18，CPR 全局/局部解码）、高度、速度（TC 19）。
- **变体（工具）**：dump1090、readsb、`modes-decoder`、自写位域解析；pyModeS 也支持 Comm-B/ACARS。
- **关联**：[[ctf-forensics-pcap-http-order-vm-opcode-reconstruction]]（pcap 提取与重建思路）、[[ctf-forensics-sstv-audio-image-decode]]（另一种信号解码题）。
- **边界**：pcap 中只有二进制原始 IQ 采样而非解码后的报文时，需先做 demod；报文残缺/非 DF17 时无法用 `pms.adsb.velocity`。

## 检测与防御

- 本卡为 CTF 取证解题思路。现实场景中 ADS-B 广播无认证、可被伪造/注入，可用于飞机位置欺骗与流量分析，防御上依赖多源校验（雷达/MLAT）。
