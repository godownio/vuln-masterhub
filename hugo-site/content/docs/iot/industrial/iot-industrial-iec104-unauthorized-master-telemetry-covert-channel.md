---
id: iot-industrial-iec104-unauthorized-master-telemetry-covert-channel
title: IEC 104 未授权主站接入：总召唤遥测值编码隐蔽信道外传
type: scenario
domain: iot
path: iot/industrial
technique: iec104-unauthorized-master-telemetry-covert-channel
tags:
- ics
- ot
- iec104
- iec60870
- scada
- unauthorized-master
- covert-channel
- telemetry
- pcap
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:47:54+08:00'
  notes: 已对照原文核对；typeid 100 总召唤、台账白名单判据、遥测值按 IOA 排序拼 ASCII 一致
url: /docs/iot/industrial/iot-industrial-iec104-unauthorized-master-telemetry-covert-channel/
draft: false
kb_aliases:
- IEC 104 未授权主站
- IEC60870-5-104 隐蔽信道
- 总召唤遥测外传
- C-IC-NA-1 信息对象值编码
---

## 一句话结论

IEC 104 远动系统若只靠台账/地址白名单区分主站、没有协议级认证，未登记的攻击者可直接连接 RTU 并发送总召唤（C-IC-NA-1，typeid 100）；RTU 返回的遥测信息对象值被攻击者预先编码为 ASCII，按信息对象地址排序拼接即可从正常遥测报文中还原外传内容。

## 原理

- IEC 60870-5-104 运行在 TCP 240 端口，RTU 侧监听，主站主动连接；链路建立走 STARTDT，应用层 ASDU 承载总召唤、遥测、遥信、遥控等。
- 总召唤类型标识为 100（C-IC-NA-1），响应 ASDU 携带大量信息对象（IOA + 遥测值）；正常遥测是模拟量/归一化值，值域有限。
- 若 RTU 没有主站白名单/协议级认证，任何能路由到 240 端口的节点都可发起总召唤；攻击者不在台账中即为未授权主站。
- 隐蔽信道：攻击者控制/影响遥测点值，把 ASCII 字节写入信息对象值；接收端按 IOA 排序后取低字节拼接，得到任意文本。遥测值在协议上仍是合法数值，流量形态与正常总召唤响应一致。
- 与 IP 层隐蔽信道不同，这类信道位于工控应用层，绕过传统 IT 流量检测；判据应结合主站台账、连接时序与遥测值域异常。

## 触发条件

- RTU/网关的 240 端口可从攻击者网络访问，且未部署 IEC 104 SA（安全认证）或主站白名单。
- 攻击者可向 RTU 发送 STARTDT 与总召唤 ASDU；RTU 接受未登记主站的连接。
- 攻击者可影响/写入遥测点值（例如通过另一个未授权控制通道、被控 RTU 配置或恶意主站），或能诱导 RTU 返回攻击者预设值。
- 接收端能抓包并解析 IEC 104 ASDU；镜像口能看到全部主站通信。
- 遥测值域检查不严，异常值不会被立即丢弃/告警。

## 利用步骤

1. 抓包并按 TCP 240/IEC 104 过滤，识别 STARTDT、总召唤（typeid 100）与响应 ASDU。
2. 统计发起总召唤的源地址，与主站台账比对；台账外的地址即未授权主站。
3. 提取总召唤响应中的信息对象：IOA（3 字节小端）+ 遥测值（2 字节有符号/无符号，按 ASDU 类型解释）。
4. 找出超出正常值域的 IOA/值，按 IOA 升序排列，取每个值的低字节拼成字节流。
5. 将字节流按 ASCII/UTF-8 解码，得到外传文本/凭据/指令。
6. 关联未授权主站与隐蔽信道：同一源地址触发的响应中出现编码序列，即可确认。

## PoC

```bash
# 统计总召唤发起者（typeid 100 = C-IC-NA-1）
tshark -r windfarm.pcap -Y "iec60870_asdu.typeid==100" \
  -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn
```

```python
def extract_measured(frame):
    body = frame[14:]                       # 跳过链路/应用层头，按实际偏移调整
    ioa = int.from_bytes(body[0:3], "little")
    value = int.from_bytes(body[3:5], "little", signed=True)
    return ioa, value

# 对未授权主站触发的响应逐个提取，按 IOA 排序后取低字节
items = sorted((ioa, value) for ioa, value in measured_items)
payload = bytes(value & 0xFF for _, value in items)
print(payload.decode(errors="replace"))
```

无真实目标 PoC：原文为 CTF pcap，ASDU 偏移、类型与 IOA 编码需按实际协议解析；卡内不包含题目 flag。

## 变体与关联

- **其他 IEC 104 字段**：遥信变位、累计量、归一化值、品质位、时标、ASDU 公共地址/原因码都可编码。
- **其他工控协议**：Modbus 寄存器、DNP3 对象、S7 数据块、OPC UA 节点值、MMS 变量。
- **控制通道**：未授权主站还可下发遥控/设点命令，造成物理影响；隐蔽信道可双向（主站写、RTU 回读）。
- **关联**：HART-IP 状态字段隐蔽信道、Modbus 未授权访问、SCADA 协议逆向、工控网络分区。

## 检测与防御

- **主站白名单**：在 RTU/防火墙层只允许登记的主站 IP/端口连接 240；拒绝未授权 STARTDT/总召唤。
- **协议级认证**：部署 IEC 62351-5/IEC 104 SA 或等效的链路认证，避免仅靠地址白名单。
- **遥测值域与业务校验**：对 IOA 值域、变化率、品质位做基线；告警超范围/固定模式/ASCII 可打印序列。
- **网络分区**：OT 网络与 IT/互联网隔离，镜像口只读；禁止公网直接访问 RTU。
- **检测**：监控未登记源地址的总召唤、异常高频连接、响应中连续 IOA 的可打印字节序列；结合台账与资产指纹。
- **响应**：阻断未授权主站，检查 RTU 配置与遥测点是否被篡改，审计其他工控协议连接，恢复可信配置。

## 可信度与边界

- 原文为 CTF pcap，未授权主站识别、总召唤响应解析与遥测值还原均有实测输出；攻击链完整。
- 实际 IEC 104 部署可能使用不同 ASDU 类型/偏移、代理/网关与认证；需按现场协议解析。
- 未在真实 RTU 复跑 PoC；卡内不包含题目 flag。
