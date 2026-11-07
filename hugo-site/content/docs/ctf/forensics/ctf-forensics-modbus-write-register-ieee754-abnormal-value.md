---
id: ctf-forensics-modbus-write-register-ieee754-abnormal-value
title: Modbus/TCP 异常写寄存器定位：0x10 多寄存器写入 + IEEE754 浮点还原
type: scenario
domain: ctf
path: ctf/forensics
technique: modbus-write-multiple-registers-ieee754-abnormal
tags:
- ctf
- forensics
- modbus
- ics
- ieee754
- pcap
- traffic-analysis
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-06'
updated: '2026-11-06'
url: /docs/ctf/forensics/ctf-forensics-modbus-write-register-ieee754-abnormal-value/
draft: false
kb_aliases:
- Modbus 功能码 16
- 0x10 写多个保持寄存器
- IEEE754 浮点
- 工控流量取证
- Modbus/TCP HEX
- 异常设定值
---

## 一句话结论

在 Modbus/TCP 抓包中先用 `modbus.func_code == 0x10` 过滤“写多个保持寄存器”，展开 MBAP+PDU 看起始寄存器号、寄存器数量、字节数和数据区；两个连续寄存器（4 字节）常被组态软件编码为大端 IEEE754 浮点，用来表示温度/压力等模拟量设定值。把数据区按 `>f` 解码并与后续正常写入对比，即可定位异常设定值，并直接按 MBAP 起止字节还原该帧的原始 HEX。

## 原理

- **Modbus/TCP 帧结构**：MBAP 头 7 字节（事务号 2 + 协议号 2 + 长度 2 + 单元号 1），随后是 PDU：功能码 1 字节 + 数据。功能码 `0x10`（十进制 16）是 Write Multiple Registers，PDU 为“起始寄存器地址 2 + 寄存器数量 2 + 字节数 1 + 数据 N”。
- **模拟量常以两个寄存器承载**：一个 16 位寄存器放不下 IEEE754 单精度浮点，所以组态软件把 32 位 float 拆成两个连续保持寄存器，按大端（高字在前）传输。寄存器数量 2、字节数 4 是典型特征。
- **异常值在写方向**：正常轮询多为功能码 1/2/3/4 的读请求；攻击者/故障注入会写单个或多个保持寄存器。对比同一寄存器地址的多次写入（如先写 639.56 再写回 620.0），可区分异常设定与正常回设。
- **原始 HEX 就是证据**：题目/取证要求“发送异常的 modbus/TCP 层 HEX 数据”时，从 MBAP 首字节截到 PDU 数据末字节，去掉空格即为完整帧；不需要重算 CRC（Modbus/TCP 没有 CRC，CRC 只存在于 Modbus RTU）。
- **为什么成立**：协议字段是明文且长度自描述，任何写操作都可按寄存器地址/数量/数据精确还原；浮点解释只是对 4 字节数据的语义映射，不改变原始帧。

## 触发条件

- 有 Modbus/TCP 抓包（pcap/pcapng），端口通常为 502。
- 流量中存在功能码 `0x10`（或 `0x06` 单寄存器写）的写操作。
- 需要判断哪个写操作异常（设定值越界、与正常值差异大），或需要提交原始 Modbus/TCP HEX。
- 数据区长度为 4 的倍数，且寄存器数量为 2 的倍数时，优先尝试 IEEE754 单精度。

## 利用步骤

1. 用 Wireshark 过滤器 `modbus.func_code == 0x10`（或 `modbus || tcp.port == 502`）筛出写多寄存器请求。
2. 选中一帧，展开 `Modbus/TCP`：记录 Transaction ID、Unit ID、起始寄存器地址、寄存器数量、字节数、数据区。
3. 若寄存器数量为 2、字节数为 4，把 4 字节数据按大端 IEEE754 解码：`struct.unpack('>f', bytes.fromhex('441fe3d7'))`。
4. 在同一寄存器地址上找后续写入，解码对比；异常值（如明显高于正常设定）即为目标。
5. 在 Wireshark 的十六进制视图从 MBAP 首字节选到数据末字节，复制为十六进制串；或按字段手工拼接，得到 `事务号+0000+长度+单元号+10+起始地址+数量+字节数+数据`。
6. 去掉空格/换行，按题目要求包成 `flag{...}` 或作为证据保存。

## PoC

```python
import struct

# 功能码 0x10 数据区常见的大端 IEEE754 单精度
for h in ("441fe3d7", "441b0000"):
    print(h, struct.unpack(">f", bytes.fromhex(h))[0])

# 重建原始 Modbus/TCP 帧（字段来自抓包）
frame = bytes.fromhex(
    "0c01"      # Transaction ID
    "0000"      # Protocol ID = Modbus
    "000b"      # Length = 11
    "01"        # Unit ID
    "10"        # Function 0x10
    "0016"      # Start register = 22
    "0002"      # Register count = 2
    "04"        # Byte count = 4
    "441fe3d7"  # Data = 639.56f
)
print(frame.hex())
```

说明：字节序也可能是小端/字交换，需结合设备手册或同流量中的已知正常值验证；功能码 `0x06` 只写一个 16 位寄存器，不能直接套 4 字节浮点。

## 变体与关联

- 变体：功能码 `0x06` 写单寄存器，值按 16 位整数/定点数解释；功能码 `0x0F` 写线圈，按位解释。
- 变体：双字/64 位浮点占 4 个寄存器，按 `>d` 解码；或使用字交换（`<f`、字节反转）。
- 变体：异常值可能写在保持寄存器、输入寄存器或线圈，需分别看功能码。
- 关联：[[ctf-forensics-modbus-private-pcap-write-register-covert]]（Modbus 写寄存器承载 Base64 隐蔽载荷）；[[iot-industrial-s7comm-elevator-multi-db-state-forgery]]（S7comm 写 DB 伪造状态）；[[iot-industrial-scada-snapshot-mmap-state-forgery]]（SCADA 状态伪造）。

## 检测与防御

- 检测：对 Modbus 写操作做基线，监控对温度/压力/液位等关键设定值寄存器的写入；异常值（超出工艺范围）立即告警。
- 检测：识别非轮询周期的写请求、非常规源 IP、写入频率突变；同一寄存器短时间被改回也值得关注。
- 防御：PLC/RTU 侧对关键寄存器做写保护或范围校验；网络分区与 Modbus 深度包检测；对 HMI/组态软件账号做最小权限。
- 防御：保留原始 pcap 与寄存器写入日志，便于按 MBAP 帧还原操作序列。
