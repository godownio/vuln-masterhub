---
id: iot-industrial-s7comm-write-var-payload-extraction
title: S7comm Write Var 流量提取：筛 func=0x05/rosctr=Job 还原 PLC 写入载荷
type: scenario
domain: iot
path: iot/industrial
technique: s7comm-write-var-payload-extraction
tags:
- iot
- industrial
- s7comm
- plc
- pcap
- wireshark
- tshark
- forensics
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V201
  verified_at: '2026-11-07T02:10:31+08:00'
  notes: 已对照原文与全部61张图核对；未复跑PoC
url: /docs/iot/industrial/iot-industrial-s7comm-write-var-payload-extraction/
draft: false
kb_aliases:
- S7comm 数据提取
- Write Var 0x05
- 西门子 S7 流量分析
- s7comm.param.func
- PLC 写入载荷
- S7 协议取证
---

## 一句话结论

S7comm 的写变量请求（`rosctr=Job`、`param.func=0x05`）在数据区携带实际写入 PLC 的字节；用 Wireshark/tshark 按这两个字段过滤，把每个 Write Var 数据项的 `Data` 按帧顺序拼接，并按 transport size 解释字节序，就能还原 HMI/工程师站写入 PLC 的原始载荷（如 ASCII 消息）。

## 原理

- **协议栈**：S7comm 通常跑在 ISO-on-TCP（TPKT + COTP，端口 102）之上；S7 PDU 头部含 `ROSCTR`（1=Job、2=Ack、3=Ack_Data、7=Userdata），参数区含功能码（0x04 Read Var、0x05 Write Var 等），数据区按“数据项”列出返回码、transport size、长度和实际数据。
- **Write Var 的语义**：HMI、SCADA、工程师站通过 0x05 把值写入 PLC 的 DB/输入/输出/标志区；数据项里的 `Data` 就是写入内容的原始字节，可能是 BYTE、WORD、DWORD、REAL 等类型，长度由 transport size 与 length 字段决定。
- **提取思路**：过滤所有 Job 类型的 Write Var 请求，按帧号/时间顺序取出每个数据项的 `Data` 字节并拼接；若一次写多个变量，需要按数据项顺序分别记录，不能简单把所有字节混在一起。
- **字节序**：S7comm 的多字节数值通常为大端（网络字节序）；`WORD`/`DWORD`/`REAL` 要按大端解释，`BYTE` 直接取单字节。ASCII 文本可直接按字节转字符。
- **为什么有效**：PLC 信任来自上位机的写请求，流量中明文携带写入值；对工控取证/协议逆向来说，Write Var 是恢复操作内容、异常设定值和攻击者注入数据的直接证据。
- **结果不一定是最终语义**：拼接出的字节可能被拆成多个变量、按位/字交错，或经过应用层编码；需要结合 DB 点位表、变量类型和业务语义还原。示例中拼接得到 `IpOtatn!oITrm_i`，再按单词/结尾标点重排为 `IIOT_important!`。

## 触发条件

- 抓到 S7comm 流量（端口 102 或映射端口），且包含完整的 Write Var 请求与数据区。
- Wireshark 能识别 S7comm 协议（未加密/未封装在私有协议中）；若为私有封装，需先剥离外层。
- 知道或能推断数据项的类型/长度/字节序；对多变量写入需要点位表。
- 目标是 PLC/工控设备，写操作未被 S7 安全机制（如写保护、密码）阻断。

## 利用步骤

1. 用 Wireshark 打开 pcap，应用过滤：`s7comm && s7comm.param.func == 0x05 && s7comm.header.rosctr == 1`。
2. 逐帧展开 `S7 Communication → Parameter (Write Var) → Item N`，记录 `Transport size`、`Length`、`Data`；或添加 `Data` 列批量查看。
3. 按帧号/时间排序，把同一数据项的 `Data` 字节拼接；若一次写多个变量，按 Item 分组。
4. 按 transport size 解释：`BYTE` 单字节、`WORD` 2 字节大端、`DWORD`/`REAL` 4 字节大端；ASCII 文本直接转字符。
5. 结合 DB 点位表/变量名，把字节映射回业务字段（设定值、状态字、字符串）；检查是否有位操作/字节交换。
6. 对异常写入（门开、越限、停机、配方修改）做时间线，关联源 IP、PLC 地址与操作员账号。

## PoC

Wireshark 过滤：

```text
s7comm && s7comm.param.func == 0x05 && s7comm.header.rosctr == 1
```

tshark 批量导出（字段名以实际 Wireshark 版本为准；若 `s7comm.data.data` 为空，改用 `-T pdml` 或 GUI 的 Data 项）：

```bash
tshark -r s7.pcapng \
  -Y 's7comm.param.func == 0x05 && s7comm.header.rosctr == 1' \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e s7comm.data.transportsize -e s7comm.data.length -e s7comm.data.data
```

Python 侧按帧拼接并转 ASCII：

```python
import subprocess

out = subprocess.check_output([
    "tshark", "-r", "s7.pcapng",
    "-Y", "s7comm.param.func == 0x05 && s7comm.header.rosctr == 1",
    "-T", "fields", "-e", "frame.number", "-e", "s7comm.data.data",
], text=True)

chunks = []
for line in out.splitlines():
    parts = line.split("\t")
    if len(parts) >= 2 and parts[1]:
        chunks.append(bytes.fromhex(parts[1].replace(":", "")))
print(b"".join(chunks).decode("latin-1"))
```

若一条报文含多个 Item，`-e s7comm.data.data` 会输出多值，需要按 `,` 或字段出现顺序拆分；必要时用 `-T pdml` 保留 Item 层级。

## 变体与关联

- **Read Var（0x04）**：读取 PLC 值的请求/响应，响应数据项同样可按 transport size 还原；可用于恢复 HMI 显示值。
- **Userdata/编程请求**：功能码不同，可能包含下载块、启动/停止 CPU、读诊断缓冲；需按 S7comm 子功能解析。
- **私有封装**：部分厂商把 S7comm 包在自定义 TCP/UDP 或 TPKT 变体中，先用 `data.data`/`tcp.payload` 剥离，再按 S7 PDU 结构解析。
- **加密/签名**：S7-1500 的机密通信或 TLS 封装会阻断明文提取；需先解密或从端点侧取证。
- **关联卡片**：[[iot-industrial-s7comm-elevator-multi-db-state-forgery]]（S7comm 多 DB 写入伪造状态）；[[ctf-forensics-modbus-write-register-ieee754-abnormal-value]]（Modbus 写寄存器异常值定位）。

## 检测与防御

- **访问控制**：PLC 启用写保护/密码，限制可写 DB 与功能码；把编程/写操作限制在工程师站白名单。
- **网络分区**：OT 网络与 IT 网络隔离，S7comm 端口只允许受控主机；部署工控防火墙做功能码/地址白名单。
- **流量审计**：记录所有 Write Var 请求的源 IP、目标 PLC、DB 号、偏移、值与时间；对非维护时段的写入、异常值、批量配方修改告警。
- **取证**：保留 pcap 与 PLC 程序/DB 备份；用点位表把原始字节映射回业务语义，避免误判。
