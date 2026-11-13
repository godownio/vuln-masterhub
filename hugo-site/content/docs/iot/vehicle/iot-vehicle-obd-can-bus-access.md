---
id: iot-vehicle-obd-can-bus-access
title: OBD-II 物理接入读取 CAN 总线报文：针脚定义、接线与请求/响应帧解析
type: scenario
domain: iot
path: iot/vehicle
technique: obd-can-bus-physical-access
tags:
- vehicle
- obd
- can-bus
- physical-access
- reconnaissance
- ecu
- can-frame
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V515
  verified_at: '2026-11-11T11:41:54+08:00'
  notes: 已对照原文及全部7张图核对（01 针脚定义、02 OBD→CAN 工具接线、03 差分电平、04/05 标准帧、06/07 扩展帧；原图均>1200px，worker 已降采样至 img_small 且内容可辨）：6/14=CANH/CANL(ISO 15765-4)、4/5 地、16 常电、7/15 ISO 9141 K/L、3/11 舒适 CAN 与原文表一致；CAN_diff=2V 显性 0、0V 隐性 1、120Ω 终端、11 位标准帧数据 0~64 位、扩展帧 29 位 ID(SRR/IDE=1,r0/r1=0) 均与图一致；EMS_Control/EMS_RPM 系数 30 取自原文报文表。原文为车联网基础教程，无具体车型/组件版本，affected_versions 留空正确；无实际抓包/报文 PoC，卡片已如实标注『无 PoC』，confidence medium 合理。dedup：与既有 CAN 卡（仲裁 ID 发现、UDS 注入、重放、信号挖掘）均为 related 非同链——本卡是其前置的 OBD 物理接入/读报文入口；dup-scan 未涉及。未执行任何接线操作。
url: /docs/iot/vehicle/iot-vehicle-obd-can-bus-access/
draft: false
kb_aliases:
- OBD 接口读 CAN
- 汽车诊断口接入
- CAN 报文读取
- OBD-II 针脚
- CANH CANL 接线
---

## 一句话结论

车辆 OBD-II 诊断口位于驾驶室易接触位置、默认无身份认证，按标准针脚把 CAN 工具的 CANH/CANL 接到 6/14 针、地接 4/5、必要时接 16 针取电后，即可在总线上发送请求帧、读取各 ECU 的响应帧并用 DBC 文件解码，获得转速、车速、故障码等车辆实时数据，为后续重放/注入等攻击提供入口。

## 原理

- **OBD-II 标准化接口**：1996 年后车型普遍使用 16 针 OBD-II 诊断座，针脚定义基本统一：4/5 为信号地/底盘地，16 为 12V 常电，6/14 为 ISO 15765-4 的 CAN-H/CAN-L，7 为 ISO 9141 K 线，15 为 L 线，3/11 为舒适 CAN-H/L，1 为点火 12V。诊断座通常在仪表台下方/脚踏板上方，物理可达。
- **CAN 差分信号**：CAN-H 与 CAN-L 构成差分对，CAN_diff≈2V 表示逻辑 0（显性），CAN_diff≈0V（两线均 2.5V）表示逻辑 1（隐性）；双绞线让外部干扰同时作用于两根线，电压差保持不变；总线两端有 120Ω 终端电阻抑制反射。
- **仲裁与帧结构**：多节点同时发送时按“线与”仲裁——显性 0 覆盖隐性 1，ID 越小优先级越高。标准帧含 SOF、11 位 ID、RTR、IDE、r0、DLC、0~64 位数据、15 位 CRC、CRC 分隔符、ACK、EOF；扩展帧使用 29 位 ID（SRR/IDE 置位、r0/r1 为 0）。CAN 收发器还做位填充（连续 5 个相同位后插入 1 个反相位）。
- **请求/响应访问 ECU**：CAN 工具（如 CANoe、USB-CAN 分析仪）接上总线后，按 ISO-TP/厂商诊断协议发送“请求帧”（目标 ECU 的诊断 ID），对应 ECU 回“响应帧”；用 DBC 文件把原始字节按信号定义（起始位、长度、系数、偏置）解码为物理量（转速、车速、温度等），也可读取/清除故障码（DTC）。
- **为什么是安全问题**：OBD 口物理可达、无口令/凭证、多数车型的 CAN 总线缺少报文认证与加密，诊断功能又天然允许读写 ECU；攻击者只要有短暂物理接触，就能被动监听或主动注入。

## 触发条件

- 能物理接触车辆 OBD-II 接口（短时进入车内即可）。
- 目标车辆 CAN 总线未做网关隔离/报文认证（多数传统车型如此）。
- 攻击者持有 CAN 接口工具（USB-CAN、CANoe、OBD 诊断仪等）与对应车型的 DBC/诊断数据库（可从公开资料/第三方工具获取）。

## 利用步骤

1. 定位 OBD-II 接口（驾驶座下方/仪表板附近），车辆处于点火/通电状态。
2. 接线：CAN 工具 CANH → OBD 6 针，CANL → 14 针，GND → 4/5 针；工具需要供电时接 16 针常电（注意电压与保险）。
3. 打开 CAN 分析工具，设置波特率（常见 500kbps；部分车型 250kbps），开始监听总线报文。
4. 按车型诊断 ID 发送请求帧，观察对应 ECU 的响应帧；用 DBC 解码数据（如 EMS_Control 报文的 EMS_RPM 信号：起始位 7、长度 8bit、系数 30、偏置 0）。
5. 记录可复现的请求/响应序列与 ID 列表，用于后续重放、注入或深入研究（解锁、诊断例程等）。

## PoC

无 PoC（物理接线与工具操作流程）。关键接线对照：

| OBD-II 针脚 | 信号 | 连接 |
|---|---|---|
| 6 | CAN-H（ISO 15765-4） | CAN 工具 CANH |
| 14 | CAN-L（ISO 15765-4） | CAN 工具 CANL |
| 4/5 | 信号地/底盘地 | GND |
| 16 | 12V 常电 | 工具供电（可选） |
| 7 / 15 | K 线 / L 线（ISO 9141） | 老车型诊断线（可选） |
| 3 / 11 | 舒适 CAN-H / CAN-L | 舒适系统总线（可选） |

示例报文定义（DBC 字段含义）：报文 ID 100、周期 10ms、8 字节，其中 `EMS_RPM` 起始位 7、长度 8bit、系数 30、偏置 0。

## 变体与关联

- 变体：不只读，CAN 帧无认证时可直接重放/注入伪造报文（如伪造车速、车门状态、诊断响应）；也可对诊断协议做模糊测试。
- 变体：部分车型的 CAN 网关把诊断口与关键总线隔离，需要先通过网关/诊断会话进入目标域；网关配置错误或双总线车型（舒适 CAN 3/11）可绕过。
- 关联：[[iot-vehicle-gps-l1-spoofing-gps-sdr-sim-hackrf]]（同为车辆物理/无线层攻击入口）、[[iot-vehicle-camera-debug-console-20000-unauth]]（车机侧未授权调试口）。
- 边界：车辆使用 CAN-FD/SecOC、网关强制认证或 OBD 口被物理锁定/禁用时，简单接入读取不成立。

## 检测与防御

- 加固：用网关隔离诊断口与安全关键总线；对诊断/控车报文做 SecOC/MAC 认证；OBD 口加物理锁或访问检测。
- 检测：车辆日志记录诊断口接入、异常诊断请求与高频/未知 ID 报文；CAN 入侵检测（ID 白名单、周期/长度异常、仲裁错误率）。
- 响应：对可疑接入做取证（工具接入时间、报文记录），评估是否发生重放/注入。
