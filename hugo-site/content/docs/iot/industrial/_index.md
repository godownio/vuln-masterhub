---
title: 工业控制
weight: 1
---

# 工业控制

## 这层是什么

PLC、SCADA、DCS 与 OT 协议。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [IEC 104 未授权主站接入：总召唤遥测值编码隐蔽信道外传](iot-industrial-iec104-unauthorized-master-telemetry-covert-channel/) | verified | high | 2026-11-06 |
| [IEC 60870-5-104 报文结构与关键帧构造：APCI 长度/控制域 I·S·U、ASDU VSQ/COT/公共地址/IOA，总召、单双点遥控（选择-执行）、对时与复位帧](iot-industrial-iec104-apci-asdu-frame-construction/) | verified | high | 2026-11-10 |
| [MMS fileWrite 恶意固件上传取证：TPKT/COTP/MMS TLV 重组与 XOR/ZIP/LZMA 分层解码](iot-industrial-mms-filewrite-firmware-upload-forensics/) | verified | medium | 2026-11-06 |
| [Modbus/TCP 写命令按来源屏蔽：放行操作员写寄存器、阻断 PLC 自动逻辑，使温度失去自动调节](iot-industrial-modbus-write-command-source-shielding/) | verified | medium | 2026-11-08 |
| [Modbus/TCP 读输入寄存器响应篡改：温度 >4300 时改写为 4100+value%200，让 HMI 持续显示安全值](iot-industrial-modbus-read-input-register-response-tamper/) | verified | medium | 2026-11-08 |
| [S7comm Write Var 流量提取：筛 func=0x05/rosctr=Job 还原 PLC 写入载荷](iot-industrial-s7comm-write-var-payload-extraction/) | verified | high | 2026-11-07 |
| [S7comm 多组件 DB 同步写入：伪造电梯开门/上行/跨层异常状态触发 HMI flag](iot-industrial-s7comm-elevator-multi-db-state-forgery/) | verified | high | 2026-11-06 |
| [SCADA 快照文件 mmap 伪造：真实反应釜越限 + 传感器/SIEM 安全值欺骗](iot-industrial-scada-snapshot-mmap-state-forgery/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
