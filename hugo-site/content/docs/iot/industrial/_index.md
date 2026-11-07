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
| [MMS fileWrite 恶意固件上传取证：TPKT/COTP/MMS TLV 重组与 XOR/ZIP/LZMA 分层解码](iot-industrial-mms-filewrite-firmware-upload-forensics/) | verified | medium | 2026-11-06 |
| [S7comm 多组件 DB 同步写入：伪造电梯开门/上行/跨层异常状态触发 HMI flag](iot-industrial-s7comm-elevator-multi-db-state-forgery/) | verified | high | 2026-11-06 |
| [SCADA 快照文件 mmap 伪造：真实反应釜越限 + 传感器/SIEM 安全值欺骗](iot-industrial-scada-snapshot-mmap-state-forgery/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
