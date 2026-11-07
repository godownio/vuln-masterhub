---
title: 硬件
weight: 1
---

# 硬件

## 这层是什么

UART/JTAG/SPI、侧信道与故障注入。

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
| [BES2300 智能音响固件提取：UART ROM Bootloader BE 协议 dump Flash](iot-hardware-bes2300-rom-bootloader-uart-dump/) | verified | high | 2026-11-06 |
| [Saleae Logic 分析 .sal 抓包：Async Serial 解码 UART 115200 8N1 还原设备文本](iot-hardware-saleae-logic-uart-decode/) | verified | high | 2026-11-07 |
| [VHDL 硬件后门识别：固定 16 位 pattern 触发后直接输出密钥](iot-hardware-vhdl-backdoor-pattern-key-output/) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
