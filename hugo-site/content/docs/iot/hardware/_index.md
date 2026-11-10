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
| [Proxmark3 USB 流量解析：按 PM3a/PM3b 帧格式提取 mf_readblock，按 blockno 还原 M1 卡 64 块数据取 flag](iot-hardware-proxmark3-usb-pcap-mifare-block-recovery/) | verified | high | 2026-11-07 |
| [Saleae Logic 分析 .sal 抓包：Async Serial 解码 UART 115200 8N1 还原设备文本](iot-hardware-saleae-logic-uart-decode/) | verified | high | 2026-11-07 |
| [Saleae Logic 解析 I2C 键盘：CardKB 地址 0x5F，过滤空报告按字节还原输入密码](iot-hardware-saleae-i2c-cardkb-keyboard-decode/) | verified | high | 2026-11-07 |
| [Saleae Logic 解析 SPI 电子墨水屏：Inky pHAT 2.13 寸，按 0x24/0x26 RAM 命令重建 buf_a/buf_b 渲染图像](iot-hardware-saleae-spi-inky-phat-epaper-frame/) | verified | high | 2026-11-07 |
| [VHDL 硬件后门识别：固定 16 位 pattern 触发后直接输出密钥](iot-hardware-vhdl-backdoor-pattern-key-output/) | verified | high | 2026-11-07 |
| [ZKTeco 生物识别终端 eMMC 拆读取固件：binwalk 定位 rootfs，/etc/shadow 破解 SSH 账号](iot-hardware-zkteco-emmc-dump-binwalk-shadow-ssh/) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
