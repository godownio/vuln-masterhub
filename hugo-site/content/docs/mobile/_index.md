---
title: 移动安全
weight: 1
---

# 移动安全

## 这层是什么

Android、iOS、HarmonyOS 应用与系统安全。

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

- [Android](android/) —— Android 应用与逆向：APK/DEX/SO、加固、Hook、动态分析与漏洞。
- [iOS](ios/) —— iOS 应用与逆向：Mach-O、IPA、越狱、Hook、动态分析与漏洞。
- [HarmonyOS](harmony/) —— HAP/APP/ABC、方舟运行时与安全机制。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [aLTEr：LTE 用户面 AES-CTR 可塑性篡改 DNS 查询，把目标 IP 改成攻击者 IP](mobile-alter-lte-user-plane-aes-ctr-dns-tamper/) | verified | medium | 2026-11-06 |
| [GSM 伪基站降级劫持：单向认证 + LAC 变化触发位置更新，明文 IMSI 与伪造短信下发](mobile-gsm-fake-bts-downgrade-sms-injection/) | verified | medium | 2026-11-06 |
| [LTE RRC 重定向降级：未完整性保护的 RRCConnectionRelease 携带 redirectedCarrierInfo 把终端赶到 2G](mobile-lte-rrc-redirect-downgrade-gsm/) | verified | medium | 2026-11-06 |
| [微信小程序 SM2/SM3/SM4 通信协议逆向与 Burp 透明加解密](mobile-miniprogram-sm-crypto-protocol-burp-transparent/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
