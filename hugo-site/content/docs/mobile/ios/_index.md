---
title: iOS
weight: 1
---

# iOS

## 这层是什么

iOS 应用与逆向：Mach-O、IPA、越狱、Hook、动态分析与漏洞。

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
| [iOS 抓包代理脚本注入篡改 API 响应：按 URL 改写 JSON 字段解锁客户端功能限制/去广告](mobile-ios-proxy-script-response-tamper-feature-unlock/) | verified | medium | 2026-11-11 |
| [iOS/macOS 伴侣应用 URL scheme 服务调用伪造：https 通用链接包装 homeassistant://call_service，点链接即可解除警报或关机](mobile-ios-url-scheme-universal-link-service-csrf/) | verified | high | 2026-11-11 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
