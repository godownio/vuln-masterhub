---
title: Metasploit
weight: 1
---

# Metasploit

## 这层是什么

模块、payload 与利用。

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
| [Metasploit CMD Stager 无下载器环境适配：按模块可用 flavor 切换传输](tools-metasploit-cmdstager-flavor-no-downloader/) | verified | high | 2026-11-05 |
| [MSF getsystem 六种提权技术对比：服务命名管道/Dropper/令牌复制/RPCSS/PrintSpoofer/EFSRPC 的实现、前提与 OPSEC 检测特征](tools-metasploit-getsystem-six-techniques-opsec/) | verified | high | 2026-11-12 |
| [MSF MS17-010 模块族源码分析：eternal_pwn 按 OS/命名管道选择利用并覆盖 token，command/psexec 的四种载荷通道](tools-metasploit-ms17-010-module-family-source-analysis/) | verified | high | 2026-11-13 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
