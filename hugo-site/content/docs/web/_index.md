---
title: Web 安全
weight: 1
---

# Web 安全

## 这层是什么

Web 应用漏洞、框架/组件利用、协议与认证、注入与文件类问题。

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

- [Java Web](java/) —— Java 生态的表达式、反序列化、框架与组件漏洞。
- [PHP Web](php/) —— PHP 反序列化、文件包含、RCE 与框架漏洞。
- [Python Web](python/) —— Python 反序列化、SSTI、框架与依赖漏洞。
- [Node.js Web](nodejs/) —— 原型链污染、反序列化、模板注入与依赖漏洞。
- [.NET Web](dotnet/) —— ViewState、BinaryFormatter、IIS 与 .NET 反序列化。
- [Go Web](golang/) —— Go Web 框架、模板、反序列化与依赖漏洞。
- [通用 Web 漏洞](generic/) —— 与语言无关的 Web 漏洞类型与利用技巧。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| （暂无卡片） | | | |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
