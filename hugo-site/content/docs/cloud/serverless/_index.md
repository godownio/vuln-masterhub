---
title: Serverless
weight: 1
---

# Serverless

## 这层是什么

函数计算、事件注入与权限。

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
| [SQS 消息属性注入 → Lambda 消费拼 SQL 的二次注入（含 event 参数枚举与 CLI v2 payload 编码）](cloud-serverless-sqs-lambda-second-order-sqli/) | verified | high | 2026-11-08 |
| [用云函数当出口 IP 池：mitmproxy 插件把整条流量改写成 POST 到函数 URL，靠云厂商 NAT 出口绕过 IP 封禁与限速](cloud-serverless-function-url-mitmproxy-egress-ip-rotation/) | verified | high | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
