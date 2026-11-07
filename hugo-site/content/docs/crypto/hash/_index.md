---
title: 哈希
weight: 1
---

# 哈希

## 这层是什么

长度扩展、碰撞、彩虹表与 HMAC 误用。

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
| [MD5 三碰撞构造：identical-prefix 二碰撞嵌套两次 + 三层嵌套协议](crypto-hash-md5-three-way-collision-nested-fastcoll/) | verified | high | 2026-11-06 |
| [MD5 二进制摘要用 strcmp 比较：空字节截断只需碰撞 3 字节前缀](crypto-hash-md5-digest-strcmp-nullbyte-truncation/) | verified | high | 2026-11-05 |
| [MD5 长度扩展攻击：已知 key 长度与 md5(secret||password)，伪造 admin 密码哈希接管账户](crypto-hash-md5-length-extension-password-forge-admin/) | verified | high | 2026-11-06 |
| [SHA256 长度扩展：secret 前缀 MAC 追加字段并伪造摘要](crypto-hash-sha256-length-extension-append-field/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
