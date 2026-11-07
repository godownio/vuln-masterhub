---
title: 模糊测试
weight: 1
---

# 模糊测试

## 这层是什么

覆盖率引导、语料、变异与崩溃分析。

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
| [Syzkaller 定向 fuzz 自定义内核驱动：syzlang 描述 + KCOV/KASAN + syz-repro 最小化](code-analysis-dynamic-fuzzing-syzkaller-custom-proc-driver-syzlang/) | verified | high | 2026-11-06 |
| [强加固 Android 应用的 Intent-aware 灰盒 fuzzer：eBPF 对象布局恢复 + Key-Value 反馈 + 选择性覆盖](code-analysis-dynamic-fuzzing-android-ebpf-intent-aware/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
