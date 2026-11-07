---
title: Frida
weight: 1
---

# Frida

## 这层是什么

Hook、插桩与自动化。

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
| [Frida Arm64Writer 动态 NOP 掉 B.NE：绕过 native 分支暴露隐藏逻辑](tools-frida-arm64writer-nop-conditional-branch/) | verified | high | 2026-11-06 |
| [Frida Native 层 Hook：导出/未导出函数定位、NativeFunction 主动调用、retval 修改与构造函数 $init](tools-frida-native-hook-export-unexport-retval-constructor/) | verified | high | 2026-11-06 |
| [Frida 源码魔改反检测：重命名进程/符号/线程/memfd/RPC 特征并编译 Android arm64 server](tools-frida-source-patch-anti-detection/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
