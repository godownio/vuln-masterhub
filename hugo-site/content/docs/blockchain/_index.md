---
title: 区块链
weight: 1
---

# 区块链

## 这层是什么

智能合约、DeFi、钱包与共识安全。

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

- [Solidity](solidity/) —— 重入、整数、权限、代理与编译器问题。
- [Move](move/) —— Sui/Aptos Move 对象模型、能力与 PTB 组合攻击。
- [DeFi](defi/) —— 闪电贷、预言机、MEV 与经济攻击。
- [钱包](wallet/) —— 私钥、签名、硬件钱包与客户端。
- [共识](consensus/) —— 共识攻击、分叉与网络层。

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
