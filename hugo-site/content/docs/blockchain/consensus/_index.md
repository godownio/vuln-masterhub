---
title: 共识
weight: 1
---

# 共识

## 这层是什么

共识攻击、分叉与网络层。

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
| [Bitcoin Core CVE-2018-17144：CheckBlock 以 false 跳过重复输入检查，恶意区块重复花费同一 UTXO](blockchain-consensus-bitcoin-cve-2018-17144-checkblock-duplicate-input-skip/) | verified | high | 2026-11-12 |
| [DPoS 确定性洗牌 + DDoS 中间委托人：恶意节点连续出块制造 6 确认双花](blockchain-consensus-dpos-deterministic-shuffle-ddos-consecutive-fork-double-spend/) | verified | high | 2026-11-12 |
| [Filecoin 共识罚没条件取反：time-offset fault 误判正常出块并漏判真实故障](blockchain-consensus-filecoin-slashing-time-offset-condition-inversion/) | verified | high | 2026-11-12 |
| [公链节点 RPC setMinerCoinbase 未校验地址格式：非法 coinbase 被接受导致挖矿收益损失](blockchain-consensus-rpc-setminercoinbase-address-validation-missing/) | verified | high | 2026-11-12 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
