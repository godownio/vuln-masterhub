---
title: DeFi
weight: 1
---

# DeFi

## 这层是什么

闪电贷、预言机、MEV 与经济攻击。

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
| [AMM 首个 LP 存款人通胀攻击：捐赠 + sync 抬高 LP 单价，后续存款向下取整被吞（MINIMUM_LIQUIDITY 防御）](blockchain-defi-amm-first-lp-inflation-donation-rounding/) | verified | medium | 2026-11-06 |
| [DEX 现货兑换价操纵：按池子余额比例反复 swap 抽干一侧储备](blockchain-defi-dex-spot-reserve-swap-drain/) | draft | high | 2026-11-07 |
| [DexTwo 任意代币兑换：未校验交易对，自建代币 1:1 换走池内全部真币](blockchain-defi-dextwo-arbitrary-token-swap-drain/) | draft | high | 2026-11-07 |
| [Solana 拍卖程序账户生命周期缺陷：关闭后同 auction_id 重建 PDA，复用旧 bidder_state 盗取 vault](blockchain-defi-solana-auction-pda-reuse-bidder-state-vault-drain/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
