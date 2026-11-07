# Move 智能合约

## 这层是什么

Sui Move 合约逻辑漏洞、类型混淆、对象归属与 DeFi 攻击。

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
| [Move 借贷对象归属缺失：公共 create 建池 + 跨池领取清算奖励窃取抵押](blockchain-move-lending-position-cross-instance-collateral.md) | verified | high | 2026-11-07 |
| [Move 奖励池快照只记人数 + 零估值存款绕过阶段检查：替换高份额用户压低 total_evaluation，领走全部奖励](blockchain-move-reward-snapshot-count-zero-evaluation-deposit.md) | verified | high | 2026-11-07 |
| [Move 恒定乘积 Swap 用旧储备且整数除法：循环兑换抽空单侧，闪贷后双侧归零](blockchain-move-amm-swap-pre-reserve-rounding-drain.md) | verified | high | 2026-11-07 |
| [Move 投票合约请求未绑定选票：request_vote 与 finish_voting 跨对象重复计票](blockchain-move-voting-vote-request-ballot-binding-missing.md) | verified | high | 2026-11-07 |
| [Move 质押池 AdminCap 未绑定 + public create：任意用户篡改 APR 触发 u64 溢出，永久锁死质押与取回](blockchain-move-staking-admincap-unbound-overflow-lock.md) | verified | medium | 2026-11-07 |
| [Move 金库买卖跨对象与 PTB 原子性：多金库刷余额和同时间戳批量卖出](blockchain-move-vault-ptb-atomicity-cross-vault.md) | verified | medium | 2026-11-07 |
| [Move 闪贷回执类型混淆：借 BUTT 还 DROP，让池子 butt 余额归零且 flashloan 解除](blockchain-move-flashloan-receipt-type-confusion.md) | verified | high | 2026-11-07 |
| [Sui Move 治理质押投票重复计票：unstake 不撤销选票 + vote 无去重，循环质押/投票抬高 no_votes](blockchain-move-governance-unstake-vote-replay-inflation.md) | verified | high | 2026-11-07 |
| [Sui Move 混币器 16 叶顺序 Merkle 树 + withdraw 暴露叶子索引：链上关联存款与取款地址](blockchain-move-mixer-small-merkle-tree-leaf-index-linkability.md) | verified | medium | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
