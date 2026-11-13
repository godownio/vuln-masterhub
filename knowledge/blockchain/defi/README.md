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
| [AMM 首个 LP 存款人通胀攻击：捐赠 + sync 抬高 LP 单价，后续存款向下取整被吞（MINIMUM_LIQUIDITY 防御）](blockchain-defi-amm-first-lp-inflation-donation-rounding.md) | verified | medium | 2026-11-06 |
| [DApp 后端代付 gas 却不校验 to/data：前端 ABI 编码可任意改写，借项目方 relayer 调任意合约的 mint/burn](blockchain-defi-dapp-backend-unvalidated-calldata-arbitrary-call-gas-sponsored.md) | verified | medium | 2026-11-08 |
| [DeFi 利润分配少付：swap 分支把待发金额覆盖为换出额，漏掉合约已有 ETH](blockchain-defi-profit-splitter-amount-overwrite-underpay.md) | verified | high | 2026-11-11 |
| [DEX 无交易费挖矿：手续费按输入币收取 + 挖矿门槛仅校验含 EOS，自建垃圾币对刷量套利](blockchain-defi-dex-zero-fee-mining-worthless-token-wash-swap.md) | verified | medium | 2026-11-11 |
| [DEX 现货兑换价操纵：按池子余额比例反复 swap 抽干一侧储备](blockchain-defi-dex-spot-reserve-swap-drain.md) | verified | high | 2026-11-07 |
| [DexTwo 任意代币兑换：未校验交易对，自建代币 1:1 换走池内全部真币](blockchain-defi-dextwo-arbitrary-token-swap-drain.md) | verified | high | 2026-11-07 |
| [EOS 币币交换假充值：contract 与 symbol 分开校验，contract0 的 sym1 冒充交易对币种](blockchain-defi-eos-swap-contract-symbol-separate-check-fake-deposit.md) | verified | medium | 2026-11-11 |
| [Solana 拍卖程序账户生命周期缺陷：关闭后同 auction_id 重建 PDA，复用旧 bidder_state 盗取 vault](blockchain-defi-solana-auction-pda-reuse-bidder-state-vault-drain.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
