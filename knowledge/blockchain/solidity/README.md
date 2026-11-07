# Solidity

## 这层是什么

重入、整数、权限、代理与编译器问题。

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
| [CREATE 地址预计算 + 公开 selfdestruct：由创建者地址与 nonce 找回丢失合约并销毁取走余额](blockchain-solidity-create-address-precompute-public-selfdestruct.md) | verified | high | 2026-11-07 |
| [EVM 猜谜蜜罐合约识别：幌子 Start 交易 + 隐藏 New 内部调用 + 管理员抢跑改哈希](blockchain-solidity-evm-guess-honeypot-detection.md) | verified | high | 2026-11-06 |
| [Shop 合约 view 价格两次调用 TOCTOU：攻击者按 isSold 切换返回值以 0 价格买入](blockchain-solidity-shop-view-price-double-call-toctou.md) | draft | high | 2026-11-07 |
| [Solidity <0.6 动态数组长度下溢：retract 把 length 减成 2^256-1，revise 任意槽写覆写 owner](blockchain-solidity-array-length-underflow-arbitrary-storage-owner.md) | verified | high | 2026-11-07 |
| [Solidity private 状态变量链上可读：eth_getStorageAt 按槽位还原动态字符串](blockchain-solidity-private-state-storage-read.md) | verified | high | 2026-11-07 |
| [可写库地址 + delegatecall 存储碰撞：先用 setFirstTime 把 slot0 改成恶意库，再借恶意 setTime 覆写 owner](blockchain-solidity-delegatecall-library-slot0-owner-hijack.md) | verified | high | 2026-11-07 |
| [透明代理存储槽冲突 + multicall 嵌套复用 msg.value：劫持 PuzzleWallet 管理员](blockchain-solidity-proxy-storage-collision-multicall-admin-hijack.md) | draft | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
