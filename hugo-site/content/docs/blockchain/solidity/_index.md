---
title: Solidity
weight: 1
---

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
| [CREATE 地址预计算 + 公开 selfdestruct：由创建者地址与 nonce 找回丢失合约并销毁取走余额](blockchain-solidity-create-address-precompute-public-selfdestruct/) | verified | high | 2026-11-07 |
| [ERC20 burn(address _from) 的 _from 参数可控：owner 可任意销毁用户代币的"中级后门"](blockchain-solidity-erc20-burn-from-param-owner-backdoor/) | verified | high | 2026-11-11 |
| [ERC20 transferFrom 余额检查用 msg.sender 而扣减 _from：小额授权触发 _from 余额下溢，凭空铸出 2^256 代币](blockchain-solidity-transferfrom-check-update-mismatch-underflow/) | verified | high | 2026-11-11 |
| [ERC20 transferFrom 缺少 allowance 前置校验：allowed 映射 0-value 下溢成巨额授权，可转走任意账户代币](blockchain-solidity-transferfrom-missing-allowance-check-underflow/) | verified | high | 2026-11-11 |
| [ERC20 购买函数循环内重复校验 msg.value 却不扣费、按当前余额+1 铸币：1 ether 指数增发绕过持有量阈值](blockchain-solidity-buy-nft-loop-msgvalue-not-consumed-balance-based-mint/) | verified | medium | 2026-11-11 |
| [EVM 猜谜蜜罐合约识别：幌子 Start 交易 + 隐藏 New 内部调用 + 管理员抢跑改哈希](blockchain-solidity-evm-guess-honeypot-detection/) | verified | high | 2026-11-06 |
| [extcodesize 合约地址检测在构造期失效：攻击合约在 constructor 中调用目标，绕过 isContract/禁止合约参与校验](blockchain-solidity-extcodesize-constructor-iscontract-bypass/) | verified | high | 2026-11-11 |
| [fallback 直接 delegatecall(msg.data) 直通库函数：调用 pwn() 选择器在代理上下文覆写 slot0 owner](blockchain-solidity-fallback-delegatecall-storage-collision-owner-hijack/) | verified | high | 2026-11-09 |
| [Merkle Tree 第二原像攻击：把内部节点冒充叶子缩短证明链，用 64 字节 packed 原像伪造空投领取（Paradigm CTF 2022 MerkleDrop）](blockchain-solidity-merkle-tree-second-preimage-internal-node-forged-leaf/) | verified | high | 2026-11-09 |
| [Shop 合约 view 价格两次调用 TOCTOU：攻击者按 isSold 切换返回值以 0 价格买入](blockchain-solidity-shop-view-price-double-call-toctou/) | verified | high | 2026-11-07 |
| [Solidity <0.6 动态数组长度下溢：retract 把 length 减成 2^256-1，revise 任意槽写覆写 owner](blockchain-solidity-array-length-underflow-arbitrary-storage-owner/) | verified | high | 2026-11-07 |
| [Solidity private 状态变量链上可读：eth_getStorageAt 按槽位还原动态字符串](blockchain-solidity-private-state-storage-read/) | verified | high | 2026-11-07 |
| [Solidity 变量歧义命名：命名返回变量遮蔽状态变量、继承中重复声明状态变量导致读取错误槽位](blockchain-solidity-variable-shadowing-ambiguity/) | verified | high | 2026-11-10 |
| [Solidity 权限合约信任调用者传入的外部 CA：伪 verify 返回 true + delegatecall 攻击合约伪造 setLevel 返回值绕过等级校验](blockchain-solidity-user-supplied-ca-contract-delegatecall-return-trust/) | verified | medium | 2026-11-11 |
| [Solidity 重入清空合约余额：withdraw 先 call 转账后清零，攻击合约 receive 递归提款直到余额为 0](blockchain-solidity-reentrancy-withdraw-call-before-zero-drain/) | verified | medium | 2026-11-11 |
| [代理 setImplementation(address) 与实现合约业务函数选择器冲突（同为 0xd784d426）：调用“安全函数”实际改掉实现地址](blockchain-solidity-proxy-selector-collision-setimplementation-hijack/) | verified | medium | 2026-11-09 |
| [公开 safeSendLp 未鉴权 + nested call 的 msg.sender 是合约自身：任意用户借 transfer 转走合约持仓 LP](blockchain-solidity-public-transfer-msgsender-contract-balance-drain/) | verified | high | 2026-11-13 |
| [可写库地址 + delegatecall 存储碰撞：先用 setFirstTime 把 slot0 改成恶意库，再借恶意 setTime 覆写 owner](blockchain-solidity-delegatecall-library-slot0-owner-hijack/) | verified | high | 2026-11-07 |
| [未初始化 UUPS/ERC1967 代理：部署时 init data 为空，攻击者抢先 initialize 成为 owner 并 mint 或升级](blockchain-solidity-uninitialized-uups-proxy-initialize-frontrun/) | verified | high | 2026-11-09 |
| [质押合约 emergencyWithdraw 未缓存金额先清零：safeTransfer 收到 0，用户本金永久锁死](blockchain-solidity-emergencywithdraw-zero-amount-order/) | verified | high | 2026-11-11 |
| [透明代理存储槽冲突 + multicall 嵌套复用 msg.value：劫持 PuzzleWallet 管理员](blockchain-solidity-proxy-storage-collision-multicall-admin-hijack/) | verified | high | 2026-11-07 |
| [锁仓合约双钱包同地址：allocate() 对同一 allocations 槽位连续赋值，2.4 亿配额被 0.1 亿覆盖，解锁额与滞留资金错位](blockchain-solidity-vesting-wallet-address-collision-allocation-overwrite/) | verified | high | 2026-11-11 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
