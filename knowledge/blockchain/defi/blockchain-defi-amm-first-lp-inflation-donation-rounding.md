---
id: blockchain-defi-amm-first-lp-inflation-donation-rounding
title: AMM 首个 LP 存款人通胀攻击：捐赠 + sync 抬高 LP 单价，后续存款向下取整被吞（MINIMUM_LIQUIDITY 防御）
type: scenario
domain: blockchain
path: blockchain/defi
technique: amm-first-depositor-lp-inflation-donation
aliases:
- 首个 LP 通胀攻击
- first depositor inflation attack
- 首存捐赠攻击
- LP token 通胀
- Uniswap V2 捐赠攻击
- 向下取整吞存款
- MINIMUM_LIQUIDITY 防御
tags:
- blockchain
- defi
- amm
- uniswap-v2
- liquidity-pool
- lp-token
- donation-attack
- rounding
- economic-attack
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V157
  verified_at: '2026-11-06T07:38:25+08:00'
  notes: 已对照原文与1张公式图核对：首存极少 LP、直接 transfer 捐赠、按 reserve 比例向下取整吞掉受害者 LP、攻击者赎回约 50% 资金；MINIMUM_LIQUIDITY=1000 防御与原文一致。原文步骤省略 sync()，卡内补为必要步骤并标注；PoC 为语义还原伪代码，未上链执行。原文 fee-on-transfer/permit 仅一行提示，已跳过。
---

## 一句话结论

在采用 `liquidity = min(amount * totalSupply / reserve)` 的 AMM 中，第一个流动性提供者可以先用最小资金拿到极少量 LP，再通过直接转账向池子捐赠并调用 `sync()` 抬高每份 LP 对应的储备；后续受害者按正常数量存款时，计算结果被 Solidity 向下取整成 1 wei LP，攻击者再赎回自己的 1 wei LP 即可拿走约一半池子，使受害者本金被稀释。

## 原理

- **LP 定价公式**：非首次存款时，Uniswap V2 用 `liquidity = min(amount0 * totalSupply / reserve0, amount1 * totalSupply / reserve1)` 计算应铸 LP。Solidity 整数除法向下取整；当 `amount * totalSupply / reserve` 小于 2 时，受害者只能拿到 1 wei LP。
- **分子/分母可被操纵**：`totalSupply` 很小（攻击者首次只铸 1 LP）时，攻击者通过 ERC20 `transfer` 直接向 pair 合约转入大量代币，再调用 `sync()` 把 `reserve0/reserve1` 更新为捐赠后的余额。分母（reserve）被抬高，受害者同额存款算出的 LP 被严重稀释。
- **捐赠归池不归人**：直接 `transfer` 不经过 `mint`，不会给捐赠者铸 LP；捐赠增加的是“每份 LP 对应的资产”，这部分价值在攻击者仍持有那 1 LP 时被其捕获。
- **攻击者赎回**：受害者存款后 `totalSupply` 变为约 2（攻击者 1 + 受害者 1）。攻击者 `burn` 自己的 1 LP，按比例拿走约 50% 的池子资产，其捐赠的本金也一并回收（扣除受害者份额后仍有净利）。
- **为什么 Uniswap V2 要锁 1000 LP**：首次 `mint` 时 `liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY`，并把 1000 LP 铸给 `address(0)`。这强制 `totalSupply` 至少为 1000，攻击者要把受害者 LP 压到 1 wei 就必须把 reserve 抬高约 1000 倍，需要百倍/千倍资金；同时攻击者自己那份被 0 地址锁定的份额永远无法赎回，显著提高攻击成本。
- **原文步骤缺了 `sync()`**：只做直接转账而不调用 `sync()`，`_reserve` 仍是旧值，受害者 `mint` 计算出的 `amount` 会把捐赠额一并算进去，反而铸出大量 LP，攻击不成立。因此“捐赠 + sync”是这条链的必要步骤。

## 触发条件

- 目标 AMM/流动性池使用“按储备比例、向下取整”的 LP 铸造公式（Uniswap V2 风格）。
- 池子处于首次流动性阶段或 `totalSupply` 很小，且没有 `MINIMUM_LIQUIDITY`/dead shares/虚拟储备等防通胀机制。
- 攻击者能成为第一个 LP，并能直接向 pair 合约转账（ERC20 普通 transfer 即可）且调用 `sync()`（若合约暴露）。
- 受害者随后在同一区块窗口内按正常金额添加流动性，且没有 `minLiquidity`/滑点保护来拒绝异常少的 LP。
- 攻击者能在受害者存款后立即赎回，且池子没有存款锁定/冷却。

## 利用步骤

1. 选择目标：新创建、`totalSupply` 很小、无最小流动性锁定的 Uniswap V2 风格池子；确认 pair 暴露 `sync()`。
2. 攻击者作为首个 LP，存入最小可行数量（如 1 wei A + 1 wei B），获得 `sqrt(1*1)=1` LP；若合约有 `MINIMUM_LIQUIDITY=1000`，该步会下溢回滚，需要改用更大初始量并接受 1000 LP 被锁。
3. 攻击者直接向 pair 合约 `transfer` 大量 tokenA/tokenB（例如各 10000），不调用 `mint`。
4. 调用 `pair.sync()`，把 `reserve0/reserve1` 更新为捐赠后的余额，使每 1 LP 对应的资产价值大幅上升。
5. 受害者调用 `addLiquidity` 存入（例如各 19000）。按 `19000 * 1 / 10000 = 1.9` 向下取整，只铸得 1 wei LP。
6. 攻击者调用 `burn` 赎回自己的 1 LP，拿走约 50% 池子（示例中约 14500 A + 14500 B），扣除捐赠本金后净赚约 4500 A/B；受害者 1 LP 虽也值约 14500，但其投入为 19000，产生约 4500 的损失。

## PoC

原文给出的是经济模型推演，未提供链上 PoC；以下为按 Uniswap V2 `mint`/`sync` 语义还原的最小步骤（Solidity 伪代码，未部署执行）：

```solidity
// 1. 攻击者首次提供 1 wei + 1 wei，获得 1 LP（无 MINIMUM_LIQUIDITY 的池子）
pair.mint(attacker);                       // totalSupply = 1, reserve0 = reserve1 = 1

// 2. 直接捐赠 10000 + 10000，并同步储备
token0.transfer(address(pair), 10000);
token1.transfer(address(pair), 10000);
pair.sync();                               // reserve0 = reserve1 = 10001

// 3. 受害者按正常金额添加流动性
token0.transfer(address(pair), 19000);
token1.transfer(address(pair), 19000);
pair.mint(victim);
// liquidity = min(19000 * 1 / 10001, 19000 * 1 / 10001) = 1 （向下取整）

// 4. 攻击者赎回 1 LP，拿走约一半池子
pair.transfer(address(pair), 1);
pair.burn(attacker);                       // 约 14500 + 14500
```

数字说明：受害者存入 19000、只得到 1 wei LP；池子总量约 29001，攻击者 1 LP 占约 50%，赎回约 14500，净赚约 4500（未计手续费与 gas）。若池子有 `MINIMUM_LIQUIDITY=1000`，攻击者需先铸出 >1000 LP，并把 reserve 抬高约 1000 倍（捐赠约 10,000,000），且 1000 LP 永久锁定，经济上通常不划算。

## 变体与关联

- **ERC4626 金库变体**：同一“首存 + 捐赠抬高 share price + 向下取整”模式适用于按 `totalAssets/totalSupply` 计价的金库，常配合“虚拟偏移/死份额”防御。
- **多资产/多池变体**：在多个池子间用闪电贷放大捐赠额，或选择 `totalSupply` 更小的池子降低成本。
- **代币变体**：fee-on-transfer/rebasing token 会改变实际到账余额，可能让 `sync()` 后的储备与预期不同，需按代币实现调整。
- **关联场景**：Uniswap V2 `swap` 的恒定乘积校验与 reserve 语义（本卡“原理”节已说明 reserve 只在 mint/swap/burn/sync 时更新，这是捐赠攻击成立的前提）；闪电贷放大经济攻击（同一 DeFi 目录下可后续补充）；ERC4626 首存通胀攻击（同模式，防御用虚拟偏移/死份额）。
- **边界**：有 `MINIMUM_LIQUIDITY`/dead shares/虚拟储备、`mint` 使用内部记账而非实时余额、或受害者设置最小 LP 数量时，攻击失败或成本大幅上升；攻击还依赖攻击者能在受害者存款后立即赎回。

## 检测与防御

- **协议层**：首次 `mint` 锁定 `MINIMUM_LIQUIDITY`（Uniswap V2 的 1000）或引入 dead shares/虚拟资产偏移，保证 `totalSupply` 与 `reserve` 的比值不会被打到极低。
- **定价层**：不要直接用 `balanceOf` 作为价格/份额计算的分母；使用经过校验的内部储备，或对捐赠/`sync` 做限制与延迟。
- **用户层**：添加流动性时设置 `amountAMin/amountBMin` 与最小 LP 数量；前端对“存入大量资产却只铸极少量 LP”做告警。
- **监控**：监控新池子的首笔 `mint` 后是否出现大额直接 `transfer` + `sync`；监控 `totalSupply` 很小而储备很大的异常池子；对同一地址在受害者存款后立即 `burn` 的行为告警。
- **响应**：发现攻击后暂停池子/路由、快照受影响用户、评估坏账；新池子上线前用 fork 测试首存/捐赠/取整组合。
