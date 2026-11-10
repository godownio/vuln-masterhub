---
id: blockchain-defi-dex-spot-reserve-swap-drain
title: DEX 现货兑换价操纵：按池子余额比例反复 swap 抽干一侧储备
type: scenario
domain: blockchain
path: blockchain/defi
technique: dex-spot-reserve-price-manipulation
aliases:
- Ethernaut Dex
- getSwapPrice 价格操纵
- AMM 现货价操纵
- 储备比例兑换
- 反复 swap 抽干池子
tags:
- blockchain
- defi
- amm
- dex
- solidity
- ethernaut
- price-manipulation
- spot-price
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V268
  verified_at: '2026-11-07T19:00:12+08:00'
  notes: 已对照原文第22关代码与逐步骤余额表核对：getSwapPrice=amount*to.balance/from.balance、无滑点/手续费；10→10、20→24、24→30、30→41、41→65、45→110 的交替 swap 序列与原文表格一致（整数除法），最终抽干 token1。dup-scan 将本卡与 DexTwo 卡判 likely_duplicate：按原文裁决两者不是同一链——本卡(Dex, 第22关)交易对合法、根因是现货价可被连续 swap 推偏；DexTwo(第23关)删除了 from/to 交易对校验、用自建代币 1:1 兑换，两者根因/触发/关卡不同，均保留（相关而非重复）。dedup 工具亦判 related。未执行 PoC。
---

## 一句话结论

DEX 的 `getSwapPrice` 直接用池子两个代币的当前余额比例报价（`amount * to.balanceOf(dex) / from.balanceOf(dex)`），每次 swap 又立即改变余额；攻击者用少量初始代币按“全额换出、交替方向”的序列连续 swap，比例逐次恶化，数步后把一侧储备抽干，池子只剩坏价。

## 原理

- 该 DEX 的兑换价不是外部预言机，而是池子现货余额比：

```
swapAmount = amount * balanceOf(to, dex) / balanceOf(from, dex)
```

  `amount` 越大、`from` 池子余额越小、`to` 池子余额越大，换出的 `to` 就越多。
- `swap` 在计算后立即执行 `from.transferFrom(user, dex, amount)` 与 `to.transferFrom(dex, user, swapAmount)`，因此每次兑换后两边储备立刻变化；下一次报价基于被自己改变后的余额，形成可被连续操纵的反馈回路。
- 没有手续费、没有滑点保护、没有 `minAmountOut`，也没有恒定乘积不变量约束；攻击者可以把每次可换出的数量取到“手里全部余额”或“池子全部余额”，让池子比例在几步内剧烈倾斜。
- 以初始玩家 10 token1 + 10 token2、池子各 100 为例：10 t1→t2 得 10 t2；20 t2→t1 得 24 t1；24 t1→t2 得 30 t2；30 t2→t1 得 41 t1；41 t1→t2 得 65 t2；最后 45 t2→t1 得 110 t1，token1 池被抽干，攻击者最终持有 110 t1 + 20 t2。

## 触发条件

- AMM/DEX 使用“当前储备余额比”作为即时报价，且报价与成交在同一笔交易/同一区块内完成，没有 TWAP 或延迟。
- 兑换无手续费、无滑点限制、无最小输出，且允许任意大小、任意次数的 swap。
- 池子储备规模有限，攻击者初始代币足以在数步内把比例推到极端；或攻击者可借助闪电贷瞬时放大初始资金。
- 目标协议把该现货价用作抵押品定价、清算价或兑换依据。

## 利用步骤

1. 读取池子 `token1/token2` 地址与双方初始余额，确认报价公式与无滑点保护。
2. 调用 DEX 的 `approve(dex, 大额度)`（该合约的 approve 会同时给两个代币授权），避免 `transferFrom` 因 allowance 失败。
3. 按交替方向连续 swap，每次尽量把手里的全部 from 代币或池子里可换出的上限投入：
   - 10 token1 → token2
   - 20 token2 → token1
   - 24 token1 → token2
   - 30 token2 → token1
   - 41 token1 → token2
   - 45 token2 → token1（换出池内剩余 110 token1）
4. 每步后重新读取余额再计算下一步；当一侧储备归零时，池子已无法按正常比例兑换，攻击者把换出的真币转回自己的地址。
5. 真实场景中可在同一笔交易内用闪电贷放大本金，先借入大量 token 推偏比例，抽干后归还贷款并保留利润。

## PoC

原文给出攻击合约与自动化脚本，核心序列如下（Solidity ^0.8.0）：

```solidity
dex.approve(address(dex), type(uint256).max);
dex.swap(token1, token2, 10);
dex.swap(token2, token1, 20);
dex.swap(token1, token2, 24);
dex.swap(token2, token1, 30);
dex.swap(token1, token2, 41);
dex.swap(token2, token1, 45);
// 之后转账取回 token1 110 / token2 20
```

原文另给出 ethers.js 循环版：每轮按当前玩家余额与池子余额计算 `getSwapPrice`，若换出量超过池子余额则以池子余额为投入，循环至任一侧储备为 0。

## 变体与关联

- 同类：把 Uniswap V2 pair 的 `getReserves()` 现货比例直接当预言机，攻击者用闪电贷在同一交易内推偏储备后借贷/清算/套利。
- 与“首个 LP 通胀攻击”不同：本卡不依赖 LP 份额舍入，而是直接操纵兑换比例抽干储备。
- 与 DexTwo 任意代币兑换卡的区别：本卡的根因是报价用现货余额且无滑点，代币交易对本身是合法的；DexTwo 的根因是缺少交易对校验。

## 检测与防御

- 不要用池子瞬时储备作为价格源；使用链上 TWAP（如 Uniswap V3 oracle）、多源聚合预言机或外部报价，并设置心跳/偏差阈值。
- 兑换增加手续费与滑点保护（`minAmountOut`），限制单笔/单区块兑换比例变化；对大额 swap 做限流。
- 加入恒定乘积不变量校验（`k` 不得下降）、储备下限与熔断；监控同一区块内方向交替、金额递增的异常 swap 序列。
- 审计关注点：报价函数是否读取 `balanceOf(this)`/`getReserves()` 的当前值并与成交在同一交易内；是否存在闪电贷放大路径。
