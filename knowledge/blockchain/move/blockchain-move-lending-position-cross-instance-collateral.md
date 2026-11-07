---
id: blockchain-move-lending-position-cross-instance-collateral
title: Move 借贷对象归属缺失：公共 create 建池 + 跨池领取清算奖励窃取抵押
type: scenario
domain: blockchain
path: blockchain/move
technique: move-lending-position-cross-instance-collateral
aliases:
- Sui 借贷合约跨池攻击
- UserPosition 未绑定 lending
- claim_liquidation_reward 跨池
- sekai_lending
- create 可见性提权
tags:
- blockchain
- move
- sui
- defi
- lending
- object-binding
- access-control
- liquidation
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:27+08:00'
  notes: 已对照原文核对；public create + UserPosition 跨池领奖链一致；未在链上复现
---

## 一句话结论

Sui Move 借贷合约 `SEKAI_LENDING` 的 `create` 是 `public`，任何人都能新建一个池子并成为其 admin；同时 `liquidate_position` 与 `claim_liquidation_reward` 都只接收 `&mut SEKAI_LENDING` 与 `&mut UserPosition`，却不校验 position 是否属于该 lending。攻击者可在自建池里对 position 做清算、再到挑战池里领取清算奖励，把挑战池的 collateral 跨实例取出；配合公共 create 带来的 admin 权限（`remove_collateral`/`withdraw_protocol_fees`/`remove_liquidity`），可凑齐 80 SEKAI + 100 collateral 的解题条件。

## 原理

- **对象引用不携带归属关系**：Move 的 `&mut SEKAI_LENDING` 和 `&mut UserPosition` 是两个独立对象引用；函数签名不会自动保证 position 是由 self 创建的。`claim_liquidation_reward(self, position)` 直接 `balance::split(&mut self.collateral_pool, position.liquidation_reward)`，只要 position 上有 `liquidation_reward`，就能从任意 lending 的抵押池取钱。
- **清算与领奖分离**：`liquidate_position(self, position, repayment)` 在 self 池里把 position 标记为已清算并写入 `position.liquidation_reward`；`claim_liquidation_reward` 在另一个池里读取同一个 position 的奖励字段并从该池的 `collateral_pool` 支付。两者没有原子绑定，也没有 position→pool 的 id 校验。
- **public create 的提权**：`public fun create(collateral_coin, sekai_coin, ctx): SEKAI_LENDING` 把调用者设为 `admin`；攻击者用 `coin::zero` 创建自己的 lending 后，就能调用 `remove_collateral`、`withdraw_protocol_fees`、`remove_liquidity` 等 admin 函数（在自己的池里）。
- **完整链条**：
  1. `claim` 领取 collateral；
  2. 在挑战池存入 collateral 并借出 SEKAI；
  3. 自建 lending2，存入流动性/抵押并借款；
  4. 在 lending2 上 `liquidate_position`（用借出的 SEKAI 还款），position 获得清算奖励；
  5. 拿同一个 position 到挑战 lending 上 `claim_liquidation_reward`，从挑战池取出 collateral；
  6. 用 lending2 的 admin 权限 `remove_collateral`/`withdraw_protocol_fees` 取回自己池里的抵押；
  7. 循环放大，最终 `donate_collateral`/`donate_sekai` 使挑战池剩 100 collateral、80 SEKAI，`is_solved` 通过。
- **数值细节**：claim 得到 10 collateral，最多借 8 SEKAI（80% LTV）；清算奖励 = 抵押 - 10% 协议费；通过循环把奖励在自建池与挑战池之间搬运，最终凑够目标余额。`convert_decimal` 用 `u64` 乘法，理论上可溢出/丢精度，但本题数值较小，不是主利用点。

## 触发条件

- `SEKAI_LENDING::create` 为 `public`（或可被任意用户调用），攻击者可自建 lending 并成为 admin。
- `liquidate_position` / `claim_liquidation_reward` / `remove_collateral` 等敏感函数不校验 `UserPosition` 与 `SEKAI_LENDING` 的从属关系。
- 清算奖励先写入 position、后由另一个函数领取，两者不在同一函数/同一池内原子完成。
- 挑战池中有足够 collateral/SEKAI 供循环搬运，且 `is_solved` 只检查最终两个余额。

## 利用步骤

1. `claim` 领取 collateral。
2. 在挑战 lending 开 position1，存入 collateral，借出 SEKAI。
3. 用 `coin::zero` 调 `create` 自建 lending2（自己成为 admin）。
4. 在 lending2 开 position2，存入流动性/抵押，借出 SEKAI；必要时用 `remove_collateral` 取回部分抵押。
5. 在 lending2 调 `liquidate_position(position2, sekai_coin)`，把 position2 标记清算并写入 `liquidation_reward`。
6. 用同一个 position2 调挑战 lending 的 `claim_liquidation_reward(position2)`，从挑战池取出 collateral。
7. 用 lending2 的 `remove_collateral`/`withdraw_protocol_fees` 取回自己池里的抵押；循环步骤 4-7 放大。
8. 把凑够的 collateral/SEKAI 通过 `donate_collateral`/`donate_sekai` 存入挑战池，使余额达到 100 collateral、80 SEKAI；调用 `is_solved`。
9. 转移 position 与剩余奖励，完成。

## PoC

```move
module the_solution::solution {
    use challenge::challenge::{Self, Challenge};
    use challenge::collateral_coin::COLLATERAL_COIN;
    use challenge::sekai_coin::SEKAI_COIN;
    use challenge::sekai_lending::{Self, SEKAI_LENDING, UserPosition};

    const SEKAI: u64 = 100000000;
    const COLLATERAL: u64 = 1000000000;

    public fun solve(challenge: &mut Challenge, ctx: &mut TxContext) {
        // 1) 领取 collateral，并在挑战池抵押/借款
        let claim = challenge::claim(challenge, ctx);
        let mut lending = challenge.get_sekai_lending_mut();
        let mut pos1 = lending.open_position(ctx);
        lending.deposit_collateral(&mut pos1, claim, ctx);
        let mut sekai = lending.borrow_coin(&mut pos1, 8 * SEKAI, ctx);

        // 2) 公共 create：自建 lending2，自己成为 admin
        let mut lending2 = sekai_lending::create(
            coin::zero<COLLATERAL_COIN>(ctx),
            coin::zero<SEKAI_COIN>(ctx),
            ctx,
        );

        // 3) 在 lending2 存款/借款/清算
        let mut pos2 = lending2.open_position(ctx);
        lending2.deposit_collateral(&mut pos2, claim2, ctx); // 需要另行准备 collateral
        let sekai2 = lending2.borrow_coin(&mut pos2, 320_000_000, ctx);
        lending2.liquidate_position(&mut pos2, sekai2, ctx);

        // 4) 关键：拿 lending2 的 pos2 到挑战 lending 领奖励
        let reward = lending.claim_liquidation_reward(&mut pos2, ctx);

        // 5) 用自己的 admin 权限取回 lending2 的抵押
        let back = lending2.remove_collateral(4 * COLLATERAL, ctx);

        // 6) 循环放大后 donate，使挑战池达到 100 collateral / 80 SEKAI
        challenge.donate_collateral(/* ... */);
        challenge.donate_sekai(/* ... */);
        challenge.is_solved();
    }
}
```

说明：PoC 为原文 exp 的结构化骨架，省略了循环、拆币与部分中间变量（原文用 22+21 次循环逐步凑余额），未在链上执行；原文通过该链拿到 sekai_lending 题目的 flag。原 exp 中还演示了 `remove_collateral` 与 `claim_liquidation_reward` 的组合。

## 变体与关联

- 变体（归属缺失）：position 不绑定 pool id；lending 不维护 `user_positions`；清算与领奖分离。
- 变体（权限）：`create` 公共可调；admin 字段由调用者决定；`remove_collateral` 等 admin 函数缺少 `self.admin == sender` 校验（在自建池中 admin 就是自己）。
- 变体（数值）：`convert_decimal` 的 `u64` 乘法溢出/精度丢失；LTV/清算阈值的取整边界。
- 关联：[[blockchain-move-flashloan-receipt-type-confusion]]（同为对象/类型绑定缺失）；[[blockchain-move-amm-swap-pre-reserve-rounding-drain]]（DeFi 取整）；[[blockchain-defi-solana-auction-pda-reuse-bidder-state-vault-drain]]（状态复用/所有权缺失）；[[blockchain-defi-amm-first-lp-inflation-donation-rounding]]。
- 边界：若 `create` 改为 `public(package)`/工厂白名单、position 绑定 pool id 并在所有敏感函数校验、清算与领奖合并为原子函数，则该链不成立；遗留的旧 lending 实例仍可能被利用。

## 检测与防御

- 检测（审计）：所有接收 `&mut Lending` 与 `&mut Position` 的函数是否校验归属；`create` 的可见性；清算奖励是否可跨池领取；admin 函数是否校验调用者。
- 防御：给 `UserPosition` 增加 `pool_id: ID` 或让 lending 维护 `user_positions: vector<UID>`，在 `liquidate_position`/`claim_liquidation_reward`/`remove_collateral`/`repay` 等函数中 `assert_position_belongs_to_self`；`create` 改为 `public(package)` 或工厂模式并限制白名单；把清算与奖励发放合并为 `liquidate_and_claim`，直接向调用者发放奖励；`convert_decimal` 用 `u128` 中间值并检查 `u64::MAX` 溢出；用 Move Prover/单元测试覆盖跨实例调用。
