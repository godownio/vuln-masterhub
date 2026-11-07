---
id: blockchain-move-governance-unstake-vote-replay-inflation
title: Sui Move 治理质押投票重复计票：unstake 不撤销选票 + vote 无去重，循环质押/投票抬高 no_votes
type: scenario
domain: blockchain
path: blockchain/move
technique: move-governance-unstake-vote-replay-inflation
aliases:
- ghost_vote
- Move 治理重复投票
- 质押投票重复计票
- unstake 未清理选票
- 循环质押投票
tags:
- blockchain
- move
- sui
- governance
- voting
- staking
- logic-bug
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T07:09:13+08:00'
  notes: 已对照原文 ghost_vote 合约源码与 solve 模块核对：vote 无去重（voted 只 push_back）、unstake 不回滚票权、循环 stake→vote(no)→unstake 抬高 no_votes，最终再 stake 保证 no_votes>balance/2，与 is_solved 条件一致。
---

## 一句话结论

Sui Move 治理合约的 `vote` 只把投票人 `push_back` 到 `proposal.voted`，既不检查是否已投过，`unstake` 也不删除/回滚用户在各提案上的票权；攻击者在同一笔交易里循环“质押 → 投反对票 → 解质押 → 再质押”，每次都用同一笔币重复累加 `no_votes`，而治理总质押 `balance` 在投票时不变，最终让 `no_votes > balance/2` 使提案关闭，满足 `is_solved` 的“提案已关闭且反对票超过总票权一半”条件。

## 原理

- **合约状态**：`Governance<C>` 维护 `proposals: vector<Proposal>`、`stakes: Table<address, u64>` 与 `balance: Balance<C>`。`Proposal` 有 `yes_votes`、`no_votes`、`is_open`、`voted: vector<address>`。
- **vote 的逻辑**：`vote(proposal_index, yes, ctx)` 先断言 `proposal.is_open`，取 `ctx.sender()`，断言 `stakes.contains(user)`，`vote_power = *stakes.borrow(user)`，然后 `proposal.voted.push_back(user)`；投赞成则 `yes_votes += vote_power`，投反对则 `no_votes += vote_power`，并且当 `no_votes > self.balance.value() / 2` 时把 `is_open = false`。
- **缺少去重**：`proposal.voted` 只是追加，`vote` 从未检查该地址是否已经在 `voted` 中；因此同一个人可以对同一提案反复投票，每次都以当前 `stakes[user]` 作为票权。
- **unstake 不清理选票**：`unstake` 只 `self.stakes.remove(user)` 并 `balance.split(amount)` 把币退给用户；它不会遍历 `proposals` 删除该用户的赞成/反对票，也不会扣减 `yes_votes`/`no_votes`。因此“解质押”后，之前计入的票权仍然留在提案里。
- **循环放大**：攻击者把自己的币反复“质押 → 投票 → 解质押”。每次质押后 `balance` 增加 `amount`、`stakes[user] = amount`，投票时 `no_votes += amount`；解质押后 `balance` 减少、`stakes` 删除，但 `no_votes` 不回滚。下一轮再质押同一笔币，`no_votes` 再 `+amount`。投票瞬间的分母 `balance` 只包含“基础质押 + 攻击者当前这笔”，不会随轮数增长，所以 `no_votes` 相对分母线性增长，很快超过一半。
- **满足 is_solved**：挑战的 `is_solved` 要求 `!proposal.is_open()` 且 `proposal.no_votes() > governance.get_balance() / 2`。循环中当 `no_votes > balance/2` 时 `vote` 会把 `is_open` 置 false；脚本随后再 `stake` 一次把币放回，使最终 `balance` 与最后一次投票时一致，因此 `no_votes > balance/2` 仍成立。
- **为什么同一笔交易/同一模块能完成**：Sui Move 的 `entry`/`public` 函数可以在一个 PTB 或一个 solve 模块里连续调用；`stake` 消耗 `Coin<C>`，`unstake` 返回新的 `Coin<C>`，脚本用 `coins = unstake(ctx)` 重新拿到币继续下一轮，循环直到 `is_open == false`。

## 触发条件

- 治理合约使用“按地址记录质押额、投票时读取当前质押额作为票权”的模型。
- `vote` 没有“每个地址每个提案只能投一次”的检查（`voted` 只追加不校验），或检查可被绕过。
- `unstake` 不删除/扣减该用户已投的票，也不阻止“投票后立即解质押”。
- 攻击者能获得初始 `Coin<C>`（挑战中的 `claim_coin` 即可），且提案处于 open 状态。
- 提案关闭/通过阈值只比较 `no_votes` 与治理总 `balance`，没有快照、时间锁或每地址票权上限。

## 利用步骤

1. 调用挑战的 `claim_coin(ctx)` 取得用于质押的 `Coin<COIN>`。
2. 进入循环：
   - `governance.stake(coins, ctx)`：把币质押，`balance` 增加、`stakes[sender] = amount`；
   - `governance.vote(GET_PROPOSAL_INDEX_TO_DECLINE(), false, ctx)`：以当前质押额投反对票，`no_votes += amount`；若 `no_votes > balance/2`，合约把 `is_open = false`；
   - `coins = governance.unstake(ctx)`：取回质押币，`balance` 减少、`stakes` 删除该地址，但 `no_votes` 不回滚；
   - 若 `proposal.is_open() == false` 则跳出循环，否则继续下一轮。
3. 循环结束后再 `governance.stake(coins, ctx)`，把币放回治理合约，使最终 `balance` 与最后一次投票时一致，保证 `no_votes > balance/2`。
4. 挑战的 `is_solved` 检查通过：提案已关闭且 `no_votes` 超过治理总余额的一半，取得 flag。
5. 若基础 `balance` 较大，循环会多跑若干轮；每轮净效果是 `no_votes += amount`，而投票时的分母仅为基础余额 + 当前这枚币，因此轮数上限由 `(基础余额 + amount) / (2*amount)` 决定。

## PoC

原文 solve 模块（整理后）：

```move
module the_solution::solution;

use challenge::challenge::{Challenge, GET_PROPOSAL_INDEX_TO_DECLINE};
use challenge::coin::COIN;

public fun solve(challenge: &mut Challenge<COIN>, ctx: &mut TxContext) {
    let mut coins = challenge.claim_coin(ctx);
    while (true) {
        challenge.get_governance().stake(coins, ctx);
        challenge.get_governance().vote(GET_PROPOSAL_INDEX_TO_DECLINE(), false, ctx);
        coins = challenge.get_governance().unstake(ctx);
        if (!challenge.get_governance()
                .get_proposal(GET_PROPOSAL_INDEX_TO_DECLINE()).is_open()) {
            break
        }
    };
    challenge.get_governance().stake(coins, ctx);
}
```

核心逻辑等价于：`no_votes` 每轮增加一次当前质押额，但 `balance` 在每轮投票时只包含一笔质押，因此同一笔币被重复计票。

## 变体与关联

- **变体：只缺少 vote 去重**。即使 `unstake` 清理票，若 `vote` 可在同一质押期内重复调用，`no_votes` 仍可在一轮内被同一票权刷高；修复必须同时做“每地址每提案一次”和“解质押撤销票”两件事。
- **变体：先投赞成再解质押**。同一缺陷也可用于抬高 `yes_votes` 或先投反对再改投赞成（若合约允许重复投票），具体取决于 `is_solved` 检查的是哪一侧。
- **关联：其他 Sui Move 投票/治理漏洞**。现有卡 [[blockchain-move-voting-vote-request-ballot-binding-missing]] 是 `VoteRequest` 未绑定 ballot 导致的跨对象重复计票，本卡是“同一 ballot/提案上重复投票 + unstake 不清理”，两者根因不同但同属“票权可重复累加”；可对照其修复思路（记录 `yes_voters`/`no_voters` 表、投票去重、解质押时删除票）。
- **关联：质押/DeFi 逻辑**。同类“状态未随资金退出而回滚”的问题也见于借贷/金库合约，可参考 [[blockchain-move-lending-position-cross-instance-collateral]]、[[blockchain-move-vault-ptb-atomicity-cross-vault]]。

## 检测与防御

- **修复 1：投票去重**。为 `Proposal` 增加 `yes_voters: Table<address, u64>` 与 `no_voters: Table<address, u64>`，`vote` 前检查两个表都不包含 `user`，投票时写入票权；不要只依赖 `voted: vector<address>` 追加而不校验。
- **修复 2：解质押撤销票**。在 `unstake` 中遍历所有提案，调用 `delete_vote` 从 `yes_voters`/`no_voters` 删除该用户并扣减 `yes_votes`/`no_votes`；或者禁止“投过票的地址在提案结束前解质押”。
- **修复 3：票权快照/上锁**。投票时锁定质押，提案结束前不可解质押；或使用快照区块的质押额计票，避免同一笔资金在投票期间反复进出。
- **审计信号**：`vote` 只做 `voted.push_back` 而无 `contains` 检查；`unstake` 不触及 `proposals`；`no_votes > balance/2` 的阈值使用实时 `balance`；存在 `stake_for` 允许任意地址代质押时还要检查代投/女巫组合。
- **边界**：本卡是 CTF 治理合约的逻辑漏洞，利用前提是攻击者能反复质押/解质押且提案阈值按实时余额计算；真实治理合约若加入时间锁、快照或每地址票权上限，利用条件会变化。
