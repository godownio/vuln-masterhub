---
id: blockchain-move-voting-vote-request-ballot-binding-missing
title: Move 投票合约请求未绑定选票：request_vote 与 finish_voting 跨对象重复计票
type: scenario
domain: blockchain
path: blockchain/move
technique: move-voting-vote-request-ballot-binding-missing
aliases:
- Move 投票重复计票
- VoteRequest 未绑定 Ballot
- finish_voting 跨 ballot
- Sui bribery_voting
- has_voted 绕过
tags:
- blockchain
- move
- sui
- voting
- object-binding
- logic-bug
- access-control
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:30+08:00'
  notes: 已对照原文核对；request_vote/finish_voting 跨 ballot 计票链一致；未在链上复现
---

## 一句话结论

Sui Move 投票合约中，`request_vote(ballot)` 会检查并设置 `ballot.has_voted=true`，返回一个含 10 票权力的 `VoteRequest`；但 `finish_voting(ballot, request)` 只把 request 里的票累加到传入的 ballot，不校验该 request 是否由同一个 ballot 签发。攻击者用 `request_vote(ballot2)` 生成请求、再用 `finish_voting(ballot1, request)` 计入 ballot1，重复多次即可让 ballot1 获得远超单次 10 票的票数（达到 21 票），满足 `get_flag` 条件。

## 原理

- **职责分离但缺少绑定**：`request_vote` 负责一次性授权（检查 `ballot.voted.is_empty()`、`!ballot.has_voted`，设置 `has_voted=true`，返回 `VoteRequest { voting_power: 10, voted: vec_map::empty() }`）；`finish_voting` 负责把 request 中的 `voted` 合并进 ballot。问题在于 `VoteRequest` 没有携带 ballot id/地址，`finish_voting` 也没有检查 `request` 与 `ballot` 的对应关系。
- **利用方式**：准备多个 ballot（或让 `request_vote` 在未投票的 ballot2 上签发请求），对每个请求调用 `vote(candidate, &mut request, 10)` 写入候选人票数，再 `finish_voting(ballot1, request)` 把 10 票累加到 ballot1。ballot1 自身的 `has_voted` 从未被设为 true（因为 request 是在 ballot2 上签发的），所以可以反复用新的 ballot 签发请求，ballot1 的票数无限增长。
- **阈值**：`default_voting_power()` 为 10，`required_votes()` 为 21；三次请求即可 30 票，超过阈值。
- **次要缺陷**：`amend_account(candidate, account)` 允许任意调用者修改 candidate 的 account，导致投票对象可被任意切换/多人投给同一 candidate；`register` 是 public，任何人都能创建 candidate。两者可作为辅助变体。
- **修复方向**：让 `VoteRequest` 绑定 ballot（存 `ballot_id` 或用泛型/一次性能力），`finish_voting` 断言 `request.ballot_id == object::id(ballot)`；或在 `finish_voting` 也检查/设置 `ballot.has_voted`，并把 request 设计为不可转移、一次性消费的能力对象；`amend_account` 限制为 candidate 所有者。

## 触发条件

- `request_vote` 只在签发时检查 `ballot.has_voted`，`finish_voting` 不校验 request 与 ballot 的绑定。
- `VoteRequest` 可被自由传递/复用到其他 ballot；`vote` 可对 request 累加票数。
- 单次投票权力（10）小于目标阈值（21），但攻击者能获取多个 ballot 或重复签发请求。
- `get_flag` 只检查 ballot 上某 candidate 的票数，不检查投票过程的合法性/次数。

## 利用步骤

1. 注册/获取一个 candidate（或使用目标 candidate）。
2. 准备 ballot1（目标计票对象）与 ballot2（用于签发请求的另一个 ballot）。
3. 调用 `request_vote(ballot2)` 得到 `VoteRequest`（10 票），对 request 调用 `vote(candidate, &mut request, 10)`。
4. 调用 `finish_voting(ballot1, request)`，10 票累加到 ballot1；ballot1.has_voted 仍为 false。
5. 换用新的 ballot（ballot3/ballot4…）重复步骤 3-4，或对同一 ballot2 若 has_voted 已置位则改用新 ballot；累计到 ≥21 票。
6. 调用 `get_flag(briber, ballot1, github_id, ctx)`，`voted.try_get(required_candidate())` 存在且 ≥ required_votes，取得 flag。
7. 可选：用 `amend_account` 把 candidate.account 改为攻击者/目标地址，影响投票对象。

## PoC

```move
module solve_bribery_voting::solve {
    use bribery_voting::ballot::{Ballot, request_vote, finish_voting};
    use bribery_voting::candidate::{Candidate, vote};

    // 第一次：正常在 ballot 上请求并计票
    public fun solve_request_vote(candidate: &mut Candidate, ballot: &mut Ballot, _ctx: &mut TxContext) {
        let mut vote_request = request_vote(ballot);
        vote(candidate, &mut vote_request, 10);
        finish_voting(ballot, vote_request);
    }

    // 关键：在 ballot2 上签发请求，却把票计入 ballot1
    public fun solve_request_vote_subsequent(
        candidate: &mut Candidate,
        ballot1: &mut Ballot,
        ballot2: &mut Ballot,
        _ctx: &mut TxContext,
    ) {
        let mut vote_request = request_vote(ballot2);
        vote(candidate, &mut vote_request, 10);
        finish_voting(ballot1, vote_request);
    }
}
```

说明：PoC 为原文 week3 exp 的整理版，未在链上执行；原文用 `request_vote(ballot2) → finish_voting(ballot1)` 的重复调用把 ballot1 票数刷到 30 并取得 flag。原文未给出修复代码，本卡按 Move 对象绑定原则给出修复方向。

## 变体与关联

- 变体（绑定缺失）：`VoteRequest` 不带 ballot id；`finish_voting` 不校验；`has_voted` 只在 request 侧设置。
- 变体（权限）：`amend_account` 任意调用者可改 candidate.account；`register` 公共可调，攻击者可批量创建 candidate/ballot。
- 变体（重复计票）：同一 request 被多次消费（若未 move 语义限制）、跨 ballot 计票、票权累加不受限。
- 关联：[[blockchain-move-lending-position-cross-instance-collateral]]（同为对象归属/绑定缺失）；[[blockchain-move-flashloan-receipt-type-confusion]]（回执未绑定类型）；[[blockchain-solidity-evm-guess-honeypot-detection]]（合约状态/权限陷阱）。
- 边界：若 `VoteRequest` 用泛型/能力对象绑定 ballot、`finish_voting` 校验 id 并原子设置 `has_voted`、或投票权力/阈值设计为不可重复累加，该链不成立。

## 检测与防御

- 检测（审计）：`request_vote` 与 `finish_voting` 是否共享同一 ballot 绑定；`VoteRequest` 是否可转移/复用；`has_voted` 在哪个函数设置；`amend_account`/`register` 的权限。
- 防御：给 `VoteRequest` 增加 `ballot_id: ID`，`finish_voting` `assert!(request.ballot_id == object::id(ballot))`；把 request 设计为 `key` 对象或不可复制的一次性能力（Move 的 `drop`/`copy` 能力要谨慎），消费后销毁；在 `finish_voting` 同时检查 `!ballot.has_voted` 并设置；限制 `amend_account` 为 candidate 所有者；对票权/阈值做单元测试与 Move Prover 不变量（总票数 ≤ 合法投票者数 × 单次权力）。
