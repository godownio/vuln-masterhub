---
id: blockchain-defi-solana-auction-pda-reuse-bidder-state-vault-drain
title: Solana 拍卖程序账户生命周期缺陷：关闭后同 auction_id 重建 PDA，复用旧 bidder_state 盗取 vault
type: scenario
domain: blockchain
path: blockchain/defi
technique: solana-auction-pda-reuse-bidder-state-vault-drain
tags:
- solana
- anchor
- pda
- account-lifecycle
- defi
- vault-drain
- missing-mut
- saturating-sub
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:14:28+08:00'
  notes: 已对照 Auction 段核对：auction_id 可重复、close 后重建同 PDA、旧 bidder_state 复用、缺 mut、saturating_sub、20% 保证金设计均吻合；PoC 未执行
url: /docs/blockchain/defi/blockchain-defi-solana-auction-pda-reuse-bidder-state-vault-drain/
draft: false
kb_aliases:
- Solana PDA 复用
- bidder_state 复用
- auction account 关闭后重建
- Anchor missing mut
- saturating_sub 重复领取
- vault 资金窃取
- Auction
---

## 一句话结论

Solana 拍卖程序用 `[AUCTION_SEED, auctioneer, auction_id]` 派生 auction PDA，用 `[BIDDER_SEED, auction, bidder]` 派生 bidder_state PDA；`close_auction` 只关闭 auction account，bidder_state 仍留在链上，而 `auction_id` 不要求唯一/递增。攻击者关闭拍卖后用相同 `auction_id` 重建同一地址的 auction（把起拍价设得极高），再用第一次拍卖遗留的 bidder_state 调 `claim_refund`；叠加 `bidder_state` 缺 `mut` 与 `deposit_count.saturating_sub(1)`，可反复从 vault 取钱，最终购买 flag。

## 原理

- **PDA 派生与关闭语义**：Auction account 的地址由 seeds + program id 决定，`close_auction` 关闭 account 后该地址可被重新初始化；bidder_state 的 seeds 依赖 auction key 与 bidder，auction 关闭不会级联关闭 bidder_state。
- **auction_id 不唯一**：创建 auction 时 `auction_id` 由用户传入，程序未要求递增/全局唯一；关闭后再次传入相同 id，PDA 重新派生为同一地址，旧 bidder_state 的 seeds（拍卖 key 相同）仍然匹配，可继续使用。
- **缺少 `mut`**：`claim_refund`、`claim_winner`、`seize_deposit` 的 `bidder_state` 未标注 `#[account(mut)]`，Anchor 生成的 exit 逻辑不会把该 account 写回链上；对 `refunded` 等字段的修改只在本次执行的内存中生效，下一次调用仍看到旧值（未退款）。
- **saturating_sub**：三个 claim 指令对 `auction.deposit_count` 使用 `saturating_sub(1)` 而非 `checked_sub`；当计数已为 0 时仍返回 0 而不 panic，允许继续执行退款/领取逻辑。
- **保证金设计**：起拍价 > 1 SOL 的拍卖要求预交 20% 保证金；低起拍价拍卖不需要保证金。攻击者先用低起拍价创建拍卖，正常出价/关闭，留下 bidder_state；再以相同 auction_id 重建高起拍价拍卖（地址相同），使旧 bidder_state 看起来属于一个“高价值拍卖”，然后用 `claim_refund` 从 vault 取走资金。
- **为什么能重复**：缺 `mut` 导致 refunded 标记不落盘，saturating_sub 允许计数为 0 时继续，两个缺陷叠加使同一 bidder_state 可反复 claim，直到 vault 被抽干。

## 触发条件

- 目标 Solana/Anchor 程序允许用户创建 auction 并传入 `auction_id`；`close_auction` 只关闭 auction account，不关闭/标记 bidder_state。
- `bidder_state` PDA 的 seeds 只依赖 auction key/bidder，不依赖 auction 的创建轮次/版本。
- `claim_refund`/`claim_winner`/`seize_deposit` 的 bidder_state 缺 `mut`，且 deposit_count 使用 `saturating_sub`。
- 攻击者能创建/关闭拍卖、出价、在拍卖结束后调用 claim；vault 中有足够资金/flag 可通过资金购买。

## 利用步骤

1. **创建廉价拍卖**：用 `create_auction` 传入 `auction_id = X`、低起拍价（≤1 SOL，免保证金），记录 auction PDA。
2. **建立 bidder_state**：用 `place_bid` 以攻击者账户出价，生成 `bidder_state` PDA（seeds 含 auction key + bidder）。
3. **正常结束/关闭**：按程序流程结束拍卖并调用 `close_auction` 关闭 auction account；bidder_state 仍存在。
4. **重建同一地址拍卖**：再次 `create_auction`，传入相同的 `auction_id = X` 和极高起拍价；PDA 与第一次相同，旧 bidder_state 的 seeds 继续匹配。
5. **利用 claim**：在第二个拍卖结束后，用旧 bidder_state 调用 `claim_refund`；由于 `bidder_state` 缺 `mut`，refunded 修改不落盘，可重复调用；`deposit_count.saturating_sub` 允许计数为 0 时继续。
6. **抽干 vault**：重复 claim，把 vault 资金转入攻击者账户；用资金在程序内购买 flag/兑换。
7. **验证**：检查攻击者余额与 vault 余额变化；若一次 claim 金额受限，循环直到足够。

## PoC

```rust
// 伪代码：利用账户生命周期
create_auction(auction_id = 1, starting_price = 0.1 SOL);   // 免保证金
place_bid(auction = auction_pda(1), amount = min);
close_auction(auction = auction_pda(1));                    // bidder_state 仍存在

create_auction(auction_id = 1, starting_price = 1000 SOL);  // 同一 PDA 地址
// ... 拍卖结束 ...
claim_refund(auction = auction_pda(1), bidder_state = old_bidder_state);
claim_refund(auction = auction_pda(1), bidder_state = old_bidder_state); // refunded 未落盘
// 重复直到 vault 资金足够购买 flag
```

原文通过 Anchor 客户端构造上述指令序列；具体账户列表/参数需按目标程序 IDL 生成。本卡不执行 PoC。

## 变体与关联

- **其它 PDA 复用**：任何“关闭后可用相同 seed 重建”的账户（拍卖、订单、质押、市场）都可能复用旧子账户；尤其子账户 seeds 依赖父账户 key 而非版本/轮次时。
- **缺 `mut` 的通用影响**：Anchor 只对 `mut` 账户生成写回；任何依赖“执行后状态持久化”的逻辑都可能失效（退款标记、计数器、状态机）。
- **saturating_sub 重复执行**：计数为 0 时仍可执行，允许重复领取/重复关闭；应使用 `checked_sub` 并显式处理 0。
- **关联**：[[blockchain-defi-amm-first-lp-inflation-donation-rounding]]（DeFi 经济攻击）、[[blockchain-solidity-evm-guess-honeypot-detection]]（合约状态机）、[[blockchain-wallet-safe-delegatecall-slot0-mastercopy-hijack]]（账户/存储复用）。
- **边界**：需要目标程序按上述方式派生/关闭账户；若程序在 close 时同时关闭 bidder_state、要求 auction_id 唯一递增、或 claim 使用 checked_sub/mut，利用失效。

## 检测与防御

- **账户生命周期**：关闭 auction 时同时关闭/标记关联 bidder_state；在 bidder_state 中记录 auction 的创建轮次/版本，seeds 或校验中包含该值，防止跨轮复用。
- **唯一性**：要求 `auction_id` 全局唯一/严格递增（或用随机 nonce），并在创建时检查 PDA 不存在；防止同地址重建。
- **状态持久化**：所有会被修改的账户标注 `mut`；对关键字段使用 `checked_sub`/`checked_add`，计数为 0 时拒绝执行；退款/领取使用一次性标记并落盘。
- **保证金逻辑**：高起拍价拍卖的保证金计算与校验在链上完成，不依赖客户端；claim 时校验拍卖轮次、状态与出价记录。
- **检测/监控**：同一 auction_id 多次创建、同一 bidder_state 多次 claim、vault 余额异常下降、deposit_count 为 0 仍调用 claim；链上审计脚本可检测这些模式。
- **响应**：暂停程序、冻结 vault、升级程序并迁移账户；审计所有 PDA 生命周期与 Anchor 约束。
