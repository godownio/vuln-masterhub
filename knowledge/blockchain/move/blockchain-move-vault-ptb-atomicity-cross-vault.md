---
id: blockchain-move-vault-ptb-atomicity-cross-vault
title: Move 金库买卖跨对象与 PTB 原子性：多金库刷余额和同时间戳批量卖出
type: scenario
domain: blockchain
path: blockchain/move
technique: move-vault-ptb-atomicity-cross-vault
aliases:
- Sui potato vault
- 多 vault 买卖
- PTB 原子批量
- timestamp % 3 卖出
- vault owner 校验缺失
tags:
- blockchain
- move
- sui
- ptb
- vault
- atomicity
- business-logic
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:33+08:00'
  notes: 已对照原文核对；多 vault/PTB 原子性思路一致，原文 PTB 捕获返回值有实现问题；未在链上复现
---

## 一句话结论

Sui Move 金库题中，`sell_potato` 只校验 `vault.owner == sender`，不校验 Potato 是否由同一个 vault 购买/烹饪；而 `init_vault` 是 `public`，攻击者可创建任意多个各自带 100 balance 的 Vault。于是可以用 vault1 买+烹饪（每轮花 4），再用 vault2 卖出（每轮 +5，且卖出成功依赖 `clock.timestamp_ms % 3 == 1`），把收益集中到 vault2；也可以利用 PTB 的原子性，把 100 次 buy-cook-sell 放进同一笔交易、共享同一时间戳，失败则整笔 abort 重试，成功则一次性把 vault 余额从 100 刷到 200 并接上 `get_flag`。

## 原理

- **owner 校验不绑定 Potato**：`buy_potato(vault)` 扣 3 生成 Potato；`cook_potato(vault, potato)` 再扣 1 并置 `cooked=true`；`sell_potato(clock, vault, potato)` 只断言 `vault.owner == sender`、`potato.cooked`，然后把奖励 `+5` 加到传入的 vault。它不检查 potato 是否由该 vault 购买，因此可以用 vault1 的余额买/烹饪，用 vault2 收卖出收益。
- **public init_vault**：`init_vault` 是 public，任何人都能创建新 Vault（每个初始 100 balance，owner 为调用者）；攻击者可创建多个 vault，用它们分别承担“支出池”和“收益池”，或分摊购买成本。
- **时间依赖与原子性**：`sell_potato` 用 `current_timestamp % 3 == 1` 决定本次卖出是否 +5；否则 Potato 被删除但不加钱。单次交易内 `Clock` 时间戳固定，PTB 可以把大量 buy-cook-sell 调用打包进同一笔交易；Move 交易是原子的——任一调用 abort 则整笔回滚，全部成功则所有卖出都看到同一个时间戳。攻击者可以在 `timestamp % 3 == 1` 时一次执行 100 轮，净收益 +100（每轮 -3-1+5=+1），余额从 100 到 200；若时间不满足，整笔 abort，换时间重试。
- **为什么可行**：经济模型假设“每个 Potato 只能在同一 vault 内买卖、每次卖出独立随机”，但 owner 校验只绑定 vault 不绑定 Potato，且时间戳是交易级共享状态；PTB 原子性把“多次独立卖出”变成“同一时刻的批量卖出”。
- **原文实现注意**：原文 `buy_potato` 用 `transfer::transfer(potato, sender)` 把 Potato 转给调用者，并未 `return`；因此原文 JS PTB 里 `const [potato] = tx.moveCall(...)` 直接捕获返回值的写法与实际函数签名不一致。实际操作需要：(a) 用返回 `Potato` 的包装函数/修改后的合约，或 (b) 在同一交易中通过对象 ID 引用刚创建的 Potato（若 PTB 支持），或 (c) 分多笔交易先买/烹饪、再按对象 ID 卖出。原文自己的“注意事项”也承认 Move 包装函数因无返回值失败，但对其 PTB 片段的可执行性说明不够严谨。

## 触发条件

- `sell_potato` 只校验 vault owner，不校验 Potato 与 vault 的归属/来源。
- `init_vault` 为 public，攻击者可创建多个 Vault。
- 卖出成功依赖可预测/可等待的链上时间（`timestamp % 3 == 1`），且 PTB 支持批量调用与原子回滚。
- `get_flag` 只检查 vault.balance ≥ 200，不检查余额来源或交易次数。

## 利用步骤

1. 创建/获取 vault1（支出池）与 vault2（收益池），两者 owner 都是攻击者；可用 public `init_vault` 创建更多。
2. 在 vault1 调 `buy_potato`（-3）生成 Potato，调 `cook_potato`（-1）置 cooked。
3. 在 vault2 调 `sell_potato(clock, vault2, potato)`：若 `timestamp % 3 == 1`，vault2 +5；否则 Potato 被删、不加钱。
4. 重复 2-3；由于每轮净 +1（-4+5），vault2 从 100 涨到 200 需要 100 次成功卖出；vault1 需能承担 100 次购买+烹饪的 400 成本（若 vault1 只有 100，则用多个支出池或改用 PTB 单池循环）。
5. PTB 方案：把 100 次 `buy→cook→sell` 放入同一 `TransactionBlock`，在 `timestamp % 3 == 1` 时提交；全部成功则 vault 余额 +100，随后在同一 PTB 调 `get_flag`；若 abort，整笔回滚后重试。
6. 调用 `get_flag(vault, ctx)`，balance ≥ 200 时触发 Flag 事件。

## PoC

```javascript
// 原文 PTB 思路（100 次 buy-cook-sell 打包；需按实际合约返回值调整）
const tx = new TransactionBlock();
const vault = tx.object(VAULT_ID);
const clock = tx.object("0x6");

for (let i = 0; i < 100; i++) {
  const [potato] = tx.moveCall({
    target: `${PACKAGE_ID}::potato::buy_potato`,
    arguments: [vault, tx.object("0x6")],
  });
  tx.moveCall({
    target: `${PACKAGE_ID}::potato::cook_potato`,
    arguments: [vault, potato, tx.object("0x6")],
  });
  tx.moveCall({
    target: `${PACKAGE_ID}::potato::sell_potato`,
    arguments: [clock, vault, potato, tx.object("0x6")],
  });
}
tx.moveCall({ target: `${PACKAGE_ID}::potato::get_flag`, arguments: [vault] });
```

说明：PoC 为原文 JS PTB 片段的结构化复现，未在链上执行；原文合约的 `buy_potato` 实际是 transfer 而非 return，`[potato]` 捕获可能不成立，需按“原文实现注意”调整。原文另给出跨 vault 的 Move 包装函数思路，并注明因 `buy_potato` 不返回 Potato 而失败。

## 变体与关联

- 变体（归属缺失）：Potato 不绑定 vault id；sell 只查 owner；buy/cook 与 sell 可用不同 vault。
- 变体（权限/资源）：`init_vault` 公共可调，任意创建 100 balance 金库；可创建多个支出池分摊成本。
- 变体（时间/原子性）：`timestamp % 3` 的伪随机；PTB 批量调用共享时间戳；交易 abort 重试；把 get_flag 放在同一 PTB 尾部形成“成功才提交”。
- 关联：[[blockchain-move-amm-swap-pre-reserve-rounding-drain]]（PTB/闪贷组合）；[[blockchain-move-lending-position-cross-instance-collateral]]（对象归属缺失）；[[blockchain-move-flashloan-receipt-type-confusion]]；[[blockchain-solidity-evm-guess-honeypot-detection]]（时间/状态依赖）。
- 边界：若 Potato 绑定 vault id 并在 sell 校验、`init_vault` 限制为一次性/私有、卖出改用不可预测随机数或不可批量重试的机制，则该链不成立；PTB 捕获转移对象的行为需以实际 SDK/合约返回值为准。

## 检测与防御

- 检测（审计）：`sell_potato` 是否校验 Potato 来源 vault；`init_vault` 可见性；卖出随机性是否来自 `Clock` 取模；`get_flag` 是否只检查余额；PTB 是否可批量调用同一函数。
- 防御：给 Potato 增加 `vault_id: ID` 并在 sell 时校验；把 buy/cook/sell 绑定为同一 vault 的状态机；`init_vault` 改为 `public(package)` 或工厂/一次性；卖出使用不可预测随机源或把时间/随机性纳入不可批量重试的设计；对 `get_flag` 增加来源/次数/状态校验；用 Move Prover 验证“余额只能通过合法买卖变化”。
