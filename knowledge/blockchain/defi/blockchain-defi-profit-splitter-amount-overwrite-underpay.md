---
id: blockchain-defi-profit-splitter-amount-overwrite-underpay
title: DeFi 利润分配少付：swap 分支把待发金额覆盖为换出额，漏掉合约已有 ETH
type: scenario
domain: blockchain
path: blockchain/defi
technique: profit-splitter-amount-overwrite-underpay
aliases:
- 利润分配错误
- _payToBudget amount 覆盖
- swap 分支金额赋值错误
- 预算合约少收
- ProfitSplitter 记账错误
tags:
- blockchain
- defi
- solidity
- business-logic
- accounting
- profit-distribution
- swap
- audit
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502
  verified_at: '2026-11-11T02:40:33+08:00'
  notes: 已对照原文 _payToBudget 代码与图04修复 diff 核对：else 分支 amount=amountsOut[1] 覆盖原差额，随后 budget.transfer(amount)，合约原有 splitterEthBalance 未转出；正确应为 splitterEthBalance.add(amountsOut[1])（图04绿行），卡片原理/触发/修复均准确。影响为预算合约少收与资金滞留，非 DoS/纯原语，逻辑由代码直接证明；severity low 合理。dedup 候选（Move 取整/闪贷、DEX 现货操纵、代理存储冲突等）均非同链；dup-scan.json 早于建卡不涉及本卡。frontmatter 无 sources/source_url；非组件无版本。
---

## 一句话结论

某 DeFi 利润分配合约的 `_payToBudget()` 在合约 ETH 余额不足以补足预算差额时，会先把部分 incoming 代币换成 ETH，但补差分支把待分配金额 `amount` 直接覆盖成本次换出的 `amountsOut[1]`，而不是"合约原有 ETH + 本次换出 ETH"；随后 `budget.transfer(amount)` 只转出换得的部分，原有 `splitterEthBalance` 被留在合约里，预算合约持续少收、资金滞留。

## 原理

- **业务目标**：把合约中多余的 incoming 代币兑换成 ETH，使预算合约 `budget` 的余额达到目标 `budgetBalance`。差额 `amount = budgetBalance - currentBudgetBalance`，合约现有 ETH 为 `splitterEthBalance`。
- **正常分支**：若 `splitterEthBalance >= amount`，直接用现有 ETH 转账即可；若不足，需要把 incoming 换成缺口 `amountOut = amount - splitterEthBalance`。
- **缺陷分支**：当 `getAmountsIn` 需要的输入超过合约持有的 incoming 余额时，代码改为把全部 incoming 换成 ETH，得到 `amountsOut[1]`，然后执行 `amount = amountsOut[1]` 覆盖了原来的待分配差额；最后的 `budget.transfer(amount)` 只发送这笔新换出的 ETH，忽略了本就在合约里的 `splitterEthBalance`。
- **正确逻辑**：该分支下应转给预算合约的总额是 `splitterEthBalance + amountsOut[1]`，即原有 ETH 加上本次换出的 ETH；直接把 `amountsOut[1]` 赋给 `amount` 会导致少付 `splitterEthBalance`。
- **影响**：预算合约长期收不到足额利润，差额资金留在 splitter 合约中；依赖预算余额的下游分配/支出出现短缺，且滞留资金可能被后续逻辑误用或因合约无提取函数而锁死。
- **为什么容易被漏掉**：变量 `amount` 在函数前段表示"目标差额"，在分支里被复用为"本次实际转出额"，语义随分支改变；审计时若只看单行赋值而不追踪资金守恒，容易忽略。

## 触发条件

- 合约使用该利润分配逻辑，且一次 `_payToBudget` 调用中 `splitterEthBalance < amount`（需要 swap 补差）。
- `getAmountsIn(amountOut)` 计算出的所需输入大于合约当前 incoming 余额，从而进入 else 分支。
- 合约中已持有一定 ETH（`splitterEthBalance > 0`），使少付部分真实存在。
- 函数可被正常业务流程触发（投资、购买、流动性操作等内部调用）。

## 利用步骤

> 本条为审计/验证路径，非攻击者直接获利链。

1. 定位 `_payToBudget`：记录 `amount`（差额）、`splitterEthBalance`（合约 ETH 余额）、`amountsOut[1]`（换出 ETH）。
2. 在 else 分支确认 `amount = amountsOut[1]`，随后 `budget.transfer(amount)`。
3. 构造 `splitterEthBalance > 0` 且 incoming 不足的场景，调用触发函数，观察预算合约只收到 `amountsOut[1]`，合约仍残留 `splitterEthBalance`。
4. 修复：`amount = splitterEthBalance.add(amountsOut[1]);`（或先转原有 ETH，再转换出部分），并补充资金守恒断言与测试。

## PoC

无 PoC（原文给出代码 diff，未部署复现）。修复示意：

```solidity
// 修复前（else 分支）
amount = amountsOut[1];
budget.transfer(amount);

// 修复后：把合约原有 ETH 与本次换出的 ETH 一起转给预算合约
amount = splitterEthBalance.add(amountsOut[1]);
budget.transfer(amount);
```

## 变体与关联

- 变体：同类"变量复用/分支内覆盖"导致的少付或多付，常见于手续费结算、收益复投、清算奖励分配；审计时对所有 `amount = ...` 赋值做数据流追踪。
- 关联：DeFi 记账与份额计算类问题参见 [[blockchain-defi-amm-first-lp-inflation-donation-rounding]]（舍入与储备记账）；本卡是分配环节的金额覆盖。
- 边界：若合约每次调用前都把 ETH 余额清零、或 `splitterEthBalance` 恒为 0，则少付不显现；若预算合约可被任意调用者补足，影响主要是资金滞留而非永久损失。

## 检测与防御

- 审计：对"目标差额"与"实际转出额"使用不同变量，避免分支内覆盖；转账前后断言 `budget.balance` 增加额等于预期，校验 `address(this).balance` 守恒。
- 测试：覆盖 `splitterEthBalance > 0/==0`、`amountsIn[0] <= incomingBalance` 与 `>` 两个分支的组合，断言预算合约收到总额正确。
- 监控：预算合约余额增长与预期分配额持续偏离、splitter 合约 ETH 余额异常累积；对长期滞留资金告警。
- 响应：修复赋值逻辑并迁移滞留资金，复核其他使用相同模式的结算函数。
