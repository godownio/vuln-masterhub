---
id: blockchain-defi-dex-zero-fee-mining-worthless-token-wash-swap
title: DEX 无交易费挖矿：手续费按输入币收取 + 挖矿门槛仅校验含 EOS，自建垃圾币对刷量套利
type: scenario
domain: blockchain
path: blockchain/defi
technique: dex-zero-fee-mining-worthless-token-wash-swap
aliases:
- 无交易费挖矿
- DeFis Network Swap 挖矿漏洞
- 垃圾币刷量挖矿
- wash trading mining
- 手续费币种错配
tags:
- blockchain
- defi
- dex
- eos
- business-logic
- mining
- fee
- economic-attack
- wash-trading
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502
  verified_at: '2026-11-11T02:40:29+08:00'
  notes: 已对照原文与图01 do_swap 代码核对：手续费按输入量计算（tmp=mul(amount_in,PROTOCOL_FEE); protocol_fee=tmp/10000）并以 asset(protocol_fee, quantity.symbol) 转给 PROTOCOL_FEE_ACCOUNT；mining_dfs 以 extended_asset(quantity,code) 参与，条件为交易对含 EOS 且 >1 EOS；自建垃圾币/EOS 对刷量逻辑成立。属经济/手续费的激励设计缺陷，原文为审计推演未链上复现，卡内 confidence medium 已体现并在边界注明；非 DoS、非纯原语，最终危害（按虚假交易量发放挖矿奖励）由代码逻辑可直接得出。dedup 候选（现货价操纵、DexTwo、Move 闪贷/取整）机制不同，非同链；dup-scan.json 早于建卡不涉及本卡。frontmatter 无 sources/source_url；非组件无版本。
---

## 一句话结论

EOS 上的 DeFis 风格 Swap 合约把协议手续费与交易手续费都按输入代币数量计算并以输入代币收取，而挖矿资格只检查交易对中含 EOS 且单笔交易额大于 1 EOS；攻击者可以自建一个毫无价值的代币与 EOS 组成交易对，反复用垃圾币兑换 EOS，手续费以垃圾币支付近乎零成本，却能持续制造交易量并领取挖矿奖励，形成"无交易费挖矿"。

## 原理

- **手续费与币种绑定在输入侧**：`do_swap` 中 `amount_in = quantity.amount`，协议费按 `amount_in * PROTOCOL_FEE / 10000` 计算后从 `amount_in` 中扣除，并以 `asset(protocol_fee, quantity.symbol)` 转账给协议费账户——即手续费永远使用**输入代币**结算；交易费（TRADE_FEE）也在 `get_amount_out` 里按输入量参与计算，同样体现为输入代币的扣减。
- **挖矿门槛只看交易对与金额**：`mining_dfs(mid, from, quantity_in_ex, quantity_out_ex)` 的参与条件仅为"交易对中包含 EOS 代币"且"交易额大于 1 EOS"，不检查输入代币是否有真实价值、不检查交易对手、不设白名单或权重。
- **攻击构造**：攻击者发行一个无价值代币 T（或使用自己控制的便宜代币），建立 T/EOS 交易对并注入少量 EOS 作为初始流动性；随后用自己的账户反复执行"T → EOS"的 swap。每笔手续费以 T 计（几乎零成本），但交易对含 EOS、金额大于 1 EOS，满足挖矿条件，按交易量累积挖矿奖励；奖励（平台币或 EOS）可提现，而 T 的成本可忽略。
- **为什么成立**：手续费的经济负担应与真实资产挂钩，但实现把计价单位设成了攻击者可无限发行的输入代币；挖矿激励按交易量发放而没有质量门槛，导致"刷量"的边际成本趋近于零而收益为正。
- **边界**：攻击收益取决于挖矿奖励价值、gas 成本、池中 EOS 深度以及协议是否有额外权重/白名单；若手续费改按 EOS 计价、或挖矿按 EOS 侧的贡献计权，则该路径失效。原文只给出逻辑推演，未提供链上交易复现与收益量化。

## 触发条件

- 目标为 EOS 链上 DeFis 风格 Swap/挖矿合约，手续费按输入代币收取且挖矿资格仅校验交易对含 EOS 与最低交易额。
- 攻击者能创建代币与交易对（或找到可低价获取的代币/交易对）。
- 挖矿奖励价值高于 swap 与 gas 成本，且奖励可按交易量累积。
- 协议未对交易代币做白名单、权重或单交易对刷量限制。

## 利用步骤

1. 阅读 `do_swap` 与 `mining_dfs`：确认手续费扣减与转账使用 `quantity.symbol`（输入代币），挖矿条件仅要求交易对含 EOS 且 `quantity.amount` 超过阈值。
2. 发行/获取无价值代币 T，创建 T/EOS 市场并注入少量 EOS 流动性。
3. 循环调用 `swap`（T → EOS），每笔金额略高于挖矿门槛；手续费以 T 支付。
4. 持续累积挖矿奖励并领取；视池子 EOS 流出情况补充流动性或换用多个交易对/账户分散刷量。
5. 将奖励变现，核算 T 成本、gas 与滑点，确认净收益。

## PoC

无 PoC（原文为代码审计与逻辑推演，未提供链上交易或脚本）。最小伪代码：

```text
create_token(T) -> 增发给自己
create_market(T, EOS) -> 注入少量 EOS 流动性
loop:
    swap(market_id, from=attacker, quantity=asset(<略高于挖矿门槛>, T), code=T)
    # 手续费以 T 扣除；mining_dfs 判定交易对含 EOS 且金额达标 -> 累积奖励
claim_mining_rewards()
```

## 变体与关联

- 变体：手续费改用池中另一种代币或 LP 份额计价时，攻击面变化；挖矿按 EOS 侧或按时间加权可抑制刷量。
- 变体：同类"激励刷量"也出现在借贷挖矿、流动性挖矿（用自建代币对刷交易量/存款量领取平台币），核心都是奖励计量指标可被低成本操纵。
- 关联：AMM 首存通胀与现货价操纵等经济攻击见 [[blockchain-defi-amm-first-lp-inflation-donation-rounding]]、[[blockchain-defi-dex-spot-reserve-swap-drain]]；本卡是激励/手续费设计层面的问题。
- 边界：若协议对低价值代币设置权重、对同一交易对限频/限额，或奖励以 EOS 侧真实贡献计算，攻击成本上升。

## 检测与防御

- 协议侧：手续费以 EOS 或稳定币等真实资产计价；对交易挖矿建立代币白名单并按资产价值/权重计算贡献；对同一交易对/地址设交易量上限、冷却与异常检测。
- 监控：新建交易对短期内出现高频、金额刚好过门槛的循环 swap；单一地址或关联地址在自建代币对刷量并集中领取奖励；奖励发放与真实 EOS 流入严重不匹配。
- 响应：暂停可疑交易对的挖矿权重、冻结/回收异常奖励、重新校准激励公式。
