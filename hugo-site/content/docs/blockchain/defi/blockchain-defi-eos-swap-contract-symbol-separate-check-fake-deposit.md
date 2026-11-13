---
id: blockchain-defi-eos-swap-contract-symbol-separate-check-fake-deposit
title: EOS 币币交换假充值：contract 与 symbol 分开校验，contract0 的 sym1 冒充交易对币种
type: scenario
domain: blockchain
path: blockchain/defi
technique: eos-extended-asset-separate-check-fake-deposit
tags:
- blockchain
- defi
- dex
- eos
- extended-asset
- validation-bypass
- fake-deposit
- business-logic
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V502
  verified_at: '2026-11-11T02:40:31+08:00'
  notes: 已对照原文与图01/02 核对：do_swap 中 check(code==contract0||code==contract1) 与 check(quantity.symbol==sym0||sym1) 为两个独立条件（第266-267行），contract0:sym1 错配组合可通过；else 分支输出 asset(amount_out,sym0)@contract0（第289-296行），与卡片描述一致；原文明确假币与 sym0 同一合约发行。原文未链上复现，卡内 confidence medium 已体现。dedup 候选（CREATE2 授权钓鱼、DexTwo 任意代币、Move 闪贷/取整）机制与链不同，非同链；dup-scan.json 早于建卡不涉及本卡。frontmatter 无 sources/source_url；非组件无版本。
url: /docs/blockchain/defi/blockchain-defi-eos-swap-contract-symbol-separate-check-fake-deposit/
draft: false
kb_aliases:
- 币币交换假充值
- DeFis Network Swap 假充值
- EOS extended_asset 校验缺陷
- contract symbol 分开判断
- 假代币换真币
---

## 一句话结论

EOS 上的 DeFis 风格 Swap 合约在 `do_swap` 里把输入代币的合约名与 symbol 分成两个独立条件校验——`code` 属于 {contract0, contract1} 且 `symbol` 属于 {sym0, sym1}——而不是校验二者的组合；攻击者用 contract0 发行的 sym1（并非交易对真正期望的 contract1:sym1）作为输入即可通过检查，被合约当作 sym1 处理后换出 contract0 的 sym0，形成"假充值"式盗兑。

## 原理

- **EOS 代币身份是 (contract, symbol) 组合**：EOS 上的 `extended_asset` 由合约账户与 symbol 唯一标识，不同合约可以发行同名 symbol；判断两个资产是否相同必须同时比较合约和 symbol。
- **缺陷代码**：`check((code == m_it->contract0 || code == m_it->contract1), "contract error"); check((quantity.symbol == m_it->sym0 || quantity.symbol == m_it->sym1), "symbol error");` 两个条件分别成立即可，`contract0:sym1` 这种组合既不是交易对的 reserve0 资产也不是 reserve1 资产，却能通过校验。
- **错误分支进入与输出**：后续 `if (code == contract0 && symbol == sym0)` 为假，走 else 分支，按 sym1 的方向计算 `amount_out`，并构造 `quantity_out = asset(amount_out, sym0)`、`quantity_out_ex = extended_asset(quantity_out, contract0)` 输出——即把攻击者存入的假币当成交易对中的 sym1，换出同一合约 contract0 发行的 sym0。
- **为什么可获利**：如果 contract0 能发行多个 symbol（攻击者控制该代币合约，或该合约支持增发/多 symbol），攻击者可以几乎零成本获得 contract0:sym1，存入后按池中比例换走有价值的 contract0:sym0，反复执行即可抽干 sym0 储备。
- **修复**：校验完整的资产组合——只允许 `(contract0, sym0)` 或 `(contract1, sym1)` 两种输入，并确保输出资产与交易对定义一致；不要分别比较 contract 与 symbol。

## 触发条件

- 目标 EOS Swap 合约使用 `extended_asset` 交易对，且输入校验按 contract、symbol 分开判断。
- 交易对某一侧合约能发行/存在多个 symbol，攻击者可低成本获得"错误组合"代币（如 contract0:sym1）。
- 池中目标输出代币（本例 contract0:sym0）有实际价值且储备充足。
- 合约未对输入资产做完整组合校验或白名单。

## 利用步骤

1. 审计 `do_swap`：确认 contract 与 symbol 是两个独立 check，未比较 `(code, symbol)` 组合。
2. 确定交易对的 (contract0, sym0) 与 (contract1, sym1)，找到一个可低成本获得的错配资产，例如由 contract0 发行的 sym1。
3. 调用 `swap`：`code=contract0`、`quantity=asset(amount, sym1)`，使两个 check 均通过并进入 else 分支。
4. 合约按 sym1→sym0 方向报价并转出 contract0 的 sym0；重复 2–3 步直至抽干目标储备或收益递减。
5. 将换出的 sym0 变现，核算假币成本与滑点。

## PoC

无 PoC（原文为代码审计，未提供链上交易）。最小调用示意：

```text
# 交易对: (contract0, sym0) / (contract1, sym1)
# 攻击输入: contract0 发行的 sym1（错配组合，两个 check 分别通过）
swap(mid=<market>, from=<attacker>, quantity=asset(<amount>, "sym1"), code="contract0")
# 合约走 else 分支，按 sym1 方向计算，输出 asset(amount_out, "sym0") @ contract0
```

## 变体与关联

- 变体：Solana/EVM 上"代币地址与符号分别校验"、跨链资产只校验 symbol 不校验合约地址，同样可被假币冒充。
- 关联：代币身份校验缺失类问题也常见于充值/提现桥接合约（只比对 symbol、不比对合约或链 ID），可参考同目录其他 DeFi 校验缺陷卡。
- 边界：若 contract0 只能发行单一 symbol、或合约改为完整 `extended_asset` 比较/白名单，该路径失效；原文未给出实际交易复现与池子规模，收益取决于储备深度。

## 检测与防御

- 协议侧：对输入/输出资产做完整 `(contract, symbol)` 组合校验，只允许交易对定义中的两个资产；对可增发/多 symbol 的代币设白名单与风险评级。
- 代码审计：搜索 `contract0/contract1` 与 `sym0/sym1` 分开判断的模式；检查所有 `extended_asset` 比较是否成对进行。
- 监控：同一交易对出现非白名单合约或错配 symbol 的 swap；短时间内异常的"低价值币换高价值币"并集中提现。
- 响应：暂停交易对、回滚/冻结异常交易，修复校验逻辑并复核其他交易对。
