---
id: blockchain-defi-dextwo-arbitrary-token-swap-drain
title: DexTwo 任意代币兑换：未校验交易对，自建代币 1:1 换走池内全部真币
type: scenario
domain: blockchain
path: blockchain/defi
technique: dex-arbitrary-token-pair-drain
aliases:
- Ethernaut DexTwo
- 假币兑换
- 任意 token swap
- 交易对未校验
- 自建 ERC20 抽干 DEX
tags:
- blockchain
- defi
- dex
- amm
- solidity
- ethernaut
- arbitrary-token
- fake-token
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V268
  verified_at: '2026-11-07T19:00:14+08:00'
  notes: 已对照原文第23关代码核对：DexTwo.swap 删除 (from==token1&&to==token2)||(from==token2&&to==token1) 校验、只保留余额检查；自建 BadToken3/BadToken4 先向 DEX 转入 100 并 approve，再 swap 1:1 抽干 token1/token2，与原文 exp 及注释一致；卡已注明原文 exp 省略了转入/授权两步需补齐。dup-scan 与 Dex 卡判 likely_duplicate：按原文裁决为不同关卡/不同根因（本卡任意代币/缺交易对校验 vs Dex 现货价操纵），均保留（related），dedup 工具亦判 related。未执行 PoC。
---

## 一句话结论

DexTwo 的 `swap` 删掉了 Dex 中 `(from==token1 && to==token2) || (from==token2 && to==token1)` 的交易对校验，任何人都能传入自建 ERC20；攻击者部署可任意铸币的假币，先给 DEX 转入与目标储备等量的假币，再用假币按 `amount * to.balance / from.balance` 以 1:1 换走池内全部真币。

## 原理

- 原版 Dex 的 `swap` 第一行强制 `from`/`to` 必须是登记过的 `token1`/`token2` 且方向合法。DexTwo 只保留了余额检查：

```
require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
```

  于是 `from`、`to` 完全由调用者指定，任意实现了 ERC20 接口的合约都能参与兑换。
- 报价公式仍为 `swapAmount = amount * balanceOf(to, dex) / balanceOf(from, dex)`。攻击者可以让“池内假币余额”和“池内真币余额”相等，使兑换比为 1:1；由于假币由攻击者自己部署、可任意 mint，成本几乎为零。
- 攻击者需要先向 DEX 转入与目标储备等量的假币（否则分母为 0 或比例不利），再授权 DEX 从自己账户划走 `amount` 假币；`swap` 随后把 DEX 持有的真币按计算数量转给攻击者。
- 对 token1、token2 各准备一个假币（或同一个假币分两次操作），即可把 DEX 中两种真币的储备全部抽干。

## 触发条件

- DEX 的 `swap` 只校验发送方余额，不校验 `from`/`to` 是否在登记的白名单/交易对中。
- 报价依赖 `balanceOf(from/dex)` 与 `balanceOf(to/dex)` 的当前值，且攻击者能向 DEX 转入任意代币。
- 攻击者能部署 ERC20 合约并任意 mint（标准 OpenZeppelin ERC20 在构造时 mint 给攻击者即可）。
- DEX 对 `to` 代币的 `approve/transferFrom` 调用不限制代币来源，且池内存在可观的真实代币余额。

## 利用步骤

1. 部署两个假币合约 `BadToken3`、`BadToken4`，构造时各 mint 1000 给攻击者。
2. 对每个假币先向 DEX 转入与目标真币储备相同的数量（如各 100），使 `getSwapAmount` 的分母与分子相等。
3. 在假币合约上调用 `approve(dex, 100)`，授权 DEX 执行 `transferFrom`。
4. 调用 `dex.swap(BadToken3, token1, 100)`：`swapAmount = 100 * 100 / 100 = 100`，DEX 把 100 枚 token1 转给攻击者。
5. 对 token2 重复：`dex.swap(BadToken4, token2, 100)`，抽干 100 枚 token2。
6. 攻击者把真币转回自己地址；假币留在池内，但已无价值。

## PoC

原文给出假币合约与 ethers.js 调用（最小化）：

```solidity
contract BadToken is ERC20 {
    constructor() ERC20("MyToken", "MT") { _mint(msg.sender, 1000); }
}
```

```javascript
const amount = 100;
// 先部署 BadToken3/BadToken4，向 DEX 各转入 amount，再在假币上 approve(DEX, amount)
await contract.swap(T3, await contract.token1(), amount);  // 抽干 token1
await contract.swap(T4, await contract.token2(), amount);  // 抽干 token2
```

原文脚本注释明确要求“DEX must have `amount` T3, and also `amount` allowance”，即向池子转入假币并完成授权是必要前置；原文 exp 片段省略了这两步，实战需补齐。

## 变体与关联

- 同类：DEX/路由合约只按用户传入的 token 地址做 `transferFrom`，不校验 token 是否在支持列表；攻击者用假币、fee-on-transfer 币或回退币（rebase/blacklist）抽干池子。
- 与 Dex 现货价操纵卡的区别：Dex 卡的交易对合法，靠反复 swap 推偏储备比例；本卡靠“任意代币无成本注入”直接 1:1 兑换，二者根因不同。
- 关联：Uniswap V2 pair 的 `swap` 本身只允许两种登记代币，因此该漏洞多见于自行实现、简化版 AMM 或聚合器。

## 检测与防御

- `swap` 入口必须校验 `from`/`to` 属于已登记且互配的交易对（`require((from==token1 && to==token2) || (from==token2 && to==token1))`），不要把用户传入的任意地址当合法代币。
- 维护代币白名单，部署时登记；新增代币需治理/多签审批，并在兑换时校验 `to` 的池内余额来自协议认可的资产。
- 报价使用可信价格源，限制单笔兑换比例；对 `balanceOf` 异常变化、假币地址与低流动性代币做监控。
- 审计关注点：`swap`/`addLiquidity` 中是否有 token 地址白名单或 pair 校验；是否直接对任意 `IERC20(from).transferFrom`。
