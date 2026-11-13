---
id: blockchain-solidity-transferfrom-check-update-mismatch-underflow
title: ERC20 transferFrom 余额检查用 msg.sender 而扣减 _from：小额授权触发 _from 余额下溢，凭空铸出 2^256 代币
type: scenario
domain: blockchain
path: blockchain/solidity
technique: erc20-check-update-mismatch-underflow
aliases:
- 检查更新不一致
- msg.sender 与 _from 混用
- 余额下溢造币
- allowed key 混用
tags:
- solidity
- erc20
- integer-underflow
- business-logic
- transferfrom
- evm
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V513
  verified_at: '2026-11-11T11:18:24+08:00'
  notes: 已对照原文与12张截图：图02 检查 balances[msg.sender] 而扣减 balances[_from]、allowed 检查用 msg.sender 扣减用 _to；图07/08 演示 B 向 A 授权10000后 A 调 transferFrom(B,A,10000)，图09 确认 B 余额下溢为 2^256-10000，与卡片一致；与 missing-allowance 卡为同文不同缺陷（balances 下溢 vs allowed 下溢），原子且互不重复，同批 related 关联成立；未设 affected_versions
---

## 一句话结论

ERC20 `transferFrom` 若用 `require(balances[msg.sender] >= _value)` 检查、却用 `balances[_from] -= _value` 扣减（且 allowance 的检查与扣减 key 也混用），攻击者用一个余额充足的账户 A 和一个余额为 0 的账户 B 即可：B 先向 A 授权小额，A 调用 `transferFrom(B, A, amount)`，A 的余额通过检查，B 的余额 0-amount 下溢成 `2^256 - amount`，B 从而凭空获得巨额代币并可转移变现。

## 原理

- 检查与更新对象不一致：`require(balances[msg.sender] >= _value)` 验证的是调用者（A）的余额，实际扣减的却是 `_from`（B）的余额。没有 SafeMath/0.8 检查时，B 的余额从 0 下溢为 `2^256 - amount`。
- 同函数的 allowance 处理也可能混用 key：检查 `allowed[_from][msg.sender]` 却扣减 `allowed[_from][_to]`，使授权校验与消耗对象错位，攻击者只需让 B 给 A 授小额（满足检查），而真正被扣的是另一个 key，不阻碍利用。
- 攻击者只需保证 A 余额 >= amount（可通过正常充值或自有资金满足），B 无需任何余额——B 只是被下溢的"造币账户"。
- 余额下溢后 B 变成巨鲸地址，可正常调用 transfer 把代币转给 A 或在场外卖掉；链上余额与总供应量并未同步增加（totalSupply 不变），但 balances 之和已超出 totalSupply，形成凭空铸币。

## 触发条件

- Solidity <0.8.0 且未使用 SafeMath（或未覆盖该减法）。
- `transferFrom` 的余额检查对象与扣减对象不一致（检查 `msg.sender`、扣减 `_from`）。
- allowance 的检查 key 与扣减 key 不一致（检查 `allowed[_from][msg.sender]`、扣减 `allowed[_from][_to]` 之类）。
- 攻击者控制两个地址：A 有余额，B 余额为 0 且能向 A 授权。

## 利用步骤

1. 审计/定位存在"检查 `msg.sender`、扣减 `_from`"的 transferFrom 合约。
2. 准备 A（有余额）与 B（余额 0，作为造币账户）。
3. 用 B 对 A 调用 `approve(A, amount)`，满足 A 发起 transferFrom 时的 allowance 检查（amount 取小值即可）。
4. A 调用 `transferFrom(_from=B, _to=A, amount)`：余额检查看 A 通过；扣减 `balances[B] -= amount` 下溢为 `2^256 - amount`。
5. B 现在持有巨额代币，调用 `transfer(A, largeAmount)` 或在场外/交易所卖出变现；最终 A 收回本金并获得赃款。

## PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract MismatchToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowed;

    function approve(address spender, uint256 amount) public returns (bool) {
        allowed[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] >= _value);            // 检查调用者
        require(allowed[_from][msg.sender] >= _value);
        balances[_from] -= _value;                           // 扣减 _from -> 下溢
        balances[_to] += _value;
        allowed[_from][_to] -= _value;                       // key 混用：_to 而非 msg.sender
        return true;
    }
}
// B.approve(A, 10000);  A.transferFrom(B, A, 10000)
// => balances[B] == 2**256 - 10000
```

原文 Remix 演示：B（余额 0）向 A 授权 10000 后，由 A 发起 `transferFrom(B, A, 10000)`，交易成功，B 的余额变为 2^256-10000，A 获得 10000 枚。

## 变体与关联

- 变体：检查 `balances[_to] + _value > balances[_to]` 之类溢出前置、但扣减对象错误，同样可构造下溢。
- 变体：`transfer` 与 `transferFrom` 的会计变量混用（share/amount、debt/reward）导致记账错位。
- 关联：[[blockchain-solidity-transferfrom-missing-allowance-check-underflow]]（同一合约族中 allowance 未检查的另一种下溢）；[[blockchain-solidity-shop-view-price-double-call-toctou]]（同属业务逻辑中的"检查与执行不一致"）。
- 限制：0.8+ 或 SafeMath 下不会下溢，但"检查-更新不一致"仍可能导致逻辑错账（如白名单、限额判断）。

## 检测与防御

- 合约侧：0.8+ 或 SafeMath；检查与扣减必须指向同一地址/同一映射 key：`require(balances[_from] >= _value)` 对应 `balances[_from] -= _value`，allowance 检查与扣减都用 `allowed[_from][msg.sender]`。
- 审计侧：逐个函数核对"条件里的对象"与"更新里的对象"是否一致，尤其 msg.sender、_from、_to 三者混用；对每个减法确认前置条件覆盖。
- 监控侧：监控同一地址余额从 0 变为接近 2^256 的异常事件，以及 balances 总和与 totalSupply 偏离。
