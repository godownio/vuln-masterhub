---
id: blockchain-solidity-transferfrom-missing-allowance-check-underflow
title: ERC20 transferFrom 缺少 allowance 前置校验：allowed 映射 0-value 下溢成巨额授权，可转走任意账户代币
type: scenario
domain: blockchain
path: blockchain/solidity
technique: erc20-transferfrom-allowance-underflow
aliases:
- transferFrom 任意转账
- allowance 下溢
- ERC20 授权校验缺失
- allowed 回绕
tags:
- solidity
- erc20
- integer-underflow
- allowance
- smart-contract
- evm
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V513
  verified_at: '2026-11-11T11:18:22+08:00'
  notes: 已对照原文与12张截图：图01 transferFrom 确无 require(allowed) 且执行 allowed[_from][msg.sender] -= _value，图04/08 Remix 交易成功，原理/触发条件/后果与原文一致；dedup 仅 related 同批 check-update-mismatch 卡与 CREATE2 钓鱼卡，非同链；原文未给版本，未设 affected_versions（<0.8 仅作前提，符合）
---

## 一句话结论

Solidity <0.8 且未用 SafeMath 的 ERC20 合约，若 `transferFrom` 在 `allowed[_from][msg.sender] -= _value` 前没有 `require(allowed[_from][msg.sender] >= _value)`，攻击者可对任意持币地址调用 `transferFrom`：授权额度从 0 下溢为 `2^256 - _value`，攻击者当即获得近乎无限的授权，随后可转走该地址全部代币。

## 原理

- EVM 的 uint256 减法在 Solidity <0.8.0 默认不做溢出检查，`0 - _value` 会回绕为 `2^256 - _value`。这与是否使用 SafeMath 决定：用了 SafeMath 的 `sub` 会 revert，未用则静默下溢。
- allowance 的扣减语义是"消耗授权额度"，但代码本身不会验证调用者是否真的获得过授权；许多实现把 `require(balances[_from] >= _value)` 当作唯一前置检查，遗漏了 `allowed[_from][msg.sender] >= _value`。
- 于是任何地址第一次调用 `transferFrom(victim, attacker, amount)` 时：余额检查通过（victim 有币），扣减 `balances[_from]` 正常，而 `allowed[victim][attacker]` 由 0 变成 `2^256 - amount`。由于 allowance 是持久化状态，后续调用不再受额度限制。
- 即使合约同时有 `assert(balances[_from] + balances[_to] == previousBalances)` 之类的总量守恒断言，也只校验余额总和，不能阻止 allowance 下溢。

## 触发条件

- 合约编译器版本 < 0.8.0，且未使用 SafeMath（或该减法未经过 SafeMath）。
- `transferFrom` 中缺少 `require(allowed[_from][msg.sender] >= _value)`。
- 受害者地址持有代币余额（任意数量，首次调用即被转走该数量）。

## 利用步骤

1. 获取目标 ERC20 合约源码（开源或反编译），确认 `transferFrom` 在扣减 allowance 前无授权额度检查。
2. 选定受害者 `_from`（有余额）与攻击者 `_to`。
3. 调用 `transferFrom(_from, attacker, amount)`，`amount` 不超过受害者余额；第一次调用即可转走该数量代币。
4. 此时 `allowed[_from][attacker] = 2^256 - amount`，继续调用 `transferFrom` 转走受害者剩余全部余额（或对同一受害者反复清空后续转入）。
5. 如需批量获利，对多个持币地址重复第 3-4 步。

## PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6; // <0.8 无内建溢出检查

contract VulnerableToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowed;

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(balances[_from] >= _value);
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed[_from][msg.sender] -= _value; // 缺 require(allowed >= _value)：0 - _value 下溢
        return true;
    }
}
// 攻击调用：transferFrom(victim, attacker, 1)
// 结果：balances 转移 1 枚，allowed[victim][attacker] == 2**256 - 1
```

原文在 Remix 中以该方式演示：`transferFrom(_from, _to, _value)` 直接以受害者地址为 `_from` 调用成功，且无任何 approve 记录。

## 变体与关联

- 变体：缺失检查的位置也可以是 `if (allowed[_from][msg.sender] < _value) revert()` 被注释掉、或被错误的条件（如 `allowed[_from][_to]`）替代。
- 关联：[[blockchain-solidity-transferfrom-check-update-mismatch-underflow]]（检查与扣减对象不一致导致的余额下溢）；[[blockchain-solidity-array-length-underflow-arbitrary-storage-owner]]（同为 <0.8 下溢但目标是数组长度与存储槽）。
- 限制：Solidity >=0.8.0 或使用 SafeMath 时该路径自动失效，需要寻找其他逻辑缺陷。

## 检测与防御

- 合约侧：升级到 Solidity >=0.8.0（内建检查）或该减法使用 SafeMath；`transferFrom` 开头加 `require(allowed[_from][msg.sender] >= _value)`。
- 审计侧：把"所有映射/余额的扣减"与"前置 require"逐一配对核对，重点看 allowance、balances、share 等会计变量。
- 监控侧：链上监控 `Approval`/`Transfer` 事件中出现的异常巨大 allowance（接近 2^256）与无授权历史的 transferFrom 调用。
