---
id: blockchain-solidity-reentrancy-withdraw-call-before-zero-drain
title: Solidity 重入清空合约余额：withdraw 先 call 转账后清零，攻击合约 receive 递归提款直到余额为 0
type: scenario
domain: blockchain
path: blockchain/solidity
technique: solidity-reentrancy-call-before-state-update-drain
aliases:
- Solidity 重入攻击
- withdraw 重入
- call 先转账后清零
- receive 递归 withdraw
- captureFlag 重入
- checks-effects-interactions 违反
- Mamma Mia
tags:
- blockchain
- solidity
- reentrancy
- defi
- ctf
- checks-effects-interactions
- evm
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V553
  verified_at: '2026-11-11T23:07:25+08:00'
  notes: 本篇无图，已按 content.md 全文核对 MammaMia 合约与攻击合约：withdraw 先 call 后 balances=0、receive 中 getBalance()!=0 则递归 withdraw、captureFlag 要求合约余额 0、resetFlag 付 0.001 ether 登记 flagResetters、getFlag 只查 flagResetters，均与原文源码一致；原文正文一处 0.01 ether 与代码 0.001 矛盾，卡内已注明以代码为准。dedup 仅 Shop TOCTOU 相关，无重入同链。未验证点：原文未给链上余额与交易哈希，重入递归是否被实际触发取决于合约当时是否持有额外存款。
---

## 一句话结论

`withdraw()` 先用 `msg.sender.call{value: bal}("")` 把余额转给调用者、之后才 `balances[msg.sender] = 0`：攻击合约在 `receive()` 里检查目标合约仍有余额就再次调用 `withdraw()`，每次重入都按同一份未清零的余额转账，直到目标合约余额被抽干；随后 `captureFlag()` 因 `address(this).balance == 0` 通过，`resetFlag()` 付 0.001 ether 登记为 flagResetter，`getFlag()` 拿到 flag。

## 原理

- **重入的本质**：EVM 里 `call{value:...}("")` 会把控制权交给接收方合约的 `receive()`/`fallback()`，此时被调用方（withdraw 所在合约）的状态尚未更新。攻击者利用这段"控制权在外部"的窗口再次进入同一函数，绕过"先检查后修改"的假设。
- **本例的状态顺序**：`uint bal = balances[msg.sender]; require(bal > 0); (bool sent,) = msg.sender.call{value: bal}(""); require(sent); balances[msg.sender] = 0;`——余额检查与清零之间夹着外部调用，且清零在调用之后；重入时 `bal` 仍是旧值，可以反复转出。
- **递归何时停止**：攻击合约的 `receive()` 写成 `if (m.getBalance() != 0) { m.withdraw(); }`，目标合约余额每转出一份就减少，直到为 0 时不再重入，外层调用正常返回并把 `balances[attacker]` 清零。这样既抽干合约（包括其他用户的存款），又让 `captureFlag()` 的 `require(address(this).balance == 0)` 成立。
- **为什么 `require(sent)` 不会坏掉**：最后一次重入发生在余额仍大于 0 时，转账成功；余额归零后的下一次判断不再发起调用，因此递归链正常收束（若在余额 0 时硬转 0.001 会失败并导致回滚，所以攻击合约要做余额检查）。
- **后续条件**：`captureFlag()` 要求 `flagCapturer == address(0)` 且合约余额为 0，把它设为攻击者；`resetFlag()` 要求 `flagCapturer == msg.sender` 且附带 ≥0.001 ether，登记 `flagResetters[msg.sender]=true` 并把 flagCapturer 复位；`getFlag()` 只检查 `flagResetters[msg.sender]`。

## 触发条件

- 目标合约的提款函数用原生币 `call` 转账且"先转账后清零"（或任何把状态更新放在外部调用之后的顺序）。
- 攻击者以合约身份调用（EOA 没有 `receive`，无法重入）；攻击合约可接收 ETH 并能在 `receive` 中再次调用目标。
- 目标合约持有可提走的余额（本题攻击者先 `deposit` 0.001 ether 建立余额；实际场景中还包括其他用户存款）。
- 目标函数没有 `nonReentrant` 锁、没有 gas 限制，调用转发全部可用 gas（`call` 默认转发全部 gas；转账 2300 gas 的 `transfer`/`send` 才难以重入）。
- 后续 `captureFlag`/`resetFlag`/`getFlag` 的条件按题目逻辑可满足。

## 利用步骤

1. 部署攻击合约，构造入口：
   - `attack1()`：`m.deposit{value: 0.001 ether}()` 建立余额；
   - `attack2()`：`m.withdraw()` 触发重入递归；
   - `attack3()`：`m.captureFlag()`（此时合约余额为 0）；
   - `attack4()`：`m.resetFlag{value: 0.001 ether}()` 登记 flagResetter；
   - `attack5()`：`m.getFlag()` 读取 flag。
2. 在攻击合约的 `receive()` 中判断目标余额：`if (m.getBalance() != 0) { m.withdraw(); }`，实现"有余额就继续提"。
3. 按顺序发起交易；观察目标合约余额变为 0、`flagCapturer` 变为攻击合约地址。
4. 调用 `getFlag()` 验证拿到 flag。

## PoC

原文攻击合约核心（Solidity 0.8.13）：

```solidity
contract Attack {
    MammaMia m;
    string flag;
    constructor(address _m) { m = MammaMia(payable(_m)); }

    function attack1() public payable { m.deposit{value: 0.001 ether}(); }
    function attack2() public { m.withdraw(); }
    function attack3() public { m.captureFlag(); }
    function attack4() public payable { m.resetFlag{value: 0.001 ether}(); }
    function attack5() public { flag = m.getFlag(); }
    function getFlag() public view returns (string memory) { return flag; }

    receive() external payable {
        if (m.getBalance() != 0) { m.withdraw(); }
    }
}
```

目标合约关键代码：

```solidity
function withdraw() public {
    require(!flagResetters[msg.sender], "The flag resetter is not allowed to withdraw");
    uint bal = balances[msg.sender];
    require(bal > 0, "No balance to withdraw");
    (bool sent, ) = msg.sender.call{value: bal}("");   // 外部调用，控制权转移
    require(sent, "Failed to send Ether");
    balances[msg.sender] = 0;                          // 状态更新在调用之后
}
```

原文未给出完整的部署与交易哈希，PoC 为代码级复现，未在本机链上执行。

## 变体与关联

- **同函数重入 / 跨函数重入**：重入目标可以是同一 withdraw，也可以是 withdraw 与 transfer 等共享余额状态的函数组合；本例是单函数递归。
- **只读重入**：价格预言机在外部调用期间读取被操纵的中间状态，造成清算/定价错误。
- **防护对照**：库内卡 `emergencyWithdraw 未缓存金额先清零` 是"顺序写反"的另一类后果（用户本金锁死），与重入相反；`Shop view 价格两次调用 TOCTOU` 是同一调用栈内两次读取不一致；可对照理解"外部调用窗口 + 状态不一致"这一共性。
- **绕过非重入锁**：跨合约/跨函数的重入、`receive` 之外的 fallback、代理合约的多次 delegatecall 等都可能绕过只加在单函数上的 nonReentrant。

## 检测与防御

- **代码模式**：遵守 checks-effects-interactions：先 `balances[msg.sender] = 0`，再转账；使用 OpenZeppelin `ReentrancyGuard` 的 `nonReentrant`；转账失败与状态回滚要一起考虑。
- **审计**：搜索所有 `call{value:...}`、`call(...)`、`delegatecall` 与状态写入的相对顺序；对"余额/份额在外部调用后才更新"的函数列为高危。
- **监控**：同一交易内对同一合约的重复调用深度异常、短时间内余额被抽干；链上监控可对 withdraw 的递归调用栈告警。
- **题目视角**：先满足"合约余额为 0"的检查（captureFlag），再处理 flagResetter 的付费登记；重入只是把"合约余额清零"的过程自动化并顺带获利。

## 备注

- 原文为 2024 BMW web3 CTF 题解（Medium-Mamma Mia）；攻击合约代码与目标源码均来自原文，未在本机链上复现。
- 原文中 resetFlag 的条件写作 `msg.value >= 0.001 ether`，正文一处误写为 0.01 ether，以代码为准。
