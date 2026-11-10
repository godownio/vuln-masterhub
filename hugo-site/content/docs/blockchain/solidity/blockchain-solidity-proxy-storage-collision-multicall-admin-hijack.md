---
id: blockchain-solidity-proxy-storage-collision-multicall-admin-hijack
title: 透明代理存储槽冲突 + multicall 嵌套复用 msg.value：劫持 PuzzleWallet 管理员
type: scenario
domain: blockchain
path: blockchain/solidity
technique: proxy-storage-collision-multicall-msgvalue-reuse
tags:
- blockchain
- solidity
- evm
- ethernaut
- proxy
- delegatecall
- storage-collision
- multicall
- msg-value
- access-control
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V268
  verified_at: '2026-11-07T19:00:16+08:00'
  notes: 已对照原文第24关代码与图02/03/04核对：PuzzleProxy/PuzzleWallet 槽位表（slot0 pendingAdmin/owner、slot1 admin/maxBalance、slot2 whitelisted、slot3 balances）、proposeNewAdmin→owner、addToWhitelist、[deposit(), multicall([deposit()])] 嵌套复用 msg.value、execute 提取 0.002 ETH（图03 getBalance=0.001）、setMaxBalance 写 slot1 成为 admin 均与原文/exp 一致。dup-scan 与 18456 的 delegatecall-library-slot0 卡 pair 判 related（漏洞入口与 sink 不同），均保留；dedup 候选 Safe slot0 卡亦 related（不同链）。未执行 PoC。
url: /docs/blockchain/solidity/blockchain-solidity-proxy-storage-collision-multicall-admin-hijack/
draft: false
kb_aliases:
- Ethernaut PuzzleWallet
- 代理存储冲突
- multicall 重复存款
- msg.value 复用
- setMaxBalance 改 admin
- 透明代理槽位错位
---

## 一句话结论

PuzzleProxy 与 PuzzleWallet 通过 delegatecall 共用同一份存储，slot0 的 `pendingAdmin`/`owner` 与 slot1 的 `admin`/`maxBalance` 变量错位；攻击者先 `proposeNewAdmin` 把自己写成 owner，再用嵌套 `multicall` 让 `deposit` 的 `depositCalled` 局部标记在子调用中重置，重复记账 `msg.value` 取走双倍资金，最后 `setMaxBalance` 把攻击者地址写入 slot1，成为代理 admin。

## 原理

- 代理模式中，代理合约把调用 `delegatecall` 给实现合约；代码在实现合约执行，但读写的是**代理合约的存储**。变量名无关，关键是存储槽编号。
- 两个合约的变量声明顺序不同，导致槽位重叠：

| slot | PuzzleProxy | PuzzleWallet |
| --- | --- | --- |
| 0 | `pendingAdmin` | `owner` |
| 1 | `admin` | `maxBalance` |
| 2 | — | `whitelisted`（mapping） |
| 3 | — | `balances`（mapping） |

- `proposeNewAdmin(address)` 写代理 slot0，实现合约的 `owner` 读的也是 slot0，因此调用后 `owner = msg.sender`（攻击合约）。
- `addToWhitelist` 只检查 `msg.sender == owner`；此时 owner 已是攻击合约，攻击合约经代理调用即可把自己加入白名单。
- `multicall` 用一个**局部** `bool depositCalled` 防止 `deposit` 被重复调用，但循环体通过 `address(this).delegatecall(data[i])` 执行。攻击者传入 `[deposit(), multicall([deposit()])]`：外层第一次 `deposit` 后 `depositCalled=true`；第二次进入嵌套 `multicall` 时创建了新的调用帧，`depositCalled` 重新初始化为 false，嵌套里的 `deposit` 再次执行。
- 两次 `deposit` 都执行 `balances[msg.sender] += msg.value`，但整笔交易只附带了一次 `msg.value`；账面上余额翻倍，实际合约只收到一份 ETH。
- 随后 `execute` 按虚增的余额提款，把合约原有 ETH 一并取走；提款后 `address(this).balance == 0`，满足 `setMaxBalance` 的前置条件。`setMaxBalance(uint256)` 写 slot1，即代理的 `admin`，攻击者地址（`uint160(attacker)`）写入后完成管理员劫持。

## 触发条件

- 可升级代理（透明代理/UUPS 等）与实现合约的存储布局不一致，且实现合约有写入冲突槽位的公开函数。
- 代理暴露 `proposeNewAdmin` 这类无权限、直接写 slot0 的函数，或实现合约的 owner 未初始化/可被覆盖。
- 实现合约的批量调用（multicall）在循环内 `delegatecall` 到自身，防重入/防重复的标记是局部变量而非存储变量或 `ReentrancyGuard`。
- 合约接受 `msg.value` 并在循环/子调用中多次使用同一个 `msg.value` 记账。
- 攻击者能调用 `setMaxBalance`（需白名单）且合约余额可被清零。

## 利用步骤

1. 通过代理调用 `proposeNewAdmin(address(attackContract))`：写 slot0，使 `wallet.owner()` 返回攻击合约。
2. 攻击合约经代理调用 `addToWhitelist(address(this))`：`msg.sender` 为攻击合约，等于 owner，白名单写入成功。
3. 构造嵌套 multicall：
   - `depositSelector = abi.encodeWithSelector(wallet.deposit.selector)`
   - `multicallData = abi.encodeWithSelector(wallet.multicall.selector, [depositSelector])`
   - 外层调用 `wallet.multicall{value: X}([depositSelector, multicallData])`
   两次 `deposit` 使 `balances[攻击合约] = 2X`，合约实际只收到 X。
4. 调用 `wallet.execute(attacker, 2X, "")` 取走本合约原有余额（原文关卡中合约原有 0.001 ETH，存入 0.001 后账面 0.002，提出 0.002，合约余额归零）。
5. 调用 `wallet.setMaxBalance(uint256(uint160(attacker)))`：写 slot1，代理 `admin` 变为攻击者，关卡判定通过；攻击合约可再 `selfdestruct` 退回剩余 ETH。

## PoC

原文 PoC 核心（Solidity ^0.8.0，节选）：

```solidity
// 1. 成为 owner
IPuzzleProxy(address(wallet)).proposeNewAdmin(address(this));
// 2. 加入白名单
wallet.addToWhitelist(address(this));
// 3. 嵌套 multicall 重复 deposit
bytes[] memory dep = new bytes[](1);
dep[0] = abi.encodeWithSelector(wallet.deposit.selector);
bytes[] memory mc = new bytes[](1);
mc[0] = abi.encodeWithSelector(wallet.multicall.selector, dep);
bytes[] memory calls = new bytes[](2);
calls[0] = dep[0];
calls[1] = mc[0];
wallet.multicall{value: 0.001 ether}(calls);
// 4. 取走双倍余额
wallet.execute(attacker, 0.002 ether, "");
// 5. 改写 slot1 成为 admin
wallet.setMaxBalance(uint256(uint160(attacker)));
```

原文注明本地测试可打通，并给出 `getBalance(instance)` 为 0.001 与通关提示截图。

## 变体与关联

- 存储冲突变体：代理与实现变量顺序不同、继承链新增变量、使用 `address implementation` 普通变量而非 EIP-1967 非结构化槽，均可造成槽位覆盖；OpenZeppelin 的 storage gap/ERC-7201 命名空间可避免。
- multicall `msg.value` 复用变体：循环内多次 `delegatecall` 可支付函数、批量执行器、聚合器；只要防重标记是局部变量或未锁定 `msg.value`，就可能重复记账。
- 与钱包类 delegatecall slot0 劫持卡（`blockchain-wallet-safe-delegatecall-slot0-mastercopy-hijack`）的区别：本卡是代理/实现存储布局错位叠加 multicall 重复存款，目标是夺取代理 admin 并盗走合约余额。

## 检测与防御

- 代理与实现必须使用一致的存储布局；升级时使用 OpenZeppelin Upgrades 插件校验存储兼容性，新增变量只能追加，使用 storage gap 或 ERC-7201 命名空间槽。
- 禁止实现合约的公开函数无权限地写入可能与代理管理变量重叠的槽位；敏感管理变量放入 EIP-1967 非结构化槽。
- multicall/批量执行器应使用 `ReentrancyGuard` 或存储型重入锁；对 `msg.value` 按每次子调用显式分摊并校验总和不大于实际收到值，禁止同一 `msg.value` 在多个子调用中重复记账。
- 提款前按实际存入金额与合约余额双重校验；`setMaxBalance` 等写入 slot1 的函数应加独立权限控制，不能只依赖白名单。
- 审计关注点：proxy/implementation 变量槽位表、`delegatecall` 循环、局部防重变量、`msg.value` 在循环中的使用。
