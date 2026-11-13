---
id: blockchain-solidity-extcodesize-constructor-iscontract-bypass
title: extcodesize 合约地址检测在构造期失效：攻击合约在 constructor 中调用目标，绕过 isContract/禁止合约参与校验
type: scenario
domain: blockchain
path: blockchain/solidity
technique: extcodesize-constructor-construction-bypass
tags:
- solidity
- evm
- smart-contract
- extcodesize
- iscontract
- reentrancy
- constructor
- access-control
- audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V529
  verified_at: '2026-11-11T15:40:21+08:00'
  notes: 已对照原文与1张截图核对：OpenZeppelin Address.sol 注释明确 isContract 对 EOA/构造中合约/将创建地址/已销毁地址返回 false，extcodesize 构造期为0 的机制成立；原文 MaliciousContract 的汇编 PoC（call(5000,0x04,...)）并非 extcodesize 调用、attack(...) public 由 EOA 调用时合约已部署 extcodesize!=0，均不成立，卡内未照抄并给出正确 constructor 攻击 PoC，纠正成立。另修正卡内两处技术错误：构造期攻击合约尚无运行时代码、目标回调不会执行 receive/fallback，不能做回调重入（已改为 constructor 内循环多次调用）；删除『部署后同交易内调用』也能绕过的错误表述，并补充 PoC 需攻击合约地址已有可提取余额的前提。dedup 候选（CREATE2/自毁地址预计算、shop 双调用 TOCTOU 等）均非同一链，dup-scan 无涉及 pair。原文无明确受影响版本（示例 pragma ^0.8.0，OZ 注释为通用说明），未设置 affected_versions。
url: /docs/blockchain/solidity/blockchain-solidity-extcodesize-constructor-iscontract-bypass/
draft: false
kb_aliases:
- extcodesize 绕过
- isContract 构造期绕过
- 合约检测绕过
- 构造函数绕过地址检查
- 禁止合约调用绕过
- contract in construction
- OpenZeppelin Address.isContract 缺陷
---

## 一句话结论

用 `extcodesize(addr) > 0` 判断地址是否为合约（OpenZeppelin `Address.isContract` 同理）在合约构造期失效：合约在 constructor 执行时代码尚未部署，`extcodesize` 返回 0，`isContract` 判定为 EOA；攻击者把调用目标合约的逻辑放进攻击合约的 constructor，`msg.sender` 是"代码为空"的合约地址，即可通过 `require(!isContract(msg.sender))` 之类"禁止合约参与"的检查，实施领取奖励/空投、资金转移、构造期内循环调用提款等操作（注意构造期攻击合约尚无运行时代码，目标回调它不会执行 `receive`/`fallback`，不能靠回调做经典重入）。

## 原理

- **EVM 部署流程**：部署合约的交易先执行 constructor，运行期字节码（runtime code）在构造函数执行结束后才写入账户；因此构造期间该账户的 code 为空。
- **extcodesize 的语义**：`extcodesize(addr)` 读取账户 code 的字节长度；构造期（以及尚未部署的地址）为 0。许多合约用它实现 `isContract`：`size > 0` 认为是合约，`size == 0` 认为是 EOA。
- **绕过**：攻击合约在 constructor 中调用目标合约的函数。目标合约里 `isContract(msg.sender)` 返回 false，于是"仅 EOA 可调用/合约禁止参与"的限制被满足；而调用方实际上是合约，可在 constructor 内执行任意逻辑（包括在一次部署交易里循环/多次调用 `withdraw`、批量领取等；构造期该合约还没有运行时代码，目标回调它不会执行 `receive`/`fallback`，因此不能用回调重入，只能在 constructor 内顺序多次调用）。
- **为什么补丁仍不彻底**：OpenZeppelin `Address.isContract` 文档明确指出，对 EOA、构造中的合约、将要创建合约的地址、已销毁合约的地址都返回 false；基于 EIP-1052 `extcodehash` 的 `AddressUtils`（判断 `codehash != 0 && codehash != keccak256('')`）在构造期 codehash 仍是空代码哈希，同样判为 false。因此 `extcodesize`/`extcodehash` 都不能作为"是否合约"的安全边界。
- **重入防护误用**：把 `!isContract(msg.sender)` 当作重入保护是错误的：它挡不住构造期合约（无代码可通过检查，且可在 constructor 内多次调用）；"是否有代码"与重入防护本就不相关。正确做法是 checks-effects-interactions 与状态锁（reentrancy guard）。

## 触发条件

- 目标合约用 `extcodesize`/`isContract` 做安全决策：禁止合约调用、仅 EOA 可领奖、防重入、地址白名单、按 EOA/合约区分费率等。
- 攻击者可部署合约，并能在其 constructor 中调用目标函数（目标函数无需回调攻击合约即可完成危害；构造期攻击合约无运行时代码，回调路径不可用）。
- 目标操作在一个交易内可完成（构造期内循环提款、领取空投/奖励、转移资金等）。
- 目标未同时使用 `tx.origin == msg.sender`、显式白名单或后续交易激活等更强约束。

## 利用步骤

1. 审计目标中所有 `extcodesize`/`isContract` 使用点，判断其是被用作"禁止合约"、防重入还是地址白名单。
2. 写攻击合约：在 constructor 内调用目标函数；constructor 中不能依赖自身代码存在（不要调用自身 external 函数），逻辑直接写在构造体内。
3. 在目标函数要求 `isContract(msg.sender) == false` 的分支中完成操作，例如调用 `withdraw`、`claim`、`transferTo`。
4. 若目标在同一次调用中回调攻击合约（如转账 ETH），注意构造期攻击合约还没有运行时代码，回调不会执行 `receive()`/`fallback()`，无法靠回调做经典重入；需要多次操作时改为在 constructor 内循环/重复调用目标函数（此时 `msg.sender` 始终是构造中的合约地址，`extcodesize` 始终为 0）。
5. 部署攻击合约（一次交易完成构造与攻击），观察目标状态变化与资金转出。

## PoC

```solidity
pragma solidity ^0.8.0;

interface IBank {
    function withdraw(uint256 amount) external;
}

// 攻击合约在构造期 extcodesize(this) == 0，
// 目标端 isContract(msg.sender) 返回 false，从而通过"禁止合约"检查
contract Attacker {
    constructor(address bank) {
        IBank(bank).withdraw(1 ether);
    }

    receive() external payable {}   // 构造期该函数不会被执行（账户尚无代码），部署后用于接收 ETH
}
```

```solidity
// 目标侧典型错误写法（原文 Bank 示例）：
require(!isContract(msg.sender), "Contracts are not allowed to withdraw.");
// isContract 用 extcodesize(addr) > 0 实现，构造期攻击地址 size == 0 → 放行
```

原文给出 `attack` 合约把调用放在 public 函数中（`function attack(address _addr) public payable { _addr.call.value(msg.value)(); }`），若由 EOA 调用则该合约已部署、`extcodesize != 0`，并不能通过检查；真正生效的写法必须把调用放进 constructor，而同交易内"先部署、构造函数返回后再调用"同样不行（部署完成后代码已存在）。另外示例假设攻击合约地址已持有可提取余额（或目标操作是 claim/领取类）；若目标是 `withdraw`，可在 constructor 内循环调用，每次 `msg.sender` 都是尚无代码的攻击合约地址。

## 变体与关联

- 变体一：`CREATE2` 预计算地址在部署前 `extcodesize == 0`，若目标把该地址当 EOA 白名单/收款人，可在后续部署合约使其具备代码（"address where a contract will be created"）。
- 变体二：已销毁合约地址（`selfdestruct`，EIP-6780 前代码在交易结束后清除）`extcodesize == 0`，可伪装 EOA；EIP-6780 之后仅同交易创建可销毁，适用范围收窄。
- 变体三：把 `extcodehash` 当替代方案不解决构造期问题（空代码哈希），只能区分"无代码账户"与"有代码账户"。
- 关联：[[blockchain-solidity-create-address-precompute-public-selfdestruct]]（CREATE2/自毁地址预计算）、[[blockchain-solidity-shop-view-price-double-call-toctou]]（同交易内重复调用/TOCTOU 类业务逻辑）、[[blockchain-solidity-transferfrom-missing-allowance-check-underflow]]（合约业务校验缺失类）。
- 边界：目标若要求 `tx.origin == msg.sender`（仅 EOA），构造期合约的 tx.origin 是部署者 EOA、msg.sender 是攻击合约，二者不等，会被挡住；若关键操作需要跨交易（如先注册后领取），构造期无法完成，需要其它路径。

## 检测与防御

- 检测（审计）：搜索 `extcodesize`、`extcodehash`、`isContract`、`Address.isContract` 的使用点，判断是否被用于安全决策；对"禁止合约参与"的检查，确认是否有 `tx.origin == msg.sender`、白名单或状态锁兜底；链上监控 constructor 直接调用敏感函数的交易（trace 中 create 后紧跟 call）。
- 修复：不要把"是否合约"作为权限/安全边界；仅允许 EOA 时用 `require(tx.origin == msg.sender)`（并注意 tx.origin 钓鱼风险）；防重入用状态锁（OpenZeppelin ReentrancyGuard）与 checks-effects-interactions；白名单用显式地址集合而非代码检测。
- 加固：对敏感操作增加时间锁/两阶段确认（部署后下一交易才生效）；审计 OpenZeppelin 版本与注释，明确 `isContract` 不适用于安全判断；对资金流出路径做限额与监控。
