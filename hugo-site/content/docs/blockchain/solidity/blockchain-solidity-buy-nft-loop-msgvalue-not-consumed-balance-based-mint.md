---
id: blockchain-solidity-buy-nft-loop-msgvalue-not-consumed-balance-based-mint
title: ERC20 购买函数循环内重复校验 msg.value 却不扣费、按当前余额+1 铸币：1 ether 指数增发绕过持有量阈值
type: scenario
domain: blockchain
path: blockchain/solidity
technique: solidity-loop-msgvalue-not-consumed-balance-based-mint-inflation
tags:
- blockchain
- solidity
- erc20
- mint
- integer-growth
- ctf
- evm
- logic-bug
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V553
  verified_at: '2026-11-11T23:07:29+08:00'
  notes: 本篇无图，已按原文 NFT.sol/process.sol 源码核对：Buy_nft 循环内 require(msg.value>=1 ether) 不按轮扣费、balance=balanceOf 后 _mint(balance+1) 指数增长、balance 映射滞后于本轮 mint、flag() 读 check_my_nft>10000；攻击合约 Buy_nft{value:1 ether}(10001)+bmw.flag() 与原文一致；另记录公开 mint() 每次 10 枚旁路（1001 次即可超阈值）。dedup 候选为 transferFrom 下溢/burn 后门等不同缺陷，无同链。未验证点：未链上复现；原文 easy-Over16 与 Safe Deposit Box 题解缺口已按跳过处理。
url: /docs/blockchain/solidity/blockchain-solidity-buy-nft-loop-msgvalue-not-consumed-balance-based-mint/
draft: false
kb_aliases:
- Buy_nft 指数铸币
- msg.value 循环内不扣费
- balanceOf+1 铸币
- BMW Bugbounty
- ERC20 无限增发
- 购买函数逻辑漏洞
---

## 一句话结论

`Buy_nft(uint256 _count)` 在 for 循环里每次都 `require(msg.value >= 1 ether)`，但 `msg.value` 是整笔调用的固定值、循环内不扣费也不消耗，且 `_mint(msg.sender, balanceOf(msg.sender) + 1)` 按"当前余额+1"铸币，导致余额每轮翻倍（0→1→3→7→…），传入足够大的 `_count` 并附 1 ether 即可在十几轮内让持有量超过 10000，满足 `flag()` 的 `check_my_nft > 10000` 检查。

## 原理

- **`msg.value` 的语义**：`msg.value` 是本次外部调用携带的 ETH 数额，在整个函数执行期间不变；在循环里写 `require(msg.value >= 1 ether)` 只证明"这笔调用至少带了 1 ether"，并不表示每轮都支付 1 ether，也不会从调用者余额里重复扣款。攻击者只需 1 ether 就通过任意多轮检查。
- **按余额铸币导致指数增长**：每轮 `balance[msg.sender] = balanceOf(msg.sender)` 取当前总量，然后 `_mint(msg.sender, balance + 1)` 再铸"当前总量+1"，新总量 = 2×旧总量 + 1。从 0 开始：1、3、7、15、31、63、127、255、511、1023、2047、4095、8191、16383——第 14 轮即超过 10000。
- **循环的提前返回**：`if (balance[msg.sender] > 10000) return` 用的是循环开头赋值的 `balance` 映射（滞后于本轮 mint），所以会在下一轮开头看到超阈值并返回；`_count` 取 10001 保证循环足够长。
- **没有余额/支付扣减**：函数从不 `require(msg.value >= _count * 1 ether)`，也不把 `msg.value` 记账或转走；合约收到的 1 ether 只是"门票"，与铸币数量脱钩。
- **flag() 的检查**：`require(processContract.check_my_nft(msg.sender) > 10000)` 读 `balance[_target]`，即上面被指数推高的映射，因此通过；随后 `reset_account()` 只是 `_mint(msg.sender, 0)`，不影响已获得的判定。
- **为什么有效**：把"循环次数"与"付费"解耦、把"铸币数量"与"固定单价"解耦，两个假设都不成立时，少量资金即可放大持有量。

## 触发条件

- 目标 ERC20/游戏合约存在"循环购买/批量铸造"函数，循环内重复校验 `msg.value` 但不按轮扣费。
- 铸币数量依赖当前余额（`balanceOf + 1`、`balance * 2` 等）而非固定值。
- 攻击者可支付一次门槛金额（本例 1 ether），并能传入较大的循环次数（无 `_count` 上限或上限很高）。
- 特权检查（如 `flag()` 的持有量阈值）只读该余额映射。

## 利用步骤

1. 确认 `Buy_nft` 的 `require(msg.value >= 1 ether)` 在循环内、`msg.value` 不随轮次减少，且 `_mint` 数量为 `balanceOf + 1`。
2. 部署攻击合约，持有目标合约实例，调用：
   ```solidity
   function attack1() public payable {
       b.Buy_nft{value: 1 ether}(10001);
       flag = bmw.flag();
   }
   ```
3. 铸币在循环内指数增长，超过 10000 后返回；随后 `bmw.flag()` 的 `check_my_nft(msg.sender) > 10000` 通过，返回 `Exploit-Success!!`。
4. 读取 flag 变量确认。

## PoC

原文攻击合约：

```solidity
function attack1() public payable {
    b.Buy_nft{value: 1 ether}(10001);
    flag = bmw.flag();
}

function attack2() public view returns (string memory) {
    return flag;
}
```

目标漏洞代码：

```solidity
function Buy_nft(uint256 _count) external payable returns (uint256) {
    for (uint256 i; i < _count; i++) {
        require(msg.value >= 1 ether, "Not enough Ether");   // 整笔调用只带 1 ether，循环内重复通过
        balance[msg.sender] = balanceOf(msg.sender);
        _mint(msg.sender, balance[msg.sender] + 1);          // 按当前总量+1 铸币 → 指数增长
        if (balance[msg.sender] > 10000) {
            return balance[msg.sender];
        }
    }
    return balance[msg.sender];
}
```

同一合约还存在更直接的缺陷：`function mint() public { _mint(msg.sender, 10); balance[msg.sender] = balanceOf(msg.sender); }` 无任何权限/付费限制，重复调用 1001 次也能超过 10000（仅需 gas）。原文选择 `Buy_nft` 路径。未在本机链上复现。

## 变体与关联

- **无权限 mint 变体**：本例的 `mint()` 公开且每次 10 枚，是最简单的"任意人增发"；审计时先看所有 `_mint` 调用点是否受权限/付费约束。
- **按余额/份额计算的变体**：`_mint(balance * 2)`、按 share 比例分红再投资、复利计算等都可能造成指数或超线性增长；对照库内 transferFrom 下溢、burn 后门等 ERC20 卡。
- **msg.value 复用变体**：multicall/批量函数里 `msg.value` 被多次使用（库内代理 multicall 卡有 `msg.value` 嵌套复用导致余额错乱），与本卡"循环内重复校验但不扣费"同源。
- **真实世界对应**：DeFi 项目的"批量购买/复投"函数若把付款校验放在循环内且不按轮记账，同样可被少量资金放大份额。

## 检测与防御

- **代码修复**：循环内按轮扣费（如 `require(msg.value >= _count * price)`，或每轮从 `balances`/`allowance` 扣减）；铸币数量使用固定单价而非当前余额；给 `_count` 设上限；`mint` 加权限或付费。
- **审计信号**：`msg.value` 在循环体内出现、`_mint` 金额由 `balanceOf` 派生、批量函数无上限、公开 `mint` 无 `onlyOwner`。
- **不变量**：铸币总量应满足 `totalSupply <= 付款金额 / 单价`；用模糊测试/不变量测试验证"付款与增发"的守恒关系。
- **运行监控**：链上监控短时间内单地址余额异常跳变、同一函数在单笔交易内大量循环事件。

## 备注

- 原文为 2024 BMW web3 CTF 题解（Hard-BMW Bugbounty）；目标与攻击合约源码来自原文，未在本机链上复现。
- `Buy_nft` 的 `require(msg.value >= 1 ether)` 在每轮都成立是因为 `msg.value` 不随循环变化；若实现改为每轮 `msg.value -= 1 ether` 或按轮扣款，该攻击不成立。
