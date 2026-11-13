---
id: blockchain-solidity-erc20-burn-from-param-owner-backdoor
title: ERC20 burn(address _from) 的 _from 参数可控：owner 可任意销毁用户代币的"中级后门"
type: scenario
domain: blockchain
path: blockchain/solidity
technique: erc20-burn-from-arbitrary-backdoor
tags:
- solidity
- erc20
- backdoor
- access-control
- burn
- token
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V513
  verified_at: '2026-11-11T11:18:25+08:00'
  notes: 已对照原文与截图：burn(address _from,uint256) 仅 onlyOwner，_from 可控可清空任意地址，SafeMath 防溢出，原文称"中级后门"；PoC 与原代码等价（emit 写法差异不影响语义）；dedup 20候选均为 new，库内无 burn 任意地址后门卡；未设 affected_versions
url: /docs/blockchain/solidity/blockchain-solidity-erc20-burn-from-param-owner-backdoor/
draft: false
kb_aliases:
- 代币销毁后门
- burn from 参数可控
- 恶意 owner 清空持币者
- onlyOwner 销毁任意地址
---

## 一句话结论

只给 `burn(address _from, uint256 _amount)` 加 `onlyOwner` 而不校验 `_from` 是否等于 `msg.sender` 或是否有 allowance，等于把"销毁任意地址代币"的特权交给 owner：项目方可随时把任意持币者的余额清零（资产被销毁、不可逆、无收益），这是审计中应识别的恶意代币后门。

## 原理

- 代币销毁的实现是 `balances[_from] -= amount` 与 `totalSupply -= amount`。若 `_from` 完全由调用参数决定，而权限控制只检查"调用者是 owner"，则 owner 可以传入任意地址作为 `_from`，扣光该地址余额并从总供应量中扣除。
- 与 `burn(uint256)`（只销毁调用者自己的币）不同，这种签名把"销毁谁的币"从调用者身份中解耦；标准实现（OpenZeppelin `ERC20Burnable`）中 `burnFrom(account, value)` 会先执行 `_spendAllowance(account, _msgSender(), value)`，即必须获得账户本人授权，因此限制了作恶空间。
- 该后门属于"中级后门"：owner 只能销毁（让目标归零），不能直接把被销毁的资产转入自己地址（但可通过先销毁对手持仓、再配合其他手段获益，例如做空或让其他持仓升值）。
- 原文示例中合约还用 SafeMath 防护了减法溢出，说明后门与整数问题无关，纯粹是权限设计与参数校验缺失。

## 触发条件

- 暴露 `burn(address _from, uint256)` 之类"代指定账户销毁"的接口。
- 仅用 `onlyOwner`（或类似角色修饰器）保护，没有 `require(_from == msg.sender || allowed[_from][msg.sender] >= amount)`。
- owner 为恶意项目方，或 owner 私钥/多签被攻破。

## 利用步骤

1. 审计代币合约，寻找带 `onlyOwner` 且 `_from` 可控的 burn/销毁函数。
2. 若自身是恶意/失陷 owner：调用 `burn(victim, balanceOf(victim))` 清空目标账户。
3. 对多个大户重复调用，可瞬间让指定地址持仓归零（事件 `Burn(_from, amount)` 会如实记录）。
4. 结合市场操作（提前做空、或在其他地址持有仓位）放大收益；也可作为谈判/勒索筹码。

## PoC

```solidity
// 原文示例的等价结构（Solidity <0.8 + SafeMath）
function burn(address _from, uint256 _unitAmount) public onlyOwner {
    require(_unitAmount > 0 && balanceOf(_from) >= _unitAmount);
    balances[_from] = SafeMath.sub(balances[_from], _unitAmount);
    totalSupply = SafeMath.sub(totalSupply, _unitAmount);
    emit Burn(_from, _unitAmount);
}
// 攻击/后门调用：burn(victim, balanceOf(victim))  // owner 可清空任意地址
```

```solidity
// 安全基线（OpenZeppelin ERC20Burnable）
function burnFrom(address account, uint256 value) public virtual {
    _spendAllowance(account, _msgSender(), value);  // 必须由 account 本人授权
    _burn(account, value);
}
```

## 变体与关联

- 变体：`mint`/`pause`/blacklist（拉黑地址禁止转账）等 owner 特权同样可被恶意使用；但 pull 式销毁且不可逆、无补偿的特征更隐蔽。
- 变体：函数名为 `burnFrom` 但内部未调用 `_spendAllowance`，签名看似标准、实现却是后门。
- 关联：[[blockchain-solidity-transferfrom-missing-allowance-check-underflow]]（同属 ERC20 方法的前置校验缺失，但后者是下溢任意转账）。
- 检测：代币安全扫描工具通常能提示 owner 特权（mint/burn/pause/blacklist）；审计时应对照 OpenZeppelin 标准实现检查 `_from` 的来源与授权。

## 检测与防御

- 合约侧：销毁接口只允许销毁 `msg.sender` 自己的余额；如必须支持代扣，使用 `_spendAllowance` 校验授权，或把 burn 权限交给时间锁/多签并公开规则。
- 用户侧：投资前检查合约是否含 owner 可销毁任意地址的函数、是否可升级、owner 是否为多签/时间锁；对高特权代币降低持仓或避免长期质押。
- 监控侧：监控 `Burn` 事件中 `_from` 非发起者地址的批量销毁，以及短时间多地址余额归零。
