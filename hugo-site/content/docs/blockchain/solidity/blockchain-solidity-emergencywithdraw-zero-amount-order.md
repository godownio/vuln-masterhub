---
id: blockchain-solidity-emergencywithdraw-zero-amount-order
title: 质押合约 emergencyWithdraw 未缓存金额先清零：safeTransfer 收到 0，用户本金永久锁死
type: scenario
domain: blockchain
path: blockchain/solidity
technique: emergencywithdraw-state-order-zero-transfer
tags:
- solidity
- defi
- business-logic
- state-order
- staking
- emergencywithdraw
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V513
  verified_at: '2026-11-11T11:18:27+08:00'
  notes: 已对照原文与图10：user.amount=0 先清零再 safeTransfer(msg.sender,user.amount)，提款恒为0、本金锁死，原文称"死亡"函数并给出缓存变量修复，一致；结果属资金永久锁定而非单纯DoS，保留成立；与 profit-splitter 少付/vesting 覆盖卡不同（状态顺序零转账），dedup 无重复；未设 affected_versions
url: /docs/blockchain/solidity/blockchain-solidity-emergencywithdraw-zero-amount-order/
draft: false
kb_aliases:
- 紧急提款死亡函数
- emergencyWithdraw 清零
- 提款金额为 0
- 状态更新顺序缺陷
---

## 一句话结论

质押池的 `emergencyWithdraw` 若先把 `user.amount = 0` 清零、再用 `user.amount` 作为转账金额（`safeTransfer(msg.sender, user.amount)`），用户调用时实际转出的永远是 0，而记账已被清零——本金留在合约、用户失去债权，该函数等价于一个"死亡函数"。

## 原理

- Solidity 的存储变量在函数内是引用：`UserInfo storage user = userInfo[_pid][msg.sender];` 之后 `user.amount = 0;` 立即写入存储；随后 `safeTransfer(address(msg.sender), user.amount)` 读到的已是 0。
- 正确的写法必须先把金额缓存到局部 `uint256 amount = user.amount;`，清零记账后再用 `amount` 转账；顺序错误使"清零"与"转账"两步之间丢失了原始数值。
- 危害方向：对普通用户是本金永久锁死（每次调用都只转 0，记账已无余额可提）；对恶意项目方，这是设计"不可提款"合约的隐蔽手法——用户以为有紧急提款权，实际无法取回资金，而合约中资金仍可被项目方通过其他特权函数转走。
- 该缺陷与奖励计算无关：即便 `rewardDebt` 等字段正确，本金提款路径本身就失效。

## 触发条件

- 质押/农场类合约提供 `emergencyWithdraw`，且在声明 `UserInfo storage user` 后先执行 `user.amount = 0`。
- 转账调用直接使用 `user.amount`（或先清零的其他 storage 字段），没有局部变量缓存。
- 用户的本金存放在合约地址（lpToken/ERC20），用户无法通过其他路径取回。

## 利用步骤

1. 审计质押合约的 `emergencyWithdraw`（或类似的 withdrawAll/panic 函数），检查"清零记账"与"转账"的先后顺序。
2. 若为恶意项目方：部署带该缺陷的合约吸引存款；用户调用紧急提款时只能收到 0，本金留在合约，再由 owner 特权函数（如 rescueTokens/withdrawReward）取走。
3. 若为攻击者：该缺陷本身不直接产生收益，但可结合 owner 权限或其他函数把锁死资金转走；在审计报告中作为高危资金损失项上报。
4. 验证方式：在测试网部署，充值后调用 emergencyWithdraw，观察 Transfer 事件金额为 0、合约余额不变。

## PoC

```solidity
// 有缺陷的顺序
function emergencyWithdraw(uint256 _pid) public {
    PoolInfo storage pool = poolInfo[_pid];
    UserInfo storage user = userInfo[_pid][msg.sender];
    user.amount = 0;              // 先清零
    user.rewardDebt = 0;
    pool.lpToken.safeTransfer(address(msg.sender), user.amount); // 读到 0
    emit EmergencyWithdraw(msg.sender, _pid, user.amount);
}

// 修复：先缓存金额
function emergencyWithdraw(uint256 _pid) public {
    PoolInfo storage pool = poolInfo[_pid];
    UserInfo storage user = userInfo[_pid][msg.sender];
    uint256 amount = user.amount;
    user.amount = 0;
    user.rewardDebt = 0;
    pool.lpToken.safeTransfer(address(msg.sender), amount);
    emit EmergencyWithdraw(msg.sender, _pid, amount);
}
```

## 变体与关联

- 变体：`withdraw`/`claim` 中先更新 `user.amount` 再计算奖励或转账，同类顺序错误导致少发、零发或重复计算。
- 变体：先 `delete userInfo[...]` 再读取字段转账。
- 关联：[[blockchain-defi-profit-splitter-amount-overwrite-underpay]]（金额被覆盖导致的少付）；[[blockchain-solidity-vesting-wallet-address-collision-allocation-overwrite]]（业务记账覆盖）。
- 检测：审计所有"读 storage → 写 storage → 用该 storage 转账"的路径，要求先用局部变量固化金额；对 withdraw/emergencyWithdraw 做 0 金额转账测试。

## 检测与防御

- 合约侧：转账前用局部变量缓存金额，清零后再转；对提款函数编写"金额必须等于清零前记账"的不变量测试。
- 项目方：紧急函数上线前在测试网演练，检查 Transfer 事件金额与合约余额变化；为突发情况保留多签救援函数并公示规则。
- 用户侧：参与质押前检查合约是否开源、紧急提款路径是否被测试覆盖；对大额存款使用分批测试提款。
