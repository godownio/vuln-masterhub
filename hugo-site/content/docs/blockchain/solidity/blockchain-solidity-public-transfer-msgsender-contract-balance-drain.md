---
id: blockchain-solidity-public-transfer-msgsender-contract-balance-drain
title: 公开 safeSendLp 未鉴权 + nested call 的 msg.sender 是合约自身：任意用户借 transfer 转走合约持仓 LP
type: scenario
domain: blockchain
path: blockchain/solidity
technique: msg-sender-context-contract-self-token-drain
tags:
- blockchain
- solidity
- erc20
- access-control
- business-logic
- evm
- msg-sender
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V662
  verified_at: '2026-11-13T08:02:17+08:00'
  notes: 已对照原文与15张截图核对：safeSendLp public 无鉴权、balanceOf(address(this))、SafeERC20.safeTransfer→token.transfer→_transfer(_msgSender(),...) 调用链与截图代码逐字一致；Remix 复现（ERC20 0xd914...、test 0xa131...、mint(test,100)、攻击者 0xCA35...(余额0) 调 safeSendLp(ERC20,0x4B20...,50)）交易日志 Transfer from=0xa131AEAD95（test 合约）to=0x4B20... value=50，余额 50/50 与卡中 PoC 一致。pragma ^0.6.12 仅为复现环境，原文无受影响产品版本，未设 versions。dedup 候选均为 transferFrom 校验/emergencyWithdraw/burn 后门等不同链。未执行合约代码。
url: /docs/blockchain/solidity/blockchain-solidity-public-transfer-msgsender-contract-balance-drain/
draft: false
kb_aliases:
- msg.sender 语境混淆
- 合约自身身份转币
- safeSendLp 任意转走
- 合约持仓被任意提取
- transfer 的 msg.sender 是合约
---

## 一句话结论

合约里一个 public 函数若用 `IERC20(token).safeTransfer(user, amount)` 把 `balanceOf(address(this))` 转给用户可控地址，而没有 `onlyOwner`/调用者身份校验，那么任何用户都能调用它把合约持仓转走：token 合约的 `transfer` 内部 `_msgSender()` 是发起这次外部调用的合约本身（不是最初发起交易的 EOA），所以被扣减的是合约余额，而不是调用者的余额。

## 原理

- EVM 的 `msg.sender` 是“直接发起本次调用的地址”。交易链 `EOA → test.safeSendLp() → token.transfer()` 中，token 合约看到的 `msg.sender` 是 `test` 合约地址，原始 EOA 只出现在更外层的调用帧里。
- OpenZeppelin ERC20 的 `transfer(recipient, amount)` 实现是 `_transfer(_msgSender(), recipient, amount)`；`_msgSender()` 返回 `msg.sender`。因此 `_balances[test] -= amount; _balances[recipient] += amount`，即从 test 合约自己的持仓扣款。
- 漏洞合约的 `safeSendLp(_lpToken, _user, _amount)` 用 `IERC20(_lpToken).balanceOf(address(this))` 读的是合约自身余额，`_user`、`_amount`、`_lpToken` 全部由调用者控制，且没有任何权限校验；当 `lpBal > _amount` 时转 `_amount`，否则把 `lpBal` 全部转出。
- 审计时容易误判“调用者自己给自己转账无害”，关键在于识别嵌套调用中身份切换：token 侧看到的调用者是那个持币的中间合约，而非外层 EOA。
- 成立条件：目标合约确实持有该 token（LP 等）；该函数 public/external 且无 onlyOwner/角色/白名单校验；token 为常规 ERC20（transfer 从 msg.sender 扣款）。

## 触发条件

- 合约持有 ERC20/LP 代币（如 `balanceOf(address(this)) > 0`）。
- 存在公开可调用的提币/派发函数，向用户指定地址执行 token 的 `transfer`/`safeTransfer`，且 token 地址与接收地址都由调用者传入。
- 没有对调用者身份或额度来源做校验（例如未要求 `msg.sender == owner`、未按 msg.sender 记账、未限制只能提取调用者自己的份额）。

## 利用步骤

1. 审计/反编译目标合约，找出把 `address(this)` 余额转给外部地址、且参数由调用者控制的 public 函数（示例 `safeSendLp(address _lpToken,address _user,uint _amount)`）。
2. 确认该函数无 onlyOwner 或调用者份额校验。
3. 以任意 EOA 调用该函数：`_lpToken` 填合约所持 LP 代币地址，`_user` 填攻击者接收地址，`_amount` 填不超过 `balanceOf(合约)` 的金额（或直接传一个大于余额的值触发 else 分支转走全部余额）。
4. token 合约按 `transfer` 的 `_msgSender()=合约` 扣减合约余额并给 `_user` 加钱；交易日志中 Transfer 事件的 `from` 为合约地址。
5. 验证：查询 `_user` 余额增加、合约余额减少。

## PoC

漏洞函数（原文 Remix 复现用，最小化）：

```solidity
contract test {
    using SafeERC20 for IERC20;
    function safeSendLp(address _lpToken, address _user, uint _amount) public {
        uint lpBal = IERC20(_lpToken).balanceOf(address(this));
        if (lpBal > _amount) {
            IERC20(_lpToken).safeTransfer(_user, _amount);
        } else {
            IERC20(_lpToken).safeTransfer(_user, lpBal);
        }
    }
}
```

Remix（JavaScript VM）复现步骤：部署 ERC20 → 部署 test 并记下地址 → `mint(test 地址, 100)` 使合约持仓非 0 → 切换到余额为 0 的攻击者 EOA，调用 `safeSendLp(<ERC20 地址>, <攻击者接收地址>, 50)` → 接收地址余额变为 50，合约余额变为 50，Transfer 日志 `from=test 合约地址`。

## 变体与关联

- 变体：直接 `token.transfer(user, amount)`（非 SafeERC20）同样成立；只要扣款账户是合约自身。
- 变体：函数按 `_amount` 与 `balanceOf(address(this))` 判断后转全部余额的 else 分支会让攻击者一次提空。
- 关联：[[blockchain-solidity-transferfrom-missing-allowance-check-underflow]]、[[blockchain-solidity-transferfrom-check-update-mismatch-underflow]]——同样是“调用上下文/账户语义混用”导致的资产损失，但那是 transferFrom 的 allowance/余额校验缺陷，本卡是公开函数 + transfer 的合约自身身份。
- 关联：[[blockchain-solidity-emergencywithdraw-zero-amount-order]]——同为提现函数的业务逻辑缺陷，方向相反（资金锁死 vs 资金被任意转走）。
- 关联：[[blockchain-solidity-reentrancy-withdraw-call-before-zero-drain]]——若该函数先转账后更新状态，还可能叠加重入。

## 检测与防御

- 审计规则：所有把 `address(this)` 的 token 余额转出的 public/external 函数必须有 onlyOwner/角色校验，或严格按 `msg.sender` 的账面份额扣减；token 地址不应完全由调用者指定。
- 明确 `msg.sender` 在当前调用帧的含义：跨合约调用时它是直接调用者，不是原始 EOA；涉及扣款/授权时用显式传入并校验的账户。
- 测试：用余额为 0 的第三方账户调用所有公开提币/派发函数，断言余额不变。
- 设计：采用 pull-payment（用户先登记份额再自提）或内部记账 + 限额，避免向任意 `_user` 转合约资产。
