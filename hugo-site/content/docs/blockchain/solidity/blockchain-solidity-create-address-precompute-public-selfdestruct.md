---
id: blockchain-solidity-create-address-precompute-public-selfdestruct
title: CREATE 地址预计算 + 公开 selfdestruct：由创建者地址与 nonce 找回丢失合约并销毁取走余额
type: scenario
domain: blockchain
path: blockchain/solidity
technique: create-address-precomputation-public-selfdestruct
tags:
- blockchain
- solidity
- evm
- create
- rlp
- selfdestruct
- access-control
- ethernaut
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:44:22+08:00'
  notes: V262 重核（重试 V253）：对照原文第17关与图02，Recovery new SimpleToken、creator 0x4C22...B316 nonce=1、keccak256(rlp([creator,nonce]))[12:]=0x246F49Ca...DA75 与浏览器 Internal Txns 转账目标一致；公开 destroy/selfdestruct 可直接调用。已修正卡片 RLP 细节：payload 22 字节、前缀 0xd6（原写 21/0xd5 有误，rlp=d6 94 <addr> 01，本地计算验证）。dedup 仅自匹配。
url: /docs/blockchain/solidity/blockchain-solidity-create-address-precompute-public-selfdestruct/
draft: false
kb_aliases:
- Ethernaut Recovery
- 合约地址预计算
- RLP nonce 计算合约地址
- 公开 selfdestruct
- 找回丢失合约
---

## 一句话结论

工厂合约 `new SimpleToken(...)` 创建的合约地址可以由创建者地址和 nonce 确定性算出：`keccak256(RLP([creator, nonce]))` 的后 20 字节；当目标代币合约把 `destroy(address payable _to)` 写成任何人都能调用、直接 `selfdestruct(_to)` 时，攻击者即使不知道合约地址，也能先算出地址再销毁合约，把余额转给自己。

## 原理

- **CREATE 地址是确定性的**：EVM 用 `CREATE` 部署合约时，新地址 = `keccak256(rlp_encode([sender, nonce]))[12:]`，只取决于创建者地址与创建者当时的 nonce。合约账户创建后 nonce 从 1 开始，因此它第一次 `new Contract` 使用的 nonce 是 1。
- **本题的创建链**：`Recovery.generateToken` 内部执行 `new SimpleToken(_name, msg.sender, _initialSupply)`；SimpleToken 由 Recovery 合约创建，文章实例中 Recovery 地址为 `0x4C22...B316`，其第一次 CREATE 的 nonce=1，算出的地址正是 `0x246F...DA75`，与区块浏览器内交易 trace 中转账目标一致。题目把该地址“弄丢”，但地址仍可从链上数据还原。
- **公开 selfdestruct 的危害**：`SimpleToken.destroy(address payable _to) public { selfdestruct(_to); }` 没有任何权限检查，任何人调用都能销毁合约，并把合约余额发送到 `_to`。攻击者只需把 `_to` 设为可控地址（或 `msg.sender`），即可拿走合约中的 ETH。
- **两种定位方式**：一是在区块浏览器看实例创建交易的 Internal Txns，找到 `new SimpleToken` 产生的地址；二是用创建者地址 + nonce 做 RLP 编码并 keccak256，取后 20 字节，完全不依赖浏览器。
- **RLP 编码细节**：20 字节地址编码为 `0x94 || address`（1+20=21 字节）；nonce=1 编码为 `0x01`（1 字节）；两项组成列表，payload 长 22 字节，列表前缀为 `0xc0 + 22 = 0xd6`。最终 `rlp = d6 94 <20-byte-address> 01`，哈希后取后 20 字节。
- **版本语义**：在 Cancun/EIP-6780 之前，`selfdestruct` 会真正删除代码并转走余额；EIP-6780 之后仅在同一交易内创建的合约会被删除，但余额转移行为仍在，攻击效果需按链的规则确认。

## 触发条件

- 目标合约由另一个合约通过 `CREATE`（`new`）部署，且创建者地址与创建 nonce 可知或可枚举。
- 目标合约存在公开的 `selfdestruct`/`destroy` 函数，或该函数缺少权限控制。
- 目标合约仍有 ETH 余额，且攻击者能构造并发送交易。
- 若使用 EIP-6780 之后的链，需确认目标合约是否在同交易内创建；否则 selfdestruct 可能只转余额不删代码。

## 利用步骤

1. 找到工厂/创建者合约地址（题目描述或链上交易 trace 可给出），确认它通过 `new` 部署目标合约。
2. 确定创建 nonce：合约账户创建后 nonce 从 1 开始，第一次 `new` 用 nonce=1；若之前创建过其他合约，按创建顺序递增。
3. 计算地址：`keccak256(rlp_encode([creator, nonce]))[12:]`；或在区块浏览器的 Internal Transactions 中直接读取目标地址。
4. 部署攻击合约（或直接用 EOA 调用），调用 `SimpleToken(target).destroy(payable(attacker))`。
5. 合约自毁，余额转入攻击者地址；确认合约代码/余额变化。

## PoC

地址预计算（Python）：

```python
from web3 import Web3
import rlp

creator = bytes.fromhex("4C22949959D3bE1d65a6E32DF59ad55BDd0bB316")
nonce = 1
rlp_encoded = rlp.encode([creator, nonce])
contract_address = Web3.to_checksum_address(Web3.keccak(rlp_encoded)[12:])
print(contract_address)
# 0x246F49Ca0Cd13d2cA435A4Ee0EEB37cddc79DA75
```

回收余额（Solidity）：

```solidity
abstract contract SimpleToken {
    function destroy(address payable _to) public virtual;
}

contract Attacker {
    function attack(address targetAddr) external {
        SimpleToken(targetAddr).destroy(payable(msg.sender));
    }
}
```

## 变体与关联

- 变体：若创建者还部署过其他合约，可从 nonce=1 枚举到当前 nonce，逐个计算地址并用 `eth_getCode` 确认哪个是目标。
- 变体：CREATE2 部署时地址为 `keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:]`，同样可预计算；若 salt 可控，攻击者甚至能提前算出未来地址。
- 变体：即使没有 selfdestruct，公开的 `transfer`/`withdraw` 等无权限函数也可结合地址预计算定位并操作丢失合约。
- 关联：[[blockchain-solidity-private-state-storage-read]]（链上数据公开，地址与状态都可离线还原）、[[blockchain-solidity-delegatecall-library-slot0-owner-hijack]]（另一类无需源码即可定位/接管合约的场景）。

## 检测与防御

- 防御：不要给 `selfdestruct` 函数留公开入口；至少加 `onlyOwner`/多签控制，或直接移除该函数。
- 防御：合约销毁/资金转出应使用 pull-payment 模式并记录事件；对高价值合约禁用 selfdestruct。
- 检测：监控链上 `SELFDESTRUCT` 操作码与 `Destroyed` 事件；对工厂合约的 `new` 地址建立索引，及时发现未在册的合约；对公开的 destroy/withdraw 函数做静态扫描（Slither 等）。
- 注意：EIP-6780 之后 selfdestruct 语义变化，审计时需按目标链的硬分叉状态判断影响。
