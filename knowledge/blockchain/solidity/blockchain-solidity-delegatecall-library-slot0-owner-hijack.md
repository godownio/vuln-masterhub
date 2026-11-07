---
id: blockchain-solidity-delegatecall-library-slot0-owner-hijack
title: 可写库地址 + delegatecall 存储碰撞：先用 setFirstTime 把 slot0 改成恶意库，再借恶意 setTime 覆写 owner
type: scenario
domain: blockchain
path: blockchain/solidity
technique: delegatecall-library-address-storage-collision
aliases:
- Ethernaut Preservation
- delegatecall 存储碰撞
- 库地址覆盖
- Preservation 关卡
- 委托调用劫持 owner
tags:
- blockchain
- solidity
- evm
- delegatecall
- storage-slot
- library
- ethernaut
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:44:19+08:00'
  notes: V262 重核（重试 V253）：对照原文第16关与图01，Preservation slot0 timeZone1Library/slot1 timeZone2Library/slot2 owner/slot3 storedTime，LibraryContract storedTime 占 slot0；两次 setFirstTime 先改 slot0 库地址、再由恶意 setTime 写 slot2 owner；攻击合约 a/b/attacker 布局与 address(uint160(_time)) 赋值一致；owner 变为 0xa131AD... 见图。dedup 仅自匹配；与 Safe delegatecall（签名欺骗改 masterCopy）和 PuzzleWallet proxy+multicall 均非同链。
---

## 一句话结论

当合约把库地址存在 slot0、并通过 `delegatecall` 调用库的 `setTime(uint256)` 时，库代码里的 `storedTime = _time` 实际写的是调用合约的 slot0；攻击者把恶意库地址当作 `_time` 传入，就能先改写库地址，再让后续 `delegatecall` 执行恶意库中写入 slot2 的 `setTime`，把 `owner` 改成自己。

## 原理

- **delegatecall 的上下文**：`A.delegatecall(B 的代码)` 执行 B 的字节码，但读写的是 A 的 storage，`msg.sender`/`msg.value` 保持不变。因此库合约的变量槽位必须与调用方保持一致，否则会互相覆盖。
- **本题的槽位错位**：`Preservation` 的布局是 slot0 `timeZone1Library`、slot1 `timeZone2Library`、slot2 `owner`、slot3 `storedTime`；而 `LibraryContract` 只有一个 `uint256 storedTime` 在 slot0。`setFirstTime(uint256 _timeStamp)` 执行 `timeZone1Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp))`，库的 `setTime` 把 `_time` 写入 slot0，于是 `timeZone1Library` 被改成了 `_time` 的低 20 字节。
- **两次调用完成劫持**：第一次 `setFirstTime(uint160(恶意库地址))` 把 slot0 改成攻击合约地址；第二次调用时 `timeZone1Library.delegatecall(...)` 实际执行攻击合约的 `setTime(uint256)`。攻击合约在 slot2 声明一个 `attacker` 变量，`setTime` 执行 `attacker = address(uint160(_time))`，由于 delegatecall 使用 Preservation 的存储，slot2 就是 `owner`，传入玩家地址即完成 owner 劫持。
- **为什么库地址可控**：合约没有提供修改库地址的 setter，但 `delegatecall` 的参数 `_timeStamp` 被库代码直接写进 slot0（本应写 `storedTime`），库地址因此变成用户可控输入；这是“库存储布局不匹配 + 用户可控 delegatecall 参数”的组合。
- **边界**：攻击合约的变量布局必须让目标变量落在调用合约的 slot2；若 `setTime` 写的是别的槽，需要相应调整攻击合约的变量声明顺序。

## 触发条件

- 合约把库/实现地址作为普通状态变量存储，并通过 `delegatecall` 调用库函数。
- 库合约的存储布局与调用合约不一致（本例：库的 `storedTime` 在 slot0，调用方 slot0 是库地址）。
- 存在公开函数把用户可控的 `uint256` 传给 `delegatecall` 的库函数，且库函数会写存储。
- 合约的敏感变量（owner、admin、实现地址等）位于攻击者可命中的槽位。
- 攻击者能部署任意合约并调用目标合约的公开函数。

## 利用步骤

1. 按目标合约的槽位布局部署攻击合约：slot0、slot1 随便声明两个变量占位，slot2 声明 `address attacker`。
2. 在攻击合约实现 `setTime(uint256 _time)`，把 `_time` 转成地址写入 slot2：`attacker = address(uint160(_time));`。
3. 调用 `Preservation.setFirstTime(uint256(uint160(address(attack))))`：原 LibraryContract 的 `setTime` 把攻击合约地址写入 slot0，覆盖 `timeZone1Library`。
4. 再调用 `Preservation.setFirstTime(uint256(uint160(player)))`：这次 delegatecall 执行攻击合约的 `setTime`，slot2（owner）被写成 `player`。
5. 调用 `owner()` 确认已变成攻击者地址。

## PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Attack {
    address public a;        // slot0 占位
    address public b;        // slot1 占位
    address public attacker; // slot2，对应 Preservation.owner

    function setTime(uint256 _time) public {
        attacker = address(uint160(_time));
    }
}
```

```solidity
// 攻击流程（player 为攻击者 EOA）
Preservation p = Preservation(target);
p.setFirstTime(uint256(uint160(address(attack)))); // 改写 slot0 库地址
p.setFirstTime(uint256(uint160(player)));          // 恶意库写 slot2 = owner
```

## 变体与关联

- 变体：若目标合约的 `setSecondTime` 使用 slot1 的库地址，可把 slot1 改成恶意库后经 `setSecondTime` 触发同一套逻辑。
- 变体：攻击合约不写 slot2 而写 slot0，可继续替换库地址形成持久控制（每次调用都路由到攻击合约）。
- 关联：[[blockchain-solidity-proxy-storage-collision-multicall-admin-hijack]]（代理与实现合约存储布局错位导致的 admin 劫持，属同一“delegatecall 存储槽碰撞”大类，但该卡是代理 + multicall 重复记账，本条是单合约库地址覆盖，触发条件与 PoC 不同）。
- 关联：[[blockchain-solidity-private-state-storage-read]]（理解 slot 布局是这类攻击的前提）。

## 检测与防御

- 防御：优先使用 Solidity 的 `library` 类型（编译器生成带布局校验的 delegatecall），不要把库地址作为普通可变状态变量；库合约的存储布局必须与调用方一致，或使用不可变（immutable/constant）库地址。
- 防御：禁止对用户可控地址执行 delegatecall；使用 OpenZeppelin 的 UpgradeableProxy/TransparentProxy 等经过审计的代理模板，并在初始化函数中加 `initializer` 保护。
- 检测：审计 delegatecall 目标是否来自 storage 或函数参数；检查库合约与调用合约的变量声明顺序是否一致；对 owner 变更事件做监控，发现 owner 被非预期地址替换立即告警。
- 注意：该卡是 CTF/Ethernaut 场景，PoC 未在链上复跑；实际利用需按目标合约槽位调整攻击合约变量布局。
