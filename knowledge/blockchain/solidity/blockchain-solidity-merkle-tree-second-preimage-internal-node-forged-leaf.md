---
id: blockchain-solidity-merkle-tree-second-preimage-internal-node-forged-leaf
title: Merkle Tree 第二原像攻击：把内部节点冒充叶子缩短证明链，用 64 字节 packed 原像伪造空投领取（Paradigm CTF 2022 MerkleDrop）
type: scenario
domain: blockchain
path: blockchain/solidity
technique: merkle-tree-second-preimage-forged-leaf
aliases:
- Merkle 第二原像攻击
- second preimage attack
- MerkleDrop
- MerkleDistributor 伪造领取
- 内部节点冒充叶子
- abi.encodePacked 叶子长度歧义
tags:
- blockchain
- solidity
- evm
- merkle-tree
- second-preimage
- merkle-distributor
- airdrop
- abi-encode-packed
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V361
  verified_at: '2026-11-09T02:18:19+08:00'
  notes: 已对照原文全文与2张图核对：02.png 将内部节点 Hash(L1,L2) 标红示意'内部节点冒充叶子'；卡内 uint256 index+address+uint96 amount = 64 字节 packed 叶子原像与内部节点同形的成因、截短一层 proof、巨大 index 不占用真实 0..63 领取位、两笔 claim（伪造 index=37 叶子 + 合法 index 8）清空余额的 PoC 均与原文代码/数值一致（S=d484...、amount=0x00000f40f0c122ae08d2207b 与原文逐字一致）。无组件版本/CVE，affected_versions 留空正确。dedup top 候选除自身外为 Solidirty 数组下溢、Move 混币器 Merkle 隐私关联等不同链，dedup_review 理由成立。dup-scan.json（2026-11-08 19:10）早于本卡建卡（2026-11-09），无涉及本卡 pair。未验证点：未本机跑 Foundry PoC；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

在 Merkle 空投/MerkleDistributor 合约里，如果叶子哈希由用户可控参数现场计算（如 `keccak256(abi.encodePacked(index, account, amount))`）且没有域分隔，而叶子原像恰好是 64 字节（与"两个 32 字节子哈希拼接"的内部节点原像同形），攻击者就能把某个合法叶子哈希与其兄弟哈希拼成一个"叶子"——它实际上就是树中的内部节点——再用截短一层的证明通过 `MerkleProof.verify`，从而伪造任意份额领取、掏空合约（Paradigm CTF 2022 MerkleDrop 的完整解法）。

## 原理

- **Merkle 验证的盲区**：`verify(proof, root, leaf)` 只验证"从你提供的 32 字节 leaf 出发，按 proof 逐层哈希能到达 root"，并不验证这个 leaf 是真正的叶子（数据块哈希）。任何能"爬到" root 的 32 字节值都被接受。
- **内部节点原像固定为 64 字节**：标准二叉树内部节点 = `H(left || right)`，原像就是两个 32 字节子哈希的拼接。
- **叶子原像撞上同一长度**：该合约用 `keccak256(abi.encodePacked(index, account, amount))` 计算叶子，参数类型为 `uint256 index + address account + uint96 amount`，packed 长度 = 32 + 20 + 12 = **64 字节**，与内部节点原像同形。这正是与标准 OpenZeppelin MerkleDistributor（`amount` 为 `uint256`，packed 出来 84 字节，无法同形）的关键差异。
- **构造方法**：从公开 tree/proof 取任意合法叶子哈希 `L` 与其兄弟哈希 `S`。令 `index = L`（32 字节）、`account = S 的前 20 字节`、`amount = S 的后 12 字节`（按 uint96 解释），则合约算出的 node = `keccak256(L || S)`，恰好等于树中 `L` 的父节点（内部节点）。拼接顺序需与建树时一致；`merkletreejs`/OZ 常用 `sortPairs` 按字节序把较小者放前，本例兄弟哈希首字节 `0xd4` 大于叶哈希，`L || S` 顺序成立。
- **截短证明**：调用时把合法 proof 的第一个元素（即 `S`）去掉，从该内部节点继续向上验证，层数少一层但仍能到达 root，`verify` 返回 true。
- **为什么能拿走资金而保留未领取账户**：claim 中记录的 `index` 是攻击者填入的 32 字节哈希（不落在真实账户的 0..63 区间），`_setClaimed` 只置位这个巨大索引对应的位，不会把任何真实账户标记为已领取；同时合约按攻击者给出的 `amount` 把代币转给攻击者地址。多笔组合即可清空合约余额，同时仍存在 0..63 中未领取的索引（CTF 判题条件）。

## 触发条件

- 合约用 Merkle 证明发放空投/白名单领取，叶子由调用者提供的字段现场哈希，且叶子原像长度恰为 64 字节（或叶子直接接受任意 32 字节哈希）。
- 合约未对叶子与内部节点做域分隔（不同前缀/不同哈希/不同编码）。
- `index`、`account`、`amount` 均由调用者控制，未与 `msg.sender` 绑定，`index` 也未做范围校验。
- 攻击者能获得某合法叶子的证明（公开 tree 文件、前端接口、链上事件均可）。
- 单笔金额受 uint96/余额限制时，可组合多笔凑满合约余额。

## 利用步骤

1. 获取 Merkle 树公开数据（tree.json、前端接口或链上领取事件），任选一个合法叶子 `L` 及其 proof。
2. 取 `S = proof[0]`（兄弟哈希），拆成前 20 字节作为 `account`、后 12 字节作为 `uint96 amount`。
3. 令 `index = L`（该合法叶子的 32 字节哈希）。
4. 用 `proof[1:]`（去掉第一个元素）调用 `claim(index, account, amount, proof[1:])`；合约内部算出 `keccak256(L || S)` 即内部节点，验证通过。
5. 合约向攻击者 `account` 转账 `amount`；巨大 `index` 不占用任何真实账户的领取位。
6. 再叠加一笔合法账户的正常领取（本例为 index 8 的账户，金额与第一笔相加恰好等于合约总余额），使合约余额归零，同时保留其他 0..63 索引仍未领取。

## PoC

```solidity
// 合法叶子 L（index=37 的账户），供伪造使用
bytes32 L = keccak256(abi.encodePacked(
    uint256(37),
    address(0x8a85e6D0d2d6b8cBCb27E724F14A97AeB7cC1f5e),
    uint96(0x5dacf28c4e17721edb)
));

// S = 该叶子的兄弟哈希（合法 proof[0]）= 前 20 字节账户 || 后 12 字节金额
// S = 0xd48451c19959e2d9bd4e620fbe88aa5f6f7ea72a00000f40f0c122ae08d2207b

// 伪造领取：合约内 node = keccak256(abi.encodePacked(index, account, amount))
//                     = keccak256(L || S) = 树中内部节点 → verify 通过
distributor.claim(
    uint256(L),                                          // index 填合法叶子哈希
    address(0xd48451c19959e2D9bD4E620fBE88aA5F6F7eA72A), // S 前 20 字节
    0x00000f40f0c122ae08d2207b,                          // S 后 12 字节（uint96）
    proofWithoutFirstElement                             // 合法 proof 去掉 proof[0]
);
```

## 变体与关联

- **更简形态**：叶子直接由调用者传入 `bytes32`（不校验与账户绑定）时，把任意内部节点当叶子、用截半 proof 验证即可；若 proof 长度不被固定，攻击者总能少走最低一层。
- **防护绕不过的变体**：给叶子与内部节点加域分隔（如叶子 `H(0x00||data)`、内部 `H(0x01||left||right)`，RFC 6962 风格），或把叶子编码改为 `abi.encode`（定长 32 字节槽，原像 96 字节），或对节点哈希再做一次哈希（double hash）——都可破坏"叶子原像 = 64 字节内部节点原像"的同形条件。
- **同族问题**：叶子哈希选择不当导致碰撞、proof 中可控元素替换、`abi.encodePacked` 对动态类型拼接歧义，都是 Merkle 验证实现常见的伪造入口。
- **关联**：[[blockchain-move-mixer-small-merkle-tree-leaf-index-linkability]] 也源于 Merkle 结构使用不当（隐私关联而非伪造）；EVM 合约其他逻辑缺陷见 [[blockchain-solidity-shop-view-price-double-call-toctou]]。
- **边界**：需要能取得合法 tree/proof；若合约把领取人绑定进叶子（`keccak(msg.sender, ...)`）或固定 proof 长度，本手法失效。

## 检测与防御

- **检测**：claim 交易的 `index` 是 32 字节哈希而非 0..N-1 范围内的整数；proof 长度比正常树高度短一层；同一领取人多笔金额之和恰等于合约余额；多个 claim 的 proof 尾部（上层节点）重复。
- **修复**：叶子与内部节点域分隔（前缀字节或不同哈希函数）；叶子用 `abi.encode`/结构化编码，使原像长度不等于 64 字节；把领取人地址绑定进叶子并校验 `index` 范围；固定 proof 长度；必要时对节点做二次哈希。
- **审计要点**：全局搜索用于叶子哈希的 `abi.encodePacked(`，检查其原像是否可能恰为两个 32 字节字；检查 claim 的 index/account/amount 是否全部由调用者控制且与领取人无关。
