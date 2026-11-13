---
id: blockchain-consensus-filecoin-slashing-time-offset-condition-inversion
title: Filecoin 共识罚没条件取反：time-offset fault 误判正常出块并漏判真实故障
type: scenario
domain: blockchain
path: blockchain/consensus
technique: filecoin-slashing-time-offset-condition-inversion
tags:
- blockchain
- filecoin
- consensus
- slashing
- logic-bug
- cve-less
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V601
  verified_at: '2026-11-12T17:18:34+08:00'
  notes: '已对照原文与图03（lotus PR #1988 diff）核对：漏洞条件 !types.CidArrsEqual(blockA.Parents, blockB.Parents) && blockA.Height != blockB.Height 被修复为 CidArrsEqual；double-fork/time-offset/parent-grinding 三类 fault 定义与 lotus-1.0.0 syscalls.go 代码一致。截图确认 PR 目标分支 v1.3.0、commit 为 8354bd91db08764128f8d0d2abba576a5c3d9f9c，核对中已修正卡内误写的 834b4491...；第二处修改为 blockB 签名校验失败提示 first→second，卡内已写明。原文仅标注 v1.3.0 修复未给受影响区间，未 set-versions。dedup 复核：候选为无关卡，非同链；dup-scan 无涉及 pair。未验证点：未在 lotus 测试网复现罚没/漏罚没流程。'
url: /docs/blockchain/consensus/blockchain-consensus-filecoin-slashing-time-offset-condition-inversion/
draft: false
kb_aliases:
- Filecoin 共识罚没
- time-offset mining fault
- parent-grinding fault
- CidArrsEqual 条件写反
- lotus 1.3.0 修复
---

## 一句话结论

Filecoin（lotus）的共识罚没校验在判断 time-offset mining fault 时把“两个区块的 parents 相同”写成了 `!CidArrsEqual(...)`，导致不同 parents、不同高度的正常出块被误判为故障而可能被罚没，同时真正的同 parents 不同高度故障被漏判；lotus v1.3.0 将条件修正为 `CidArrsEqual` 并修正另一处错误提示。

## 原理

- Filecoin 的 `VerifyConsensusFault` 识别三类矿工故障：
  - double-fork mining fault：同一矿工在相同高度产生两个不同 CID 的区块；
  - time-offset mining fault：同一矿工在不同高度出块，但两个区块有相同的 parent tipset（相当于在同一父集上分叉出不同高度）；
  - parent-grinding fault：A、C 同高同 parents，B 的 parents 包含 C 不包含 A，用来证明 B 漏掉了 A。
- 正确判断 time-offset 的条件是 `CidArrsEqual(blockA.Parents, blockB.Parents) && blockA.Height != blockB.Height`：parents 相同才说明是在同一父集上“时间偏移”出块。
- 漏洞代码写成 `!CidArrsEqual(blockA.Parents, blockB.Parents) && blockA.Height != blockB.Height`：只要 parents 不同且高度不同就判 fault，而这是正常链上出块的常见形态；同时真正同 parents 不同高度的故障因为条件取反而漏判。
- 后果：诚实矿工可能被错误罚没（损失质押/算力），真实作恶者反而逃过罚没，属于共识层罚没逻辑的完整性问题。修复提交为 lotus `8354bd91...`（PR #1988，目标分支 v1.3.0），并顺带把 blockB 校验失败提示中的 `first` 改为 `second`。

## 触发条件

- 目标 Filecoin 节点/lotus 版本存在该条件取反缺陷（v1.3.0 之前的相关版本）。
- 存在 `VerifyConsensusFault` 调用路径（罚没举证/仲裁），且提交的 blockA/blockB 满足 parents 不同、高度不同。
- 罚没逻辑被链上/仲裁方采信，错误扣罚矿工抵押。

## 利用步骤

1. 审计目标 lotus 版本 `chain/vm/syscalls.go` 的 `VerifyConsensusFault`，确认 time-offset 条件是否为 `!CidArrsEqual`。
2. 构造/选取两个 parents 不同、高度不同的正常区块作为 blockA、blockB，调用罚没举证流程。
3. 观察仲裁结果：若被判定为 `ConsensusFaultTimeOffsetMining`，说明误判成立，可按流程罚没诚实矿工。
4. 反向验证：构造同 parents、不同高度的真实 time-offset 故障，观察是否漏判（未被罚没）。
5. 修复验证：升级到 v1.3.0 后重复步骤，条件应恢复正确行为。

## PoC

原文给出修复 diff：

```go
// 修复前
if !types.CidArrsEqual(blockA.Parents, blockB.Parents) && blockA.Height != blockB.Height {
    consensusFault = &runtime.ConsensusFault{
        Target: blockA.Miner,
        Epoch:  blockB.Height,
        Type:   runtime.ConsensusFaultTimeOffsetMining,
    }
}
```

```go
// 修复后
if types.CidArrsEqual(blockA.Parents, blockB.Parents) && blockA.Height != blockB.Height {
    ...
}
```

- 原文未给出链上罚没交易的完整复现；需在本地 lotus 测试网构造区块与举证交易。
- 三类 fault 的判定代码（double-fork/time-offset/parent-grinding）均可在 `syscalls.go` 中对照审计。

## 变体与关联

- 同类“条件取反/漏判”在共识罚没、Slash 逻辑中危害大：误罚没诚实节点会破坏经济安全，漏判会纵容双签/分叉。
- 共识层逻辑缺陷可对照 [[blockchain-consensus-rpc-setminercoinbase-address-validation-missing]]、[[blockchain-consensus-dpos-deterministic-shuffle-ddos-consecutive-fork-double-spend]]。

## 检测与防御

- 升级到修复版本；对罚没判定条件做单元测试覆盖三类 fault 的正反例。
- 罚没前增加人工复核/多实现交叉校验，避免单点逻辑错误直接扣罚质押。
- 监控异常罚没事件与漏罚没案例，保留举证区块与判定日志。
