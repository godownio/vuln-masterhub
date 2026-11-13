---
id: blockchain-consensus-dpos-deterministic-shuffle-ddos-consecutive-fork-double-spend
title: DPoS 确定性洗牌 + DDoS 中间委托人：恶意节点连续出块制造 6 确认双花
type: scenario
domain: blockchain
path: blockchain/consensus
technique: dpos-deterministic-shuffle-ddos-consecutive-fork
tags:
- blockchain
- consensus
- dpos
- double-spend
- ddos
- fork
- crypti
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V601
  verified_at: '2026-11-12T17:18:30+08:00'
  notes: 已对照原文《区块链共识机制深入刨析(下)》全文与图05/06 核对：crypti 101 委托人/10s 一块/每轮约 16.8 分钟、seedSource=floor(height/101)+(height%101>0?1:0) 经 SHA256 得轮内固定种子、shuffle 伪代码、控制 1/10/70/31/13/25 六个委托人对中间诚实节点 DDoS 造成连续出块与 6 确认双花均与原文一致；PoC dpos-pbft 的 npm install 目录图与 node main.js -b 10 输出（height 4 分叉，fork1 c364b1... / fork2 ad5241...，send fork1/2 至 0/5/7/8）与原文日志一致。图01/02 为 proposerByVRF 出块者随机数代码，属文中共识压迫攻击段落，未单独建卡合理。dedup 复核：候选仅同篇另两卡及无关 Web/RPC/钱包卡，非同链；ingest/reports/dup-scan.json 无涉及本篇卡片的 pair。原文无组件受影响版本，未设置 affected_versions。未验证点：未运行 dpos-pbft PoC。
url: /docs/blockchain/consensus/blockchain-consensus-dpos-deterministic-shuffle-ddos-consecutive-fork-double-spend/
draft: false
kb_aliases:
- DPoS 双花
- 委托人间隔攻击
- DDoS 忠诚节点 连续出块
- crypti shuffle 种子
- dpos-pbft 分叉
---

## 一句话结论

DPoS 每轮用固定种子洗牌出 101 个委托人，同一轮内出块顺序完全确定；攻击者只要控制其中若干个不相邻的委托人，并在自己两个出块槽位之间 DDoS 掉中间的诚实委托人，就能让恶意节点连续出块、把分叉维持到 6 个确认以上，使两条链上相互冲突的交易都被确认，完成双花。

## 原理

- DPoS 由当前委托人列表按固定时间片轮流出块。crypti 的实现中，每轮 101 个委托人、10 秒一块、一轮约 16.8 分钟；洗牌种子由轮次高度计算：`seedSource = floor(height/101) + (height%101>0?1:0)`，经 SHA256 后作为本轮固定种子。
- 洗牌只依赖轮次高度，**同一轮内种子不变**，因此 101 个委托人的出块顺序在轮开始时就已确定，攻击者可以提前知道自己与哪些诚实节点相邻/间隔。
- 正常分叉会被“最长链同步”消除：诚实委托人在恶意区块之后继续出块，最长链很快回到诚实分支。但如果攻击者对夹在恶意委托人之间的诚实节点发起 DDoS，使其无法出块/传播，恶意委托人就能在时间片上连续出块，分叉持续拉长。
- 当分叉长度超过 6 个区块，两个分支上的交易都获得 ≥6 次确认；若攻击者在两条分支放入相互冲突的交易（如一笔转给交易所、一笔转回自己），即可在一条链上提币后在另一条链上继续使用同一笔资产，形成双花。
- 攻击门槛：控制若干委托人（本例 6 个，位置 1/10/70/31/13/25）+ 能对间隔中的诚实委托人做 DDoS；无需算力。

## 触发条件

- 目标链采用 DPoS，且每轮洗牌种子只依赖轮次高度、轮内不变（确定性排序）。
- 攻击者控制的委托人数量/票数足以在排序中占多个槽位（不必连续）。
- 攻击者能对中间诚实委托人发起有效 DDoS 或网络隔离，使其错过出块槽位。
- 交易所/收款方按 6 个区块确认入账，且不校验分叉/最终性。

## 利用步骤

1. 获取目标链的委托人列表与洗牌算法，按当前轮高度算出本轮出块顺序。
2. 标记自己控制的委托人位置，找出两个恶意槽位之间的诚实委托人。
3. 在恶意槽位出块时构造两条冲突交易分支（同一笔 UTXO 分别转给不同收款方），把 fork1/fork2 分别发给不同节点。
4. 对中间诚实委托人发起 DDoS/断网，使其无法出块；恶意委托人按时间片连续出块，拉长两条分叉。
5. 等待两条分支都达到 6 个确认：先在一条链上完成提币/交易，再在另一条链上使用同一资产。
6. 停止攻击后最长链同步会收敛到其中一条，另一条上的交易被回滚，但已完成的链下/跨链动作无法撤回。

## PoC

原文用 `sqfasd/dpos-pbft` 模拟：

```bash
npm install
node main.js -b 10   # 第 10 个节点在第 4 高度制造两个 fork
```

```text
fork on node: 10, height: 4,
 fork1: c364b1d02a455b6bb02e1f6e87631d40564b5a4b591be71693574d5b086e316c,
 fork2: ad52413c950b4ecd9efcce3d71a5e153bd13b69261bf3824ebc607b637389f5f
send fork1 to 0
send fork2 to 5
send fork1 to 7
send fork2 to 8
```

- 日志显示高度 4 出现分叉，不同节点分别接受 fork1/fork2；真实攻击还需配合 DDoS 让中间诚实节点缺席。
- 原文脚本 `shuffle(height)` 展示了固定种子洗牌，可直接复算任意轮的出块顺序。

## 变体与关联

- 若链使用 VRF/随机信标选 proposer，需评估随机数是否可被当前出块者偏置（见共识随机数操纵类问题）；本条是“顺序确定 + 网络压制”组合。
- PBFT/Tendermint 类 BFT 共识的类似攻击是视图切换/超时操纵，但需要 1/3 以上作恶或网络分区。
- 关联：[[blockchain-consensus-rpc-setminercoinbase-address-validation-missing]]（共识节点配置类问题）。

## 检测与防御

- 检测：短时间内同一轮内多个委托人错过槽位、分叉深度异常增长；对委托人的 DDoS 流量；交易所在 6 确认内出现链重组。
- 防御：增加确认数/最终性 gadget、随机化洗牌种子（承诺-揭示/VRF）、委托人分散与 DDoS 防护、监控出块缺席与分叉；交易所对深度重组做风控。
