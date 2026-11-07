---
id: blockchain-move-mixer-small-merkle-tree-leaf-index-linkability
title: Sui Move 混币器 16 叶顺序 Merkle 树 + withdraw 暴露叶子索引：链上关联存款与取款地址
type: scenario
domain: blockchain
path: blockchain/move
technique: move-mixer-small-merkle-tree-leaf-index-linkability
tags:
- blockchain
- move
- sui
- mixer
- merkle-tree
- privacy
- linkability
- ctf
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T07:09:11+08:00'
  notes: 已对照原文 Suinado Cash 字节码核对：deposit 顺序 insert、withdraw Arg5 经 leaf_at 校验、Arg6 收款地址与 WithdrawalEvent 公开、16 叶固定树；原文据此在链上关联资金去向取得 flag，卡片如实标注为隐私/可关联性缺陷而非盗币。
url: /docs/blockchain/move/blockchain-move-mixer-small-merkle-tree-leaf-index-linkability/
draft: false
kb_aliases:
- Suinado Cash
- Sui 混币器隐私破解
- Merkle 树混币关联
- 叶子索引泄露
- 存取款地址关联
---

## 一句话结论

基于 Merkle 树的 Sui Move 混币器若把 Merkle 树固定为 16 个叶子、按存款顺序直接追加叶子，并在 `withdraw` 的公开入参里携带叶子索引，则任何人都能在链上把“第 i 笔存款”与“以叶子 i 取款的那笔交易”关联起来；取款交易的 `WithdrawalEvent`/转账参数又暴露收款地址，于是混币器的匿名性被完全打破，可直接得到资金去向地址（该 CTF 以此为 flag）。

## 原理

- **混币器的隐私假设**：混币器通过让存款与取款之间没有直接链上关联来提供匿名性。用户存款时提交一个承诺（commitment），取款时用零知识/成员证明证明自己知道某个承诺的原像，并把币转给任意地址；观察者只能看到“有一笔存款”和“有一笔取款”，无法确定谁对应谁。
- **16 叶固定树 + 顺序插入**：该合约的 `MerkleTree` 只有 16 个叶子（`max_leaves`/固定容量），`deposit` 直接调用 `merkle_tree::insert(&mut tree, commitment)` 把承诺按到达顺序追加为叶子 0、1、2……；叶子索引就是存款的先后顺序，存款事件 `DepositEvent` 又带有存款人和承诺，因此在浏览器/全节点上可以无歧义地把每个叶子索引映射回具体存款交易。
- **withdraw 公开叶子索引**：`withdraw` 的入参包含 `Arg5: u64`（要取款的叶子索引），合约用 `merkle_tree::leaf_at(&tree, Arg5)` 取出叶子并与 `hash::blake2b256(bcs(secret)||bcs(nullifier))` 比较，再校验 Merkle 证明与已知根。Sui 的 entry function 参数会随交易公开，因此任何人都能看到“这次取款对应叶子 i”。
- **事件暴露收款地址**：取款成功后合约 `transfer::public_transfer(coin, Arg6)` 并按 `Arg6` 发出 `WithdrawalEvent`；`Arg6` 就是资金去向地址。
- **关联成立的原因**：叶子 i 唯一对应第 i 笔存款（顺序插入 + 固定 16 叶），而取款交易公开声明“我从叶子 i 取款”，收款地址又是公开的；把两者按 i 拼接即可得到“存款人 → 收款地址”的映射。混币器本应隐藏的正是这条边。
- **为什么不是直接盗币**：外部观察者不知道 `secret`/`nullifier`，不能替别人取款；本场景破坏的是匿名性/不可关联性，而非资金所有权。原文的 CTF 目标是分析资金去向，属于隐私破解而非盗窃。
- **根因组合**：固定小容量匿名集（最多 16 个叶子）+ 叶子按存款顺序顺序插入 + 取款交易公开叶子索引 + 事件公开收款地址，四者叠加使关联变成一次查表。

## 触发条件

- 目标 Sui Move 混币器合约使用 Merkle 树，树容量固定且很小（本例 16 叶），叶子按存款顺序追加。
- `withdraw` 的公开参数包含叶子索引（或任何能直接定位到具体叶子的信息），且交易参数/事件在链上可读。
- 存款事件包含承诺/存款人，且叶子索引可由插入顺序推出。
- 攻击者/观察者能访问链上数据（浏览器、全节点 RPC、`sui client` 查询对象与交易）。

## 利用步骤

1. 获取 Mixer 对象地址，读取其 `MerkleTree` 的 `nodes`/`leaf_count`/`max_leaves`，确认树容量与叶子排列顺序。原文给出的命令是 `sui client object <address> --json > out.json`。
2. 拉取该 Mixer 的存款事件/交易历史，按 `merkle_tree::insert` 的调用顺序给每笔存款编号 0..N-1；存款事件中的 `DepositEvent` 给出存款人与承诺，建立“叶子索引 → 存款人/承诺”的表。
3. 找到目标取款交易，读取其公开的 `withdraw` 参数 `Arg5`（叶子索引）与 `Arg6`（收款地址），以及 `WithdrawalEvent` 中的收款地址。
4. 用 `Arg5` 查第 2 步的表，得到对应存款人；再用 `Arg6`/事件得到资金去向地址，即完成存款与取款的关联。
5. 若叶子数已达上限、无法继续插入，可结合树对象中的全部 16 个叶子与全部取款记录，一次性还原整个匿名集的映射关系。
6. 原文还给出了 `build_proof` 的字节码逻辑：先算 `index = nodes.len() - max_leaves + leaf_index`（叶子在扁平 nodes 数组中的位置），再按 `index % 2 == 0 ? index-1 : index+1` 取兄弟节点，循环 `tree_depth` 次后 `index = (index-1)/2`，即可为任意已知叶子构造证明；这说明只要知道某个存款的 secret/nullifier，就能精确指定叶子取款，进一步方便按索引关联。

## PoC

原文未给自动化关联脚本；最小复现按下面步骤即可（无需与合约交互）：

```text
# 1. 取 Mixer 对象（含 MerkleTree.nodes/leaf_count）
sui client object <mixer_object_id> --json > out.json

# 2. 在浏览器/全节点按 insert 顺序列出 DepositEvent，得到 leaf_index -> depositor/commitment
# 3. 找到目标 WithdrawalEvent/取款交易，读出公开的 leaf_index 与 recipient
# 4. leaf_index 对应第 2 步的存款，recipient 即资金去向；关联完成
```

原文给出的叶子索引定位公式（用于理解叶子与存款的一一对应）：

```text
index = tree.nodes.length - tree.max_leaves + leaf_index
for i in 0..tree_depth:
    sibling = (index % 2 == 0) ? index - 1 : index + 1
    proof.push(tree.nodes[sibling])
    index = (index - 1) / 2
```

## 变体与关联

- **变体：树容量更小/更大**。容量越小，匿名集越小、关联越容易；容量大但叶子仍按顺序插入且索引公开时，仍可用“存款顺序 ↔ 叶子索引”的确定性映射做关联。
- **变体：索引不公开但事件/证明可枚举**。若证明路径长度固定且叶子可枚举，仍可通过链上交易的重放/模拟枚举出叶子编号。
- **关联：Merkle 证明构造**。原文另一道 Proof of Commitment 要求为存款构造有效证明，核心就是上面的兄弟节点循环与 `leaf_at` 校验；理解该算法有助于确认叶子索引与承诺的对应关系。相关 Move 合约漏洞可参考 [[blockchain-move-voting-vote-request-ballot-binding-missing]]、[[blockchain-move-amm-swap-pre-reserve-rounding-drain]]。

## 检测与防御

- **设计侧**：混币器不应把叶子的插入顺序/索引作为公开取款参数；使用固定或更大的匿名集，插入时打乱/随机化叶子位置，采用不泄露具体叶子的零知识成员证明，并避免事件中直接关联存款与取款的可见字段。
- **审计侧**：检查 `withdraw` 的公开参数是否包含 `leaf_index`、`nullifier` 以外的定位信息；检查 `MerkleTree` 容量与插入逻辑是否让叶子索引可预测；检查 `DepositEvent`/`WithdrawalEvent` 是否暴露可用于关联的地址或承诺。
- **运营侧**：监控同一叶子索引的存款与取款时间关联、固定小额匿名集上的批量关联分析；对混币器用户提示“匿名集大小”与“交易图关联”风险。
- **边界**：这是匿名性/隐私缺陷，不是资金盗窃；外部观察者没有 secret/nullifier 时无法取走资金，但可以破坏混币器的核心隐私承诺。
