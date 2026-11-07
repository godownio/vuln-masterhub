---
id: blockchain-solidity-evm-guess-honeypot-detection
title: EVM 猜谜蜜罐合约识别：幌子 Start 交易 + 隐藏 New 内部调用 + 管理员抢跑改哈希
type: scenario
domain: blockchain
path: blockchain/solidity
technique: evm-guess-honeypot-detection
tags:
- blockchain
- ethereum
- evm
- solidity
- honeypot
- scam
- storage-slot
- internal-transaction
- tx-origin
- front-running
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V159
  verified_at: '2026-11-06T07:45:36+08:00'
  notes: 已对照原文与9张截图核对：合约0xf327...cFD源码、slot0 question/slot1 responseHash、公开问题What is at the end of a rainbow?与公开答案letteR W、slot1实际哈希0xf152950b...与keccak256(abi.encode(" letteR W "))=0x9f16d1bc...不一致、Start交易State Changes为空、隐藏内部交易经0x3cccb...调用New写入responseHash/question、Try失败不revert且无事件、tx.origin限制、admin哈希映射与抢跑New/Stop描述均与原文一致。未验证点：链上交易与fork模拟未在本机复跑；原文无sources/source_url；非组件漏洞，未设置versions。
url: /docs/blockchain/solidity/blockchain-solidity-evm-guess-honeypot-detection/
draft: false
kb_aliases:
- 猜谜蜜罐
- 竞猜合约骗局
- EVM honeypot
- Start 幌子交易
- 隐藏内部交易改答案
---

## 一句话结论

以太坊“猜谜赢奖池”类合约可用一笔看似公开答案的 `Start` 交易作幌子，实际由另一合约内部调用 `New()` 预置不可反推的 `responseHash`；受害者按公开答案调用 `Try()` 并附带超过门槛的 ETH 时交易 success 却不转账，资金被吞。识别关键是直接读 storage 槽比对哈希，并用 Advanced Mode 检查隐藏内部交易与状态变更。

## 原理

- 合约状态布局为 `string question`（slot 0）、`bytes32 responseHash`（slot 1）、`mapping(bytes32=>bool) admin`（slot 2）。`responseHash` 非 public，浏览器 UI 不展示，但链上 storage 可直接读取。
- `Start(_question, _response)` 只在 `responseHash == 0` 时写入 `question` 与 `responseHash`。若管理员已通过 `New()` 预置非零哈希，公开的 `Start` 交易不会产生任何状态变更，其 calldata 中的“问题+答案”只是诱饵。
- `New()` 与 `Stop()` 带 `isAdmin`，可随时改答案哈希或提走全部余额，且无时间锁、多签或事件。`admin` 映射的键是 `keccak256(abi.encodePacked(msg.sender))`，构造函数只接收预计算哈希，隐藏管理员地址。
- `Try()` 在哈希不匹配时没有 revert、没有事件，交易 status 仍为 success，只是不执行转账；受害者从回执上很难看出“条件未满足”。
- `require(msg.sender == tx.origin)` 禁止合约调用，使受害者无法用带余额校验的包裹合约先小额验证再参与。
- 抢跑：`Try()` 交易进入 mempool 后公开可见，管理员可用更高 gas 先发 `New()` 改哈希（或 `Stop()` 提款），受害者交易随后打包时条件不成立，ETH 被吞。
- 核心成因：答案校验完全依赖一个管理员可任意重写的非 public 哈希，失败路径静默，真实状态写入与公开可见交易分离，形成状态欺骗。

## 触发条件

- 目标为竞猜/答题类合约，奖池余额显著（数 ETH 级），但公开交互记录极少。
- `responseHash` 非 public，且存在管理员可改哈希/提款的函数。
- 分析者只依赖浏览器默认视图、公开 getter 或 `Start` 交易 calldata 推断答案。
- 受害者以 EOA 直接调用 `Try()`，并附带超过合约门槛的 ETH。

## 利用步骤

骗局侧流程：

1. 部署合约，构造函数只接收管理员地址的 `keccak256` 哈希，隐藏管理员身份。
2. 部署辅助合约，由辅助合约内部调用 `New(question, responseHash)`，把答案哈希设为不可反推值（如随机 bytes32），同时写入问题文本。
3. 向合约注入数 ETH 奖池，制造高净值假象。
4. 用管理员 EOA 发送一笔 `Start(question, 公开假答案)` 交易；因 `responseHash` 已非零，该交易不写状态，只在 calldata 中留下“答案”作为诱饵。
5. 宣传“猜谜赢 ETH”，诱导受害者分析合约后调用 `Try("公开答案")` 并附带超过门槛的 ETH。
6. 交易 success 但不转账；管理员可再抢跑 `New()` 改哈希或 `Stop()` 提款，重复布局。

识别侧对应检查：读 slot 1 与公开答案哈希比对；用 Advanced Mode/Phalcon 查内部交易与 State Changes；本地 fork 模拟 `Try()` 看是否真的触发转账。

## PoC

无 PoC（不需要利用代码）。链上验证命令：

```bash
# 1. 读公开问题
cast call <contract> "question()(string)" --rpc-url <RPC>
# 2. 读 slot 1 的 responseHash（非 public 状态变量）
cast storage <contract> 1 --rpc-url <RPC>
# 3. 计算公开答案的 abi.encode 哈希并比对
cast keccak $(cast abi-encode "f(string)" "<public-answer>")
# 4. 用 Etherscan Advanced Mode 或 Phalcon 查内部交易，确认是否存在对 New() 的调用
cast tx <txhash> --rpc-url <RPC>
```

判定：slot 1 的值与第 3 步结果不一致，且 `Start` 交易的 State Changes 为空，即说明公开答案无效、真实哈希被隐藏调用改写。

## 变体与关联

- 变体：不通过 `New()`，而用初始化函数、代理升级、`selfdestruct` + recreate 等方式预置哈希。
- 变体：要求先存入/授权 ERC-20 再“兑奖”，扩大损失面。
- 变体：管理员不直接 `Stop()`，而是把奖池转走后再重新注入，维持诱饵。
- 变体：无管理员后门，但答案本身不可猜（哈希不可反推），靠暴力猜测门槛获利。
- 关联：MEV/抢跑、tx.origin 钓鱼、智能合约 storage layout 审计。

## 检测与防御

- 交互前直接读 storage 槽，验证非 public 的答案哈希与 `keccak256(abi.encode(公开答案))` 是否一致；不一致直接放弃。
- 在 Etherscan/Phalcon 用 Advanced Mode 查看内部交易与 State Changes；公开交易的 State Changes 为空说明是幌子。
- 本地 fork 模拟 `Try()` 调用（eth_call / anvil fork），确认是否真的触发转账，而不是只看交易 status。
- 检查是否存在无时间锁的 admin 改哈希/提款函数、无事件、tx.origin 限制等组合特征；多特征叠加视为高风险。
- 对陌生竞猜/空投类合约不转入超过可承受损失的 ETH；不要因合约已验证、奖池高就认为可信。
- 监控：对 `New`/`Stop` 调用、管理员改哈希后紧跟提款的行为做链上告警。
