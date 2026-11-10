---
id: blockchain-defi-dapp-backend-unvalidated-calldata-arbitrary-call-gas-sponsored
title: DApp 后端代付 gas 却不校验 to/data：前端 ABI 编码可任意改写，借项目方 relayer 调任意合约的 mint/burn
type: scenario
domain: blockchain
path: blockchain/defi
technique: dapp-backend-calldata-to-unvalidated-relayer-arbitrary-call
tags:
- blockchain
- web3
- defi
- access-control
- abi
- relayer
- gas-sponsored
- business-logic
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:14:26+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原文给出前端断点定位 E=O.encodeFunctionData(i,u)/requestSafeSignTx、POST /api/.../transaction/send 的 data(0x6a761202 外层 execTransaction) 与 nonce、mint(0x40c10f19)/burn(0x9dc29fac) 的完整 calldata 以及链上回执描述，卡片 PoC 与之一致；危害在测试链已打通（凭空 mint、burn 任意地址），主网退化为调用任意 public 方法并消耗项目方 gas 一点已在卡片变体中标注，属原文陈述。未复跑任何交易。
url: /docs/blockchain/defi/blockchain-defi-dapp-backend-unvalidated-calldata-arbitrary-call-gas-sponsored/
draft: false
kb_aliases:
- 篡改 ABI 编码调用任意合约
- transaction/send 未校验目标合约
- relayer 代付 gas 任意调用
- Safe execTransaction 中转篡改
---

## 一句话结论

Web3 申购类 DApp 的「代付 gas」链路里，前端 JS 生成 `to`（目标合约）与 `data`（ABI 编码/calldata）后直接 POST 到 `/api/.../transaction/send`，后端只检查格式与签名有效性、不校验 `to` 是否在白名单、`data` 是否等于预期方法；攻击者用浏览器断点把这两个字段换掉，就能借项目方 relayer 的余额与签名，以项目方身份对**任意合约的任意 public 方法**发起交易（例如凭空 `mint`、或 `burn` 别人的余额）。

## 原理

- **ABI 编码即 calldata**：EVM 交易的 `data` = 4 字节函数选择器 + 参数，`to` = 目标合约地址；两者一改就换了「调谁、调什么方法」。前端把这些当作普通 JSON 字段提交，等于把「交易意图」交给了客户端。
- **代付 gas 的信任错位**：项目方为了让用户免 gas，用自己（或 Magic/Safe）的钱包签名并发送交易，后端在拿到用户提交的 `to`/`data` 后转手组装、签名、上链。安全性完全依赖后端对这两个字段的校验——一旦缺失，攻击者获得的是「项目方账户发起任意调用」的能力。
- **Safe 多签中转不增加安全性**：本例 `data` 再套一层 `execTransaction`（Safe 的执行入口），`to`/`data` 作为内层参数传进去；外层签名由项目方生成，攻击者只需改内层参数，Safe 内部会照常执行——多签只保护「谁批准」，不保护「批准的内容是否被事后替换」。
- **为什么签名不能被直接伪造也没关系**：攻击者不需要伪造 `signatures`，走前端 JS 生成合法签名、只在发送前改字段，服务端签名与请求体之间的绑定若没做（或做的是外层而不是内层），签名依旧有效。
- **经济后果**：受影响的代币若 `mint`/`burn` 未加权限，攻击者可凭空造币或用 `burn` 销毁任意地址余额；即便受限，也能调用任意 public 方法（如 `transfer`、`approve`）并让项目方支付 gas。

## 触发条件

- DApp 采用「项目方代付 gas / relayer」模式：前端生成 `to`+`data`，后端或中继服务用自有账户签名并上链。
- 后端对 `to` 没有合约地址白名单，对 `data` 没有「只允许 subscribe/redeem 等指定选择器 + 参数形状」的校验。
- 外层签名（如 Safe `execTransaction` 的 `signatures`）与内层 `to`/`data` 没有强绑定，或绑定发生在前端。
- 目标链上存在可被任意调用的高价值方法（测试链的 `mint`/`burn` 无权限最典型；主网可退化为任意 public 方法调用 + 消耗项目方 gas）。

## 利用步骤

1. 打开 DevTools → Sources，在申购按钮附近下断点；控制台常会打印 `[methods, params]`，据此定位到 `E = O.encodeFunctionData(i, u)` 与 `requestSafeSignTx({chainId,to,data,nonce})`。
2. 记录正常流程的 `to`（项目方交易合约或用户 Safe 钱包）与 `data`（`subscribe(address,address,uint256,uint256)` 的 ABI 编码）。
3. 在 `send` 之前篡改：把 `data` 换成目标方法的 ABI 编码（如 `mint(address,uint256)`），把 `to` 换成目标 ERC20 合约地址。
4. 放行继续执行（F8），请求照常发到 `/api/.../transaction/send`，后端签名并上链。
5. 到区块链浏览器用返回的交易哈希核对：Receipt 中 Internal Txns 显示 Safe/relayer → 目标合约为被篡改的方法调用。

## PoC

ABI 编码（篡改后的 `data`，调用 `mint(address,uint256)`，给某地址铸 1 个代币）：

```
0x40c10f19
000000000000000000000000176791d147bef3f62dadde535604f339a1758e44
0000000000000000000000000000000000000000000000000000000000000f4240
```

调用 `burn(address,uint256)`，销毁某地址 10 个（`0x989680`）代币：

```
0x9dc29fac
000000000000000000000000b891626e1b89c572d2a9d3324473d0b280f45cad
0000000000000000000000000000000000000000000000000000000000989680
```

提交接口形态（外层 Safe 执行、内层为被篡改的 `to`/`data`）：

```json
{
  "chainId": "11155111",
  "to": "<项目方/用户 Safe 钱包或中转合约>",
  "data": "0x6a761202<execTransaction 参数，其中内层 to=目标合约, innerData=mint/burn 编码>",
  "nonce": 32
}
```

原请求体的 `data` 前缀 `0x6a761202` 即 Safe `execTransaction` 的选择器，其后依次是内层 `to`、`value`、`data`、`operation`、`signatures` 等。

## 变体与关联

- **同链路的其它落点**：把 `to` 换成任意 ERC20，`data` 用标准 `transfer`，耗费项目方 gas 做批量转账；或调用 `approve` 给自己授权后自行转走。
- **钱包侧信任问题**：Safe delegatecall 槽位劫持（[[blockchain-wallet-safe-delegatecall-slot0-mastercopy-hijack]]）与本卡同属 Safe 中转被滥用，但那边改的是实现槽，本卡改的是内层调用参数。
- **后端校验缺失的通用形态**：与 Web2 的「服务端不校验业务参数、只信前端」完全同源，可参照 [[web-generic-auth-header-value-equality-sole-access-gate]] 中「唯一门槛在客户端」的模式。

## 检测与防御

- **检测**：监控中继/签名服务的请求，统计同一调用方短期内 `to` 落在白名单外、`data` 选择器与业务方法不一致的交易；链上监测项目方 relayer 发起的历史未出现过的选择器；代币 `mint`/`burn` 事件的异常铸币量。
- **防御**：后端建立合约地址 + 方法选择器白名单，并校验参数语义（金额、收款方、时间戳上限）；重算 calldata 与前端声明的方法是否一致；把签名与内层 `to`/`data` 强绑定（服务端组装、用户只签最终 hash）；代币合约的 `mint`/`burn` 加角色权限。
