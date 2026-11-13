---
id: web-generic-auth-public-chain-wallet-ui-unauth-api-frontend-route-first
title: 公链钱包 Web UI 鉴权缺陷：前端路由先渲染后校验 + 钱包 Controller 消息接口无认证，未登录可枚举/删除/创建地址
type: scenario
domain: web
path: web/generic/auth
technique: public-chain-wallet-ui-unauth-message-api-frontend-route-first
tags:
- web
- auth
- access-control
- unauthorized
- angularjs
- wallet
- blockchain
- stomp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V572
  verified_at: '2026-11-12T11:00:34+08:00'
  notes: 已对照原文（12896，168 行）与 18 张截图逐张核对（本卡对应图01-11）：app.controllers.js 先 currentPage/updatePageSubscriptions 再调 /user/getLoginInfo，if(!result.data||!result.data.success) 才 $location.path('/login')（图01，放大确认判断方向）；第251行 $stomp.send('/app/getWalletInfo') 与图2 的 $stomp.send('/app/removeAddress',{value:...}) 支持卡内 PoC destination；WalletController @RestController/@MessageMapping getWalletInfo/newAddress/importAddress/removeAddress/generateMnemonic 无会话/角色校验（图3）；WalletService.removeAddress keystore.removeKey+flushWalletToDisk（图4）；未认证 wallet 页可列账户、删除 account#10、删除后列表变化、新建助记词地址 aaa（图5-11），界面 Sinoc Harmony v2.3/1.9.0SNAPSHOT 仅环境说明。修正：PoC 中删除地址由 account#9 的 0x27ae… 改为原文实际删除的 account#10 地址 0x4CC2C93bbB70836c9D81BF8cbE0be665e19c052（图6/7 放大核对）。dedup：与 web-generic-auth-vue-router-frontend-guard-bypass 等为 related（不同组件/场景），无同链卡；dup-scan 无涉及。未设 affected_versions（原文未声明受影响版本）。未验证点：未复跑 STOMP 帧（原文未给完整 WS 客户端）。
url: /docs/web/generic/auth/web-generic-auth-public-chain-wallet-ui-unauth-api-frontend-route-first/
draft: false
kb_aliases:
- 钱包 Web UI 未授权
- 公链钱包接口鉴权缺失
- AngularJS 路由先渲染后鉴权
- WalletController 未鉴权
- 删除钱包地址 keystore
- 未登录操作钱包
---

## 一句话结论

公链节点的钱包 Web UI 在 AngularJS 的 `$routeChangeSuccess` 中先更新页面与订阅、再请求 `/user/getLoginInfo` 判断登录，导致未认证用户点击 Wallet 时页面先渲染、随后才跳登录；同时后端 `WalletController` 的钱包消息接口（`getWalletInfo`、`newAddress`、`importAddress`、`removeAddress`、`generateMnemonic`）没有认证/授权校验，未登录者可直接调用这些接口枚举地址、创建/导入地址，甚至删除地址并连带删除服务器上的 keystore 文件。

## 原理

- **前端路由先于鉴权**：`app.controllers.js` 在 `$routeChangeSuccess` 里先设置 `currentPage`、更新页面订阅，然后才判断 `path != "/login"` 并调用 `/user/getLoginInfo`；失败才 `$location.path("/login")`。因此 `/wallet` 页面会先完成渲染与数据订阅，攻击者可在跳转前看到钱包页面并操作。
- **后端消息接口无认证**：`WalletController`（Spring `@RestController` 中的 `@MessageMapping`）直接暴露 `getWalletInfo/newAddress/importAddress/removeAddress/generateMnemonic`，方法前后都没有会话或角色校验；前端通过 STOMP `$stomp.send('/app/removeAddress', {value: addr})` 调用，攻击者用未登录的 WebSocket/STOMP 会话发送同形消息即可。
- **删除地址的真实影响**：`WalletService.removeAddress` 会 `keystore.removeKey(address)`、`flushWalletToDisk()` 并广播 `getWalletInfo` 刷新；即删除的不只是列表项，而是服务器保存的 keystore 私钥文件。若私钥只存在服务器端（原文发送界面提示 “Private key is kept on server in sharable storage”），删除后对应地址的资产可能无法再动用。
- **为什么成立**：页面可见性、前端路由与后端接口被当作同一道鉴权边界，但 SPA 路由守卫与 `@MessageMapping` 方法都不构成服务端强制认证；攻击者不需要账号，只要网络可达节点 Web UI 即可。
- **附加风险**：原文指出若攻击者能物理接触并取得 seed phrase，可在本地 Web 端直接转账、无视登录认证；说明钱包安全模型依赖 seed/keystore 的保密而非 UI 登录。

## 触发条件

- 公链节点提供 Web UI（原文目标为 Sinoc Harmony 节点，界面显示 `v2.3`/`1.9.0SNAPSHOT`，仅作环境说明，非受影响版本声明）。
- 前端路由在认证判断前渲染页面，且钱包页面的数据订阅在跳转前建立。
- 后端钱包消息接口（STOMP `@MessageMapping` 或等价 RPC）没有会话/角色校验，且未做 CSRF/Origin 限制。
- 服务器端保存 keystore 私钥文件（删除地址会删 key）；或目标钱包地址有余额。

## 利用步骤

1. 访问节点 Web UI，点击 Wallet；观察 URL 先出现 `/wallet`、随后才跳 `/login`，确认页面在鉴权前已渲染。
2. 打开浏览器 DevTools 的 Network/WebSocket 或 Burp，记录钱包页面调用的 STOMP destination（如 `/app/getWalletInfo`、`/app/removeAddress`）。
3. 在一个未登录的 WebSocket/STOMP 会话中重放消息：先发 `getWalletInfo` 拉取地址列表（无需登录即可返回数据）。
4. 选取目标地址，发送 `removeAddress`（`value` 为地址）；服务端删除 keystore key 并刷新列表，确认地址从页面消失。
5. 也可用 `newAddress`/`importAddress` 创建或导入攻击者可控地址，影响钱包后续收款/转账。
6. 若取得 seed phrase 或 keystore 密码，可在本地 Web 端直接发起转账，绕过登录；记录影响面并评估资金损失。

## PoC

```text
# STOMP 帧（未登录 WebSocket 会话即可发送；destination 按实际抓包替换）
SEND
destination:/app/getWalletInfo
content-type:application/json

{}
^@

SEND
destination:/app/removeAddress
content-type:application/json

{"value":"0x4CC2C93bbB70836c9D81BF8cbE0be665e19c052"}
^@
```

```javascript
// 前端等价调用（需先建立 STOMP 连接）
$stomp.send('/app/removeAddress', { value: '0x4CC2C93bbB70836c9D81BF8cbE0be665e19c052' });
```

说明：原文在未认证状态下通过 UI 成功删除 `account#10` 并创建新地址；完整 WebSocket/STOMP 客户端代码未给出，本卡按前端调用形态还原，未复跑。

## 变体与关联

- 变体：前端路由守卫只检查 localStorage token 存在性、或使用 Vue/React 同类守卫；绕过方式见 [[web-generic-auth-vue-router-frontend-guard-bypass]]。
- 关联：后端只校验登录不校验角色的越权见 [[web-generic-auth-missing-function-level-role-check]]；未授权创建管理员接管后台见 [[web-generic-auth-unauth-user-create-admin-takeover]]。
- 关联：公链节点 RPC 的另一类问题（addnode SSRF 端口探测）见 [[web-generic-ssrf-blockchain-node-rpc-addnode-port-probe]]；RPC 参数校验缺失见 [[blockchain-consensus-rpc-setminercoinbase-address-validation-missing]]。
- 边界：后端对每个 `@MessageMapping` 做独立会话/角色校验、WebSocket 握手含认证、或钱包私钥不在服务器保存时，危害显著降低（页面可见但接口拒绝）。

## 检测与防御

- 检测：未登录 WebSocket/STOMP 会话向 `/app/getWalletInfo`、`/app/removeAddress`、`/app/newAddress` 等 destination 发送消息；同一来源在跳转登录前访问 `/wallet` 并调用接口；keystore 文件被删除/钱包地址数量异常变化。
- 防御：所有消息接口在服务端独立认证与授权（Spring Security + STOMP 拦截器，基于会话/Token 校验）；前端守卫只作 UX，不作为安全边界；`removeAddress` 等破坏性操作要求二次认证（密码/2FA）；钱包私钥不应以可被服务端删除的明文/可导出形式集中保存；限制 Web UI 暴露面。
- 响应：发现未授权调用后立即下线 Web UI 或加认证，审计 keystore 删除记录与地址余额，恢复备份并轮换 seed。
