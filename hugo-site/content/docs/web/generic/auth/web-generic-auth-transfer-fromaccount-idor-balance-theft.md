---
id: web-generic-auth-transfer-fromaccount-idor-balance-theft
title: 转账接口信任客户端 fromAccountId：水平越权扣划任意账户余额购买高价商品
type: scenario
domain: web
path: web/generic/auth
technique: transfer-source-account-idor-balance-theft
tags:
- web
- auth
- idor
- horizontal-privilege-escalation
- business-logic
- payment
- transfer
- jwt
- api
- account-takeover
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V245
  verified_at: '2026-11-07T13:13:36+08:00'
  notes: 已对照原文与图11-13核对：注册普通用户 admin888 的账户 ID=4、余额000；抓包 POST /api/transaction 仅 Bearer JWT，body 含 fromAccountId/toAccountId/amount；将 fromAccountId 改为1（管理员猜测）、toAccountId=4、amount=900000000 后连续 200（图12），余额升至55001000.00（图13），购买 SuperVLM 商品成功弹窗返回 Secret flag{OOxqTL0M52DzgyU187NKJwduWYBbpVrH}（图13），与卡片一致。卡内 gift 购买接口路径为按页面抓包还原，原文未贴购买请求。cve 空、无版本正确。dedup 与 mall 订单越权/优惠券越权为不同对象/参数，判 new 成立。未验证点：未复跑；amount 单位与余额数值以截图为准。
url: /docs/web/generic/auth/web-generic-auth-transfer-fromaccount-idor-balance-theft/
draft: false
kb_aliases:
- fromAccountId 越权
- 转账接口水平越权
- 扣划他人账户余额
- accountId 参数篡改
- 转账对象校验缺失
- business logic IDOR
---

## 一句话结论

`POST /api/transaction` 仅凭 JWT 判断“已登录”，却把请求体里的 `fromAccountId` 当作转出账户直接扣款，不校验该账户是否属于当前令牌用户；把 `fromAccountId` 从自己的账户改成他人（本例猜测并验证为管理员）的账户 ID，即可用受害者余额向自己的 `toAccountId` 转账，再消费这笔“白得”的余额购买高价礼物，拿到本应付费才能获得的 flag/敏感数据。

## 原理

- **对象级授权缺失（BOLA/IDOR）**：接口从 `Authorization: Bearer <JWT>` 中能解析出 `userId`，但业务层直接把客户端提交的 `fromAccountId`、`toAccountId`、`amount` 作为转账三元组执行，未做“`fromAccountId` 的属主 == 令牌 `userId`”的校验。
- **余额是服务端状态，但入口由客户端指定**：转账通常实现为 `UPDATE accounts SET balance = balance - amount WHERE id = fromAccountId` 与 `UPDATE accounts SET balance = balance + amount WHERE id = toAccountId`；只要 `WHERE` 条件里没有 `owner_id = current_user`，任何知道账户 ID 的登录用户都能扣划该账户。
- **账户 ID 可枚举/可猜测**：注册后自己的账户是 4，转账表单默认出现 4；把 `fromAccountId` 改成 1、`toAccountId` 保持 4、`amount` 填超大值（本例 `900000000` 分），服务端返回 200，页面余额变为 `$355001000.00`，证明扣的是账户 1 的钱、加的是自己账户 4。
- **资金可消费为业务收益**：应用内礼物（如“SuperVLM Model Toolkit All-in-One”，标价 `$100000000.00`）购买时只校验余额，余额既已被越权转账抬高，即可直接买下并在成功响应中返回 gift 的 `Secret`（flag），完成从越权到敏感数据获取的闭环。
- **为什么 JWT 不能防住**：JWT 只证明“我是用户 4”，不证明“账户 1 归用户 4 所有”；服务端把身份认证（authentication）误当成授权（authorization），且前端下拉框/隐藏字段提供了账户 ID 的传参位置，篡改成本极低。

## 触发条件

- 存在登录态与账户/钱包模型，转账、支付、提现等接口接受客户端传入的来源账户 ID（`fromAccountId`、`payerId`、`sourceAccount` 等）。
- 服务端只校验登录令牌有效，未校验来源账户归属，或仅在前端限制下拉选项。
- 目标账户 ID 可枚举（连续整数、注册接口回显、转账页默认值等）。
- 应用内有可用余额购买的商品/服务，且购买成功会返回 flag、卡密、密钥等敏感数据（CTF 场景常见）。

## 利用步骤

1. 注册/登录普通账号，进入转账或购买页面，抓取 `POST /api/transaction` 请求，记录 JWT、自己的账户 ID（如 4）与请求体字段 `fromAccountId`、`toAccountId`、`amount`。
2. 先用自己的账户做一次正常小额转账，确认接口行为与余额变化，排除风控/二次确认。
3. 把 `fromAccountId` 改为其他账户 ID（从 1 开始枚举，管理员/系统账户常为 1），`toAccountId` 保持自己的账户，`amount` 填一个足够大的值。
4. 发送请求；若返回 200 且自己的余额增加，说明来源账户归属校验缺失，越权成立。
5. 用虚增后的余额购买目标商品（如高价 gift），在购买成功响应/弹窗中读取 `Secret`/flag。
6. 可进一步枚举 `toAccountId`/`fromAccountId`，确认是否存在任意账户扣款、任意账户加款或负金额等变体。

## PoC

```http
POST /api/transaction HTTP/1.1
Host: TARGET
Content-Type: application/json
Authorization: Bearer <自己的 JWT>

{"fromAccountId":1,"toAccountId":4,"amount":900000000}
```

```http
POST /api/gifts/purchase HTTP/1.1
Host: TARGET
Content-Type: application/json
Authorization: Bearer <自己的 JWT>

{"giftId":<高价礼物 ID>,"accountId":4}
```

说明：原文通过修改 `fromAccountId` 为 1、`toAccountId` 为 4、`amount` 为 `900000000` 成功把余额抬高到 `$355001000.00` 并购买 gift；实际字段名以目标接口为准，购买接口路径按页面抓包确定。

## 变体与关联

- 变体：`amount` 为负数或 0 时，`balance - (-amount)` 可能给对方加钱或给自己加钱；结合整数溢出/精度问题可放大。
- 变体：`toAccountId` 也可任意指定，可把他人账户余额转到自己或第三方账户，形成完整资金盗取链。
- 变体：接口用账户号（account number）而非自增 ID 时，可通过注册接口、转账回执、账单等泄露账户号后同样篡改。
- 关联：[[web-generic-auth-mall-pay-success-idor-zero-cost-order]]（订单支付状态越权改已支付）、[[web-generic-auth-mall-cancel-user-order-idor]]（订单取消越权）、[[web-generic-payment-amount-tamper-no-order-binding]]（支付金额客户端直传）。
- 边界：若服务端从 JWT/session 派生 `fromAccountId`、或对账户 ID 做属主查询后再扣款，则本条不成立；若仅前端下拉框限制而接口仍信任参数，则仍可利用。

## 检测与防御

- 检测（代码审计）：搜索转账/支付 handler 中对 `fromAccountId`、`payerId`、`sourceAccount` 的直接使用；确认 SQL/ORM 的 `WHERE` 是否包含 `owner_id = current_user_id`。
- 检测（黑盒）：注册两个账号，A 向 B 正常转账后，用 B 的令牌把 `fromAccountId` 改为 A 的账户 ID，观察 A 的余额是否被扣、B 是否到账。
- 修复：来源账户必须从服务端会话/JWT 派生，或查询后校验 `account.ownerId == token.userId`；`toAccountId` 做存在性与状态校验；金额做正数、上限与精度校验。
- 加固：对转账接口增加二次确认、幂等键、风控与审计日志；账户 ID 使用不可枚举的随机标识；购买接口校验订单与支付流水绑定。
