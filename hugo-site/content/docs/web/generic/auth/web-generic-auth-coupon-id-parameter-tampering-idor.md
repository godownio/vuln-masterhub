---
id: web-generic-auth-coupon-id-parameter-tampering-idor
title: 下单接口 couponId 参数越权：使用他人新用户优惠券完成折扣下单
type: scenario
domain: web
path: web/generic/auth
technique: coupon-id-parameter-tampering-idor
tags:
- web
- auth
- idor
- business-logic
- coupon
- order
- parameter-tampering
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:30+08:00'
  notes: 已对照原文与 img11-13 核对：createOrderV2 的 couponId 从 1085908 改为 1085907 后订单优惠 4.95、实付 0、新用户5折券，与原文一致；未复跑。
url: /docs/web/generic/auth/web-generic-auth-coupon-id-parameter-tampering-idor/
draft: false
kb_aliases:
- couponId 越权
- 使用他人优惠券
- 优惠券 ID 遍历
- 下单参数篡改
- coupon 参数未绑定用户
---

## 一句话结论

下单接口 `GET /order/createOrderV2` 直接信任客户端传入的 `couponId`，只按优惠券 ID 计算折扣，不校验该券是否属于当前用户、是否已被使用或是否适用于该订单；把他人（如新用户）的优惠券 ID 填进请求即可完成折扣下单。

## 原理

- 优惠券在下单时通常以 `couponId` 形式从客户端回传，服务端据此查询券面额、门槛、状态并计算应付金额。
- 若服务端只校验券存在/未过期/满足金额门槛，而没有校验 `coupon.user_id == 当前登录用户`，则任意已知或可枚举的券 ID 都可被当前账号使用。
- 原文中自己新用户券 ID 为 `1085908`，尝试相邻的 `1085907` 成功用于下单；订单详情显示优惠金额 4.95 元、实付 0 元，并标注“新用户5折券”，证明他人券已被套用。
- 优惠券 ID 常为自增数字，遍历/相邻猜测即可发现有效券；部分系统还存在一券多用、重复使用、叠加使用等衍生问题。
- 本质是对象级授权缺失（IDOR）+ 金额计算信任客户端参数：服务端没有把“券的归属/使用状态”和“下单用户/订单”绑定。

## 触发条件

- 攻击者拥有可正常登录的普通账号，能进入下单流程。
- 下单接口接受客户端提交的 `couponId`（query 或 body），且券 ID 可预测/可枚举。
- 服务端未校验优惠券归属、使用人、使用次数、适用商品/门店/渠道。
- 订单金额由服务端按券计算（若同时信任客户端金额，可直接改价，危害更高）。

## 利用步骤

1. 用自己账号领取/使用一张优惠券，抓取下单请求，记录 `couponId` 字段位置与请求格式。
2. 观察券 ID 是否连续，尝试相邻 ID（如自己的 1085908 改成 1085907）或按范围遍历。
3. 提交订单并在订单详情/支付页核对优惠金额、实付金额与券名称，确认他人券被应用。
4. 可进一步测试同一 `couponId` 重复下单、并发下单、与其他优惠叠加、跨账号复用。
5. 只验证折扣是否生效，不完成真实支付或造成大规模资金损失；记录订单号、券 ID 与金额变化作为证据。

## PoC

```http
GET /order/createOrderV2?payType=14&sourceId=907498&goodId=19&couponId=1085907&firstOrder=0&openId=<openId> HTTP/1.1
Host: target
Cookie: <普通用户会话>
Accept: application/json
```

下单后订单详情（原文）：

```text
订单金额:  ¥9.9
优惠金额:  ¥4.95   ← 使用了他人新用户 5 折券
实付金额:  ¥0
优惠券:    新用户5折券
```

## 变体与关联

- 变体：优惠券 ID 可放在 JSON body、表单或数组中；批量提交多个 couponId 测试叠加。
- 变体：同类财务参数（积分抵扣、余额、红包、礼品卡、发票、地址 ID）若只按 ID 查询而不校验归属，也可能被越权使用。
- 关联：[[web-generic-payment-amount-tamper-no-order-binding]]（金额参数篡改）、[[web-generic-auth-mall-cancel-user-order-idor]]（订单对象越权）、[[web-generic-account-deletion-new-user-benefit-reuse]]（新人权益滥用）。
- 边界：服务端校验券归属与使用状态、按用户维度做原子扣减、订单金额完全由服务端计算且券与订单绑定后，本越权不成立。

## 检测与防御

- 修复：下单时按“couponId + 当前用户 ID + 未使用 + 在有效期内 + 适用商品/门店”查询优惠券；不满足直接拒绝，不使用客户端传来的券属性。
- 加固：优惠券与订单在服务端绑定，使用记录做唯一约束/幂等键，防止并发重复使用；金额由服务端重新计算并校验。
- 检测：同一券 ID 被多个用户/多笔订单使用；同一用户短时间内尝试大量不同 couponId；订单优惠金额与券面额、商品不匹配；下单失败率异常升高。
- 响应：冻结异常券、回滚异常订单优惠、审计资金损失，并排查是否存在批量枚举。
