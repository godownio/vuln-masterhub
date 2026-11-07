---
id: web-generic-auth-order-comment-idor-missing-ownership
title: 订单评价接口按 orderId 越权：只校验服务状态不校验订单归属，可评价他人订单
type: scenario
domain: web
path: web/generic/auth
technique: order-comment-idor-missing-ownership
aliases:
- 订单评价越权
- createComment IDOR
- orderId 遍历评价
- 评价接口未校验订单归属
- 水平越权 订单评价
tags:
- web
- auth
- idor
- horizontal-privilege-escalation
- business-logic
- order
- comment
- enumeration
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:29+08:00'
  notes: 已对照原文与 img07-10 核对：GET /order/createComment 只校验订单状态返回 101003，未校验订单归属；六位 orderId 遍历出现 code=0，PoC/响应与原文一致；未复跑。
---

## 一句话结论

订单评价接口 `GET /order/createComment` 只检查订单是否处于“服务已结束”状态，不校验该订单是否属于当前登录用户；订单号是六位可预测数字，攻击者遍历 orderId 就能给他人订单写入评价，操纵服务者评分与评价内容。

## 原理

- 评价接口把客户端提交的 `orderId` 直接作为订单唯一标识，服务端只做业务状态校验（例如“服务尚未结束”时返回 `code=101003`），没有把订单的买家/下单账号与当前会话主体做比对。
- 订单号往往是自增或短数字（原文为六位数），遍历成本极低；对处于可评价状态的订单，接口返回 `code=0` 并写入评价（`data` 返回评价 ID 或相关标识）。
- 由于评价内容、评分等级、标签、是否选择老师/评价老师都由请求参数控制，攻击者可对任意订单插入虚假好评/差评，影响服务者信誉与平台排序。
- 本质仍是对象级授权缺失（IDOR）：URL 级鉴权只能保证“普通用户可访问用户端接口”，无法保证“用户只能操作自己的订单”。

## 触发条件

- 攻击者拥有一个可正常登录的普通账号。
- 目标订单处于接口允许评价的状态（服务已结束），且订单 ID 可预测/可枚举。
- 评价接口只校验登录态与订单状态，未校验订单归属，也未要求短信/二次确认。
- 评价内容未做严格的、与订单关联的一致性校验（例如订单商品/服务与评价内容不匹配也能提交）。

## 利用步骤

1. 用自己的账号下一单并完成服务（或找到自己的历史订单），抓取“去评价”请求，记录路径与参数：`orderId`、`serviceLevel`、`serviceComment`、`commentTag`、`chooseTeacher`、`commentTeacher` 等。
2. 先用自己订单确认评价成功，观察成功响应结构与评价 ID。
3. 将 `orderId` 放入 Burp Intruder/Repater，按数字递增或枚举六位号段，按响应码/长度筛选可评价订单（原文遍历时出现 `code=0` 的成功响应）。
4. 对成功命中的他人订单提交自定义评价内容，确认评价出现在对方订单/服务者主页。
5. 控制请求频率，避免大规模污染；记录请求、响应与评价页面截图作为证据。

## PoC

```http
GET /order/createComment?orderId=226729&serviceLevel=2&serviceComment=test&commentTag=%7C%7C&chooseTeacher=1&commentTeacher=1 HTTP/1.1
Host: target
Cookie: <普通用户会话>
Accept: application/json
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":101003,"msg":"该订单尚未结束服务！","data":null,"tid":""}
```

把 `orderId` 换成已结束服务的他人订单后，响应变为 `{"code":0,"msg":null,"data":<评价ID>,"tid":""}`，即评价写入成功。原文用六位订单号遍历，多条请求返回 200。

## 变体与关联

- 变体：评价修改、追评、删除评价、评分接口同样只按 `orderId`/`commentId` 操作，可扩展到篡改他人已有评价。
- 变体：若评价内容会展示给其他用户且未过滤，可进一步测试存储型 XSS；若评价影响返现/积分，可进一步刷奖励。
- 关联：[[web-generic-auth-mall-cancel-user-order-idor]]、[[web-generic-auth-mall-pay-success-idor-zero-cost-order]]（同为订单对象缺少归属校验，但操作与影响不同：取消/支付 vs 评价）。
- 边界：订单 ID 使用不可预测 UUID、接口校验订单归属、或评价前要求服务完成确认+本人身份校验时，利用不成立。

## 检测与防御

- 修复：评价前按“订单 ID + 当前用户 ID + 可评价状态”查询订单，查不到直接返回 403/404；评价表写入时同时记录操作者与订单归属。
- 加固：订单号使用不可预测 ID（UUID/带签名）仅作辅助，核心仍是服务端对象级授权；评价内容与订单商品/服务做关联校验。
- 检测：同一账号短时间内对大量不同订单提交评价；评价操作者与订单买家不一致；同一 IP/设备遍历连续 orderId；评价内容高度重复或异常。
- 响应：清洗已产生的越权评价，审计评分数据，通知受影响服务者，必要时回滚信誉分。
