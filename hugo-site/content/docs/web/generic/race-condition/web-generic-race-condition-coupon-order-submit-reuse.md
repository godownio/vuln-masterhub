---
id: web-generic-race-condition-coupon-order-submit-reuse
title: 订单提交并发复用优惠券：20 并发请求各自成单，每单都减 100
type: scenario
domain: web
path: web/generic/race-condition
technique: coupon-order-submit-race-reuse
tags:
- web
- race-condition
- payment
- coupon
- business-logic
- turbo-intruder
- concurrency
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V266
  verified_at: '2026-11-07T18:17:48+08:00'
  notes: 已对照原文与28张图核对：race.py 20并发/100连接/gate=race1 与图9一致；图10显示20行响应均200、235 words、705 length；图8订单-100、合计2049与卡的描述一致。dedup 与 web-generic-race-condition-coupon-concurrent-claim-stack 相似度高（0.9047，领取 vs 下单核销端点不同、PoC请求不同），判定非同一链、保留，卡内已写区别。未验证点：未复跑PoC。
url: /docs/web/generic/race-condition/web-generic-race-condition-coupon-order-submit-reuse/
draft: false
kb_aliases:
- 优惠券并发使用
- 优惠卷并发重复使用
- 订单并发复用券
- Turbo Intruder 并发下单
- coupon race order submit
---

## 一句话结论

提交订单时，服务端对“优惠券是否已使用/可用次数”的检查与“创建订单、扣减券次数”的写入不是原子操作；攻击者把同一笔带券订单的提交请求用 Turbo Intruder 20 并发同时放行，多个请求都通过券校验并各自创建订单，最终每笔订单都减 100 元，同一张券被重复使用多次。

## 原理

- 正常逻辑：提交订单时校验 `coupon.used == false`（或剩余次数 > 0），创建订单并记录优惠金额，然后把券标记为已使用/扣减次数，整个过程应在事务/锁中原子完成。
- 若检查与写入分离（先 SELECT 校验，再 INSERT 订单、UPDATE 券），并发请求会在第一个请求写入完成前都读到“券可用”的旧状态，于是各自生成订单并附带同一券的折扣。原文用 Turbo Intruder 的 gate 机制把 20 个请求同时放行，20 个响应均为 `200`、长度 `705`，随后订单列表显示每笔订单都优惠了 100 元。
- 该缺陷与“领取券并发”不同：领取竞态发生在发券接口（同一张券被重复领取）；本卡发生在**下单/核销**接口（同一张已领取的券被重复用于多笔订单）。两者根因都是“先查后写 + 无原子约束”，但利用点与危害（直接产生多笔已支付/待支付折扣订单）不同。

## 触发条件

- 下单/提交订单接口接受 `couponId` 或券使用参数，且券的可用性校验与订单创建/券核销不是原子操作。
- 同一用户可对同一券并发提交多笔订单；订单创建没有幂等键或“一券一单”唯一约束。
- 支付/订单系统允许这些订单并存（即使后续只支付其中一笔，也可能配合取消/退款逻辑放大）。
- 攻击者能抓包重放下单请求，并使用 Turbo Intruder 等并发工具（原文 20 并发）。

## 利用步骤

1. 在购物车/结算页选择可用优惠券（原文为面额 100 元的券），进入提交订单请求，抓包。
2. 把请求发送到 Burp Turbo Intruder，加载并发脚本 `race.py`（`concurrentConnections=20`、`requestsPerConnection=100`、`pipeline=False`）。
3. 把 20 个相同下单请求按 gate `race1` 排队，`openGate('race1')` 同时放行，等待响应。
4. 观察响应：20 个请求均返回 200、长度一致（原文 705），说明并发提交成功。
5. 查看订单列表：每笔订单都应用了同一张券的 100 元优惠；可继续支付/利用订单逻辑造成资金损失。
6. 变体：结合取消订单返还券、退款、积分抵扣等状态机进一步放大。

## PoC

原文 Turbo Intruder `race.py`：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=100,
                           pipeline=False)
    for i in range(20):
        engine.queue(target.req, target.baseInput, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

原图显示 20 行响应均为 `Status 200`、`Words 235`、`Length 705`；订单页面显示每笔订单优惠 100 元。

## 变体与关联

- 与 `web-generic-race-condition-coupon-concurrent-claim-stack`（领取接口并发重复领券）互补：本卡是下单核销阶段并发复用已领取的券。
- 与双设备取消订单复用券卡（`web-generic-payment-coupon-cancel-pending-order-reuse`）的区别：本卡依赖并发窗口，不依赖取消/支付页滞留。
- 同类：积分抵扣并发、余额支付并发、库存扣减并发、优惠码/兑换码并发核销。

## 检测与防御

- 券核销使用原子条件更新：`UPDATE user_coupon SET used=1 WHERE id=? AND used=0`，受影响行数为 0 即拒绝下单；或使用 `SELECT ... FOR UPDATE`、数据库事务 + 唯一约束（user_id, coupon_id, order_id）。
- 下单接口增加幂等键（请求 ID/订单号），同一券只允许绑定一笔有效订单；订单创建与券核销在同一事务中完成。
- 对提交订单接口做频率限制与并发控制；支付回调再次校验券与订单绑定关系。
- 监控：同一用户/同一券在秒级出现多笔订单；响应长度/状态高度一致的批量请求；订单表中同一券 ID 关联多个订单。
