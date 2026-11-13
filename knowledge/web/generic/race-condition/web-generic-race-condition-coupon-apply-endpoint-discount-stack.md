---
id: web-generic-race-condition-coupon-apply-endpoint-discount-stack
title: 购物车优惠券 apply 接口并发重复提交：同一张一次性券在单笔订单上重复叠加，1337 元商品 24.07 元成交
type: scenario
domain: web
path: web/generic/race-condition
technique: coupon-apply-concurrent-discount-stack
aliases:
- 优惠券 apply 并发
- 单券多次叠加折扣
- 限次优惠券条件竞争
- limit overrun race
- 购物车优惠券竞态
- PROMO20 叠加
tags:
- web
- race-condition
- business-logic
- coupon
- payment
- burp-turbo-intruder
- repeater-parallel
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V599
  verified_at: '2026-11-12T17:06:55+08:00'
  notes: 已对照原文通读并逐张核对26图：图10-13 Turbo Intruder apply 请求(csrf+PROMO20)、race-single-packet 脚本 range(100)、批响应多为302+Coupon applied、reduction -1312.93/总价24.07，与卡一致；图14-15为Repeater并行组等价解法。dedup top候选为下单复用券/领券竞态/取消复用等，端点与叠加模型不同，非同一链，worker new判断成立。原文无组件版本，未写affected_versions正确。未验证点：未复跑PoC（PortSwigger靶场）。
---

## 一句话结论

购物车"应用优惠券"接口在"检查该券是否已用/是否可用"和"把折扣写入订单"之间不是原子操作：把同一个一次性优惠券的 apply 请求并发 100 份同时发出，约 18 个请求都通过了检查，折扣在单笔订单上被重复叠加（`1337 × 0.8^18 ≈ 24.07`），最终用 24.07 元买下 1337 元的商品——限制"每券只能用一次"的校验被并发绕过。

## 原理

- **校验与写入分离**：apply 接口的典型流程是：查券状态（未使用/有效）→ 计算折扣 → 更新订单总价 → 标记券已用。若前几步不是在同一事务/锁里完成，并发请求会同时读到"券未使用"的旧状态。
- **为什么折扣会叠加**：每个请求都基于当前订单金额计算 20% 折扣并写回总价。串行时第二次 apply 会因券已用被拒；并发时 N 个请求各自完成"读总价 → 乘 0.8 → 写回"，最终总价约为原价乘 `0.8^K`（K 为实际写入次数）。本例 1337 元经约 18 次成功写入后为 `1337×0.8^18≈24.07` 元，页面显示 reduction `-1312.93`。
- **单包攻击提高命中率**：Turbo Intruder 用 `Engine.BURP2` + `concurrentConnections=1` + gate 把 100 个请求在同一 TCP 包内发出，把到达间隔压到微秒级，使大量请求在任一请求把券标记为已用之前完成折扣计算。Repeater 的 `Send group (parallel)` 原理相同，成功率略高但操作更繁琐。
- **关键观察信号**：并发批次中大量响应为 `302 Location: /cart` + 响应体 `Coupon applied`，而正常串行第二次 apply 会返回 "Coupon already applied"；结算页出现同一券码的大额 reduction 与异常低的总价。
- **与"并发领券"的区别**：本卡的竞态发生在"已持有券的 apply/核销"环节（同一张券在一笔订单上叠加）；领取接口的重复领券与横向枚举券 ID 见 `[[web-generic-race-condition-coupon-concurrent-claim-stack]]`，下单接口复用优惠券见 `[[web-generic-race-condition-coupon-order-submit-reuse]]`，三者竞态端点不同。

## 触发条件

- 购物车支持输入优惠券码并"应用"，且券设计为一次性/单笔订单只能使用一次。
- apply 接口的"券可用性检查 → 折扣计算 → 订单金额写入 → 标记已用"非原子（无数据库行锁、无原子 UPDATE 条件、无幂等键）。
- 目标支持并发请求（HTTP/2 单包攻击最佳；HTTP/1.1 可用多连接并发或 Repeater 并行组）。
- 结算前存在可观察的金额/折扣变化，便于判断成功次数。

## 利用步骤

1. 登录自己的账号，把高价商品加入购物车，记录原价（本例 1337）。
2. 在购物车输入优惠券码（如 `PROMO20`），抓取 apply 请求（含 CSRF token、cookie、`coupon=...`）。
3. 把请求发送到 Turbo Intruder，选择 `examples/race-single-packet-attack.py`，将并发数从默认 20 调到 100（次数越多命中越高）。
4. 点击 Attack，观察响应：大量 `302 /cart` 且回显 `Coupon applied` 说明多次折扣写入成功；若失败可重试。
5. 关闭拦截/forward 掉挂起请求后回到购物车，确认同一券码出现大额 reduction、总价远低于原价。
6. Place order 完成低价购买；记录原始价、叠加后价与订单号作为证据。
7. 替代手法：把 apply 请求复制多份放入 Repeater 同一 group，`Send group (parallel)` 同时发送。

## PoC

Turbo Intruder（单包攻击，100 并发）：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    for i in range(100):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

请求模板：

```http
POST /cart/coupon HTTP/2
Host: target
Cookie: session=<自己的会话>
Content-Type: application/x-www-form-urlencoded
Content-Length: 52

csrf=<token>&coupon=PROMO20
```

判据：并发批次中多条 302 + `Coupon applied`；购物车显示同一券码 reduction 约 `-1312.93`、total 约 `24.07`。

## 变体与关联

- **端点变体**：优惠券核销可能在 `/cart/coupon`、`/checkout/apply-coupon`、`/order/discount` 等；同一竞态也适用于积分抵扣、礼品卡余额、满减活动等"一次性权益"。
- **叠加模型**：折扣可能是乘法叠加（本例 `0.8^K`）、加法叠加（每次减固定金额），或直接覆盖 total；按响应观察实际模型。
- **工具变体**：Turbo Intruder 单包攻击、Repeater 并行组、多线程脚本（requests + ThreadPool）均可；HTTP/2 单包成功率最高。
- **关联**：领券接口竞态 `[[web-generic-race-condition-coupon-concurrent-claim-stack]]`、下单复用券 `[[web-generic-race-condition-coupon-order-submit-reuse]]`、多端点订单换货 `[[web-generic-race-condition-multi-endpoint-cart-item-swap-checkout]]`。
- **边界**：若 apply 使用数据库唯一约束/原子条件更新、或每笔订单只允许一条券记录，叠加不成立；金额由服务端最终重算且忽略客户端折扣时，也会失败。

## 检测与防御

- **原子核销**：用 `UPDATE coupons SET used=1 WHERE id=? AND used=0` 检查受影响行数，或在订单优惠记录上加唯一约束（order_id + coupon_id）；折扣计算与金额写回放在同一事务并加行锁。
- **幂等与限流**：apply 请求带幂等键；同一订单/用户的 apply 请求串行化（单飞锁），拒绝并发重复提交。
- **服务端重算**：下单/支付时按数据库中的券状态与商品价格重新计算应付金额，不信任客户端提交的总价或折扣。
- **检测信号**：同一会话/订单在毫秒级出现多个 apply 请求；同一券码在一笔订单上出现多条优惠记录或金额异常；单笔订单 reduction 接近或超过商品原价；Turbo Intruder/并行组的批量 302 响应。
