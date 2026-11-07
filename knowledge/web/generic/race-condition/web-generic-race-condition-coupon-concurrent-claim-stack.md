---
id: web-generic-race-condition-coupon-concurrent-claim-stack
title: 优惠券领取接口并发竞态：同券重复领取 + 横向枚举高面额券 ID 实现无限叠加
type: scenario
domain: web
path: web/generic/race-condition
technique: coupon-claim-race-id-enumeration-stack
aliases:
- 优惠券并发领取
- 优惠券横向并发
- 优惠券无限领取
- coupon race condition
- 领取接口竞态
- Turbo Intruder 并发
- 优惠券叠加使用
tags:
- web
- race-condition
- business-logic
- coupon
- concurrency
- id-enumeration
- payment
- src
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V241
  verified_at: '2026-11-07T13:11:08+08:00'
  notes: 已对照原文、61张本地图及5张外链图核对；Turbo Intruder 20并发、24张券与支付叠加成立；200元券是原文举例，已修正为未实测；接口路径/参数名为通用还原，PoC 未复跑。
---

## 一句话结论

商城优惠券领取接口在“查询用户是否已领取/库存是否充足”与“写入领取记录/扣减库存”之间不是原子操作，用 Turbo Intruder 等工具把同一 `couponId` 的 20 个请求同时放行，就能让同一账号重复领取同一张券；同时券 ID 可枚举，横向对不同面额活动券的 ID 并发领取，可越过新人/回归用户资格拿到本不符合条件的券（文章另举例可用 200 元回归券），最终在支付时叠加抵扣，造成直接资金损失。

## 原理

- **先查后写的竞态**：典型实现是 `SELECT count(*) FROM user_coupon WHERE user_id=? AND coupon_id=?`（或查库存/领取状态），若满足条件再 `INSERT` 领取记录并 `UPDATE coupon SET stock=stock-1`。两个步骤之间没有事务锁、唯一索引或原子条件更新时，并发请求会同时通过“未领取”检查，然后各自插入一条记录，形成一券多领。
- **并发窗口**：单请求串行执行时检查与写入间隔很短；把 20 个请求用同一连接门（gate）同时放行，可以让多个请求的检查都在第一个写入提交之前完成，显著提高成功率。原文用 20 个并发连接、每个连接 100 个请求、`pipeline=False` 放行同一批请求，返回状态码 200、长度一致，账号券包最终出现 24 张券，证明同一券被重复领取。
- **横向枚举绕过资格**：领取接口通常只按客户端传入的 `couponId` 查券，只校验券存在/未过期/库存，未校验“该券是否面向当前用户人群”。优惠券 ID 常为自增数字或活动编号，遍历相邻 ID 或不同面额活动的 ID，即可把新人券、回归券、高面额券一并领取；原文即通过横向并发不同金额的券 ID 领到多张不同面额券，200 元回归券只是文中举例，并非实测结果。
- **叠加放大**：支付页把所有可用券的折扣累加，未限制同订单可用张数、券类型互斥或最低消费组合，重复领取的多张券可同时抵扣，危害从“多领几张”升级为“几乎零成本下单”。
- **为什么服务端没挡住**：没有数据库唯一约束 `(user_id, coupon_id)`、没有 `INSERT ... ON CONFLICT`/`SELECT FOR UPDATE`/Redis 分布式锁、没有幂等键；前端按钮置灰/倒计时只是客户端限制，直接重放请求即可绕过。

## 触发条件

- 攻击者拥有可正常登录的普通账号，能进入领券/会员中心并抓取领取请求。
- 领取接口接受客户端提交的 `couponId`（或活动 ID/券模板 ID），且该 ID 可预测/可枚举。
- 服务端缺少原子性保护（唯一索引、行锁、条件更新、分布式锁、幂等键）与每用户限领校验。
- 优惠券可在支付时叠加使用，或可与其他优惠组合。
- 接口没有有效的频率限制/风控，或并发数在允许范围内。

## 利用步骤

1. 登录商城，进入领券/会员中心，点击“领取”并抓包，记录领取接口的完整请求（URL、`couponId`、Cookie/Token、必要的签名/CSRF 参数）与正常响应。
2. 先用 Burp Repeater 连续发送 2–3 次同一请求，观察是否出现“已领取”限制；若第二次仍 200，说明可能缺少幂等。
3. 使用 Turbo Intruder（或 curl/xargs 并发）把同一 `couponId` 的 20 个请求用 gate 同时放行，检查响应状态码/长度是否全部一致；随后回到券包查看同一券是否出现多张。
4. 记录当前券 ID，枚举相邻 ID、不同面额活动 ID、新人/回归活动 ID；对每个候选 ID 重复并发领取，确认能否领到本无资格的高面额券。
5. 进入结算/支付页，选择可叠加的券组合，确认多张券同时抵扣；比较应付金额与券面额，验证资金损失。
6. 可进一步测试“使用/核销”接口的并发（同一券并发使用多次）、库存超卖、退款后券状态回滚等衍生竞态。

## PoC

```python
# Burp Turbo Intruder（原文脚本）：20 个并发连接，同一请求同时放行
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

```bash
# 无 Turbo Intruder 时的并发近似（curl + xargs，20 并发）
seq 20 | xargs -P20 -I{} curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
  -X POST 'https://TARGET/api/coupon/claim' \
  -H 'Cookie: SESSION=<自己的会话>' \
  -H 'Content-Type: application/json' \
  --data '{"couponId":<目标券ID>}'
```

说明：原文未给出具体接口路径与参数名，`/api/coupon/claim`、`couponId` 为按常见实现还原；实际以抓包为准。原文观察到 20 个并发请求均返回 200 且长度一致，券包出现 24 张券（文章称含 20/50/100 元面额），支付时可叠加。

## 变体与关联

- 变体：同一券并发“使用/核销”可让一张券抵扣多次；并发“退款”可让券与退款金额同时回到账户。
- 变体：库存扣减无原子性时并发领取可造成超卖，券实际数量超过库存上限。
- 变体：新人券/回归券按用户标签发放，但领取接口不校验标签，横向枚举券 ID 即可越权领取（与优惠券 IDOR 叠加）。
- 变体：多账号 + 并发可绕过“每账号限领”，再集中到同一订单使用（若券可转赠/共享）。
- 关联：[[web-generic-auth-coupon-id-parameter-tampering-idor]]（券 ID 未绑定用户，下单时使用他人券）、[[web-generic-race-condition-tip-reputation-role-escalation]]（并发打赏导致负余额/声望提升）、[[web-generic-account-deletion-new-user-benefit-reuse]]（新用户权益重复利用）。
- 边界：若数据库有 `(user_id, coupon_id)` 唯一索引、领取用原子条件更新或分布式锁、且支付严格限制券叠加，则本条不成立；若只是前端按钮禁用/延迟，仍可直接并发绕过。

## 检测与防御

- 检测（黑盒）：对同一领取请求并发 2–20 次，比较响应与券包数量；遍历相邻 `couponId` 检查是否存在人群/资格校验；在支付页尝试多券叠加。
- 检测（代码审计）：搜索领券 handler 中的 `SELECT` 后 `INSERT`/`UPDATE` 模式，确认是否缺少事务、唯一索引、`FOR UPDATE`、`ON CONFLICT` 或幂等键；检查 `couponId` 是否做归属/资格校验。
- 修复：数据库增加 `UNIQUE(user_id, coupon_id)`；用 `INSERT ... ON CONFLICT DO NOTHING` 或 `UPDATE ... WHERE stock > 0` 的原子条件更新扣库存；关键路径加 Redis/DB 分布式锁与幂等键。
- 加固：服务端校验券的领取资格（人群标签、渠道、时间窗）、每用户限领数量与频率；支付侧限制同订单券数量/类型互斥与最低消费；监控同一用户短时间大量领券/异常见券 ID 枚举并告警。
