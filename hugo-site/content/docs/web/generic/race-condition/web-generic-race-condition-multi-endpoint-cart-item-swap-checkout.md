---
id: web-generic-race-condition-multi-endpoint-cart-item-swap-checkout
title: 多端点条件竞争：校验与扣款之间并发换货，10 元礼品卡订单夹带 1337 元夹克（加/删商品、用券、结算同组并行）
type: scenario
domain: web
path: web/generic/race-condition
technique: multi-endpoint-cart-item-swap-during-checkout
tags:
- web
- race-condition
- business-logic
- e-commerce
- payment
- cart
- burp-repeater
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V599
  verified_at: '2026-11-12T17:06:59+08:00'
  notes: 已对照原文与图20-26：Gift Card $10、夹克$1337、Group2四请求并行（移除夹克请求体productId=1&quantity=-2&redir=CART与图24一致）、最终余额-$1277并solved（图25）；图26为支付优惠券+添加夹克等价组合。dedup top候选为负数量篡改、交易状态TOCTOU、单端点券竞态，均非同链，new判断成立。添加商品与结算请求体原文未完整给出，卡内PoC为合理构造。未验证点：未复跑PoC。
url: /docs/web/generic/race-condition/web-generic-race-condition-multi-endpoint-cart-item-swap-checkout/
draft: false
kb_aliases:
- 多端点条件竞争
- multi-endpoint race condition
- 购物车换货竞态
- 结算校验间隙改购物车
- add jacket remove jacket checkout
- PortSwigger multi-endpoint
---

## 一句话结论

结算流程在一个请求/响应周期内串行调用多个接口（校验购物车合法性与余额 → 生成支付订单 → 扣款），而这些步骤之间没有对购物车做快照或加锁：把"添加夹克、移除夹克、添加/核销礼品卡、提交结算"等不同端点的请求放进同一并行组同时发出，服务器会在校验时看到低价商品（10 元礼品卡）、扣款后却按包含 1337 元夹克的购物车完成订单——用 10 元买到 1337 元商品，甚至把店铺余额扣成负数。

## 原理

- **多端点竞态的窗口**：与单端点"同一接口重复提交"不同，本场景的冲突发生在**不同端点**之间——`POST /cart`（加/删商品）、`POST /cart/coupon`（用券）、`POST /cart/checkout`（提交订单/扣款）。结算请求内部要依次校验购物车、计算金额、调用支付/扣减余额、写入订单；这些后台调用之间的时间差就是竞争窗口。
- **校验与扣款用的不是同一份购物车状态**：如果校验时读取的是"礼品卡 10 元"的购物车，扣款也按 10 元执行，而订单履约/发货读取的是请求完成后的购物车（已被并发的 add jacket 改成夹克），就会出现"付低价、拿高价"。
- **为什么要精心排列顺序**：并发的加夹克与减夹克请求会互相改变购物车；把"添加夹克 → 移除夹克 → 添加礼品卡 → 提交结算"放在同一并行组，并确保每次购物车里都有一张礼品卡（或优惠券商品），可以在校验/扣款的不同阶段让购物车呈现不同内容。重复多次提高命中概率，直到订单以低价包含目标商品。
- **另一种等价构造**：把"支付/核销优惠券"的数据包与"添加夹克"的数据包放同一并行组，同样卡在支付与订单落库之间——本质都是让"价格依据"和"商品清单"在窗口内错位。
- **为什么危害大**：直接造成资金损失（低价买高价、余额扣成负数），且不依赖任何代码漏洞，纯业务逻辑时序问题；单端点重复请求的同类场景见 `[[web-generic-race-condition-coupon-apply-endpoint-discount-stack]]`。

## 触发条件

- 结算接口在一次请求内串行调用多个后端服务（校验库存/余额、计算价格、扣款、写订单），步骤间无购物车快照/分布式锁。
- 购物车是服务端共享状态，多个端点（加/删商品、用券、结算）可并发修改同一购物车。
- 支付/扣款依据的金额与最终订单商品清单不是同一份原子快照。
- 攻击者能同时向多个端点发请求（Burp Repeater 并行组或脚本并发）。

## 利用步骤

1. 正常走一遍购买流程，记录各端点：`POST /cart`（productId/quantity/redir）、`POST /cart/coupon`、`POST /cart/checkout`，确认购物车与结算的先后关系。
2. 准备低价商品（礼品卡/优惠券类）加入购物车，确认总价处于低位。
3. 抓取"添加夹克、移除夹克、添加礼品卡、提交结算"四个请求，放入 Repeater 同一 group。
4. 按 添加夹克 → 移除夹克 → 添加礼品卡 → 提交结算 的顺序配置并行发送（`Send group (parallel)`），确保每次购物车中都有低价商品。
5. 发送并观察：订单是否包含夹克而扣款按礼品卡金额；失败则重复多组，或改用"支付优惠券 + 添加夹克"同组并行。
6. 成功后检查店铺余额/订单详情作为证据，停止测试并恢复购物车。

## PoC

```http
### 1) 添加夹克（并行组成员）
POST /cart HTTP/2
Host: target
Cookie: session=<自己的会话>
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1&redir=CART

### 2) 移除夹克（quantity 为负，制造购物车状态变化）
POST /cart HTTP/2
Host: target
Cookie: session=<自己的会话>
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=-2&redir=CART

### 3) 添加低价礼品卡
POST /cart HTTP/2
Host: target
Cookie: session=<自己的会话>
Content-Type: application/x-www-form-urlencoded

productId=2&quantity=1&redir=CART

### 4) 提交结算（与上面三个请求同一并行组）
POST /cart/checkout HTTP/2
Host: target
Cookie: session=<自己的会话>
Content-Type: application/x-www-form-urlencoded

csrf=<token>
```

操作方式：Burp Repeater 中 Ctrl+R 复制出各请求 → 全选加入同一 group → `Send group (parallel)`，重复多轮直到订单以低价包含高价商品。

## 变体与关联

- **端点组合变体**：`添加高价商品 + 提交结算`、`核销优惠券 + 添加高价商品`、`修改数量 + 结算`；核心是让"价格依据"与"商品清单"错位。
- **单端点对照**：同一接口并发重复 apply 优惠券见 `[[web-generic-race-condition-coupon-apply-endpoint-discount-stack]]`；领券接口并发见 `[[web-generic-race-condition-coupon-concurrent-claim-stack]]`；下单复用券见 `[[web-generic-race-condition-coupon-order-submit-reuse]]`。
- **状态机类竞态**：订单状态与结算任务之间的 TOCTOU 见 `[[web-generic-race-condition-transaction-status-toctou-limit-bypass]]`。
- **边界**：结算时对购物车做快照/加锁、支付前重新计算并校验订单商品与金额、加分布式事务或幂等键，均可关闭窗口；并发顺序与网络时延影响成功率，需多轮尝试。

## 检测与防御

- **购物车快照**：提交结算时对购物车行加锁并生成不可变快照，后续校验、计价、扣款、订单落库全部基于该快照；结算期间禁止修改购物车（乐观锁版本号/分布式锁）。
- **金额与商品一致性**：支付前在服务端重新计算订单金额并校验与实际商品清单一致；扣款金额与订单金额强绑定，余额不足直接拒绝。
- **幂等与去重**：结算请求带幂等键，防止并发重复下单；对同一购物车的并发写操作串行化。
- **检测信号**：同一会话在毫秒级对加购/删购/结算多个端点发起请求；订单商品与支付金额严重不匹配；余额被扣成负数；结算期间购物车发生多次变更。
