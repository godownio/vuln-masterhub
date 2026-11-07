---
id: web-generic-payment-negative-quantity-offset
title: 购物车接受负数量：负数商品抵消高价商品金额实现低价购买
type: scenario
domain: web
path: web/generic
technique: negative-quantity-price-offset
tags:
- web
- business-logic
- payment
- ecommerce
- cart
- negative-quantity
- price-manipulation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T09:20:01+08:00'
  notes: 已对照原文与图07-10核对：ShoppingCartController.settlePage 按 goodsCount*sellingPrice 累加后仅判断 priceTotal<1；图08 POST /shop-cart {"goodsId":10195,"goodsCount":-4} 返回 200 SUCCESS，图09 购物车显示 3999×5 与 2599×-4、合计 9599，图10 订单详情同时含 3999×5 与 2599×-4 两条明细且状态为待支付，负数量抵消订单金额成立，与卡内一致。原文未给 newbee-mall 版本，未写 affected_versions 正确。注意原文图10 仅到下单待支付、未展示最终支付成功，卡内“下单”表述准确。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
url: /docs/web/generic/web-generic-payment-negative-quantity-offset/
draft: false
kb_aliases:
- 负数量购物
- 低价购
- 购物车数量负数
- 负数抵消订单金额
- 商品数量未校验
---

## 一句话结论

电商结算页只校验“购物车总价 ≥ 1”，却没有校验每件商品数量必须为正；攻击者把高价商品正常加入购物车，再加入数量为负数（如 `-4`）的低价商品，负数小计会抵消大部分金额，最终以远低于商品价值的总价下单。

## 原理

- 加入购物车接口 `POST /shop-cart` 直接接收客户端 JSON 的 `goodsId` 与 `goodsCount`，未对 `goodsCount` 做 `> 0` 的校验，负数被原样写入购物车。
- 结算页 `/shop-cart/settle` 遍历购物车条目，按 `goodsCount * sellingPrice` 累加得到 `priceTotal`，只判断 `priceTotal < 1` 时失败；它把“总价大于 1”当作合法订单，未逐项校验数量为正、单价为正或小计为正。
- 订单金额由此等于正商品小计加上负商品小计。攻击者选择数量足够大的负数低价商品，即可把总价压到任意大于 1 的值，而订单中仍包含高价商品。
- 根因是把“金额校验”做成对聚合结果的单点检查，而没有在写入购物车、结算、下单三个环节对数量与单价做范围约束；客户端可控制数量，聚合结果自然可被负数操纵。

## 触发条件

- 购物车/下单接口接受客户端提交的 `goodsCount`，且未限制为大于 0 的整数。
- 结算页按 `数量 × 单价` 求和后只校验总价下限，未逐项校验数量/小计。
- 订单创建后按购物车条目生成订单明细，负数条目未被过滤或拒绝。
- 攻击者拥有普通用户账号并能访问购物车与结算功能。

## 利用步骤

1. 登录普通账号，选择高价商品加入购物车（如数量 5）。
2. 抓取 `POST /shop-cart` 请求，把 `goodsCount` 改为负数加入低价商品；若接口限制单次修改，可分多次添加。
3. 打开结算页，确认总价被负数抵消到可接受的低值，且高价商品仍在购物车中。
4. 提交订单并完成支付，核对订单详情：高价商品数量正常、低价商品为负数量、实付金额被压低。
5. 记录请求、购物车页面与订单详情作为证据；验证后停止，不批量下单。

## PoC

```http
POST /shop-cart HTTP/1.1
Host: target
Content-Type: application/json

{"goodsId":10195,"goodsCount":-4}
```

```text
响应：{"resultCode":200,"message":"SUCCESS","data":null}
购物车：高价商品 3999 元 × 5 = 19995 元；低价商品 2599 元 × -4 = -10396 元；
合计 9599 元，订单仍包含 5 件高价商品。
```

## 变体与关联

- 变体：数量改为 `0` 或小数（若字段允许）制造零金额/精度问题；或把单价字段一并提交篡改。
- 变体：优惠券/积分抵扣与负数小计叠加，把应付金额压到最低支付门槛以上。
- 变体：退款/售后接口按负数量计算退款金额，可能反向多退。
- 关联：[[web-generic-client-side-score-trust]]（信任客户端上报数值导致业务结果被伪造的同类根因）。
- 关联：[[web-generic-auth-mall-pay-success-idor-zero-cost-order]]（支付状态可被客户端直接改写，与本卡的金额操纵可组合）。

## 检测与防御

- 防御：购物车写入、结算、下单三处都校验 `goodsCount` 为大于 0 的整数并设上限；价格以服务端商品表为准，禁止客户端提交单价/小计。
- 防御：订单金额计算后逐项校验每条明细的 `数量 > 0`、`小计 >= 0`，任一不满足即拒绝；不要只校验聚合总价。
- 防御：优惠、积分、退款等金额计算统一使用服务端可信数据，并做正负范围校验。
- 检测：购物车/订单中出现负数量或零数量条目；订单总价远低于商品原价合计；同一账号短时间大量添加负数量商品；支付金额与商品目录价差异异常。
