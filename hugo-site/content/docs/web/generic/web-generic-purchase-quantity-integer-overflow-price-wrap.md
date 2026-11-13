---
id: web-generic-purchase-quantity-integer-overflow-price-wrap
title: 购买数量填超大整数触发金额计算溢出：以极少余额买下天价商品
type: scenario
domain: web
path: web/generic
technique: purchase-quantity-integer-overflow-price-wrap
tags:
- web
- business-logic
- e-commerce
- integer-overflow
- quantity
- price-manipulation
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V527
  verified_at: '2026-11-11T15:07:08+08:00'
  notes: 已对照原文 content.md 与全部 31 张图（含 03/04 两个 GIF；16 张超 1200px 已降采样后读取，无失败）。截图核对：FlagB 标价 999063388 金币（图27/28/30）、购买数量输入 424672867399（图30）、购买成功后背包数量 849345734796（图30，实测约 2×提交值-2，非恰好 2 倍，已在原理中更正表述）、提示关键词『溢出』（图29）、原文 gold 为 906。原文未给服务端代码，price×quantity 回绕为推断（卡片已注明），PoC 未执行。dedup：与 web-generic-payment-negative-quantity-offset 为 related 非同链（负数抵消 vs 正数乘法溢出），其余候选 new；dup-scan 无跨卡重复对。无产品版本/CVE，不设 affected_versions。保留。
url: /docs/web/generic/web-generic-purchase-quantity-integer-overflow-price-wrap/
draft: false
kb_aliases:
- 购买数量整数溢出
- 数量溢出买高价商品
- price quantity overflow
- 超大量购买
- 金额回绕
---

## 一句话结论

当购买/兑换流程用定长整数计算「单价 × 数量」且未做上限与溢出校验时，把购买数量提交成超大整数（如 424672867399）可使总价在 32/64 位整数中回绕为小值或负值，从而通过余额校验，用极少金币买下标价近十亿的昂贵商品。

## 原理

- 常见实现是 `total = price * quantity`，类型为 32 位 `int` 或 64 位 `long`，没有溢出检查；当数量超过 `MAX_VALUE / price` 时乘积回绕（signed overflow），总价变成负数或很小的正数。
- 余额校验通常只看聚合结果：`wallet >= total` 或 `wallet - total >= 0`。总价回绕为负时扣款可能反向变成加钱；回绕为小正数时则以远低于真实价值的金额成交。数量字段往往只校验「正整数/不超过库存」，没有合理上限。
- 本例 CTF 商店中 FlagB 标价 999,063,388 金币，提交购买数量 424,672,867,399（乘积约 4.24×10^20，超过 64 位有符号上限 2^63≈9.22×10^18）后成功购买，背包中数量显示为 849,345,734,796（约提交值的 2 倍、差 2，换算公式不明），证明服务端确实按该数量参与了运算并发生回绕。原文未给出服务端代码，具体回绕位宽与扣款公式为推断。
- 本质与「负数量抵消」同类：金额计算信任客户端数量且不校验中间结果范围；区别是本卡不依赖负数，而是利用正数乘法溢出，因此能绕过「数量必须为正」的校验。

## 触发条件

- 购买/兑换/下单接口接收客户端提交的数量，且只校验正整数与库存，没有数量上限或合理性校验。
- 金额计算使用定长整数（`int`/`long`/其他有界类型），无溢出检测，余额校验依赖该计算结果。
- 攻击者拥有普通账号与少量余额，目标商品单价较高（便于更快触发溢出）。
- 服务端未在订单明细中逐项校验小计为正或总价与明细一致。

## 利用步骤

1. 选择单价高的商品，记录单价 P（本例 999,063,388）。
2. 估算溢出阈值：64 位有符号时取 quantity > 2^63/P（P≈1e9 时约 4.2×10^11 即可）；32 位整数所需数量小得多。
3. 抓取购买请求，把数量字段改为该超大值提交，观察余额变化、响应与背包/订单中的实际数量。
4. 若扣款异常变小或余额反增，立即停止并保存请求/响应证据；不要重复放大以免造成业务数据异常。
5. 对比「负数量」方法：若服务端校验数量 > 0，可优先尝试本卡的溢出路径。

## PoC

```http
POST /api/shop/buy HTTP/1.1
Host: target
Content-Type: application/json

{"itemId": 5, "quantity": 424672867399}
```

计算示意：`999063388 × 424672867399 ≈ 4.24×10^20 > 2^63`，64 位有符号乘法回绕后总价变为小值/负值，余额校验通过。PoC 未在本机执行；不同语言/位宽/字段类型阈值不同，需按目标实现调整。

## 变体与关联

- 变体：负数数量抵消订单金额（见 [[web-generic-payment-negative-quantity-offset]]）；本卡是其互补路径，适合服务端拒绝负数时使用。
- 变体：小数/科学计数法、单位换算（分与元、千与个）叠加放大；优惠券/积分抵扣同样按超大数量计算导致溢出。
- 变体：库存、积分、经验值、兑换码次数等凡是「数量×单价/权重」的地方都可能出现同类回绕。
- 关联：[[web-generic-purchase-quantity-limit-client-side-only-bypass]]（数量上限缺失的另一种利用）、[[binary-pwn-signed-int-add-overflow-negative-check-bypass]]（有符号整数溢出绕过负数校验的通用原理）。

## 检测与防御

- 服务端对数量做合理上限（限购、库存、单笔上限）与类型校验，拒绝超出业务范围的数值。
- 金额计算使用大整数或十进制类型，运算后显式检查溢出与范围；订单明细逐项校验 `数量 > 0`、`小计 >= 0`、总价等于明细之和。
- 支付/扣款以服务端计算的最终金额为准，任何客户端提交的数量都要重新校验；对异常大数量与余额异常变化设置监控告警。
- 检测：订单/背包出现异常大数量；扣款金额远低于商品标价；同一账号短时间内提交超大整数数量；金额字段出现负数或回绕后的小值。
