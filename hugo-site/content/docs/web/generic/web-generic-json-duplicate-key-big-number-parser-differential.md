---
id: web-generic-json-duplicate-key-big-number-parser-differential
title: JSON 重复键/大数解析差异：前端校验 last-wins、Go jsonparser first-wins 导致负数量与零元结算
type: scenario
domain: web
path: web/generic
technique: json-parser-differential-duplicate-key-big-number
tags:
- web
- json
- parser-differential
- duplicate-key
- big-number
- business-logic
- payment
- go
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-08T00:32:17+08:00'
  notes: 已对照原文与14张图：图02 Python/jsonschema 对重复 qty 取最后值(1)通过、负 id 被拒；图03 Go jsonparser 取第一个 qty=-1；图04 结算 5x100 + 1x200=300；图14 Go 对大数 GetInt 得 0，与卡内重复键/大数两变体一致。原文为 lab1 复现实验，未本机复跑；无组件版本区间故未设 affected_versions。dedup 除自身外 top 候选均为不同链（CouchDB CVE、Go casefold、PHP query-string 等），非同链重复。
url: /docs/web/generic/web-generic-json-duplicate-key-big-number-parser-differential/
draft: false
kb_aliases:
- JSON 解析差异
- JSON parser differential
- 重复键优先级
- 大数解析为 0
- jsonparser first wins
- jsonschema last wins
- JSON 解释器不一致
- 解析器不一致业务逻辑绕过
---

## 一句话结论

多组件系统里若前端校验层和业务层使用不同的 JSON 解析器，重复键优先级差异（Python `json`/`jsonschema` 取最后一个，Go `buger/jsonparser` 取第一个）或大数处理差异（Python 保留任意精度整数并校验通过，Go `GetInt` 解析失败返回 0 且错误被忽略）会让同一份 JSON 在校验层和业务层得到不同值；攻击者可让校验层看到合法数量、业务层实际使用负数或 0，实现负数量抵消、零元结算等业务逻辑绕过。

## 原理

- RFC 8259 对重复键没有强制规定：object 内部的 name 应唯一，但出现重复时行为“不可预测”，不同实现可能只保留最后一个、只保留第一个、报错或保留全部。因此同一份 JSON 跨解析器没有互操作保证。
- Python 侧：`json.loads('{"qty": -1, "qty": 1}')` 得到 `{'qty': 1}`（last-wins）；`jsonschema.validate()` 校验的是这个已解析对象，看到 `qty=1`，满足 `minimum: 1`，校验通过。
- Go `buger/jsonparser` 侧：`jsonparser.GetInt(value, "qty")` 在重复键上返回第一个出现的 `-1`（first-wins），且调用方通常忽略 error。业务层用 `-1` 计算购物车总价。
- 典型架构：Flask + jsonschema 作为前置校验代理，真正的下单/结算逻辑在 Go 微服务。校验层认为第二件商品数量为 1，业务层按 -1 计算，于是 `5×$100 + (-1)×$200 = $300`，而不是正常的 `$700`。
- 大数变体同理：Python3 的 int 是任意精度，`qty=10^96` 能原样解析并通过只检查 `minimum` 的 schema；Go 的 `GetInt` 对超出 int64 的数字解析失败并返回 0（error 被忽略），业务层于是按数量 0 结算，收据显示巨额数量但 `Total Charged: $0`。
- 根因不是单个解析器的 bug，而是“校验的数据”和“使用的数据”来自两次独立解析；只要解析器在重复键、数字范围、字符截断、注释等宽泛规则上存在差异，就可能出现校验/使用不一致。解析器越多、微服务越多，可组合出的差异对越多。

## 触发条件

- 同一 JSON 请求体被至少两个组件解析，且解析器对重复键优先级或数值范围处理不同（如 Python `json` vs Go `jsonparser`、网关校验 vs 后端业务）。
- 校验组件基于自己的解析结果做约束判断（minimum/maximum/required），业务组件基于另一次解析结果做金额、数量、权限等安全决策。
- 攻击者能控制 JSON body（`Content-Type: application/json`），可插入重复键或超大整数。
- 业务逻辑中存在可用数值操纵的字段（数量、单价、折扣、积分、额度等）。

## 利用步骤

1. 摸清架构：确认前置校验/网关使用的语言与解析库（如 Flask + jsonschema），以及后端业务使用的语言与解析库（如 Go `buger/jsonparser`）。
2. 探测重复键优先级：发送 `{"a":1,"a":2}`，通过回显/报错/业务结果判断每个组件取第一个还是最后一个；也可用数组内对象的重复键测试。
3. 探测数值边界：发送超大整数、`1e4096`、`Infinity`、`NaN`、负零等，观察校验层与业务层是报错、截断、置 0 还是保留。
4. 构造冲突体：让校验层取到合法值、业务层取到恶意值。例如把恶意值放在第一个、合法值放在第二个（校验 last-wins、业务 first-wins）；或把 `id` 设为合法范围内的值、`qty` 设为超大整数（Python 通过、Go 得 0）。
5. 调用下单/结算/兑换接口，核对收据金额、库存扣减、积分变动，确认业务层实际使用的数值。
6. 扩大影响：负数量抵消高价商品、0 数量免费获取、巨额数量配合 0 单价、结合折扣/优惠券/退款逻辑。

## PoC

重复键：Python 校验层看到 `qty=1` 通过，Go `jsonparser` 看到第一个 `qty=-1` 计算总额。

```json
{
  "orderId": 10,
  "cart": [
    {"id": 0, "qty": 5},
    {"id": 1, "qty": -1, "qty": 1}
  ]
}
```

```bash
curl 192.168.56.130:5000/cart/checkout -H "Content-Type: application/json" -d @lab1_req.json
# Receipt:
# 5x Product A @ $100/unit
# 1x Product B @ $200/unit
# Total Charged: $300      # 500 + (-1)*200，正常应为 700
```

大数变体：Python 保留 `10^96` 并通过 `minimum` 校验，Go `GetInt` 解析失败返回 0，总额为 0。

```json
{
  "orderId": 10,
  "cart": [
    {"id": 8, "qty": 999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999}
  ]
}
```

```bash
curl 192.168.56.130:5000/cart/checkout -H "Content-Type: application/json" -d @lab1_alt_req.json
# Receipt:
# 999999...999x $100 E-Gift Card @ $100/unit
# Total Charged: $0
```

最小语言验证：

```python
import json
json.loads('{"qty": -1, "qty": 1}')   # {'qty': 1}  last-wins
```

```go
qty, _ := jsonparser.GetInt(value, "qty") // 重复键取第一个；超大数解析失败返回 0
```

## 变体与关联

- 大数变体：与重复键同属 lab1 的第二种解法，触发点从“键优先级”换成“数值范围/精度”，PoC 与校验/使用差异见上。
- 注释截断：`{"description":"...","test":2,"extra":/*,"test":1,"extra2":*/}` 在不同库中结果不同——GoJay 得 `test=2`，Java JSON-iterator 得 `test=1` 且 `extra="/*"`，GSON 丢弃注释尾部，simdjson 保留 `extra2` 且 `test=2`。这类差异可用来制造“键碰撞”，但原文只给出解析结果、没有端到端目标，未单独成卡。
- 序列化差异：Java JSON-iterator 对 `{"test":1,"test":2}` 取值 `1` 但 `toString()` 输出 `{"test":2}`；C++ rapidjson 取值 `2` 但 `toString()` 保留两个键。若系统“解析后校验、再序列化给下游”，也会出现校验/使用不一致。
- 非法 Unicode 代理项截断（`superadmin\ud888` 归一化为 `superadmin`）是另一类解析差异，见 [[web-generic-auth-json-invalid-unicode-surrogate-role-truncation]]。
- 同类 CVE 思路：CouchDB CVE-2017-12635 用重复 `roles` 键绕过管理员创建限制，见 [[web-generic-rce-couchdb-cve-2017-12635-12636]]。
- 同一“负数结算”sink 的直接路径（不依赖解析差异）见 [[web-generic-payment-negative-quantity-offset]]；本卡是校验层/业务层解析不一致的绕过路径，触发条件与 PoC 不同。
- 宽松 JSON：部分解析器接受 `application/x-www-form-urlencoded` body 中的 JSON 片段（如 `{"test":1}=`），可用于 CSRF/内容类型混淆场景，原文未给出完整利用。

## 检测与防御

- 解析层禁用重复键：Python `json.loads(..., object_pairs_hook=reject_duplicates)`；Go 用 `encoding/json` 的自定义 token 扫描或第三方严格模式；Jackson 开启 `STRICT_DUPLICATE_DETECTION`；serde 配置重复字段报错。
- 校验与使用同源：在同一个服务、同一次解析结果上完成校验和业务计算；网关只做转发时，把规范化后的对象传给下游，禁止下游重新解析原始 body。
- 数值约束：拒绝超出安全整数范围（如 `|n| > 2^53`）的数值、拒绝 `NaN`/`Infinity`；金额用 decimal 类型并有明确 `maximum`/`minimum`；对数量、单价做业务层二次校验，不只依赖 schema。
- 架构审计：盘点所有 JSON 解析器组合，重点找“校验用 A、业务用 B”的微服务/网关；用重复键、超大数、非法 surrogate、注释、控制字符做互操作 fuzz。
- 监控：请求体中重复键比例、超长数字 token、校验层 4xx 但业务层 200 的差异请求；对结算金额与数量做服务端一致性核对。
