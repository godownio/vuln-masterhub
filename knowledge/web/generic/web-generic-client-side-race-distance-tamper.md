---
id: web-generic-client-side-race-distance-tamper
title: 客户端提交赛跑距离参数篡改：服务端信任模拟输入直接发放 flag
type: scenario
domain: web
path: web/generic
technique: client-side-race-distance-tamper
aliases:
- 赛跑距离篡改
- Base64 请求体参数篡改
- 客户端模拟参数可信
- chase 接口
- 业务逻辑参数篡改
tags:
- web
- business-logic
- client-side-trust
- parameter-tampering
- base64
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:59+08:00'
  notes: 已对照原文 Base64 请求/响应截图核对；距离篡改与 flag 解码一致；PoC 未复跑。
---

## 一句话结论

当赛跑/竞速类接口把客户端提交的 `achilles_distance`、`tortoise_distance` 等模拟参数直接当成服务端事实，并据此判定胜负、返回 flag 时，攻击者只需把“阿基里斯”的距离改得比“乌龟”大，重新 Base64 编码后提交，即可跳过正常游戏过程拿到奖励。

## 原理

- 客户端把比赛参数序列化为 JSON，再做 Base64 编码放进请求体（如 `{"data":"eyJhY2hpbGxlc19kaXN0YW5jZSI6..."}`）；服务端解码后按这些距离模拟比赛。
- 服务端没有保存权威的比赛状态，也没有校验距离的取值范围、增长速度或来源，只根据客户端提交的数值判断谁先到达终点；因此攻击者可以任意设置双方距离。
- Base64 只是编码，不是签名/加密；攻击者可以解码、修改 JSON、重新编码，请求体看起来仍是合法格式。
- 本例把 `achilles_distance` 设为 `1110000000`、`tortoise_distance` 设为 `1100000000`，让阿基里斯“跑得更远/更快”，服务端返回的 `data` 再 Base64 解码即得到 flag。
- 根因是信任边界错误：比赛结果本应由服务端权威状态/规则计算，却由客户端提供的参数决定；这与“客户端上报分数/点击次数”属于同一类业务逻辑缺陷。

## 触发条件

- 存在竞速/小游戏/模拟类接口，客户端提交距离、速度、时间、分数等参数。
- 服务端直接使用这些参数判定胜负/发放奖励，未做范围校验、签名或服务端重算。
- 请求体只是 Base64/JSON 等可逆编码，没有完整性保护（HMAC/签名）。
- 奖励（flag、优惠券、积分）由该判定结果直接触发。

## 利用步骤

1. 抓取正常比赛请求，识别请求体中的 Base64/JSON 字段与参数名（如 `achilles_distance`、`tortoise_distance`）。
2. 解码 Base64，修改参数使己方获胜（如把阿基里斯距离设为远大于乌龟）。
3. 重新 JSON 序列化并 Base64 编码，保持字段名/类型一致。
4. 重放 `POST /chase`，解码响应中的 `data` 字段，读取 flag/奖励。
5. 若服务端校验数值范围，尝试边界值、负数、极大值、类型混淆（字符串/数组）等；若校验总距离，保持总和不变但调整分配。

## PoC

```python
import base64, json, requests

body = {"achilles_distance": 1110000000, "tortoise_distance": 1100000000}
data = base64.b64encode(json.dumps(body, separators=(",", ":")).encode()).decode()
r = requests.post("http://target/chase", json={"data": data})
print(base64.b64decode(r.json()["data"]).decode())  # {"flag": "..."}
```

手工步骤：

```text
1. Base64 解码请求体 -> {"achilles_distance":1110000000,"tortoise_distance":1100000000}
2. 修改数值 -> 重新 Base64 编码
3. POST /chase {"data":"<新编码>"}
4. Base64 解码响应 data -> flag
```

## 变体与关联

- 变体：距离换成速度、时间、点击次数、关卡进度、骰子点数、抽卡概率等；核心是客户端控制判定输入。
- 变体：参数有签名但签名密钥硬编码/可预测，或签名只覆盖部分字段，可篡改未签名字段或重放。
- 变体：服务端用浮点数/整数溢出、NaN、负数等边界值绕过范围检查。
- 关联：[[web-generic-client-side-score-trust]]（客户端上报分数/点击次数换奖励）、[[web-generic-payment-amount-tamper-no-order-binding]]（金额参数篡改）、[[web-generic-race-condition-tip-reputation-role-escalation]]（竞态改业务状态）。
- 边界：服务端保存权威比赛状态、对参数做签名/范围校验/重算、奖励与客户端结果解耦时，本手法失效。

## 检测与防御

- 服务端保存权威比赛状态与规则，按事件/时间逐步计算，不信任客户端提交的距离/速度/结果。
- 对客户端参数做范围、类型、单调性校验；奖励判定只使用服务端状态。
- 若必须接收客户端模拟参数，使用 HMAC/签名保护完整请求体，并绑定会话、时间戳与一次性 nonce。
- 检测：同一会话提交异常大的距离/速度、双方参数比例失衡、请求体 Base64 解码后字段与正常值差异大；短时间内重复提交并直接领取奖励。
- 响应：对异常参数做风控/限速，回收异常发放的奖励，审计业务逻辑接口的参数校验。
