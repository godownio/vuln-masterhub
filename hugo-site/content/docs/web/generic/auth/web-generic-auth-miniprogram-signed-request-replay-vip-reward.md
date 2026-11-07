---
id: web-generic-auth-miniprogram-signed-request-replay-vip-reward
title: 小程序邀请注册请求可重放：sign+timestamp 只防篡改不防重放，重复领取 7 天 VIP
type: scenario
domain: web
path: web/generic/auth
technique: signed-request-replay-non-idempotent-reward
tags:
- web
- auth
- replay
- signature
- timestamp
- business-logic
- idempotency
- miniprogram
- vip
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:32+08:00'
  notes: 已对照原文与 img19-23 核对：/applets/userRegister 的 sign+timestamp 原样重放均 code=0，会员有效期从 2024-12-08 变为 2026-05-10；未复跑。
url: /docs/web/generic/auth/web-generic-auth-miniprogram-signed-request-replay-vip-reward/
draft: false
kb_aliases:
- 签名请求重放
- userRegister 重放
- 邀请绑定重放刷会员
- sign+timestamp 不防重放
- 幂等缺失重复发奖
---

## 一句话结论

小程序邀请注册接口 `POST /applets/userRegister` 使用 `sign`+`timestamp` 做完整性校验，但没有 nonce/一次性消费/幂等控制；攻击者原样重放同一份已签名请求，每次都会再次执行“邀请绑定成功并赠送 7 天 VIP”，可无限叠加会员时长。

## 原理

- 请求 URL 带 `sign` 与 `timestamp`，body 含 `referrerId`、`mobile`、`sourceId`、`timestamp` 等字段；服务端校验签名与时间戳，确保参数未被篡改。
- 校验通过后，业务逻辑把“邀请绑定”和“赠送 7 天会员”当作每次请求都执行的动作，没有记录该 `sign`/`timestamp` 是否已使用，也没有对“同一邀请人+同一手机号”做唯一性约束或幂等键。
- 因此攻击者抓包后把请求原样发到 Repeater/Intruder 重复发送，每次都返回 `code=0`，会员有效期持续累加（原文从 2024-12-08 刷到 2026-05-10，约两年）。
- 签名在这里只解决“内容不能被改”，不解决“请求不能被重放”；时间戳通常只校验新鲜度窗口，在窗口内重放完全合法。本质是状态变更接口缺少幂等与防重放设计。

## 触发条件

- 目标小程序存在邀请注册/绑定有礼流程，成功后发放会员、积分、红包等权益。
- 请求带 `sign`/`timestamp`（或类似签名头），但服务端没有 nonce 记录、签名一次性消费或业务幂等键。
- 攻击者能抓到至少一份有效请求（自己的邀请流程即可），且签名在时间窗内可重放。
- 发奖逻辑不按“邀请人+被邀请人”去重，也不校验同一手机号是否已绑定过。

## 利用步骤

1. 进入“邀请有礼”，生成邀请链接/二维码，用自己的账号完成一次邀请绑定，抓取 `POST /applets/userRegister` 请求。
2. 原样重放一次，确认返回成功且会员天数增加；记录会员到期时间作为基线。
3. 将请求放入 Burp Intruder/Repeater 重复发送（控制频率），观察每次是否都返回 `code=0` 且到期时间继续后移。
4. 若时间戳窗口有限，可在窗口内高并发重放；若签名包含 body 哈希，保持 body 完全不变即可。
5. 记录重放次数、响应与会员到期时间变化作为证据，验证后停止，避免对业务造成异常数据。

## PoC

```http
POST /applets/userRegister?sign=B43369DA38154CD9757706E3B709682C&timestamp=1729442602682 HTTP/1.1
Host: target
Content-Type: application/json
Usertoken:
Xweb_xhr: 1

{"referrerId":"950485","code":"","mobile":"13555555555","sourceId":"6","stuInfo":"","timestamp":1729442602682}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":0,"msg":null,"data":"<会员到期时间/标识>","tid":""}
```

重复发送同一请求，`data` 与会员到期时间持续变化；原文重放后会员从 2024-12-08 延长到 2026-05-10。

## 变体与关联

- 变体：同类可重放的状态变更接口包括签到、领券、领积分、邀请奖励、抽奖、投票、点赞、订单状态变更；只要签名不绑定一次性 nonce 且业务不幂等即可尝试。
- 变体：时间戳不在签名范围内时可改时间戳；签名覆盖 body 时保持 body 不变；签名只覆盖部分参数时可测试参数走私。
- 关联：[[web-generic-auth-api-signature-method-scope-replay-bypass]]（签名无时效/跨方法重放，侧重绕过签名过滤器）、[[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]（nonce/弱签名伪造）、[[web-generic-client-timestamp-replay-typing-speed-bypass]]（客户端时间戳重放）。
- 边界：服务端使用一次性 nonce/jti 并持久化消费记录、按业务主键做唯一约束、或对邀请关系与手机号做强去重时，重放不会重复发奖。

## 检测与防御

- 修复：签名内容绑定 HTTP 方法、路径、body 哈希、timestamp 和一次性 nonce；服务端在时间窗内校验并原子消费 nonce，重复使用直接拒绝。
- 加固：发奖/绑定接口使用业务幂等键（如 inviteId、被邀请人手机号哈希），数据库唯一约束保证同一邀请关系只发一次；状态变更记录操作流水。
- 检测：同一 `sign`/`timestamp`/nonce 在短时间内重复出现；同一账号会员到期时间异常快速增长；同一邀请人对应大量绑定记录；邀请接口请求频率异常。
- 响应：回滚异常发放的会员与奖励，审计邀请关系，封禁异常账号，并排查是否存在并发重放。
