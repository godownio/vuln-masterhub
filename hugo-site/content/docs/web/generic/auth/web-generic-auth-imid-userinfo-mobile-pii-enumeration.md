---
id: web-generic-auth-imid-userinfo-mobile-pii-enumeration
title: 聊天用户信息接口按 imId 越权：遍历获取服务者真实手机号与 userId
type: scenario
domain: web
path: web/generic/auth
technique: imid-userinfo-mobile-pii-enumeration
tags:
- web
- auth
- idor
- pii
- mobile
- enumeration
- chat
- information-disclosure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:34+08:00'
  notes: 已对照原文与 img14-15 核对：GET /user/getUserInfoByIm?imId=pro126667 返回 userId 886133、userType 1、真实手机号，imId 可遍历为原文陈述；未复跑。
url: /docs/web/generic/auth/web-generic-auth-imid-userinfo-mobile-pii-enumeration/
draft: false
kb_aliases:
- imId 越权查询
- getUserInfoByIm 信息泄露
- 聊天接口泄露真实手机号
- 服务者手机号枚举
- IM 用户信息 IDOR
---

## 一句话结论

聊天页的用户信息接口 `GET /user/getUserInfoByIm?imId=<id>` 只按 imId 查询并返回用户资料，不校验该 imId 是否与当前用户存在会话关系；由于 imId 可枚举（如 `pro` + 数字），攻击者能批量获取服务者的真实手机号、userId、用户类型等 PII，而平台本应只暴露虚拟号码。

## 原理

- IM 聊天页为了展示对方头像/昵称，会调用用户信息接口，以 `imId` 作为唯一标识查询用户资料；服务端只校验请求已登录，没有校验当前用户是否有权查看该 imId 对应的人（例如是否在同一会话、是否本人）。
- 响应中的 `data` 包含 `userId`、`userType`、`mobile` 等字段，其中 `mobile` 是服务者的真实手机号；平台业务本应通过虚拟号码通话保护双方隐私。
- `imId` 常为可预测格式（原文形如 `pro126667`，前缀 + 递增数字），攻击者可从自己的聊天对象出发，遍历/相邻猜测其他服务者的 imId，批量收集真实号码。
- 这属于对象级授权缺失（IDOR）+ 过度返回敏感字段；即使不做遍历，攻击者只要打开任意聊天框抓包，也能通过接口直接确定对方信息。

## 触发条件

- 攻击者拥有可正常登录的普通账号，能进入聊天/消息页面。
- 用户信息接口以客户端传入的 `imId`/`userId` 查询，且只校验登录态。
- imId 可预测或可从其他接口获得，响应包含真实手机号等敏感字段。
- 接口无频率限制或限制不足以阻止低频枚举。

## 利用步骤

1. 登录普通账号，进入与服务者的聊天页，抓取 `GET /user/getUserInfoByIm?imId=<self_or_peer>` 请求。
2. 确认响应中包含 `userId`、`userType`、`mobile` 等字段，记录字段含义。
3. 将 imId 放入 Burp Intruder，按前缀+数字递增/相邻猜测遍历，按响应长度/手机号格式过滤有效结果。
4. 批量提取真实手机号与 userId，评估是否可用于撞库、钓鱼、密码重置或线下骚扰。
5. 控制请求频率并脱敏保存证据；不将泄露数据用于未授权用途。

## PoC

```http
GET /user/getUserInfoByIm?imId=pro126667 HTTP/1.1
Host: target
Cookie: <普通用户会话>
Accept: application/json
```

```json
{
  "code": 0,
  "msg": null,
  "data": {
    "userId": 886133,
    "userType": 1,
    "mobile": "1831****"
  },
  "tid": ""
}
```

响应中的 `mobile` 为服务者真实手机号（原文未脱敏），`userId` 可继续用于其他接口的越权测试。

## 变体与关联

- 变体：将 `imId` 换成 `userId`、`accId`、`personId` 等其他用户标识，测试同一接口或其他用户资料接口。
- 变体：泄露的真实手机号可喂给登录/找回密码/短信接口，测试“手机号+验证码”账号接管链。
- 关联：[[web-generic-auth-mobile-person-permission-userid-idor-pii]]（userId 遍历泄露师生 PII）、[[web-generic-auth-api-param-fuzz-idcard-pii-enumeration]]（参数枚举 + PII 越权）、[[web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak]]（普通用户拉取全量手机号）。
- 边界：接口校验当前用户与目标 imId 的会话/好友关系、返回脱敏或虚拟号码、imId 使用不可预测 UUID 且做限速时，批量枚举受限。

## 检测与防御

- 修复：用户信息接口按“当前用户与目标 imId 存在有效会话/订单关系”做对象级授权；本人信息与聊天对象信息分开返回。
- 加固：聊天场景只返回昵称/头像/虚拟号码，真实手机号不下发；对 `userId`/`imId` 等标识做不可预测化；对批量查询做速率限制与审计。
- 检测：同一账号短时间内查询大量不同 imId；响应含真实手机号格式；同一 IP/设备的高频枚举；聊天页请求 imId 与当前会话对象不匹配。
- 响应：评估泄露范围，通知受影响服务者，轮换虚拟号绑定，排查是否已用于钓鱼或账号接管。
