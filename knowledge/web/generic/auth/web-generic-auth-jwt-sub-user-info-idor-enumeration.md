---
id: web-generic-auth-jwt-sub-user-info-idor-enumeration
title: 用户详情接口以 JWT sub 为主键且不校验归属：改 sub 遍历批量拉取用户 PII（手机号/邮箱/生日）
type: scenario
domain: web
path: web/generic/auth
technique: jwt-sub-user-info-idor-enumeration
aliases:
- JWT sub 遍历用户信息
- user/info 越权查询
- ApiContext.getUserId 越权
- 用户信息泄露 POC
- sub 改 ID 批量拉取用户
tags:
- java
- spring-boot
- jwt
- idor
- user-enumeration
- pii-leak
- authorization
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V627
  verified_at: '2026-11-12T23:19:38+08:00'
  notes: V627 已对照 12601 原文与 12 张图核对：图 08 显示 ApiDemoController#userInfo 使用 ApiContext.getUserId()（JWT sub），图 10 Burp 实测 /api/.../user/info 返回 200 及 nickName/avatar/gender/birthday/mobile/email 字段，与卡面原理和 PoC 一致；图 11/12 为 buildJWT(sub) 生成的 tokens.txt 字典。dedup 结论 new：kaifangqian 缺权限注解、getTokenById 签发、DeepAudit 列表缺角色、spring-rbac 删除越权等候选均为不同实现与不同 sink，非同链；与本篇卡 1 构成前后利用链但各自原子、不重复。已修正：1) 「文中 12 张图显示」改为「图 10 实测响应」；2) 术语 OWL 改为 BOLA。未验证点：响应中目标用户 ID 与 sub 的对应关系因打码无法独立确认，按原文表述采信；批量遍历仅有字典生成过程、无批量结果截图。
---

## 一句话结论

Spring Boot API 的用户详情接口（`/api/.../user/info`）直接用 `ApiContext.getUserId()`（即 JWT `sub`）作为查询主键返回用户资料，不校验请求者是否有权查看该 ID；攻击者把 JWT 的 `sub` 改成任意用户 ID 即可逐个获取昵称、头像、性别、生日、手机号、邮箱等 PII，遍历 ID 空间即可批量拉取全站用户信息。

## 原理

- 鉴权链路只负责“token 验签通过”，用户身份完全取自 JWT `sub`：`ApiContext.getUserId()` 从 token 解析出用户 ID，业务方法用它查库。
- 用户详情接口按该 ID `select * from user where id = ?` 返回资料，缺少“当前登录用户 == 被查询用户”或角色校验，也不掩码手机号/邮箱等敏感字段。
- 攻击者持有任意有效 token（正常注册即可，或利用硬编码密钥自签，见关联卡）后，只需改动 `sub` 就能以任意用户身份查询资料；无需密码、无需知道对方账号。
- 为什么成立：把“身份凭证”与“资源标识”混为一谈。JWT 的 `sub` 设计为“谁在请求”，服务端却把它同时当作“要查谁”；缺少对象级授权（BOLA/IDOR 防护）时，`sub` 可遍历即等于用户表可遍历。

## 触发条件

- 目标 API 使用 JWT 且 `sub` 为用户 ID/主键，验证签名后直接以 `sub` 查询数据。
- 存在返回用户资料的接口（如 `/api/.../user/info`），且无对象级权限校验、无字段脱敏。
- 攻击者可获得有效 JWT（注册/登录或利用 [[web-generic-jwt-demo-passtoken-getusertoken-defaultsecret-forgery]] 中的硬编码密钥自签）。
- 用户 ID 为连续整数或可预测格式，能批量遍历。

## 利用步骤

1. 用任意账号或 demo 接口拿到一个 JWT，确认 `sub` 含义（jwt.io 解码）。
2. 把 `sub` 改为 1、2、3…（或使用 Java/Python 脚本批量生成不同 `sub` 的有效签名 token）。
3. 每个 token 放入 `Authorization: Bearer ...` 请求 `/api/.../user/info`（或对应详情接口）。
4. 观察响应是否返回目标用户资料；若 200 且含 mobile/email 等字段，确认越权。
5. 批量遍历并汇总，评估泄露规模；必要时抽样非本账号 ID 证明越权（避免只测到自己的账号）。

## PoC

```http
GET /api/<module>/user/info HTTP/1.1
Host: target
Authorization: Bearer <sub=目标用户ID 的有效 JWT>
```

```http
HTTP/1.1 200 OK
{"code":200,"message":"ok","data":{"nickName":"...","avatar":"...","gender":"...","birthday":"...","mobile":"1xxxxxxxxxx","email":"xxx@example.com"}}
```

原文 POC 思路：枚举 id → 用项目的 `buildJWT(sub)` 逻辑生成 `Bearer` token 字典（`tokens.txt`）→ Python 依次放入 `Authorization` 头请求 → 按响应是否含用户资料判定。文中图 10 的 Burp 实测响应显示该接口返回昵称、头像、性别、生日、手机号、邮箱等字段（其余图为代码审计与 token 字典生成过程）。

## 变体与关联

- **前置**：[[web-generic-jwt-demo-passtoken-getusertoken-defaultsecret-forgery]]（硬编码密钥 + 未授权 demo token 接口）。
- **同类 IDOR 用户枚举**：[[web-generic-auth-nuims-getuser-userid-idor-password-hash]]、[[web-generic-auth-imid-userinfo-mobile-pii-enumeration]]、[[web-generic-auth-mobile-person-permission-userid-idor-pii]]、[[web-generic-auth-user-api-plaintext-password-phone-enumeration]]。
- **变体**：除 `sub` 外，很多接口把用户 ID 放在 query/body（`userId=`），效果相同；遍历时注意 WAF 频率限制，可分布式或加延时。
- **升级**：若详情接口返回密码哈希/身份证等更敏感字段，危害升级；若同时存在修改资料接口，可进一步评估账号接管。

## 检测与防御

- **修复**：详情接口做对象级授权——仅允许查询自身资料，或按角色（管理员）校验；`sub` 只作为“当前用户”，资源 ID 必须单独校验归属。
- **数据最小化**：响应中手机号/邮箱等做掩码，按调用者权限返回字段；避免回传不必要 PII。
- **检测**：同一 token 短时间内 `sub` 不变但请求大量不同用户资源；同一来源使用大量不同 `sub` 的 JWT 访问详情接口；用户详情接口访问量异常（批量遍历特征）。
- **加固**：用户 ID 使用不可枚举的 UUID；接口加频控与行为分析。
