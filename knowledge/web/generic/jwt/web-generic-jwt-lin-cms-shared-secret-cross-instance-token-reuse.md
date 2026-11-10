---
id: web-generic-jwt-lin-cms-shared-secret-cross-instance-token-reuse
title: lin-cms-springboot 多实例共用同一 token-secret：在一个站点登录拿到的 Bearer token 可直接访问另一站点的管理接口
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-shared-secret-cross-instance-token-reuse
aliases:
- 跨站点 JWT 复用
- token-secret 共用
- 一证通吃多实例
- Authorization 跨站复用
- lin-cms token 通用
tags:
- jwt
- hs256
- shared-secret
- cross-instance
- horizontal-movement
- authorization-bypass
- cms
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:36:12+08:00'
  notes: 已对照原文核对：两站各自登录取 token、删除 Authorization 头 401+10012、带 A 站 token 打 B 站 /cms/admin/group/all 返回用户组列表(200)，与原文图11-19一致；已把 PoC 中原先误写的 10001 权限不足修正为 10012 请传入认证头字段；未验证点：未复测 identity 在两库不对应时的枚举路径
---

## 一句话结论

由于同一套 lin-cms-springboot 代码在多个实例上沿用 `application.yml` 里同一个 `token-secret`，且服务端只验签不校验"这个 token 是不是本站签发的"，在站点 A 登录后拿到的 `Authorization: Bearer <token>` 原样拿去打站点 B 的 `/cms/admin/**` 接口同样通过——不需要知道 B 的任何账号，也不需要知道 secret。

## 原理

- **验签只依赖 secret**：`DoubleJWT` 的 `JWTVerifier` 用固定 secret 校验签名；只要 secret 相同，A 站签发的 token 在 B 站验签同样通过，服务端不会比对"签发方"。
- **`identity` 是数据库主键而非业务唯一主体**：授权依据是 payload 里的 `identity`（用户 id），而不是"该用户属于哪个站点"。两个实例若用相同的建库/初始化脚本，管理员 id 同为 1，A 站管理员的 token 在 B 站恰好映射到 B 站的管理员。
- **缺少 issuer/audience 绑定**：payload 只有 `type`、`scope`、`identity`、`exp`，没有 `iss`/`aud`/站点标识；即便两站用户 id 不同，只要 `identity` 在那个库里存在且权限足够，也会被接受。
- **为什么危害大于单站提权**：单站提权需要拿到 secret 或管理员口令；跨实例复用只需要"在任意一个实例上拥有一个账号登录"，就能横向拿到所有同 secret 站点的管理权限——攻击面从"一个站"变成"一批用同一份配置部署的站"。
- **原文的验证方式**：在两个站点分别登录拿到 token，把 A 站 token 贴到 B 站请求的 `Authorization` 头，删除该头则返回 401、带上则返回业务数据，证明服务端只认 token 不认来源。

## 触发条件

- 目标是与另一个已知实例同源的 lin-cms-springboot 部署（同一份 `application.yml` 模板、`token-secret` 未按实例改造）。
- 服务端只校验签名与 `identity`，不校验 `iss`/`aud`/站点标识，也不校验 token 与本地会话存储的一致性。
- 攻击者在任意一个同 secret 的实例上拥有可用账号（甚至只需该实例上某个用户的合法 token）。
- 两个实例的 `identity` 含义一致（都用自增主键做授权），且目标 id 在对方库里存在。

## 利用步骤

1. 指纹：至少发现两个同源 lin-cms-springboot 站点（相同路径 `/cms/user/login`、相同错误码 `10021/10031`、相同响应结构）。
2. 在站点 A 用任意账号登录，抓到带 `Authorization: Bearer <token>` 的请求。
3. 直接在站点 B 的同一路径（如 `GET /cms/admin/group/all`）重放，只保留 A 的 token。
4. 对比：删除 `Authorization` 头应返回 401；带上 A 的 token 若返回业务数据，即证明跨实例复用成立。
5. 若 `identity` 在两库中不对应，遍历/试探 1~N 的 `identity`（或结合注册接口拿到自己的 id 后推断管理员 id）寻找可用的高权 id。
6. 复用范围扩大到所有同 secret 实例（同一厂商的 SaaS 多租户部署、镜像批量部署的 CMS 集群）。

## PoC

```http
# 站点 A 登录
POST /cms/user/login HTTP/1.1
Host: site-a
Content-Type: application/json

{"username":"user","password":"pass"}
```

```json
{"access":"eyJ0eXAiOiJKV1Qi...","refresh":"..."}
```

```http
# 用 A 的 token 打站点 B
GET /cms/admin/group/all HTTP/1.1
Host: site-b
Authorization: Bearer eyJ0eXAiOiJKV1Qi...
Accept: application/json
```

```json
# 删除 Authorization 头时：
{"request":"GET /cms/admin/group/all","code":10012,"message":"请传入认证头字段"}
# 带 A 的 token 时：返回用户组列表（200）
```

## 变体与关联

- 变体：secret 相同但用户 id 体系不同时，改用"注册一个账号 → 拿到自己 id → 猜管理员 id（常见 1/2）"的方式定位可用 identity。
- 变体：若两实例共用同一数据库/Redis 会话，则连 token 都不需要伪造，直接复用会话即可。
- 关联：[[web-generic-jwt-lin-cms-fixed-secret-identity-claim-privilege-escalation]]（同产品、同一 secret 下的自签提权，本卡解决"不知道 secret 也能横向"的问题）、[[web-generic-jwt-example-config-hardcoded-secret]]（硬编码密钥的通用面）、[[web-generic-auth-sessionfilter-username-cache-key-session-hijack]]（另一类"会话被他人复用"的鉴权缺陷）。
- 边界：部署方为每个实例生成独立 secret、增加 `iss`/`aud` 校验或站点绑定、把授权改为查本地角色表时失效。

## 检测与防御

- 修复：每个实例使用独立 secret（部署时生成并注入），禁止共用一份 `application.yml`；在 token 中加入 `iss`/`aud`（站点标识）并在验签时强制校验。
- 修复：授权不要直接用自增主键；改为服务端按 (站点, 用户) 查角色，并校验 token 与本地会话/版本号一致。
- 加固：缩短有效期、实现吊销；管理接口做来源与角色二次校验。
- 检测：同一 token 在短时间内出现在多个不同 Host 的请求中；JWT 的 `iss` 缺失或与当前站点不符；跨站点相同 `identity` 的管理请求。
