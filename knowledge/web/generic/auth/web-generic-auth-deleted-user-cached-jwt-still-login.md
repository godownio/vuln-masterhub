---
id: web-generic-auth-deleted-user-cached-jwt-still-login
title: 用户删除后 Redis 缓存的 JWT 未撤销：已删除账号仍可登录查询交易数据
type: scenario
domain: web
path: web/generic/auth
technique: deleted-user-cached-jwt-login-residual
aliases:
- 已删除用户仍可登录
- 删除账号 JWT 残留
- Redis JWT 未失效
- 幽灵账号登录
- 账号删除会话未撤销
tags:
- jwt
- redis
- session
- account-deletion
- auth-bypass
- stale-token
- sensitive-data
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:18:11+08:00'
  notes: 已对照原文数据删除与恢复一节及图 28-30 核对：题目明确 Redis 中 JWT 残留、已删除用户可商家登录、管理员测试账号；原文未给请求级 PoC，卡内判定思路与黄色标记/终端输出一致；未复跑系统。
---

## 一句话结论

系统把登录态以 JWT 形式保存在 Redis 中，但删除 MySQL 用户时只删数据库记录、没有同步撤销 Redis 里的 JWT；在令牌过期前，已删除用户仍可用原账号登录交易数据查询系统（部分账号登录后功能异常但已通过认证），形成“幽灵账号”式的认证残留。

## 原理

- 登录态与用户生命周期解耦：认证中间件通常只校验 JWT 的签名和 `exp`，并信任 payload 中的用户标识（如 user_id/login_id），不再回查用户表；删除用户只执行 `DELETE FROM users ...`，既没有删除 Redis 中的 token key，也没有把该用户写入 token 黑名单或递增 token 版本号。
- Redis 中的 JWT 往往有较长 TTL 或滑动续期；数据库记录消失并不影响 token 本身的有效性，因此旧凭证继续通过认证。
- 这会造成三类登录结果：数据库已删除且 Redis 无 token 的账号登录失败；仍在 Redis 中残留 token 的已删除账号可以登录；由于关联的用户资料/权限数据已从 MySQL 删除，登录后部分页面报错或功能异常（例如提示“用户信息未找到”），但其已认证的 API 仍能访问交易数据。
- 根因是“账号删除没有同时撤销活动会话/令牌”。删除动作必须使所有已签发凭证失效，否则账号删除不构成安全边界；管理员测试账号被删除后残留，危害更大。

## 触发条件

- 应用使用 Redis（或同类缓存）保存 JWT、刷新令牌或会话，认证中间件只验签/查缓存，不回查用户状态。
- 删除用户的实现只删 MySQL 记录，没有删除 Redis token、没有黑名单/版本号机制。
- 攻击者仍掌握被删除账号的登录凭据，或此前获取的 JWT 尚未过期。
- 账号在删除前具有业务或管理权限；删除后权限判断仍依赖 token 中的角色/缓存数据。

## 利用步骤

1. 获取目标系统的用户清单（例如后台导出的 xlsx 用户表），逐一用账号密码尝试登录。
2. 按响应分类：登录失败/直接跳首页；正常登录；登录成功但功能异常（页面报错、数据为空、“用户信息未找到”等）。
3. 重点抓取第三类账号的登录响应和后续业务请求，确认服务端仍接受其 JWT 并返回交易/用户数据。
4. 在用户清单中留意管理员测试账号；若其同样处于“已删除但可登录”状态，尝试访问数据库管理或其他高权限功能。
5. 对可登录的已删除账号做批量验证，并保留登录响应、接口响应作为证据。

## PoC

该案例未给出请求级 PoC，仅给出账号判定与结果整理脚本。最小验证思路：

```python
# 伪代码：逐账号登录，再用返回的 token 访问登录后接口
for user, pwd in users:
    r = sess.post(login_url, json={"username": user, "password": pwd})
    token = r.json().get("token") if r.ok else None
    if token:
        api = sess.get(api_url, headers={"Authorization": "Bearer " + token})
        print(user, api.status_code, api.text[:200])
```

判定要点不是登录页是否报错，而是登录返回的 token 能否继续访问只对登录用户开放的 API；出现“登录成功但业务页面报错”的账号应优先核对是否已被删除。

## 变体与关联

- 同类缺陷：软删除用户但未清理 session；JWT 黑名单缺失；Refresh Token 未撤销；Redis 会话残留；用户改名/降权后旧 token 仍带旧角色。
- 关联场景：JWT 仅验签不校验 role 导致垂直越权；注销-重注册循环复用新人权益（同属账号生命周期缺陷，但目标分别是认证残留与营销风控）。
- 若 Redis 未授权可写，还可主动改写缓存的 JWT/session 伪造身份，属于另一条链。

## 检测与防御

- 删除用户时在同一事务或可靠补偿任务中删除 Redis token/refresh token/session，并将用户状态置为 disabled。
- 认证中间件每次请求校验用户状态或 token 版本号，而不仅验签和过期时间；使用短 TTL access token + 可撤销 refresh token。
- 对已删除用户名的登录和 API 访问设置告警，定期比对 Redis token 主体与用户表。
- 删除后重新登录必须失败：凭据校验要查询用户表，不能只信任缓存中的身份。
