---
id: web-generic-jwt-xiaozhi-default-hs256-secret-forgery
title: 小智 ESP32 管理平台：JWT 未配置时回退硬编码 HS256 密钥，可伪造 admin 令牌
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-default-hardcoded-hs256-secret
tags:
- jwt
- hs256
- hardcoded-secret
- java
- spring
- auth-bypass
- xiaozhi
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:10:29+08:00'
  notes: 已对照原文与图22-26核对：tryAuthenticateWithToken 取 Authorization Bearer 或 X-WX-Token，validateToken 用 getSecretKey；DEFAULT_SECRET 常量为 xiaozhi_jwt_secret_key_must_be_at_least_256_bits_long_for_hs256，configSecret 为空时回退；jwt.io 以该 secret 验签成功，payload sub=1/username=admin。未验证点：文章未展示用伪造 token 访问后台的请求/响应；frontmatter 无 sources/source_url。
url: /docs/web/generic/jwt/web-generic-jwt-xiaozhi-default-hs256-secret-forgery/
draft: false
kb_aliases:
- 小智 ESP32 JWT 伪造
- xiaozhi_jwt_secret_key_must_be_at_least_256_bits_long_for_hs256
- JWT 默认密钥
- HS256 硬编码密钥
- Authorization Bearer 伪造
- X-WX-Token 伪造
---

## 一句话结论

小智 ESP32 管理平台的 `JwtUtil` 在配置文件未提供 `jwt.secret` 时回退到硬编码常量 `xiaozhi_jwt_secret_key_must_be_at_least_256_bits_long_for_hs256`，并用它做 HS256 签名/校验；攻击者用该公开默认值即可自签 `sub=1`/`username=admin` 的合法 JWT，通过 `Authorization: Bearer` 或 `X-WX-Token` 头直接以管理员身份访问接口。

## 原理

- 鉴权入口：`AuthenticationInterceptor#tryAuthenticateWithToken` 从 `Authorization` 头取 `Bearer <token>`，没有则取 `X-WX-Token` 头，然后 `jwtUtil.validateToken(token)`，通过后 `getUserIdFromToken(token)` 查用户并建会话。
- 密钥逻辑：`private static final String DEFAULT_SECRET = "xiaozhi_jwt_secret_key_must_be_at_least_256_bits_long_for_hs256";`，`@Value("${jwt.secret:#{null}}") private String configSecret;`，`getSecretKey()` 返回 `configSecret != null ? configSecret : DEFAULT_SECRET`，再 `Keys.hmacShaKeyFor(secret.getBytes(UTF_8))`。
- 缺陷：默认密钥是源码中的固定字符串，所有未显式配置 `jwt.secret` 的部署共用同一密钥；系统没有强制修改、没有启动告警、也不是随机生成。HS256 是共享密钥 HMAC，知道密钥即可签发任意 claims。
- 伪造：按应用的 claims 结构生成 token（文章示例 header `{"alg":"HS256"}`，payload 含 `sub:"1"`、`username:"admin"`、`exp`、`iat`、`jti`），用默认密钥签名；`validateToken` 只校验签名与过期，不校验签发者/受众，因此伪造 token 通过。
- 版本差异：文章指出最新版从 token 取 `userId`（`sub`），部分旧版本取 `username`；两种 claims 都可按目标版本构造。
- 危害：无需密码获得 admin 会话与后台全部权限；结合未授权用户查询可确认目标 userId。

## 触发条件

- 目标为小智 ESP32 Server Java 管理平台，且部署未在配置中覆盖 `jwt.secret`（使用默认常量）。
- 攻击者可访问受保护接口，并能发送 `Authorization` 或 `X-WX-Token` 头。
- 目标 JWT 校验只验证签名/过期，不额外校验签发者、受众或 token 版本。

## 利用步骤

1. 确认目标使用 JWT 鉴权（未登录访问受保护接口返回 401；响应/前端代码出现 Bearer）。
2. 用默认密钥 `xiaozhi_jwt_secret_key_must_be_at_least_256_bits_long_for_hs256` 在本地生成 HS256 token，payload 设置 `sub` 为目标 userId（如 admin 的 `1`）或 `username=admin`，`exp` 设为未来时间。
3. 发送请求时带 `Authorization: Bearer <伪造token>`（或 `X-WX-Token: <伪造token>`）。
4. 访问 `/api/config/query`、`/api/user/queryUsers` 等受保护接口，确认返回 200 与管理员数据。
5. 若不知道 userId，先用未授权 `/api/user/query?username=admin` 获取。

## PoC

```text
# 默认密钥（源码常量）
xiaozhi_jwt_secret_key_must_be_at_least_256_bits_long_for_hs256

# Header
{"alg":"HS256"}

# Payload（按最新版取 userId）
{"sub":"1","username":"admin","exp":1764343985,"iat":1764257585,"jti":"a1a2c785-4b88-49cd-8a05-0645153ec2a1"}
```

```http
GET /api/config/query?start=1&limit=10&configType=llm&provider=&configName=&modelType= HTTP/1.1
Host: target.example:10808
Authorization: Bearer <用默认密钥签名的 HS256 token>
Accept: application/json
```

```text
# 预期：HTTP/1.1 200，返回后台配置数据；jwt.io 用上述 secret 校验签名显示 "Signature Verified"。
# 旧版本可把 payload 改为 {"username":"admin"} 走 username 查询分支。
```

## 变体与关联

- 变体：`X-WX-Token` 头与 `Authorization: Bearer` 等价；两者都进入 `validateToken`。
- 变体：旧版本从 token 取 `username`，新版本取 `userId`，按目标版本选择 claims。
- 关联：[[web-generic-jwt-example-config-hardcoded-secret]]（示例配置硬编码 JWT 密钥的通用模式）；[[web-generic-jwt-weak-hmac-key-bruteforce]]（弱 HMAC 密钥爆破）；[[web-generic-auth-xiaozhi-cookie-username-impersonation]]（同系统 Cookie username 冒充）；[[web-generic-auth-xiaozhi-public-paths-user-prefix-unauth-data-exposure]]（获取 userId/username）。
- 边界：文章用 jwt.io 验证了默认密钥可签出合法 token，并在代码层确认校验逻辑；未展示用伪造 token 访问后台的完整请求/响应。

## 检测与防御

- 检测：审计 `JwtUtil` 等签名工具是否存在硬编码默认密钥；检查配置是否覆盖 `jwt.secret`；监控使用同一 secret 签发、claims 异常（`sub=1`、`username=admin`）的 token。
- 修复：移除默认密钥，未配置时启动失败；使用至少 256 位随机密钥并通过环境变量/密钥管理下发；轮换已泄露的默认密钥。
- 加固：JWT 校验增加签发者、受众、kid 与 token 版本校验；短期 token + 刷新机制；管理后台增加二次认证与异常登录检测。
