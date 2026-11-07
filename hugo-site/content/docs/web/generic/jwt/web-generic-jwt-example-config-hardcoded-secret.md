---
id: web-generic-jwt-example-config-hardcoded-secret
title: 示例配置硬编码 JWT SECRET_KEY，用公开默认值伪造 admin 令牌
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-hardcoded-example-secret
tags:
- jwt
- hs256
- hardcoded-secret
- default-config
- authentication-bypass
- admin
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:28:13+08:00'
  notes: 已对照原文核对：env.example 硬编码 SECRET_KEY=quantdinger-secret-key-change-me，原文声明用该密钥自签 admin token，图05 请求携带 HS256 Bearer token 并成功到达 verifyCode，支持该利用链；原文未展示自签过程与前后对比，confidence=medium 合理。PoC 未在本机执行。
url: /docs/web/generic/jwt/web-generic-jwt-example-config-hardcoded-secret/
draft: false
kb_aliases:
- 默认 SECRET_KEY
- env.example 密钥泄露
- 硬编码 JWT 密钥
- 示例配置密钥
- JWT 默认密钥伪造
---

## 一句话结论

项目把 JWT 的 `SECRET_KEY` 硬编码在 `env.example`/README/一键部署脚本里且未强制修改，攻击者拿到这个公开默认值后即可自行签发 `role=admin` 的合法令牌，直接绕过认证。

## 原理

- HS256 用共享 secret 对 header.payload 做 HMAC；验证方用同一 secret 校验。谁掌握 secret，谁就能签发任意 payload。
- 示例配置为了“开箱即用”常写入固定值（如 `change-me`、项目名、`secret`），部署者直接复制 `.env` 后密钥仍是公开值。
- 攻击者从公开仓库、Docker 镜像、部署文档或泄露的 `.env` 取得该值，按应用的 claims 结构（`sub`、`role`、`exp` 等）自签令牌。
- 之所以成立：JWT 的安全性完全依赖密钥保密；密钥一旦公开，签名就不再是信任凭证。

## 触发条件

- 应用使用 HS256/HS384/HS512；
- `SECRET_KEY` 在示例配置、文档或镜像中硬编码且未在启动时强制更换；
- 攻击者能获取该默认值（公开仓库、镜像层、备份、README）；
- 令牌 claims 结构可推断（观察自己账号的 token、前端代码或错误信息）。

## 利用步骤

1. 在目标项目的公开仓库/镜像/文档中查找 `SECRET_KEY`、`JWT_SECRET`、`env.example`。
2. 注册或登录一个普通账号，取得合法 JWT，解析 payload 了解字段结构。
3. 用泄露的 secret 重新签名，把用户标识改为 admin、角色改为管理员、延长 `exp`。
4. 携带伪造令牌访问管理接口；若服务端还校验其他字段（`iss`、`aud`、版本号），按真实 token 补齐。

## PoC

```python
import jwt, time

secret = "<env.example 中的 SECRET_KEY 默认值>"
payload = {
    "sub": "admin",
    "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 86400 * 365,
}
print(jwt.encode(payload, secret, algorithm="HS256"))
```

```http
POST /api/indicator/verifyCode HTTP/1.1
Host: target
Authorization: Bearer <伪造的 token>
Content-Type: application/json

{"code": "..."}
```

响应从 `401` 变为业务成功（如 `Verification passed!`），即认证被绕过。

## 变体与关联

- 变体：默认 secret 在 Docker Compose、Helm values、CI 变量模板中；多环境共用同一 secret；密钥从 `SECRET_KEY` 回退到硬编码字符串；签名算法为 RS256 但私钥随仓库泄露。
- 关联：[[web-generic-jwt-weak-hmac-key-bruteforce]]（密钥弱但未公开，需离线爆破）；[[web-generic-jwt-alg-none-bypass]]、[[web-generic-jwt-rs256-hs256-confusion]]（算法层绕过）。
- 影响边界：需要 HS 系列算法与可获取的默认密钥；若部署时已替换为随机值，则退化为弱密钥爆破问题。
- 置信度说明：原文给出了默认密钥并声明已自签 admin token，后续请求以该 token 成功到达执行接口，但未单独展示 token 签发与前后对比，故 confidence 定为 medium。

## 检测与防御

- 检测：仓库/镜像扫描发现 `SECRET_KEY` 固定值；运行时配置与示例值相同；同一密钥在多环境复用；JWT 的 `sub/role` 与签发来源不匹配。
- 防御：启动时检测 `SECRET_KEY` 是否为默认/空值并拒绝启动；用 `secrets.token_urlsafe` 生成每环境独立密钥；密钥只从密钥管理服务注入，不写入仓库/镜像；定期轮换并使旧 token 失效。
